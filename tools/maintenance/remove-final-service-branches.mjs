// One-time owner-approved cleanup. Keep SHA and PR identity checks before any deletion.
const REPO = 'Ai-b0ss/windows-bridge-core';
const targets = [
  { name: 'chore/bridge-five-stage-reliability-release-20261114', sha: 'fa4f46d8eeea0d86a9cda4492b99e22f753a1174', pr: 94 },
  { name: 'chore/final-post-release-branch-prune-20261114', self: true },
];
const apply = process.argv.includes('--apply');
const token = process.env.GH_TOKEN;
if (process.env.GITHUB_REPOSITORY !== REPO || !token) throw Error('Repository or GitHub token mismatch');
if (apply && (process.env.GITHUB_EVENT_NAME !== 'push' || process.env.GITHUB_REF !== 'refs/heads/main')) {
  throw Error('Deletion is permitted only after a push to main');
}
const base = 'https://api.github.com/repos/' + REPO;
async function api(method, url, allow404 = false) {
  const response = await fetch(base + url, {
    method,
    headers: {authorization: 'Bearer ' + token, accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28', 'user-agent': 'ff-final-ref-cleanup'},
    signal: AbortSignal.timeout(25000),
  });
  if (allow404 && response.status === 404) return null;
  if (!response.ok) throw Error(method + ' ' + url + ' failed with HTTP ' + response.status);
  return response.status === 204 ? null : response.json();
}
const [open, all] = await Promise.all([
  api('GET','/pulls?state=open&per_page=100'),
  api('GET','/pulls?state=all&per_page=100'),
]);
if (!Array.isArray(open) || open.length >= 100 || !Array.isArray(all) || all.length >= 100) {
  throw Error('PR pagination incomplete; stop rather than risk deleting live branches');
}
const headOwners = open.filter(p => targets.some(t => t.name === p.head?.ref) && p.head?.repo?.full_name === REPO);
for (const t of targets) {
  const expected = t.self
    ? all.find(p => p.head?.ref === t.name && p.head?.repo?.full_name === REPO)
    : all.find(p => p.number === t.pr);
  if (!expected || expected.head?.ref !== t.name || expected.head?.repo?.full_name !== REPO) {
    throw Error('Expected same-repo PR missing for ' + t.name);
  }
  const refUrl = '/git/ref/heads/' + t.name.split('/').map(encodeURIComponent).join('/');
  const initial = await api('GET',refUrl,true);
  if (!initial) {
    console.log('ALREADY_ABSENT ' + t.name);
    continue;
  }
  const sha = t.self ? expected.head?.sha : t.sha;
  if (!/^[a-f0-9]{40}$/.test(sha || '') || initial.object?.sha !== sha ||
      expected.head?.sha !== sha || (t.pr && expected.number !== t.pr)) {
    throw Error('Pinned SHA or PR mismatch for ' + t.name);
  }
  const newOpen = headOwners.filter(p => p.head?.ref === t.name);
  if (newOpen.some(p => !t.self || p.number !== expected.number)) {
    throw Error('Branch now has an unrelated open PR ' + t.name);
  }
  if (apply && (!expected.merged_at || newOpen.length)) {
    throw Error('PR is not merged or branch still has an open PR ' + t.name);
  }
  if (!apply && t.self && !expected.merged_at && expected.state !== 'open') {
    throw Error('Review branch is neither active nor merged');
  }
  if (!apply && !t.self && !expected.merged_at) throw Error('Service branch PR not merged');
  if (!apply) {
    console.log('VERIFIED_DRY_RUN ' + t.name + ' PR#' + expected.number + ' ' + sha);
    continue;
  }
  const fresh = await api('GET',refUrl,true);
  if (!fresh || fresh.object?.sha !== sha) throw Error('Ref moved before deletion: ' + t.name);
  await api('DELETE', '/git/refs/heads/' + t.name.split('/').map(encodeURIComponent).join('/'));
  if (await api('GET',refUrl,true)) throw Error('Ref still exists: ' + t.name);
  console.log('VERIFIED_DELETED ' + t.name + ' PR#' + expected.number + ' ' + sha);
}
console.log('FINAL_HOUSEKEEPING_' + (apply ? 'APPLIED' : 'CHECKED'));
