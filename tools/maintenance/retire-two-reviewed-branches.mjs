// One-time, owner-approved retirement of two legacy refs. Archive survives in Git history.
// This module never removes branches other than the two immutable allowlisted names/SHA values.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = 'Ai-b0ss/windows-bridge-core';
const EXPECTED = Object.freeze([
  { name: 'feat/trusted-skill-input-20261030', sha: 'c86e8809ed5c79f91e2de41df233fcc5192cc3d5' },
  { name: 'security/pin-public-ci-actions-20261027', sha: '0b9688a22e11bda57fb085d7d0d7e8493974ca7c' },
]);
const apply = process.argv.includes('--apply');
const token = process.env.GH_TOKEN;
const base = 'https://api.github.com/repos/' + REPO;

function assert(condition, message) {
  if (!condition) throw Error(message);
}

assert(process.env.GITHUB_REPOSITORY === REPO, 'Unexpected repository');
assert(token, 'GitHub token missing');
if (apply) {
  assert(process.env.GITHUB_EVENT_NAME === 'push', 'Apply requires main push');
  assert(process.env.GITHUB_REF === 'refs/heads/main', 'Apply is restricted to main');
}
const here = path.dirname(fileURLToPath(import.meta.url));
const archive = JSON.parse(fs.readFileSync(path.join(here, 'merged-branches-2026-11-14.json'), 'utf8'));
assert(archive.schema === 'ff-merged-branch-archive-v1' && archive.repository === REPO, 'Archive mismatch');
assert(Array.isArray(archive.preservedBranches) && archive.preservedBranches.length === EXPECTED.length, 'Archive count changed');
for (const target of EXPECTED) {
  assert(archive.preservedBranches.some(x => x.name === target.name && x.sha === target.sha), 'Missing archived immutable SHA: ' + target.name);
}

async function api(method, suffix, missingAllowed = false) {
  const reply = await fetch(base + suffix, {
    method,
    headers: {
      authorization: 'Bearer ' + token,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'ff-reviewed-branch-retirement',
    },
    signal: AbortSignal.timeout(25000),
  });
  if (missingAllowed && reply.status === 404) return null;
  assert(reply.ok, method + ' ' + suffix + ': HTTP ' + reply.status);
  return reply.status === 204 ? null : reply.json();
}

function refSuffix(name) {
  return name.split('/').map(encodeURIComponent).join('/');
}

const [open, pilot, integrated, pinned, main, pinnedCompare] = await Promise.all([
  api('GET', '/pulls?state=open&per_page=100'),
  api('GET', '/pulls/68'),
  api('GET', '/pulls/69'),
  api('GET', '/pulls/51'),
  api('GET', '/branches/main'),
  api('GET', '/compare/' + EXPECTED[1].sha + '...main'),
]);

assert(Array.isArray(open) && open.length < 100, 'Too many open pull requests to audit');
assert(pilot.state === 'closed' && pilot.merged_at === null &&
  pilot.head?.ref === EXPECTED[0].name && pilot.head?.sha === EXPECTED[0].sha, 'Experimental PR 68 provenance changed');
assert(integrated.merged_at && pinned.merged_at, 'Integration/CI PR not merged');
assert(pinnedCompare.status === 'ahead' || pinnedCompare.status === 'identical', 'CI branch not ancestor of main');
assert(main.name === 'main' && main.commit?.sha, 'main ref missing');

let removed = 0;
for (const target of EXPECTED) {
  assert(!open.some(p => p.head?.ref === target.name && p.head?.repo?.full_name === REPO),
    'New open PR uses branch: ' + target.name);
  const ref = refSuffix(target.name);
  const current = await api('GET', '/git/ref/heads/' + ref, true);
  if (!current) {
    console.log('ALREADY_ABSENT ' + target.name);
    continue;
  }
  assert(current.object?.sha === target.sha, 'Head moved; refusing deletion: ' + target.name);
  if (!apply) {
    console.log('VERIFIED_DRY_RUN ' + target.name + ' ' + target.sha);
    continue;
  }
  // Final compare just before deletion; GitHub does not expose conditional DELETE on refs.
  const fresh = await api('GET', '/git/ref/heads/' + ref);
  assert(fresh.object?.sha === target.sha, 'Head raced; refusing deletion: ' + target.name);
  await api('DELETE', '/git/refs/heads/' + ref);
  const gone = await api('GET', '/git/ref/heads/' + ref, true);
  assert(gone === null, 'Ref still present after deletion: ' + target.name);
  removed++;
  console.log('VERIFIED_DELETED ' + target.name + ' ' + target.sha);
}
console.log(JSON.stringify({mode: apply ? 'apply' : 'dry-run', reviewed: EXPECTED.length, deleted: removed, immutable_archive: 'tools/maintenance/merged-branches-2026-11-14.json'}));
