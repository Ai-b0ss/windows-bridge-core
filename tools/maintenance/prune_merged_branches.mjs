import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPOSITORY = 'Ai-b0ss/windows-bridge-core';
const directory = path.dirname(fileURLToPath(import.meta.url));
const archiveFile = path.join(directory, 'merged-branches-2026-11-14.json');

export function eligible(entry, branch, pr, openPrs = []) {
  if (!entry || !/^(docs|feat|fix|p0|security|test)\/[a-zA-Z0-9_.-]+$/.test(entry.name)) return false;
  if (!/^[a-f0-9]{40}$/.test(entry.sha || '')) return false;
  if (!branch || branch.name !== entry.name || branch.commit?.sha !== entry.sha) return false;
  if (!pr || pr.number !== entry.pr || !pr.merged_at) return false;
  if (pr.head?.ref !== entry.name || pr.head?.sha !== entry.sha || pr.head?.repo?.full_name !== REPOSITORY) return false;
  if (openPrs.some(p => p.head?.ref === entry.name && p.head?.repo?.full_name === REPOSITORY)) return false;
  return true;
}

async function run() {
  const apply = process.argv.includes('--apply');
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (process.env.GITHUB_REPOSITORY !== REPOSITORY || !token) {
    throw Error('Expected repository and GitHub Actions token are required');
  }
  if (apply && (process.env.GITHUB_EVENT_NAME !== 'push' || process.env.GITHUB_REF !== 'refs/heads/main')) {
    throw Error('Deletion is allowed only on a reviewed push to main');
  }
  const archive = JSON.parse(fs.readFileSync(archiveFile, 'utf8'));
  if (archive.schema !== 'ff-merged-branch-archive-v1' || archive.repository !== REPOSITORY) throw Error('Invalid archive');
  const records = archive.candidates;
  if (!Array.isArray(records) || records.length !== 62 || new Set(records.map(x => x.name)).size !== records.length) {
    throw Error('Pinned allowlist size or uniqueness differs from review');
  }
  async function api(method, endpoint, allow404 = false) {
    const result = await fetch('https://api.github.com/repos/' + REPOSITORY + endpoint, {
      method,
      headers: {
        authorization: 'Bearer ' + token,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'ff-branch-housekeeping'
      },
      signal: AbortSignal.timeout(20000)
    });
    if (allow404 && result.status === 404) return null;
    if (!result.ok) throw Error(method + ' ' + endpoint + ' HTTP ' + result.status);
    return result.status === 204 ? null : result.json();
  }
  async function allPages(endpoint) {
    const output = [];
    for (let page = 1; page <= 5; page++) {
      const suffix = (endpoint.includes('?') ? '&' : '?') + 'per_page=100&page=' + page;
      const rows = await api('GET', endpoint + suffix);
      if (!Array.isArray(rows)) throw Error('Invalid collection result');
      output.push(...rows);
      if (rows.length < 100) return output;
    }
    throw Error('Too many pages, manual review required');
  }
  const [branches, closed, open] = await Promise.all([
    allPages('/branches'), allPages('/pulls?state=closed'), allPages('/pulls?state=open')
  ]);
  const branchMap = new Map(branches.map(b => [b.name, b]));
  const prMap = new Map(closed.map(p => [p.number, p]));
  let eligibleCount = 0, absent = 0, protectedCount = 0, deleted = 0;
  for (const record of records) {
    const branch = branchMap.get(record.name);
    if (!branch) { absent++; console.log('ALREADY_ABSENT ' + record.name); continue; }
    if (!eligible(record, branch, prMap.get(record.pr), open)) {
      protectedCount++;
      console.log('SKIPPED_CHANGED_OR_UNVERIFIED ' + record.name);
      continue;
    }
    eligibleCount++;
    if (!apply) { console.log('SAFE_DRY_RUN ' + record.name + ' PR#' + record.pr); continue; }
    const ref = record.name.split('/').map(encodeURIComponent).join('/');
    const fresh = await api('GET', '/git/ref/heads/' + ref, true);
    if (!fresh || fresh.object?.sha !== record.sha) {
      protectedCount++;
      console.log('SKIPPED_SHA_RACE ' + record.name);
      continue;
    }
    await api('DELETE', '/git/refs/heads/' + ref);
    deleted++;
    console.log('DELETED ' + record.name + ' PR#' + record.pr + ' ' + record.sha);
  }
  console.log(JSON.stringify({mode: apply ? 'apply' : 'dry-run', pinned: records.length, eligible: eligibleCount, deleted, absent, preserved: protectedCount, deliberatelyUnlisted: archive.preservedBranches.length}));
  if (!apply && (eligibleCount + absent !== records.length || protectedCount)) throw Error('Live branch state differs from pinned archive; stop and review');
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(error => { console.error('CLEANUP_FAILED ' + error.message); process.exitCode = 1; });
}
