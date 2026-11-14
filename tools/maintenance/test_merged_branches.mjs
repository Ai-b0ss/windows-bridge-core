import test from 'node:test';
import assert from 'node:assert/strict';
import { eligible } from './prune_merged_branches.mjs';

const sha='abcdef0123456789abcdef0123456789abcdef01';
const entry={name:'fix/squashed-merged-patch',sha,pr:42};
const branch={name:entry.name,commit:{sha}};
const pr={number:42,merged_at:'2026-11-14T10:00:00Z',head:{ref:entry.name,sha,repo:{full_name:'Ai-b0ss/windows-bridge-core'}}};

test('accepts only unchanged SHA and an already-merged PR', () => {
  assert.equal(eligible(entry,branch,pr),true);
});
test('rejects branches updated after merge, unmerged, foreign or changed PRs', () => {
  assert.equal(eligible(entry,{...branch,commit:{sha:'f'.repeat(40)}},pr),false);
  assert.equal(eligible(entry,branch,{...pr,merged_at:null}),false);
  assert.equal(eligible(entry,branch,{...pr,number:43}),false);
  assert.equal(eligible(entry,branch,{...pr,head:{...pr.head,sha:'f'.repeat(40)}}),false);
  assert.equal(eligible(entry,branch,{...pr,head:{...pr.head,repo:{full_name:'other/repo'}}}),false);
});
test('rejects newly opened PRs, main and unsafe names', () => {
  assert.equal(eligible(entry,branch,pr,[{head:{ref:entry.name,repo:{full_name:'Ai-b0ss/windows-bridge-core'}}}]),false);
  assert.equal(eligible({...entry,name:'main'},branch,pr),false);
  assert.equal(eligible({...entry,name:'../../private'},branch,pr),false);
});
