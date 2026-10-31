// Node check run by tests/test_browser_observed_change.py (no browser needed).
import {BrowserSidecar} from '../runtime/bridge-v3/cua_browser_sidecar.mjs';

function engine(fingerprints, verifyResult) {
  let i = 0;
  return {
    attach: async () => ({}), capabilities: async () => ({}),
    fingerprint: async () => fingerprints[Math.min(i++, fingerprints.length - 1)],
    snapshot: async () => ({fingerprint: 'A', entities: [{role: 'button', name: 'Go', actions: ['click', 'hover']}]}),
    resolve: async () => ({locator: {}, ambiguous: false, changed: false}),
    act: async () => ({}), verify: async () => verifyResult, identity: async () => ({}),
  };
}

async function run(fps, action, verify) {
  const sc = new BrowserSidecar(engine(fps, {verified: false, reason: 'postcondition_required'}));
  const {surface_id} = await sc.attach({});
  const obs = await sc.observe(surface_id);
  // fingerprint() is called twice in act: before, after (the snapshot is always 'A')
  return sc.act(surface_id, {ref: obs.entities[0].ref, generation: obs.generation, action, verify});
}

const out = {};
// before 'A', after 'B' -> page changed
out.click_changed = (await run(['A', 'B'], 'click', null)).verified;
out.click_changed_kind = (await run(['A', 'B'], 'click', null)).verification_result?.kind;
// nothing changed -> must stay unverified
out.click_unchanged = (await run(['A', 'A'], 'click', null)).verified;
// hover must never be promoted
out.hover_changed = (await run(['A', 'B'], 'hover', null)).verified;
// caller-supplied postcondition is left to the engine
out.explicit_postcondition = (await run(['A', 'B'], 'click', {url: 'x'})).verified;
console.log(JSON.stringify(out));
