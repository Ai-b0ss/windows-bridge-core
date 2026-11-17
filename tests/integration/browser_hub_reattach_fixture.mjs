// Child process for browser_hub_reattach_smoke.mjs: the real BrowserHub over a real CDP
// connection to a disposable headless Chromium. Never the owner's Chrome or profile.
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {BrowserHub, serve} from '../../runtime/bridge-v3/ff_browser_hub.mjs';

const [endpointFile, ledgerFile, cdpPort, playwrightRoot] = process.argv.slice(2);
const {chromium} = createRequire(path.join(playwrightRoot, 'package.json'))('playwright-core');
const connector = {
  describe: () => ({transport: 'cdp-isolated-test-browser', isolated_profile: true}),
  async connect() {
    const browser = await chromium.connectOverCDP(`http://127.0.0.1:${cdpPort}`);
    const context = browser.contexts()[0];
    return {browser, context, async listTargetIds() {
      const session = await browser.newBrowserCDPSession();
      try { return (await session.send('Target.getTargets')).targetInfos.filter(info => info.type === 'page').map(info => info.targetId); }
      finally { await session.detach().catch(() => {}); }
    }};
  },
};
const hub = new BrowserHub(connector, {ledgerFile});
const server = await serve(hub, {key: process.env.FF_BROWSER_HUB_KEY});
fs.writeFileSync(endpointFile, JSON.stringify({port: server.address().port}));
