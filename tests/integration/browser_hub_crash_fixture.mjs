// Synthetic page adapter only. Real Node HTTP/lifecycle; no Chrome or credentials.
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import {BrowserHub, serve} from '../../runtime/bridge-v3/ff_browser_hub.mjs';

const [endpoint, effects] = process.argv.slice(2);
class Page extends EventEmitter {
  address = 'about:blank'; closed = false;
  isClosed() { return this.closed; }
  url() { return this.address; }
  mainFrame() { return this; }
  async title() { return 'synthetic'; }
  async goto(url) { this.address = url; }
  async close() { this.closed = true; this.emit('close'); }
  async evaluate() {
    fs.appendFileSync(effects, 'effect\n');
    // A durable synthetic effect precedes abrupt loss of response and page handles.
    process.exit(77);
  }
}
const browser = new EventEmitter();
browser.isConnected = () => true;
browser.close = async () => {};
const context = new EventEmitter();
context.newPage = async () => new Page();
const hub = new BrowserHub({describe: () => ({synthetic: true}), connect: async () => ({browser, context})});
const server = await serve(hub, {key: process.env.FF_BROWSER_HUB_KEY});
fs.writeFileSync(endpoint, JSON.stringify({port: server.address().port}));
