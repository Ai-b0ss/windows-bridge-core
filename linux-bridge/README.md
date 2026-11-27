# FF Linux Bridge v3 (Level 2)

Zero-dependency Python 3.10+ Linux bridge with full **Level 1 (Shell, Code, Files, Processes, Batch)** and **Level 2 (Chrome/Chromium CDP Browser Automation)** capabilities, 100% wire-compatible with [`cloudflare-worker/`](../cloudflare-worker/) and `FlightController` for NAT traversal without a public IP.

## Highlights
- **Zero pip dependencies:** pure Python 3.10+ standard library (including a built-in RFC 6455 WebSocket + Chrome DevTools Protocol client — no 300 MB Playwright browser download required).
- **Wire-compatible with FF Bridge v3:** listens on `http://127.0.0.1:39073/rpc`, authenticates with `X-FF3-Key` (`0600` secret file), supports `request_status` reconciliation and `batch`, and plugs directly into `cloudflare-worker/agent/cf-bridge-agent.mjs`.
- **Safe defaults:** loopback-only bind, atomic UTF-8 file writes with optional `expected_sha256` optimistic locking, process-group timeout termination, optional `--workspace-root` confinement, and loopback-only CDP connections.

## Quick Start (Linux)

```bash
cd linux-bridge
chmod +x install.sh
./install.sh
```

Or run directly without systemd:

```bash
PYTHONPATH=. python3 -m ff_linux_bridge.server --port 39073
```

Check health:

```bash
curl -s http://127.0.0.1:39073/health
```

## Connecting Behind NAT via Cloudflare Worker

Because `ff_linux_bridge` speaks the exact same `/rpc` + `X-FF3-Key` protocol as Windows Bridge v3, you can reuse `cloudflare-worker/agent/cf-bridge-agent.mjs` directly on Linux:

1. Deploy the Cloudflare Worker from [`cloudflare-worker/README.md`](../cloudflare-worker/README.md).
2. Install Node 18+ and run `npm install` inside `cloudflare-worker/`.
3. Create `~/.config/ff-linux-bridge/cf-agent.env`:
   ```bash
   FF_MCP_BASE=https://<your-worker>.workers.dev
   FF_DEVICE_NAME=my-linux-box
   FF_DEVICE_TOKEN_FILE=/home/<user>/.config/ff-linux-bridge/device-token.txt
   FF_RPC_SECRET_FILE=/home/<user>/.config/ff-linux-bridge/rpc-secret.txt
   FF_RPC_URL=http://127.0.0.1:39073/rpc
   ```
4. Start the agent:
   ```bash
   cd cloudflare-worker
   set -a && source ~/.config/ff-linux-bridge/cf-agent.env && set +a
   node agent/cf-bridge-agent.mjs
   ```

## Operations (42 total)

- **System & Shell (12):** `ping`, `capabilities`, `device_status`, `system_info`, `env_info`, `run_shell`, `run_code` (`python`, `bash`, `node`), `process_list`, `process_kill`, `service_status`, `batch`, `request_status`.
- **Files (12):** `read_file`, `write_file`, `patch_file`, `edit_file`, `delete_file`, `list_dir`, `make_dir`, `move_path`, `copy_path`, `file_info`, `find_files`, `search_text`.
- **Browser / CDP (18):** `browser_launch` (headless or headed, auto-detects `chromium`/`google-chrome`), `browser_connect` (attach to an already running Chrome on `127.0.0.1:9222`), `browser_status`, `browser_close`, `browser_tabs`, `browser_open`, `browser_close_tab`, `browser_navigate`, `browser_eval`, `browser_text`, `browser_snapshot`, `browser_click`, `browser_type`, `browser_wait`, `browser_screenshot`, `browser_cookies`, `browser_upload`, `browser_pdf`.

## Running Tests

```bash
cd linux-bridge
PYTHONPATH=. python3 -m unittest discover -s tests -v
```
