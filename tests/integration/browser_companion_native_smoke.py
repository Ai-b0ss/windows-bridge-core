"""Windows Native Messaging acceptance with disposable headless Chrome for Testing."""
from __future__ import annotations

import argparse
from collections import deque
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import queue
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import winreg

RUNTIME = Path(__file__).resolve().parents[2] / 'runtime' / 'bridge-v3'
sys.path.insert(0, str(RUNTIME))
from cua_browser_companion import BrowserCompanionClient, CompanionError
from cua_universal_fastpath import _LocalWebSocket
from ff_win_owned_job import OwnedJobProcess

EXTENSION_ID = 'mmhkecdcdceeibbhalmfhjleeebgdbhk'
HOST_NAME = 'com.ff.browser_companion'
REGISTRY = r'Software\Google\Chrome\NativeMessagingHosts'
CONTENT = b'FF Browser Companion isolated test\n'
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Fixture(http.server.BaseHTTPRequestHandler):
    def handle(self):
        with contextlib.suppress(ConnectionResetError):
            super().handle()

    def do_GET(self):
        if self.path.startswith('/file?'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename="probe.bin"')
            self.send_header('Content-Length', str(len(CONTENT)))
            self.end_headers()
            self.wfile.write(CONTENT)
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'<!doctype html><title>isolated FF Companion test</title>')

    def log_message(self, *_args):
        pass


def fetch(port, path):
    with OPENER.open(f'http://127.0.0.1:{port}{path}', timeout=1.0) as response:
        return json.load(response)


def wait_for(check, *, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.075)
    raise TimeoutError('COMPANION_GATE_TIMEOUT')


def cdp(endpoint, method, params=None):
    ws = _LocalWebSocket(endpoint, 4)
    try:
        ws.send(json.dumps({'id': 1, 'method': method, 'params': params or {}}))
        while True:
            response = json.loads(ws.recv())
            if response.get('id') == 1:
                if response.get('error'):
                    raise RuntimeError(f'CDP_FAILED_{method}')
                return response['result']
    finally:
        ws.close()


def evaluate(target, expression):
    reply = cdp(target['webSocketDebuggerUrl'], 'Runtime.evaluate', {
        'expression': expression, 'returnByValue': True, 'awaitPromise': True,
    })
    if reply.get('exceptionDetails'):
        raise RuntimeError('FIXTURE_EVALUATION_FAILED')
    return reply['result'].get('value')


def verify_native_host_exit(host, *, with_pending_request=False):
    origin = f'chrome-extension://{EXTENSION_ID}/'
    proc = subprocess.Popen([str(host), origin], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    frames = queue.Queue()

    def read_frames():
        while prefix := proc.stdout.read(4):
            count = int.from_bytes(prefix, 'little')
            if not 0 < count < 4096:
                return
            frames.put(json.loads(proc.stdout.read(count)))

    reader = threading.Thread(target=read_frames, daemon=True)
    reader.start()
    try:
        assert frames.get(timeout=8) == {'type': 'host_ready', 'protocol_version': 1}
        if with_pending_request:
            try:
                BrowserCompanionClient(host.parent).request('health', timeout_ms=500)
            except CompanionError as error:
                assert error.code == 'BROWSER_COMPANION_IPC_RESPONSE_TIMEOUT'
            else:
                raise AssertionError('RESPONSE_TIMEOUT_NOT_ENFORCED')
            command = frames.get(timeout=2)
            assert command['type'] == 'command' and command['method'] == 'health' and 'auth' not in command
        proc.stdin.close()
        assert proc.wait(timeout=4) == 0
        assert proc.stderr.read() == b''
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=4)
        reader.join(timeout=1)
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()


@contextlib.contextmanager
def registration(name, manifest, root):
    key_path = REGISTRY + '\\' + name
    manifest_path = root / 'isolated-native-host.json'
    manifest_path.write_text(json.dumps({**manifest, 'name': name}), encoding='utf-8')
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, '', 0, winreg.REG_SZ, str(manifest_path))
    try:
        yield
    finally:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _ = winreg.QueryValueEx(key, '')
        if value != str(manifest_path):
            raise RuntimeError('TEST_REGISTRATION_OWNERSHIP_CHANGED')
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)


def run(chrome, downloads):
    with tempfile.TemporaryDirectory(prefix='ff-companion-smoke-') as directory:
        root = Path(directory).resolve()
        bridge = root / 'bridge'
        installer = RUNTIME / 'cua_browser_companion_install.ps1'
        powershell = shutil.which('pwsh.exe') or 'powershell.exe'
        build = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-File', str(installer),
                                '-BridgeRoot', str(bridge), '-SkipChromeRegistration'],
                               capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if build.returncode:
            raise RuntimeError('COMPANION_BUILD_FAILED: ' + build.stderr.decode('utf-8', 'replace').strip())
        host_manifest = json.loads((bridge / 'cua_browser_companion_native_host.json').read_text())
        (bridge / 'secret').write_text(secrets.token_hex(32), encoding='ascii')
        verify_native_host_exit(Path(host_manifest['path']))
        verify_native_host_exit(Path(host_manifest['path']), with_pending_request=True)
        ext = bridge / 'browser_companion'
        worker = ext / 'service_worker.js'
        host_name = HOST_NAME + '_test_' + secrets.token_hex(12)
        source = worker.read_text(encoding='utf-8')
        marker = "const HOST = '" + HOST_NAME + "';"
        if source.count(marker) != 1:
            raise RuntimeError('TEST_HOST_MARKER_MISSING')
        worker.write_text(source.replace(marker, f"const HOST = '{host_name}';"), encoding='utf-8')
        profile = root / 'profile'
        default = profile / 'Default'
        default.mkdir(parents=True)
        download_dir = root / 'downloads'
        download_dir.mkdir()
        (default / 'Preferences').write_text(json.dumps({'download': {
            'default_directory': str(download_dir), 'prompt_for_download': False, 'directory_upgrade': True,
        }}), encoding='utf-8')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f'http://127.0.0.1:{server.server_port}'
        proc = OwnedJobProcess([str(chrome), '--headless=new', f'--user-data-dir={profile}',
                                '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check',
                                '--disable-background-networking', f'--load-extension={ext}', origin],
                               cwd=str(root), env=os.environ)
        stderr_tail = deque(maxlen=20)
        def drain_stderr():
            for line in proc.stderr:
                stderr_tail.append(line.decode('utf-8', 'replace').strip())
        threading.Thread(target=drain_stderr, daemon=True).start()
        try:
            active_port = profile / 'DevToolsActivePort'
            def chrome_started():
                if proc.poll() is not None:
                    raise RuntimeError(f'CHROME_EXITED_BEFORE_START: {proc.returncode}, {list(stderr_tail)}')
                return active_port.is_file()
            wait_for(chrome_started, timeout=30)
            port = int(active_port.read_text('ascii').splitlines()[0])
            targets = lambda: fetch(port, '/json/list')
            ext_url = f'chrome-extension://{EXTENSION_ID}/service_worker.js'
            worker_target = wait_for(lambda: next((item for item in targets() if item['url'] == ext_url), None))
            page = wait_for(lambda: next((item for item in targets() if item['url'] == origin + '/'), None))
            diagnostics = lambda: evaluate(worker_target, 'globalThis.ffCompanionDiagnostics?.()')
            def missing_host():
                state = diagnostics()
                return state if state and state.get('last_disconnect_code') == 'HOST_NOT_FOUND' else None
            missing = wait_for(missing_host)
            with registration(host_name, host_manifest, root):
                client = BrowserCompanionClient(bridge)
                connected = wait_for(lambda: safe_health(client))
                assert connected['protocol_version'] == 1 and connected['downloads'] is True
                assert connected['native_connection']['state'] == 'CONNECTED'
                assert connected['native_messaging'] is True and connected['physical_input'] is False
                wrong_root = root / 'wrong-auth'
                wrong_root.mkdir()
                (wrong_root / 'secret').write_text(secrets.token_hex(32), encoding='ascii')
                try:
                    BrowserCompanionClient(wrong_root, pipe_path=client.pipe_path).health()
                except CompanionError as error:
                    assert error.code == 'IPC_AUTH_FAILED'
                else:
                    raise AssertionError('UNAUTHORIZED_IPC_REQUEST_ACCEPTED')
                for number in range(downloads):
                    operation_id = f'dl-companion-{number:04d}'
                    url = f'{origin}/file?operation={number}'
                    spec = {'operation_id': operation_id, 'expected_url': url,
                            'expected_filename': 'probe.bin', 'timeout_ms': 25000}
                    assert client.prepare_download(spec)['state'] == 'PREPARED'
                    cdp(page['webSocketDebuggerUrl'], 'Page.navigate', {'url': url})
                    result = client.wait_download(operation_id, 23000)
                    if result['state'] != 'COMPLETE':
                        browser_item = evaluate(worker_target, 'chrome.downloads.search({limit:1}).then(items => items.map(({state,danger,error,bytesReceived,totalBytes}) => ({state,danger,error,bytesReceived,totalBytes})))')
                        raise AssertionError((number, result['state'], result['terminal_reason'], browser_item))
                    filename = Path(result['item']['filename'])
                    assert filename.parent == download_dir / 'FF-CUA' / operation_id
                    assert hashlib.sha256(filename.read_bytes()).digest() == hashlib.sha256(CONTENT).digest()
                    assert client.cleanup_download(operation_id)['cleanup_complete'] is True
                    assert not filename.exists()
                result = {'ok': True, 'chrome': fetch(port, '/json/version')['Browser'],
                          'installed_extension_version': connected['extension_version'],
                          'missing_host': missing, 'native_handshake': connected['native_connection'],
                          'owned_downloads_verified_and_removed': downloads,
                          'idle_native_host_eof_exit': True, 'pending_native_host_eof_exit': True,
                          'ipc_response_timeout': True, 'wrong_secret_denied': True,
                          'profile_isolation': True, 'physical_input': False}
        finally:
            proc.terminate_tree(timeout=10)
            result_members = proc.active_members()
            proc.close()
            server.shutdown()
            server.server_close()
        result['owned_job_members_after_cleanup'] = result_members
        with contextlib.suppress(FileNotFoundError):
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY + '\\' + host_name):
                raise RuntimeError('TEST_REGISTRATION_LEAKED')
        result['disposable_registration_removed'] = True
        return result


def safe_health(client):
    try:
        return client.health()
    except CompanionError as error:
        if error.code != 'BROWSER_COMPANION_UNAVAILABLE':
            raise
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chrome-for-testing', type=Path, required=True)
    parser.add_argument('--downloads', type=int, default=35)
    args = parser.parse_args()
    if not args.chrome_for_testing.is_file() or args.downloads < 1:
        parser.error('provide an existing Chrome for Testing executable and a positive download count')
    print(json.dumps(run(args.chrome_for_testing.resolve(), args.downloads), ensure_ascii=False))
