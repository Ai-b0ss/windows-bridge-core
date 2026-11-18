"""Real owned Chrome affinity, quota and reconnect through a disposable Windows Hub."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time

from private_product_acceptance import ProductGate, Observer, check
from cua_private_browser import MAX_TABS
from ff_hub import HubError
from ff_win_process_identity import process_identity_matches


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        content = b'<!doctype html><title>Affinity fixture</title><h1>Affinity fixture</h1>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        self.server.posts += 1
        self.send_response(204)
        self.end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    output = parser.parse_args().output.resolve()
    check(not output.exists(), 'OUTPUT_MUST_BE_NEW')
    gate = ProductGate(output)
    observer = Observer()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    server.posts = 0
    threading.Thread(target=server.serve_forever, daemon=True).start()
    result = {}
    failure = None
    try:
        gate.start()
        client = gate.client('one')
        browser = gate.call(client, 'private_browser', {'command': 'open'}, 'affinity-open')
        gate.own_tree(browser['pid'])
        browser_id = browser['browser_id']
        check(observer.window(browser['desktop'], browser['hwnd'], browser['pid']), 'CHROME_NOT_ON_PRIVATE_DESKTOP')
        tab = gate.browser(client, browser_id, 'tabs')['tabs'][0]['tab_id']
        url = f'http://127.0.0.1:{server.server_port}/'
        gate.browser(client, browser_id, 'navigate', 'affinity-navigate', tab_id=tab, url=url)
        gate.wait_read(client, browser_id, tab, 'Affinity fixture')
        initial = gate.browser(client, browser_id, 'info')
        check(not ({'cdp_port', 'cdp_endpoint', 'browser_ws_endpoint', 'browser_ws_path'} & initial.keys()), 'RAW_ENDPOINT_LEAK')
        args = {'browser_id': browser_id, 'command': 'evaluate', 'tab_id': tab,
                'expression': 'window.counter = (window.counter || 0) + 1'}
        started = time.monotonic()
        for index in range(100):
            check(gate.call(client, 'private_browser', args, f'affinity-mutation-{index}')['value'] == index + 1,
                  'WRONG_FIXTURE_COUNTER')
        duration = time.monotonic() - started
        replay = gate.call(client, 'private_browser', args, 'affinity-mutation-99')
        check(replay['deduplicated'] and replay['value'] == 100, 'DURABLE_DUPLICATE_EXECUTION')
        transport = gate.browser(client, browser_id, 'info')['transport']
        check(transport['generation'] == initial['transport']['generation'] == 1, 'UNEXPECTED_CDP_RECONNECT')
        check(transport['attached_tabs'] == 1, 'UNEXPECTED_TAB_ATTACHMENT')
        tabs = gate.browser(client, browser_id, 'tabs')
        check(len(tabs['tabs']) == 1 and tabs['tabs'][0]['tab_id'] == tab and tabs['unclaimed_pages'] == 0,
              'TARGET_AFFINITY_OR_TAB_LEAK')
        result.update(operations=100, elapsed_seconds=round(duration, 2), connections_during_repeat=1,
                      stable_browser_and_tab=True, deduplicated=True)

        extras = [gate.browser(client, browser_id, 'tab_open', f'affinity-tab-{index}')['tab_id']
                  for index in range(MAX_TABS - 1)]
        gate.call(client, 'private_browser', {'browser_id': browser_id, 'command': 'tab_open'},
                  'affinity-tab-over-quota', expect='PRIVATE_TAB_LIMIT')
        check(len(gate.browser(client, browser_id, 'tabs')['tabs']) == MAX_TABS, 'QUOTA_DID_NOT_BIND')
        for index, extra in enumerate(extras):
            gate.browser(client, browser_id, 'tab_close', f'affinity-close-{index}', tab_id=extra)
        check([item['tab_id'] for item in gate.browser(client, browser_id, 'tabs')['tabs']] == [tab], 'CLOSE_TAB_LEAK')
        result['tab_cap'] = MAX_TABS

        timeout_args = {**args, 'timeout_s': .15, 'expression':
                        "new Promise(resolve=>setTimeout(()=>fetch('/late',{method:'POST'}).then(resolve),700))"}
        try:
            gate.call(client, 'private_browser', timeout_args, 'affinity-unknown')
        except HubError as error:
            check(error.code == 'PRIVATE_CDP_OUTCOME_UNKNOWN', 'UNEXPECTED_TIMEOUT_ERROR_' + error.code)
        else:
            raise RuntimeError('MISSING_TIMEOUT')
        check(gate.call(client, 'request_status', {'request_key': 'affinity-unknown'})['state'] == 'unknown',
              'MISSING_UNKNOWN_RECEIPT')
        gate.call(client, 'private_browser', timeout_args, 'affinity-unknown', expect='REQUEST_OUTCOME_UNKNOWN')
        readback = gate.browser(client, browser_id, 'evaluate', 'affinity-readback', tab_id=tab, expression='window.counter')
        check(readback['value'] == 100, 'RECONNECT_LOST_PAGE_STATE')
        recovered = gate.browser(client, browser_id, 'info')['transport']
        check(recovered['generation'] == transport['generation'] + 1 and recovered['attached_tabs'] == 1,
              'RECONNECT_DID_NOT_REATTACH_EXACT_TARGET')
        time.sleep(.8)
        check(server.posts == 1, 'LATE_MUTATION_NOT_EFFECT_ONCE')
        check(gate.cancel(client)['cleanup_verified'] and not Path(browser['profile_path']).exists(), 'PROFILE_LEAK')
        result.update(connections_after_fault=2, independent_server_posts=server.posts, unknown_receipt=True,
                      profile_removed=True)
    except Exception as error:
        failure = error
    finally:
        try:
            gate.cleanup()
        except Exception as error:
            failure = failure or error
        server.shutdown()
        server.server_close()
        gate.log.close()
        observation = observer.finish(output, gate.owned)
        failure = failure or (RuntimeError('OWNER_OBSERVER_FAILED') if not observation['samples'] or observation['error']
                              or observation['foreground_owned'] or observation['private_input'] else None)
        result.update(status='FAIL' if failure else 'PASS', error=str(failure) if failure else None,
                      owner_observer=observation,
                      owned_processes_closed=not any(process_identity_matches(*item) for item in gate.owned))
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False))
    return int(failure is not None)


if __name__ == '__main__':
    raise SystemExit(main())
