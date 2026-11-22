import sys,tempfile,unittest,json
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/bridge-v3'))
from cua_private_browser import MAX_TABS,PrivateBrowser,PrivateBrowserError,_BrowserConnection,safe_name,valid_url,READ_COMMANDS
from ff_hub import Hub,HubError

class BrokerContracts(unittest.TestCase):
    def test_external_paths_and_unsafe_urls_fail_before_io(self):
        for value in ('../secret','C:/secret','a\\b','..','a..b','NUL.txt','com1','file.','',None):
            with self.subTest(value=value),self.assertRaises(PrivateBrowserError):safe_name(value)
        for value in ('file:///C:/secret','javascript:alert(1)','http://user:pass@example.com','http://[invalid',None):
            with self.subTest(value=value),self.assertRaises(PrivateBrowserError):valid_url(value)
        self.assertEqual(valid_url('https://example.com/path'),'https://example.com/path')
    def test_postcondition_and_stale_ref_denied_before_effect(self):
        b=PrivateBrowser.__new__(PrivateBrowser);b.snapshots={'tab':'current'};b.page=Mock();b.send=Mock();b.evaluate=Mock()
        with self.assertRaisesRegex(PrivateBrowserError,'PRIVATE_POSTCONDITION_REQUIRED'):
            b.dispatch({'command':'act','tab_id':'tab','snapshot':'old','ref':'0','operation':'click'})
        with self.assertRaisesRegex(PrivateBrowserError,'PRIVATE_STALE_TARGET'):
            b.dispatch({'command':'act','tab_id':'tab','snapshot':'old','ref':'0','operation':'click','postcondition':{'type':'text_includes','value':'ok'}})
        b.send.assert_not_called();b.evaluate.assert_not_called()
    def test_mutations_never_classified_as_reads(self):
        for command in ('act','upload','evaluate','navigate','tab_open','tab_close','download_prepare'):self.assertNotIn(command,READ_COMMANDS)
    def browser_with_connection(self):
        broker=PrivateBrowser.__new__(PrivateBrowser)
        broker.verified_chrome=Mock(return_value={'cdp_port':1234,'browser_ws_endpoint':'ws://127.0.0.1:1234/devtools/browser/a'})
        broker.tabs={'tab'}
        broker.cdp=_BrowserConnection()
        return broker

    def test_target_session_and_upload_object_stay_on_the_same_socket(self):
        import cua_private_browser as module
        broker=self.browser_with_connection()
        socket=Mock()
        socket.recv.side_effect=[json.dumps(reply) for reply in (
            {'id':1,'result':{'sessionId':'attached-tab'}},
            {'id':2,'sessionId':'attached-tab','result':{'result':{'objectId':'connection-local-object'}}},
            {'id':3,'sessionId':'attached-tab','result':{}},
            {'id':4,'sessionId':'attached-tab','result':{'result':{'value':42}}})]
        with patch.object(module,'_LocalWebSocket',return_value=socket) as constructor:
            broker.send('Runtime.evaluate',{},'tab',followup=lambda result:('DOM.setFileInputFiles',{'objectId':result['result']['objectId'],'files':['owned-fixture']}))
            self.assertEqual(broker.evaluate('tab','42'),42)
        self.assertEqual(constructor.call_count,1)
        requests=[json.loads(call.args[0]) for call in socket.send.call_args_list]
        self.assertEqual(requests[0]['params'],{'targetId':'tab','flatten':True})
        self.assertEqual([request['sessionId'] for request in requests[1:]],['attached-tab']*3)
        self.assertEqual(requests[2]['params']['objectId'],'connection-local-object')
        socket.close.assert_not_called()

    def test_partial_send_is_unknown_and_only_the_next_command_reattaches(self):
        import cua_private_browser as module
        broker=self.browser_with_connection()
        first, second=Mock(),Mock()
        first.recv.return_value=json.dumps({'id':1,'result':{'sessionId':'first-session'}})
        first.send.side_effect=[None,TimeoutError('partial send')]
        second.recv.side_effect=[json.dumps(reply) for reply in (
            {'id':3,'result':{'sessionId':'second-session'}},
            {'id':4,'sessionId':'second-session','result':{'result':{'value':'still owned'}}})]
        with patch.object(module,'_LocalWebSocket',side_effect=[first,second]) as constructor:
            with self.assertRaisesRegex(PrivateBrowserError,'PRIVATE_CDP_OUTCOME_UNKNOWN') as failure:
                broker.evaluate('tab','effect()')
            self.assertTrue(failure.exception.details['outcome_unknown'])
            self.assertEqual(constructor.call_count,1)
            self.assertEqual(broker.evaluate('tab','read()'),'still owned')
        first.close.assert_called_once()
        self.assertEqual(json.loads(second.send.call_args_list[0].args[0])['params']['targetId'],'tab')
        self.assertEqual(json.loads(second.send.call_args_list[1].args[0])['params']['expression'],'read()')

    def test_new_targets_cannot_exceed_limit_or_retry_an_unknown_creation(self):
        broker=self.browser_with_connection()
        broker.unknown_tab_open=False
        broker.pages=Mock(return_value=[{'targetId':str(i)} for i in range(MAX_TABS)])
        broker.send=Mock(side_effect=PrivateBrowserError('PRIVATE_CDP_OUTCOME_UNKNOWN',outcome_unknown=True))
        with self.assertRaisesRegex(PrivateBrowserError,'PRIVATE_TAB_LIMIT'):
            broker.dispatch({'command':'tab_open'})
        broker.send.assert_not_called()
        broker.pages.return_value=[]
        with self.assertRaisesRegex(PrivateBrowserError,'PRIVATE_CDP_OUTCOME_UNKNOWN'):
            broker.dispatch({'command':'tab_open'})
        with self.assertRaisesRegex(PrivateBrowserError,'PRIVATE_TAB_OPEN_RECONCILIATION_REQUIRED'):
            broker.dispatch({'command':'tab_open'})
        broker.send.assert_called_once()

class DurableProductContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.hub=Hub(Path(self.temp.name),browser=Mock(running=Mock(return_value=False)))
        self.addCleanup(self.hub.store.close);self.addCleanup(self.hub.shutdown)
        self.session=self.hub.dispatch({'op':'session_open','args':{'agent_id':'agent','task_id':'task'}})
    def call(self,op,args=None,key=None):
        return self.hub.dispatch({'op':op,'args':args or {},'session_id':self.session['session_id'],'session_secret':self.session['session_secret'],'request_key':key})
    def test_mutating_broker_requires_key_and_deduplicates_submit(self):
        self.hub._private_browser=Mock(return_value={'verified':True})
        with self.assertRaisesRegex(HubError,'REQUEST_KEY_REQUIRED'):self.call('private_browser',{'command':'act'})
        self.hub._private_browser.assert_not_called()
        self.call('private_browser',{'command':'act'},'submit-once-001');result=self.call('private_browser',{'command':'act'},'submit-once-001')
        self.assertTrue(result['deduplicated']);self.hub._private_browser.assert_called_once()
    def test_unknown_effect_remains_unknown_without_replay(self):
        self.hub._private_browser=Mock(side_effect=HubError('PRIVATE_CDP_OUTCOME_UNKNOWN',attempted=True,outcome_unknown=True,retry_safe=False))
        with self.assertRaisesRegex(HubError,'PRIVATE_CDP_OUTCOME_UNKNOWN'):self.call('private_browser',{'command':'evaluate'},'unknown-request')
        with self.assertRaisesRegex(HubError,'REQUEST_OUTCOME_UNKNOWN'):self.call('private_browser',{'command':'evaluate'},'unknown-request')
        self.assertEqual(self.hub._private_browser.call_count,1);self.assertEqual(self.call('request_status',{'request_key':'unknown-request'})['state'],'unknown')
    def test_cancel_receipt_readable_after_close_but_work_denied(self):
        self.call('task_cancel',key='cancel-task-001')
        self.assertTrue(self.call('task_cancel',key='cancel-task-001')['deduplicated'])
        self.assertEqual(self.call('request_status',{'request_key':'cancel-task-001'})['state'],'completed')
        with self.assertRaisesRegex(HubError,'SESSION_CLOSED'):self.call('private_browser',{'command':'read'})
    def test_profile_cleanup_failure_is_never_reported_verified(self):
        hidden=Mock(browser_profile_cleanup=[{'root':'owned-fixture','removed':False}],editor_profile_cleanup=[])
        self.hub._hidden[self.hub._owner(self.session)]=hidden
        result=self.call('task_cancel',key='cancel-failed-profile')
        self.assertFalse(result['cleanup_verified']);self.assertFalse(result['profile_cleanup'][0]['removed'])
    def test_idle_shutdown_refuses_tasks_and_closes_session_open_race(self):
        callback=Mock();self.hub._shutdown_request=callback
        with self.assertRaisesRegex(HubError,'HUB_BUSY'):self.hub.dispatch({'op':'hub_shutdown_idle'})
        callback.assert_not_called();self.call('task_cancel',key='idle-cancel-task')
        self.assertTrue(self.hub.dispatch({'op':'hub_shutdown_idle'})['idle_verified'])
        with self.assertRaisesRegex(HubError,'HUB_STOPPING'):self.hub.dispatch({'op':'session_open','args':{'agent_id':'new','task_id':'new'}})
