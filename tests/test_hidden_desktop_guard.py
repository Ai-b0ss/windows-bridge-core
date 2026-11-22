import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/bridge-v3'))
import cua_desktop_identity as identity

class PrivateDesktopGuard(unittest.TestCase):
    def test_active_or_changed_desktop_denied_before_dispatch(self):
        for state in ({'current':'Default','input':'Default'},
                      {'current':'FFBridge-Agent-a','input':'FFBridge-Agent-a'},
                      {'current':'FFBridge-Agent-b','input':'Default'}):
            with self.subTest(state=state),patch.object(identity,'desktop_identity',return_value=state):
                with self.assertRaisesRegex(identity.DesktopIdentityError,'HIDDEN_DESKTOP_IDENTITY_INVALID'):
                    identity.require_private_desktop('FFBridge-Agent-a')

    def test_owner_desktop_changes_are_observed_on_every_request(self):
        states=[{'current':'FFBridge-Agent-a','input':'Default'},
                {'current':'FFBridge-Agent-a','input':'Winlogon'}]
        with patch.object(identity,'desktop_identity',side_effect=states) as call:
            self.assertEqual(identity.require_private_desktop('FFBridge-Agent-a'),states[0])
            self.assertEqual(identity.require_private_desktop('FFBridge-Agent-a'),states[1])
            self.assertEqual(call.call_count,2)
