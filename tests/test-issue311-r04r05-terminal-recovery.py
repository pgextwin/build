#!/usr/bin/env python3
"""Original expired 17-target failure reconciliation and hostile recovery tests."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recovery',ROOT/'scripts/issue311-r04r05-terminal-recovery.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FIXTURE=json.loads((ROOT/'tests/fixtures/issue311-expired-original17.json').read_text())
NOW=datetime(2026,10,29,11,0,tzinfo=timezone.utc)

class RecoveryTests(TestCase):
    def setUp(self):
        self.f=copy.deepcopy(FIXTURE)
    def evaluate(self,now=NOW):
        f=self.f
        return m.authenticate_failed_source(f['pin'],f['state'],f['run'],f['originalRequest'].encode(),f['commit'],now)
    def test_original_failure_closes_all_17_quarantined(self):
        before=copy.deepcopy(self.f['state']);after=self.evaluate()
        self.assertEqual(self.f['state'],before)
        self.assertEqual(after['revision'],before['revision']+1)
        self.assertEqual(after['terminal'],'QUARANTINED')
        self.assertEqual(set(after['targets'].values()),{'QUARANTINED'})
        self.assertEqual(len(after['targets']),17)
        self.assertEqual(after['sourceRun'],before['sourceRun'])
        self.assertEqual(after['eventTransport'],'BOUNDED_WATCHDOG')
        self.assertFalse(after['publisherAuthorized'])
        m.store.require_transition(before,after)
    def test_success_running_rerun_foreign_source_denied(self):
        for key,val in [('conclusion','success'),('status','in_progress'),('run_attempt',2),('head_sha','a'*40),('path','.github/workflows/attacker.yml'),('actor',{'login':'attacker'}),('event','workflow_dispatch')]:
            with self.subTest(key=key,val=val):
                self.setUp();self.f['run'][key]=val
                with self.assertRaisesRegex(ValueError,'source is successful'):self.evaluate()
    def test_deadline_not_reached_and_already_terminal_denied(self):
        with self.assertRaises(ValueError):self.evaluate(datetime(2026,10,29,3,0,tzinfo=timezone.utc))
        self.f['state']=self.evaluate()
        with self.assertRaises(ValueError):self.evaluate()
    def test_tampered_request_and_missing_target_denied(self):
        self.f['originalRequest']=self.f['originalRequest'].replace('AUDIT_ONLY','PREPARE')
        with self.assertRaises(ValueError):self.evaluate()
        self.setUp();self.f['state']['targets'].pop('pgextwin/orafce')
        with self.assertRaises(ValueError):self.evaluate()
    def test_recovery_schema_scope_deadline_and_duplicates(self):
        rid='r-20261029-r04r05terminalproof01';before='a'*40
        r={'schemaVersion':1,'kind':'pgextwin-expired-state-recovery','requestId':rid,'mode':'AUDIT_ONLY','baseMainSha':before,'expiresAt':'2026-10-29T12:00:00Z','publicReleaseAuthorized':False,'recoveries':[self.f['pin']]}
        path='.github/execution-requests/'+rid+'.json'
        m.validate_recovery(json.dumps(r).encode(),path,before,NOW)
        for mutate in [lambda x:x.update(publicReleaseAuthorized=True),lambda x:x.update(mode='PUBLISH_ELIGIBLE'),lambda x:x.update(expiresAt='2026-10-29T10:00:00Z'),lambda x:x.update(baseMainSha='b'*40),lambda x:x['recoveries'].append(x['recoveries'][0])]:
            bad=copy.deepcopy(r);mutate(bad)
            with self.assertRaises(ValueError):m.validate_recovery(json.dumps(bad).encode(),path,before,NOW)
    def test_no_app_mint_when_original_authentication_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td,mock.patch.object(m,'OUTPUT',str(Path(td)/'receipt.json')),mock.patch.object(m,'authenticated_recovery',side_effect=ValueError('DENY')),mock.patch.object(m.writer,'mint_token') as mint:
            self.assertEqual(m.run(),1);mint.assert_not_called()
            r=json.loads(Path(m.OUTPUT).read_text());self.assertEqual(r['result'],'FAILED');self.assertFalse(r['publicationAuthorized'])

if __name__=='__main__':main()
