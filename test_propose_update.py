"""Only closed public metadata may create recoverable review proposals."""
import base64
import copy
import json
import unittest
from unittest.mock import patch

import propose_update as propose
import discover_updates as discovery


class ProposalTests(unittest.TestCase):
    def setUp(self):
        policy=discovery.load_policy()
        self.data=dict(schema=1,status='review_required',automatic_build_or_install=False,
                       reviewed_donor=policy['donor'],recoveries=[],incremental_otas=[],errors=[],
                       coverage=discovery.COVERAGE,sources=[dict(p,observed_sha='f'*40,changed=True) for p in policy['sources']])
        self.report=propose.public_report(json.dumps(self.data).encode())
        self.writes=[];self.branch_exists=False;self.branch_head='a'*40;self.content=None;self.prs=[];self.fail_pr=False

    def api(self,path,payload=None):
        if payload is not None:self.writes.append((path,payload))
        if path=='repos/example/public':return {'default_branch':'main','private':False}
        if '/git/ref/heads/codex/' in path:
            if not self.branch_exists:raise propose.ApiError(404)
            return {'object':{'sha':self.branch_head}}
        if path.endswith('/git/ref/heads/main'):return {'object':{'sha':'a'*40}}
        if path.endswith('/git/refs'):
            self.branch_exists=True;return {}
        if '/contents/' in path:
            if payload is not None:self.content=base64.b64decode(payload['content']);return {}
            if self.content is None:raise propose.ApiError(404)
            return {'content':base64.b64encode(self.content).decode(),'sha':'c'*40}
        if '/pulls?' in path:return self.prs
        if path.endswith('/pulls'):
            if self.fail_pr:raise propose.ApiError(403)
            self.prs=[{'number':17}];return self.prs[0]
        raise AssertionError('unexpected API route')

    def run_proposal(self):
        with patch.object(propose,'api',side_effect=self.api):return propose.propose('example/public',self.report)

    def test_invalid_sensitive_and_unexpected_fields_do_not_call_api(self):
        bad=[{},[],dict(self.data,status='incomplete'),dict(self.data,automatic_build_or_install=True),
             dict(self.data,private_note='unstructured private note')]
        nested=copy.deepcopy(self.data);nested['sources'][0]['private_note']='not public';bad.append(nested)
        for data in bad:
            with patch.object(propose,'api') as api,self.assertRaises((ValueError,TypeError,KeyError)):
                propose.propose('example/public',json.dumps(data).encode())
            api.assert_not_called()

    def test_existing_same_report_and_pr_are_not_overwritten(self):
        self.branch_exists=True;self.content=self.report;self.prs=[{'number':3}]
        self.assertEqual(self.run_proposal()['status'],'existing_review_pull_request')
        self.assertEqual(self.writes,[])

    def test_different_existing_review_branch_is_preserved(self):
        self.branch_exists=True;self.branch_head='b'*40;self.content=b'different'
        with self.assertRaisesRegex(ValueError,'do not overwrite'):self.run_proposal()
        self.assertEqual(self.writes,[])

    def test_new_branch_retained_when_github_forbids_automatic_pr(self):
        self.fail_pr=True
        result=self.run_proposal()
        self.assertEqual(result['status'],'review_branch_ready');self.assertEqual(len(self.writes),3)
        self.assertTrue(self.writes[1][0].endswith('/contents/maintenance/discovery.json'))
        self.assertNotIn('updates/erhai',str(self.writes))

    def test_retry_recovers_created_branch_without_file(self):
        self.branch_exists=True
        self.assertEqual(self.run_proposal()['status'],'review_pull_request_ready')
        self.assertEqual(len(self.writes),2)

    def test_retry_recovers_file_without_pr(self):
        self.branch_exists=True;self.content=self.report
        self.assertEqual(self.run_proposal()['status'],'review_pull_request_ready')
        self.assertEqual(len(self.writes),1)

    def test_retry_replaces_untouched_inherited_previous_report(self):
        self.branch_exists=True;self.content=b'older public discovery report'
        self.assertEqual(self.run_proposal()['status'],'review_pull_request_ready')
        self.assertEqual(self.content,self.report);self.assertEqual(len(self.writes),2)

    def test_recovery_fields_are_rebuilt_and_nested_notes_are_rejected(self):
        pins=json.loads((discovery.ROOT/'inputs.json').read_text())['donor']
        rows=discovery.check_updates.compare_catalog([dict(device='mica',url=pins['url'],md5=pins['zip_md5'],
                    dateupdated=pins['published'],buildidentifier=pins['build']+'_'+pins['version'])],pins)
        rows[0]['newer_than_reviewed_donor']=False
        self.data['recoveries']=rows
        self.assertEqual(json.loads(propose.public_report(json.dumps(self.data).encode()))['recoveries'],rows)
        rows[0]['private_note']='do not publish'
        with self.assertRaises(ValueError):propose.public_report(json.dumps(self.data).encode())


if __name__=='__main__':unittest.main()
