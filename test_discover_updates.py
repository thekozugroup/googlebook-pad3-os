"""Public metadata discovery never downloads, trusts or installs a candidate."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

import discover_updates as discover


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.policy = discover.load_policy()
        self.pins = json.loads((discover.ROOT / 'inputs.json').read_text())['donor']
        self.fp = 'Dell/mica/mica:17/CL3B.260622.276.R2/16560795:user/release-keys'
        self.url = self.policy['reviewed_ota_urls'][0]
        self.catalog = [{'device':'mica', 'url':self.pins['url'], 'md5':self.pins['zip_md5'],
                         'dateupdated':self.pins['published'], 'buildidentifier':self.pins['build']+'_'+self.pins['version']}]
        self.data = {discover.check_updates.CATALOG_URL:json.dumps(self.catalog),
                     discover.INDEX:'<a href="/ota/2850">'+self.fp+'</a>',
                     'https://otachecker.com/ota/2850':self.fp+'<a href="'+self.url+'">Download</a>'}
        for p in self.policy['sources']:
            self.data['https://api.github.com/repos/'+p['repository']+'/git/ref/heads/'+p['branch']] = json.dumps({'object':{'sha':p['reviewed_sha']}})

    def test_known_incremental_and_stale_recovery_are_not_new_updates(self):
        result = discover.discover(self.policy, self.pins, self.data.__getitem__)
        self.assertEqual(result['status'], 'no_observed_change')
        self.assertFalse(result['automatic_build_or_install'])
        self.assertFalse(result['recoveries'][0]['newer_than_reviewed_donor'])
        self.assertEqual(result['incremental_otas'][0]['trust'], 'discovery_only_not_signature_verified')
        self.assertEqual(result, discover.discover(self.policy, self.pins, self.data.__getitem__))

    def test_new_ota_url_and_source_head_require_review(self):
        self.data['https://otachecker.com/ota/2850'] = self.fp+'<a href="'+self.url.replace('2baa54369b6da92a157653a99cb0426b59bc2061', 'f'*40)+'">new</a>'
        self.assertEqual(discover.discover(self.policy,self.pins,self.data.__getitem__)['status'], 'review_required')
        self.data['https://otachecker.com/ota/2850'] = self.fp+'<a href="'+self.url+'">known</a>'
        source=self.policy['sources'][0];self.data['https://api.github.com/repos/'+source['repository']+'/git/ref/heads/'+source['branch']]=json.dumps({'object':{'sha':'f'*40}})
        self.assertTrue(discover.discover(self.policy,self.pins,self.data.__getitem__)['sources'][0]['changed'])

    def test_unavailable_or_empty_index_is_incomplete_not_no_update(self):
        for value in ['', '<a href="/ota/1">another device</a>']:
            self.data[discover.INDEX]=value
            self.assertEqual(discover.discover(self.policy,self.pins,self.data.__getitem__)['status'],'incomplete')
        def failure(url):
            if url==discover.INDEX:raise OSError('private diagnostic must not escape')
            return self.data[url]
        result=discover.discover(self.policy,self.pins,failure)
        self.assertNotIn('private diagnostic',json.dumps(result))

    def test_only_exact_mica_records_and_google_download_links_are_selected(self):
        self.assertEqual(discover.index_records('<a href="https://evil.invalid/ota/1">'+self.fp+'</a>'), [])
        self.assertEqual(discover.index_records('<a href="/ota/1">other/mica/mica:17/a/1:user/release-keys</a>'), [])
        for url in [self.url+'?token=private', self.url.replace('ota.googlezip.net','evil.invalid'), self.url+'/extra']:
            with self.assertRaises(ValueError):discover.ota_urls(self.fp+'<a href="'+url+'">bad</a>',self.fp)
        with self.assertRaises(ValueError):discover.ota_urls('<a href="'+self.url+'">bad source</a>',self.fp)

    def test_metadata_fetch_rejects_firmware_auth_and_local_hosts_before_network(self):
        for url in [self.url,'http://127.0.0.1/x','https://user:pass' + '@' + 'otachecker.com/list','https://otachecker.com/list?token=private']:
            with patch.object(discover.urllib.request,'build_opener') as opener,self.assertRaises(ValueError):discover.fetch(url)
            opener.assert_not_called()

    def test_oversized_metadata_is_rejected(self):
        class Response:
            headers={'Content-Length':str(discover.MAX_BYTES+1)}
            def __enter__(self):return self
            def __exit__(self,*args):pass
        with patch.object(discover.urllib.request,'build_opener') as opener:
            opener.return_value.open.return_value=Response()
            with self.assertRaises(ValueError):discover.fetch(discover.INDEX)

    def test_wrong_or_missing_github_revision_is_incomplete(self):
        p=self.policy['sources'][0];key='https://api.github.com/repos/'+p['repository']+'/git/ref/heads/'+p['branch']
        for value in ['not-a-commit',None]:
            self.data[key]=json.dumps({'object':{'sha':value}})
            self.assertEqual(discover.discover(self.policy,self.pins,self.data.__getitem__)['status'],'incomplete')

    def test_one_unavailable_detail_does_not_hide_other_records(self):
        self.data[discover.INDEX]+='<a href="/ota/2851">'+self.fp+'</a>'
        def request(url):
            if url.endswith('/2851'):
                error=urllib.error.HTTPError(url,404,'private error text',{},None);error.close();raise error
            return self.data[url]
        result=discover.discover(self.policy,self.pins,request)
        self.assertEqual(result['status'],'incomplete');self.assertEqual(len(result['incremental_otas']),1)
        self.assertEqual(result['errors'][0]['http_status'],404)
        self.assertNotIn('private error text',str(result))


if __name__=='__main__':unittest.main()
