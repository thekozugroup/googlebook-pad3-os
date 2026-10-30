"""Synthetic privacy failures must remain visible in history, without leaking values."""
from pathlib import Path
import subprocess
import tempfile
import unittest

import privacy_audit as audit
from export_public import Scanner


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.repo=Path(self.tmp.name)
        self.git('init','-q');self.git('config','user.name','GoogleBook Maintainers');self.git('config','user.email','maintainers'+'@'+'users.noreply.github.com')
        (self.repo/'source.txt').write_text('public source\n');self.git('add','.');self.git('commit','-qm','initial')

    def git(self,*args):return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.DEVNULL)

    def test_clean_history_passes_with_project_role_identity(self):
        result=audit.audit(self.repo,Scanner(),history=True)
        self.assertEqual(result['findings'],[]);self.assertEqual(result['history_commits'],1)

    def test_removed_secret_still_blocks_history(self):
        value='gh'+'p_'+'a'*36
        (self.repo/'source.txt').write_text(value);self.git('add','.');self.git('commit','-qm','bad fixture')
        (self.repo/'source.txt').write_text('public source');self.git('add','.');self.git('commit','-qm','remove fixture')
        self.assertEqual(audit.audit(self.repo,Scanner())['status'],'passed')
        result=audit.audit(self.repo,Scanner(),True)
        self.assertEqual(result['status'],'blocked');self.assertTrue(any(f['classification']=='token' for f in result['findings']))
        self.assertNotIn(value,str(result))

    def test_known_owner_pattern_and_sensitive_filename_are_redacted(self):
        scanner=Scanner();owner='synthetic-owner-fixture';scanner.add_secret(owner.encode())
        (self.repo/(owner+'.txt')).write_text(owner)
        result=audit.audit(self.repo,scanner)
        self.assertEqual(result['status'],'blocked');self.assertNotIn(owner,str(result))
        self.assertIn('sensitive_filename',{f['classification'] for f in result['findings']})

    def test_url_credentials_and_unknown_commit_email_are_not_exempt(self):
        value=b'https://user:password' + b'@' + b'example.invalid/repo'
        self.assertIn('url_credentials',{f['classification'] for f in audit.check(value,'fixture',Scanner())})
        mail=b'person'+b'@'+b'private.test'
        self.assertIn('email',{f['classification'] for f in audit.check(mail,'git-commit',Scanner(),metadata=True)})

    def test_public_role_exemption_never_hides_known_exact_patterns(self):
        scanner=Scanner();value=b'maintainers'+b'@'+b'users.noreply.github.com';scanner.add_secret(value)
        self.assertIn('known_secret',{f['classification'] for f in audit.check(value,'git-commit',scanner,metadata=True)})

    def test_only_the_reviewed_historical_url_fixture_is_exempt(self):
        path='components/updater/tests/UpdateCoreTest.java'
        self.assertNotIn('url_credentials',{f['classification'] for f in audit.check(audit.URL_TEST,path,Scanner())})
        self.assertIn('url_credentials',{f['classification'] for f in audit.check(audit.URL_TEST,'unrelated.py',Scanner())})
        self.assertIn('url_credentials',{f['classification'] for f in audit.check(audit.URL_TEST.replace(b'token',b'actual-value'),path,Scanner())})

    def test_removed_sensitive_filename_reusing_existing_blob_is_detected(self):
        name='synthetic-sensitive-name';scanner=Scanner();scanner.add_secret(name.encode())
        (self.repo/name).write_bytes((self.repo/'source.txt').read_bytes())
        self.git('add','.');self.git('commit','-qm','add alias')
        self.git('rm',name);self.git('commit','-qm','remove alias')
        result=audit.audit(self.repo,scanner,True)
        self.assertEqual(result['status'],'blocked');self.assertNotIn(name,str(result))
        self.assertTrue(result['history_trees'])

    def test_credential_filename_is_redacted_and_utf16_metadata_email_is_not_hidden(self):
        path='https://user:password'+chr(64)+'localhost/file'
        result=audit.check(b'content',path,Scanner())
        self.assertIn('sensitive_filename',{f['classification'] for f in result});self.assertNotIn(path,str(result))
        value=('person'+chr(64)+'private.test').encode('utf-16-le')
        self.assertIn('email',{f['classification'] for f in audit.check(value,'git-commit',Scanner(),metadata=True)})

    def test_mixed_encoding_metadata_never_uses_ascii_role_exemptions(self):
        role=b'maintainers' + b'@' + b'users.noreply.github.com'
        private=('person'+chr(64)+'private.test').encode('utf-16-le')
        value=b'line1\nline2\nline3\n'+role+b'\n'+private
        expected=[f for f in Scanner().scan(value,'git-commit') if f['classification']=='email']
        result=[f for f in audit.check(value,'git-commit',Scanner(),metadata=True) if f['classification']=='email']
        self.assertTrue(expected);self.assertEqual(result,expected)


if __name__=='__main__':unittest.main()
