#!/usr/bin/env python3
"""Create a metadata-only review branch/PR. Never modify ROM pins or publish OTAs."""
import base64
import hashlib
import json
import os
import re
import subprocess
from urllib.parse import quote

from export_public import Scanner
import discover_updates as discovery


class ApiError(ValueError):
    def __init__(self, status):
        self.status = status


def api(endpoint, payload=None):
    args=['gh','api',endpoint]
    if payload is not None:
        args+=['--method','POST' if endpoint.endswith(('/git/refs','/pulls')) else 'PUT','--input','-']
    r=subprocess.run(args,input=None if payload is None else json.dumps(payload),capture_output=True,text=True,timeout=30)
    if r.returncode:
        try:status=int(json.loads(r.stdout).get('status',0))
        except (ValueError,TypeError):status=0
        raise ApiError(status)
    return json.loads(r.stdout)


def optional(endpoint):
    try:return api(endpoint)
    except ApiError as error:
        if error.status==404:return None
        raise


def public_report(report):
    if len(report) > 128 * 1024:
        raise ValueError('report exceeds bound')
    data = json.loads(report)
    fields = {'schema', 'status', 'reviewed_donor', 'recoveries', 'incremental_otas',
              'sources', 'errors', 'automatic_build_or_install', 'coverage'}
    policy = discovery.load_policy()
    if (not isinstance(data, dict) or set(data) != fields or type(data['schema']) is not int
            or data['schema'] != 1 or data['status'] != 'review_required' or data['errors'] != []
            or data['automatic_build_or_install'] is not False or data['coverage'] != discovery.COVERAGE
            or data['reviewed_donor'] != policy['donor']):
        raise ValueError('only closed discovery review reports may be proposed')
    for name, limit in [('recoveries', 64), ('incremental_otas', 32), ('sources', len(policy['sources']))]:
        if not isinstance(data[name], list) or len(data[name]) > limit:
            raise ValueError('report list exceeds bound')
    pins = json.loads((discovery.ROOT / 'inputs.json').read_text())['donor']
    recovered = []
    for row in data['recoveries']:
        if not isinstance(row, dict) or row.get('device') != 'mica':
            raise ValueError('unexpected recovery device')
        candidate = {'device': row['device'], 'url': row['url'], 'md5': row['zip_md5'],
                     'dateupdated': row['published']}
        if row['version'] is not None:
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,96}', row['version']):
                raise ValueError('invalid recovery version')
            candidate['buildidentifier'] = row['build'] + '_' + row['version']
        rebuilt = discovery.check_updates.compare_catalog([candidate], pins)[0]
        rebuilt['newer_than_reviewed_donor'] = int(rebuilt['build']) > int(policy['donor']['build'])
        if row != rebuilt:
            raise ValueError('recovery report differs from validated public fields')
        recovered.append(rebuilt)
    sources = []
    if len(data['sources']) != len(policy['sources']):
        raise ValueError('source coverage is incomplete')
    for row, pin in zip(data['sources'], policy['sources']):
        sha = row['observed_sha']
        if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{40}', sha):
            raise ValueError('invalid observed source')
        rebuilt = dict(pin, observed_sha=sha, changed=sha != pin['reviewed_sha'])
        if row != rebuilt:
            raise ValueError('unexpected source fields')
        sources.append(rebuilt)
    otas = []
    for row in data['incremental_otas']:
        if (not re.fullmatch(r'https://otachecker\.com/ota/[1-9][0-9]{0,7}', row['record'])
                or not re.fullmatch(discovery.FINGERPRINT, row['source_fingerprint'])
                or not re.fullmatch(discovery.OTA, row['url'])):
            raise ValueError('invalid public OTA fields')
        rebuilt = {name: row[name] for name in ('record', 'source_fingerprint', 'url')}
        rebuilt.update(new_url=row['url'] not in policy['reviewed_ota_urls'], trust='discovery_only_not_signature_verified')
        if row != rebuilt:
            raise ValueError('unexpected OTA fields')
        otas.append(rebuilt)
    if not (any(r['newer_than_reviewed_donor'] for r in recovered) or any(r['new_url'] for r in otas)
            or any(r['changed'] for r in sources)):
        raise ValueError('report contains no observed change')
    clean = dict(schema=1, status='review_required', reviewed_donor=policy['donor'], recoveries=recovered,
                 incremental_otas=otas, sources=sources, errors=[], automatic_build_or_install=False,
                 coverage=discovery.COVERAGE)
    report = (json.dumps(clean, indent=2, sort_keys=True) + '\n').encode()
    if Scanner().scan(report, 'maintenance/discovery.json'):
        raise ValueError('discovery report failed public-data scan')
    return report


def propose(repo, report):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('invalid repository')
    report = public_report(report)
    digest = hashlib.sha256(report).hexdigest()[:16]
    branch = 'codex/upstream-' + digest
    path = 'maintenance/discovery.json'
    prefix = 'repos/' + repo
    metadata = api(prefix)
    base = metadata['default_branch']
    if metadata.get('private') is not False or not re.fullmatch(r'[A-Za-z0-9_.-]+', base):
        raise ValueError('public default branch required')
    existing = optional(prefix + '/git/ref/heads/' + branch)
    current = optional(prefix + '/contents/' + path + '?ref=' + quote(branch, safe='')) if existing is not None else None
    if current is None or base64.b64decode(current['content'], validate=False) != report:
        head = api(prefix + '/git/ref/heads/' + base)['object']['sha']
        if not re.fullmatch('[0-9a-f]{40}', head):
            raise ValueError('invalid main revision')
        if existing is None:
            api(prefix + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': head})
        elif existing['object']['sha'] != head:
            raise ValueError('partial review branch moved; do not overwrite')
        previous = current if existing is not None else optional(prefix + '/contents/' + path + '?ref=' + quote(branch, safe=''))
        payload = {'message': 'Record upstream changes for compatibility review', 'branch': branch,
                   'content': base64.b64encode(report).decode()}
        if previous is not None:
            payload['sha'] = previous['sha']
        api(prefix + '/contents/' + path, payload)
    result = {'status': 'review_branch_ready', 'branch': branch}
    pulls = api(prefix + '/pulls?state=all&head=' + quote(repo.split('/')[0] + ':' + branch, safe=''))
    if pulls:
        result.update(status='existing_review_pull_request', number=int(pulls[0]['number']))
        return result
    try:
        pr = api(prefix + '/pulls', {'title': 'Review upstream GoogleBook and device-source changes',
                 'head': branch, 'base': base,
                 'body': 'Automated public-metadata discovery only. No firmware has been trusted, patched, signed, installed or published. Review maintenance/discovery.json, verify Google signatures and update the reviewed profile before using the native pipeline.'})
        result.update(status='review_pull_request_ready', number=int(pr['number']))
    except ApiError:
        result['pull_request_creation'] = 'unavailable; compare the retained review branch in GitHub'
    return result


def main():
    try:
        repo=os.environ['GH_REPO'];report=base64.b64decode(os.environ['DISCOVERY_REPORT'],validate=True)
        result=propose(repo,report);print(json.dumps(result))
        summary=os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary,'a') as f:f.write('Upstream review: **'+result['status']+'**, branch `'+result['branch']+'`. No release/feed changes.\n')
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('{"status":"proposal_blocked","private_diagnostics_withheld":true}');return 1


if __name__=='__main__':raise SystemExit(main())
