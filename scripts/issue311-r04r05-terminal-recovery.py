#!/usr/bin/env python3
"""Bounded protected-push reconciliation of expired, failed original requests.

Only the approved build-only state App persists a fail-closed terminal. This is
an explicit recovery, not a delivered workflow_run event, source rerun, or
publication grant. Successful and already-terminal requests are never changed.
"""
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

store = load('terminal_store', 'scripts/issue311-lifecycle-store.py')
life = store.lifecycle
contract = load('terminal_contract', 'scripts/issue311-request-contract.py')
bridge = load('terminal_bridge', 'scripts/issue311-r05-windows-completion-bridge.py')
writer = load('terminal_writer', 'scripts/issue311-writer-runtime.py')
WORKFLOW = 'Issue 311 finite expired original state recovery (NONPUBLISHING)'
SOURCE_WORKFLOW = '.github/workflows/issue311-r05-unified17.yml'
SOURCE_NAME = 'Issue 311 R05 unified 17 App persisted original Windows (NONPUBLISHING)'
OUTPUT = 'issue311-r04r05-terminal-recovery.json'

def need(ok, reason):
    if not ok:
        raise ValueError('TERMINAL_RECOVERY_DENY ' + reason)

def original_contents(path, ref):
    record = bridge.get_json('repos/pgextwin/build/contents/' + path + '?ref=' + ref)
    need(record.get('encoding') == 'base64', 'original Contents unavailable')
    raw = base64.b64decode(record['content'].replace('\n', '').replace('\r', ''), validate=True)
    need(store.blob_hash(raw) == record.get('sha'), 'original Git blob mismatch')
    return record, raw

def validate_recovery(raw, path, before, now):
    r = json.loads(raw, object_pairs_hook=store.unique_pairs)
    need(type(r) is dict and set(r) == {'schemaVersion', 'kind', 'requestId', 'mode',
         'baseMainSha', 'expiresAt', 'publicReleaseAuthorized', 'recoveries'}, 'recovery schema')
    need(r['schemaVersion'] == 1 and r['kind'] == 'pgextwin-expired-state-recovery'
         and r['mode'] == 'AUDIT_ONLY' and r['publicReleaseAuthorized'] is False
         and re.fullmatch(r'r-20\d{6}-r04r05terminal[a-z0-9-]{4,30}', r['requestId'])
         and path == '.github/execution-requests/' + r['requestId'] + '.json'
         and r['baseMainSha'] == before
         and now < life.parse_utc(r['expiresAt']) <= now + timedelta(hours=2),
         'untrusted, expired or privileged recovery')
    need(type(r['recoveries']) is list and 1 <= len(r['recoveries']) <= 4, 'recovery bound')
    seen = set()
    for x in r['recoveries']:
        need(type(x) is dict and set(x) == {'requestId', 'stateBlobSha', 'sourceRunId',
             'sourceHeadSha', 'requestSha256'} and life.REQ.fullmatch(x['requestId'])
             and store.SHA1.fullmatch(x['stateBlobSha']) and life.SHA1.fullmatch(x['sourceHeadSha'])
             and life.SHA256.fullmatch(x['requestSha256'])
             and type(x['sourceRunId']) is int and x['sourceRunId'] > 0
             and x['requestId'] != r['requestId'] and x['requestId'] not in seen,
             'duplicate or malformed recovery target')
        seen.add(x['requestId'])
    return r

def authenticated_recovery(now):
    ev = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes(), object_pairs_hook=store.unique_pairs)
    head, before = os.environ['GITHUB_SHA'], ev.get('before', '')
    need(os.environ['GITHUB_REPOSITORY'] == 'pgextwin/build'
         and os.environ['GITHUB_WORKFLOW'] == WORKFLOW and os.environ['GITHUB_EVENT_NAME'] == 'push'
         and os.environ['GITHUB_REF'] == 'refs/heads/main' and os.environ['GITHUB_ACTOR'] == 'ShutenOishi'
         and os.environ['GITHUB_RUN_ATTEMPT'] == '1' and ev.get('ref') == 'refs/heads/main'
         and ev.get('sender', {}).get('login') == 'ShutenOishi'
         and ev.get('repository', {}).get('full_name') == 'pgextwin/build'
         and ev.get('created') is False and ev.get('deleted') is False
         and ev.get('after') == head and before != head and life.SHA1.fullmatch(before),
         'not original protected recovery push')
    need(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == head, 'checkout drift')
    diff = subprocess.check_output(['git', 'diff', '--name-status', before, head], text=True).splitlines()
    need(len(diff) == 1 and diff[0].startswith('A\t.github/execution-requests/r-'), 'request-only addition required')
    path = diff[0].split('\t')[1]
    raw = subprocess.check_output(['git', 'show', 'HEAD:' + path])
    recovery = validate_recovery(raw, path, before, now)
    _, remote = original_contents(path, head)
    need(remote == raw, 'local recovery != immutable GitHub original')
    branch = bridge.get_json('repos/pgextwin/build/branches/main')
    need(branch.get('protected') is True and branch.get('commit', {}).get('sha') == head, 'protected main drift')
    return recovery, hashlib.sha256(raw).hexdigest()

def authenticate_failed_source(x, state, run, original, commit, now):
    life.validate(state)
    need(state['requestId'] == x['requestId'] and state['requestSha256'] == x['requestSha256']
         and state['sourceHeadSha'] == x['sourceHeadSha']
         and state['sourceRun'] == {'id': x['sourceRunId'], 'attempt': 1}
         and state['terminal'] is None and state['completionRun'] is None
         and state['targetScope'] == sorted(bridge.win17.TARGETS)
         and all(v == 'PENDING' for v in state['targets'].values())
         and now >= life.parse_utc(state['expiresAt']), 'state not expired pending original 17')
    need(run.get('id') == x['sourceRunId'] and run.get('head_sha') == x['sourceHeadSha']
         and run.get('name') == SOURCE_NAME and run.get('path') == SOURCE_WORKFLOW
         and run.get('event') == 'push' and run.get('head_branch') == 'main'
         and run.get('actor', {}).get('login') == 'ShutenOishi' and run.get('run_attempt') == 1
         and run.get('status') == 'completed' and run.get('conclusion') in ('failure', 'cancelled', 'timed_out'),
         'source is successful, running, foreign or rerun')
    path = '.github/execution-requests/' + x['requestId'] + '.json'
    # Historical validation only: this does not renew expired execution rights.
    decl = contract.validate_declaration(original, path, now=life.parse_utc(run['created_at']))
    d = json.loads(original, object_pairs_hook=store.unique_pairs)
    need(decl['rawSha256'] == x['requestSha256'] and decl['mode'] == 'AUDIT_ONLY'
         and set(decl['targets']) == set(bridge.win17.TARGETS)
         and d['expiresAt'] == state['expiresAt'] and d['resumeFrom'] is None
         and commit.get('sha') == x['sourceHeadSha']
         and commit.get('parents', [{}])[0].get('sha') == d['source']['centralMainSha'],
         'historical request/source/state binding mismatch')
    return life.event_deadline(state, state['revision'], 'protected-expired-original-recovery',
        now=now.isoformat().replace('+00:00', 'Z'), source_completed=False,
        original_source_sha=x['sourceHeadSha'], completion_lookup='UNKNOWN')

def run():
    receipt = {'schemaVersion': 1, 'result': 'FAILED', 'publicationAuthorized': False,
               'eventTransport': 'PROTECTED_MAIN_PUSH_FINITE_RECOVERY', 'originalsReexecuted': False}
    token = None
    try:
        recovery, raw_sha = authenticated_recovery(datetime.now(timezone.utc))
        prepared = []
        for x in recovery['recoveries']:
            record, _ = original_contents(store.PREFIX + x['requestId'] + '.json', store.BRANCH)
            blob, state = store.unpack(record, x['requestId'])
            need(blob == x['stateBlobSha'], 'state CAS pin changed')
            source = bridge.get_json('repos/pgextwin/build/actions/runs/' + str(x['sourceRunId']))
            _, original = original_contents('.github/execution-requests/' + x['requestId'] + '.json', x['sourceHeadSha'])
            commit = bridge.get_json('repos/pgextwin/build/commits/' + x['sourceHeadSha'])
            terminal = authenticate_failed_source(x, state, source, original, commit, datetime.now(timezone.utc))
            prepared.append((x, blob, state, terminal, source['conclusion']))
        # Mint the approved build-only token only after all original read gates.
        token = writer.mint_token(os.environ['STATE_WRITER_PRIVATE_KEY'])
        cas = store.CAS(lambda method, endpoint, payload: writer.api(method, endpoint, token, payload))
        rows = []
        for x, blob, state, terminal, conclusion in prepared:
            latest_blob, latest = cas.read(x['requestId'])
            need(latest_blob == blob and latest == state, 'App prewrite CAS changed')
            proof = cas.write(terminal, previous=state, expected_blob=blob)
            after_blob, after = cas.read(x['requestId'])
            need(after == terminal and after['terminal'] == 'QUARANTINED', 'terminal original readback mismatch')
            rows.append({'requestId': x['requestId'], 'sourceRunId': x['sourceRunId'],
                'sourceConclusion': conclusion, 'terminal': 'QUARANTINED', 'targets': after['targets'],
                'stateGitBlobSha': after_blob, 'stateRevision': after['revision'], 'persistence': proof})
        receipt.update(result='RECOVERED_FAIL_CLOSED', requestId=recovery['requestId'],
                       recoveryRequestSha256=raw_sha, perRequest=rows)
    except Exception as exc:
        receipt['reason'] = str(exc)[:400]
    finally:
        if token is not None:
            writer.revoke_and_prove_401(token)
    Path(OUTPUT).write_text(json.dumps(receipt, sort_keys=True) + '\n')
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['result'] == 'RECOVERED_FAIL_CLOSED' else 1

if __name__ == '__main__':
    raise SystemExit(run())
