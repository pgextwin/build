#!/usr/bin/env python3
"""R11 transition preflight: genuine protected-main GET, no writer/cron changes.

Inventory is not migration acceptance. Never create a credential, PR,
Release, workflow dispatch, schedule, or source-kind authorization.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

EXTENSIONS = (
    'pg_bigm','pg_cron','pg_hint_plan','pgaudit','set_user','pg_repack',
    'pg_ivm','pg_qualstats','plpgsql_check','orafce','hypopg','wal2json',
    'pg_partman','pg_stat_monitor','pgtap','pg_variables','pg_store_plans',
)
CENTRAL = ('build','catalog','website')
SHA40 = re.compile(r'[0-9a-f]{40}\Z')
CRON = '30 * * * *'
HYPOPG_CRON = '41 * * * *'
WORKFLOW_PATH = '.github/workflows/update-watch.yml'

class Denied(ValueError): pass

def need(ok, why):
    if not ok: raise Denied('R11_INVENTORY_DENY '+why)

def unique(pairs):
    result = {}
    for key,value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def api(route):
    need(os.environ.get('GH_TOKEN'), 'missing authenticated read-only GET token')
    need(re.fullmatch(r'repos/pgextwin/[a-z0-9_-]+/(branches/main|contents/\.github/workflows(?:/[a-zA-Z0-9._-]+\.ya?ml)?\?ref=[a-f0-9]{40})',route),
         'GET outside workflow inventory allowlist')
    run = subprocess.run(['gh','api','--method','GET',route],capture_output=True,
                         text=True,timeout=45,check=False)
    need(run.returncode == 0 and 0 < len(run.stdout) < 4_000_000,
         'authenticated GitHub GET failed')
    return json.loads(run.stdout,object_pairs_hook=unique)

def branch(repo):
    result=api(f'repos/pgextwin/{repo}/branches/main')
    sha=result.get('commit',{}).get('sha')
    need(result.get('name')=='main' and result.get('protected') is True
         and type(sha) is str and SHA40.fullmatch(sha),
         'unprotected/unknown main '+repo)
    return sha

def blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()

def file_get(repo,path,commit):
    need(path.startswith('.github/workflows/') and path.endswith(('.yml','.yaml')),
         'outside workflow file')
    result=api(f'repos/pgextwin/{repo}/contents/{path}?ref={commit}')
    need(result.get('type')=='file' and result.get('encoding')=='base64'
         and type(result.get('content')) is str,'not original file response')
    raw=base64.b64decode(result['content'].replace('\n',''),validate=True)
    need(0<len(raw)<300_000 and result.get('sha')==blob(raw),
         'Git object does not match original YAML bytes')
    return raw,result['sha']

def workflow(raw):
    # Strict narrow stdlib reader for Actions top-level on/jobs, not arbitrary YAML.
    need(type(raw) is bytes and 0 < len(raw) < 300_000,
         'invalid workflow source')
    try: lines=raw.decode('utf-8').splitlines()
    except UnicodeDecodeError as exc: raise Denied('invalid UTF-8 workflow') from exc
    keys={}
    for i,line in enumerate(lines):
        if not line or line.lstrip().startswith('#') or line[0].isspace():continue
        match=re.match(r'^(on|jobs):(?:\s*(.*))?$',line)
        if match:
            need(match[1] not in keys,'duplicate top-level workflow key')
            keys[match[1]]=(i,match[2] or '')
    need(set(keys)=={'on','jobs'},'missing top-level workflow trigger/jobs')
    def section(name):
        pos,inline=keys[name]
        end=len(lines)
        for j in range(pos+1,len(lines)):
            line=lines[j]
            if line and not line[0].isspace() and not line.lstrip().startswith('#'):
                end=j;break
        return inline,lines[pos+1:end]
    inline,raw_on=section('on')
    on={}
    if inline:
        if re.fullmatch(r'\[[a-z_ ,]+\]',inline):
            on={v.strip():None for v in inline.strip('[]').split(',')}
        elif re.fullmatch(r'[a-z_]+',inline): on={inline:None}
        else:raise Denied('unsupported inline workflow events')
    else:
        event=None
        for line in raw_on:
            if not line.strip() or line.lstrip().startswith('#'):continue
            match=re.match(r'^  ([a-z_]+):(?:\s*.*)?$',line)
            if match:
                event=match[1]
                need(event not in on,'duplicate workflow event')
                on[event]=None if event!='schedule' else []
            elif event=='schedule':
                cron=re.match(r'''^    - cron:\s*['"]?([^'"#]+?)['"]?\s*(?:#.*)?$''',line)
                if cron:on[event].append({'cron':cron[1].strip()})
    _,raw_jobs=section('jobs')
    jobs={};job=None;current=None
    for line in raw_jobs:
        if not line.strip() or line.lstrip().startswith('#'):continue
        match=re.match(r'^  ([a-zA-Z0-9_-]+):\s*$',line)
        if match:
            job=match[1];need(job not in jobs,'duplicate workflow job')
            jobs[job]={};current=None
        elif job:
            key=re.match(r'^    (if|uses):\s*(.*)$',line)
            if key:
                current=key[1];jobs[job][current]=key[2].strip().strip('\"')
            elif current and line.startswith('      '):
                jobs[job][current]+=' '+line.strip()
            else:current=None
    need(on and jobs,'no workflow events/jobs')
    return {'on':on,'jobs':jobs}

def events(data):
    return data['on']

def extension_status(repo,raw):
    data=workflow(raw)
    on=events(data)
    schedule=on.get('schedule',[])
    need(type(schedule) is list and all(type(x) is dict and type(x.get('cron')) is str for x in schedule),
         'unrecognized extension cron structure '+repo)
    crons=[x['cron'] for x in schedule]
    expected=[CRON,HYPOPG_CRON] if repo=='hypopg' else [CRON]
    need(crons==expected, 'schedule changed without transition acceptance '+repo)
    need('push' in on and 'workflow_run' in on,
         'required push/workflow_run removed '+repo)
    authorize=data['jobs'].get('authorize')
    need(type(authorize) is dict and authorize.get('if')=="github.event_name == 'schedule'",
         'schedule-dependent authorize changed '+repo)
    need(type(authorize.get('uses')) is str and
         authorize['uses'].startswith('pgextwin/build/.github/workflows/operator-update-auto.yml@'),
         'schedule authorizer no longer immutable '+repo)
    return {'cron':crons,'scheduleDependentAuthorize':True,
            'pushPreserved':True,'workflowRunPreserved':True,
            'migrationAccepted':False}

def inventory(repo,commit,entries):
    need(type(entries) is list and all(type(x) is dict for x in entries),
         'invalid original workflow directory')
    paths=sorted(e['path'] for e in entries if e.get('type')=='file' and
                 e.get('name','').endswith(('.yml','.yaml')))
    need(len(paths)==len(set(paths)) and all(x.startswith('.github/workflows/') for x in paths),
         'duplicate/out-of-directory workflow list')
    scheduled=[]
    for path in paths:
        raw,sha=file_get(repo,path,commit)
        on=events(workflow(raw))
        if 'schedule' in on:
            jobs=workflow(raw)['jobs']
            schedule_sensitive=[k for k,v in jobs.items() if type(v) is dict and
                                'schedule' in str(v.get('if',''))]
            scheduled.append({'path':path,'gitBlobSha':sha,
                 'cron':[x.get('cron') for x in on['schedule']] if type(on['schedule']) is list else None,
                 'scheduleSensitiveJobs':schedule_sensitive,
                 'migrationAccepted':False})
    return {'repository':'pgextwin/'+repo,'mainSha':commit,'workflowCount':len(paths),
            'scheduleWorkflows':scheduled,'migrationAccepted':False}

def assess(extension_rows,central_rows):
    need(type(extension_rows) is list and len(extension_rows)==17 and
         {x['repository'] for x in extension_rows}=={'pgextwin/'+r for r in EXTENSIONS},
         'incomplete 17-extension inventory')
    need(type(central_rows) is list and len(central_rows)==3 and
         {x['repository'] for x in central_rows}=={'pgextwin/'+r for r in CENTRAL},
         'incomplete central inventory')
    need(all(x['schedule']['migrationAccepted'] is False for x in extension_rows)
         and all(x['migrationAccepted'] is False for x in central_rows),
         'incomplete inventory falsely marked migrated')
    return {'schemaVersion':1,'kind':'ISSUE311_R11_AUTHENTICATED_SCHEDULE_INVENTORY',
            'nonpublishing':True,'runtimeEnabled':False,'publicationAuthorized':False,
            'writerUsed':False,'appKeyUsed':False,'scheduleRemoved':False,
            'migrationAccepted':False,'r11_01Accepted':False,'r11_02Accepted':False,
            'legacyScheduleMustRemain':True,
            'reason':'SUBSTITUTE_NORMAL_NEGATIVE_AND_LEGACY_WRITER_CONFLICT_NOT_YET_ACCEPTED',
            'extensions':extension_rows,'central':central_rows}

def serial(obj):
    return (json.dumps(obj,ensure_ascii=True,indent=2,sort_keys=True)+'\n').encode('ascii')

def collect():
    need(os.environ.get('GITHUB_REPOSITORY')=='pgextwin/build' and
         os.environ.get('GITHUB_REF')=='refs/heads/main' and
         os.environ.get('GITHUB_EVENT_NAME')=='push' and
         os.environ.get('GITHUB_RUN_ATTEMPT')=='1',
         'not genuine first protected main-push GET')
    main=os.environ.get('GITHUB_SHA','')
    need(SHA40.fullmatch(main) and branch('build')==main,
         'build main shifted/unprotected')
    rows=[]
    for repo in EXTENSIONS:
        sha=branch(repo)
        raw,digest=file_get(repo,WORKFLOW_PATH,sha)
        rows.append({'repository':'pgextwin/'+repo,'mainSha':sha,
                     'workflow':WORKFLOW_PATH,'gitBlobSha':digest,
                     'schedule':extension_status(repo,raw)})
    centers=[]
    for repo in CENTRAL:
        sha=main if repo=='build' else branch(repo)
        entries=api(f'repos/pgextwin/{repo}/contents/.github/workflows?ref={sha}')
        centers.append(inventory(repo,sha,entries))
    for row in rows+centers:
        repo=row['repository'].split('/',1)[1]
        need(branch(repo)==row['mainSha'],'main shifted mid-audit '+repo)
    return assess(rows,centers)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',required=True)
    p.add_argument('--verify',action='store_true')
    args=p.parse_args()
    try:
        raw=serial(collect())
        target=Path(args.output)
        if args.verify:
            need(target.is_file() and target.read_bytes()==raw,
                 'separate Runner original authenticated GET mismatch')
        else: target.write_bytes(raw)
        print('ISSUE311_R11_READONLY_ORIGINAL_GET_MATCH',hashlib.sha256(raw).hexdigest(),
              'NO_CRON_REMOVAL_NO_PUBLISH')
        return 0
    except Exception as e:
        print('ISSUE311_R11_INVENTORY_INCOMPLETE',type(e).__name__,str(e)[:180],file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
