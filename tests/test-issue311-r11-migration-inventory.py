#!/usr/bin/env python3
"""Hostile offline R11 gate tests. No network and no authority to migrate."""
from copy import deepcopy
import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('r11',Path('scripts/issue311-r11-migration-inventory.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=b'''name: candidate
on:
  schedule:
    - cron: "30 * * * *"
  push:
    branches: [main]
  workflow_run:
    workflows: ["Windows CI/CD"]
    types: [completed]
jobs:
  authorize:
    if: github.event_name == 'schedule'
    uses: pgextwin/build/.github/workflows/operator-update-auto.yml@d8904ebc377e33034b71108d42de940d6b6c9979
'''
assert m.extension_status('orafce',base)['migrationAccepted'] is False
hypo=base.replace(b'  push:',b'    - cron: "41 * * * *"\n  push:')
assert m.extension_status('hypopg',hypo)['cron']==[m.CRON,m.HYPOPG_CRON]
count=0
def reject(repo,source):
    global count
    try:m.extension_status(repo,source)
    except (ValueError,KeyError,TypeError): count+=1;return
    raise AssertionError('R11 unsafe schedule switch accepted')
reject('orafce',base.replace(b'  schedule:',b'  workflow_dispatch:'))
reject('orafce',base.replace(b"    if: github.event_name == 'schedule'",b"    if: github.event_name == 'push'"))
reject('orafce',base.replace(b'  workflow_run:',b'  workflow_dispatch:'))
reject('orafce',base.replace(b'  push:',b'  workflow_dispatch:'))
reject('orafce',base.replace(b'30 * * * *',b'15 * * * *'))
reject('hypopg',base)
reject('orafce',hypo)
reject('orafce',base.replace(b'operator-update-auto.yml@',b'wrong.yml@'))
reject('orafce',b'\xff\xfe')
rows=[{'repository':'pgextwin/'+x,'schedule':{'migrationAccepted':False}} for x in m.EXTENSIONS]
centers=[{'repository':'pgextwin/'+x,'migrationAccepted':False} for x in m.CENTRAL]
r=m.assess(rows,centers)
assert r['r11_01Accepted'] is False and r['r11_02Accepted'] is False
assert r['legacyScheduleMustRemain'] is True and r['writerUsed'] is False
assert r['publicationAuthorized'] is False
for x,y in ((rows[:-1],centers),(rows,centers[:-1])):
    try:m.assess(x,y)
    except ValueError:count+=1
    else:raise AssertionError('partial inventory falsely accepted')
unsafe=deepcopy(centers);unsafe[0]['migrationAccepted']=True
try:m.assess(rows,unsafe)
except ValueError:count+=1
else:raise AssertionError('migrated central without evidence')
assert count==12,count
print('ISSUE311_R11_OFFLINE_NEGATIVE_PASS',count,'NO_CRON_REMOVAL')
