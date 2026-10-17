#!/usr/bin/env python3
"""PR-only inert Git checkout/runner inventory. No GH_TOKEN/Signer/Writer access.

May inspect local .git/config in its disposable job, never prints its bytes.
Do not infer absence of credentials in the separately pinned deployed Signer.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

class Deny(ValueError): pass
LEAK = re.compile(
    r"(?i)(authorization\s*[:=]|extraheader\s*=|x-access-token|"
    r"github_pat_|gh[pousr]_[A-Za-z0-9]+|"
    r"(?:GH_TOKEN|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)\s*=|"
    r"(?:\[credential\]|credential\s*\.\s*helper)|password\s*[:=])"
)
def inspect_bytes(raw):
    """Never return or log the examined bytes; synthetic fixtures only in tests."""
    if not isinstance(raw,bytes) or len(raw)>50000:
        raise Deny("unsafe file size")
    if LEAK.search(raw.decode("utf-8",errors="replace")):
        raise Deny("potential credential persistence")
    return True
def inspect_workspace(workspace):
    root=Path(workspace)
    if not root.is_dir() or root.is_symlink():
        raise Deny("invalid job workspace")
    dotgit=root/".git"
    if not dotgit.is_dir() or dotgit.is_symlink():
        raise Deny("missing or redirected Git configuration")
    candidates=[dotgit/"config",dotgit/"credentials"]
    modules=dotgit/"modules"
    if modules.exists():
        if modules.is_symlink(): raise Deny("redirected git modules")
        candidates.extend(modules.rglob("config"))
    checked=0
    for item in candidates:
        if item.is_symlink(): raise Deny("redirected Git config")
        if item.exists():
            if not item.is_file(): raise Deny("unexpected credential file type")
            inspect_bytes(item.read_bytes())
            checked+=1
    if not (dotgit/"config").is_file():
        raise Deny("no checked Git configuration")
    return checked
def safe_version(value):
    return value if isinstance(value,str) and re.fullmatch(r"[A-Za-z0-9._ +()/-]{1,100}",value) else "UNKNOWN"
def read_only_version(exe):
    binary=shutil.which(exe)
    if not binary:return "NOT_PRESENT"
    try:
        result=subprocess.run([binary,"--version"],capture_output=True,text=True,
                              timeout=8,check=False,stdin=subprocess.DEVNULL)
        if result.returncode:return "NOT_OBSERVED"
        return safe_version((result.stdout or "").strip().splitlines()[0])
    except (OSError,TimeoutError,IndexError):
        return "NOT_OBSERVED"
def main():
    # The separate sandbox checkout is only a local non-publishing negative
    # proof. Never pass github.token or any secret into this job environment.
    out={"decision":"SANDBOX_NOT_PROVEN","goB":"NO_GO","g4":"NO_GO",
         "g5":"NO_GO","signerRuntimeCredentialIsolationProven":False,
         "writerTokenIsolationProven":False,"publicationAuthorized":False}
    try:
        if any(os.environ.get(x) for x in ("GH_TOKEN","GITHUB_TOKEN")):
            raise Deny("unexpected explicit token environment")
        if os.environ.get("GITHUB_EVENT_NAME")!="pull_request" or \
           os.environ.get("GITHUB_HEAD_REF")!="issue-75-signer-credential-external-proof" or \
           os.environ.get("GITHUB_REPOSITORY")!="pgextwin/build" or \
           os.environ.get("GITHUB_JOB")!="issue75_sandbox_probe":
            raise Deny("untrusted job context")
        count=inspect_workspace(os.environ.get("GITHUB_WORKSPACE",""))
        out.update(decision="SANDBOX_NONPERSISTENT_CHECKOUT_ONLY",
                   inspectedGitFiles=count,
                   pythonVersion=safe_version(platform.python_version()),
                   runnerOs=safe_version(os.environ.get("RUNNER_OS","")),
                   runnerArchitecture=safe_version(os.environ.get("RUNNER_ARCH","")),
                   imageOs=safe_version(os.environ.get("ImageOS","")),
                   imageVersion=safe_version(os.environ.get("ImageVersion","")),
                   chocolateyCliVersion=(read_only_version("choco")
                                        if os.environ.get("RUNNER_OS")=="Windows"
                                        else "NOT_APPLICABLE"),
                   sandboxCheckoutCredentialFound=False,
                   signerRuntimeCredentialIsolationProven=False)
    except (Deny,OSError,TypeError,ValueError):
        out["reasonCode"]="SANDBOX_IDENTITY_OR_LOCAL_GIT_CONFIG_UNPROVEN"
    print(json.dumps(out,sort_keys=True))
    # No positive signed Publisher receipt is possible from this result.
    return 0
if __name__=="__main__":sys.exit(main())
