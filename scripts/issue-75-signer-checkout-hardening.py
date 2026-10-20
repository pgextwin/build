#!/usr/bin/env python3
"""Issue #75: inert Signer checkout-hardening patch proof + Action root inventory.

Offline only: no GitHub API, no secrets, no Signer invocation, no commit
mutation, no Publisher permission. A proposed byte diff is NOT a deployed pin.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
# The 5756b3c5 immutable historical Signer must remain an exact fixture:
# the main-branch source is changed only for FUTURE separately approved pins.
SIGNER = ROOT / "tests/fixtures/issue-75-original-signer-5756b3c5.yml"
MAIN_CANDIDATE = ROOT / ".github/workflows/build-extension-attested.yml"
EVIDENCE = ROOT / "evidence/issue-75/action-roots-signer-hardening-20261017.json"
EXPECTED_SIGNER = "93a0a7641253735cf5adb845c768981c79f75b46"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
ACTIONS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "5b0524f730db83f9513c18ab31a6c086c7239076", "faf0e22120b3e68dd2d480968fe3ae5227079ad4", "8254fdcb2607245529e80705d59fa93407c07c00"),
    "actions/setup-python": ("ece7cb06caefa5fff74198d8649806c4678c61a1", "7a9a7b634ec348b35b882f1f14fcaa4d41836a8e", "62d9ae1b7b09a47477d1816ce3dcbd3e477c97b0", "2c14c5496daa839d0f3771408b302e81d75cade3"),
    "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "7cb4d1e81db55320b41217e1a78a1a46e3d2baef", "7b5e8775fc15bcc6a4a83897ccc9d00b722d5284", "98611229ac6c2b129cdcf813ccb68a1590bd4e8f"),
    "actions/download-artifact": ("3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "8b8c65029ccad20750a29fecb438eca5a607fc57", "c8e8d8fd5b0870b7aaa920099b202943979353bf", "511ccd68589c860b1d48d956dbf37d777a1c1245"),
    "actions/attest": ("1e69f48acb82d1966a394da916b4c1698aa569d6", "f3d593f3020cf14b65d2789e3788d015354475e9", "abb24e7f936f4326f55b99c0cbc1b77cca2f3146", "cb69a9a5b16fc356366a7e8d259a8fd4cb159d3d"),
    "actions/create-github-app-token": ("bcd2ba49218906704ab6c1aa796996da409d3eb1", "9f45ab3e2605ffeb987d3e029f27ee4d96bca6a0", "6120d7e4883ec0491b2afa6dcb1c845218ca5ae7", "41e12c94a9c70ec4135eecb750ca10247c10febf"),
}
class Deny(ValueError): pass
def need(ok, message):
    if not ok: raise Deny(message)
def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
def unique(pairs):
    out = {}
    for k,v in pairs:
        need(k not in out, "duplicate evidence field")
        out[k]=v
    return out
def record(raw):
    need(len(raw) < 40000, "oversize action inventory")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
def hardened_signer(raw):
    """Propose five exact checkout changes in memory without changing any repository."""
    need(blob(raw) == EXPECTED_SIGNER, "Signer pinned source bytes drift")
    need(b"\r\n" not in raw, "unexpected Signer line endings")
    lines = raw.decode("utf-8").splitlines(keepends=True)
    uses = re.compile(r"^        uses: actions/checkout@([a-f0-9]{40})(?:\s+#.*)?$")
    loc = [i for i,l in enumerate(lines) if uses.fullmatch(l.rstrip("\n"))]
    need(len(loc) == 5 and all(uses.fullmatch(lines[i].rstrip("\n")).group(1) ==
                               CHECKOUT_SHA for i in loc), "Signer five pinned checkout steps changed")
    updates=[]
    for i in loc:
        end=next((j for j in range(i+1,len(lines))
                  if re.match(r"^      - ",lines[j]) or
                  re.match(r"^  [a-zA-Z_]+:",lines[j])),len(lines))
        step="".join(lines[i:end])
        need("persist-credentials:" not in step and "token:" not in step
             and "ssh-key:" not in step, "checkout already remediated or credentials overridden")
        with_lines=[j for j in range(i+1,end) if lines[j].startswith("        with:")]
        need(len(with_lines)<=1, "checkout ambiguous with map")
        replacement=("          persist-credentials: false\n" if with_lines
                     else "        with:\n          persist-credentials: false\n")
        updates.append((with_lines[0]+1 if with_lines else i+1,replacement))
    for i,addition in reversed(updates):
        lines.insert(i,addition)
    proposed="".join(lines).encode("utf-8")
    need(proposed.count(b"persist-credentials: false") == 5
         and proposed.count(("uses: actions/checkout@"+CHECKOUT_SHA).encode()) == 5
         and blob(proposed)!=EXPECTED_SIGNER, "unsafe future Signer proposal")
    return proposed
def verify_main_candidate(main_bytes, historical_bytes):
    """Check actual main source equals the exact minimal 5-checkout proposal.

    This is a source comparison, not a new authorized signer digest or proof of
    issued Sigstore certificates, security isolation or Publisher approval.
    """
    proposal = hardened_signer(historical_bytes)
    need(type(main_bytes) is bytes and main_bytes == proposal,
         "main source does not match immutable minimal checkout-only hardening")
    return {
        "mainSourceOnlyCheckoutPersistenceDisabled": 5,
        "futureSignerSourceBlob": blob(main_bytes),
        "historicalPinnedSignerBlob": EXPECTED_SIGNER,
        "actualPublishedSignerPinMigrated": False,
        "realSignerOidcVerified": False,
        "publicationAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }

def inspect(evidence, signer_bytes):
    need(type(evidence) is dict and evidence.get("schemaVersion")==1
         and evidence.get("kind")=="ISSUE75_SIGNER_CHECKOUT_ACTION_ROOTS_OFFLINE_NO_GO",
         "unknown root inventory")
    s=evidence.get("signer")
    need(type(s) is dict and s == {
         "repository":"pgextwin/build",
         "commit":"5756b3c5136a8bf4db710016cfe97555f0a71c6d",
         "workflow":".github/workflows/build-extension-attested.yml",
         "blob":EXPECTED_SIGNER,
         "checkoutOccurrences":5,
         "persistCredentialsDisabledOccurrences":0}, "active Signer pin or checkout observations drift")
    actions=evidence.get("actions")
    need(type(actions) is dict and set(actions)==set(ACTIONS),
         "unexpected, missing, or extra Action root")
    for action,(commit,manifest,lock,dist) in ACTIONS.items():
        a=actions[action]
        need(type(a) is dict and a=={
            "commit":commit, "manifestBlob":manifest, "lockBlob":lock,
            "distTree":dist, "observation":"root_tree_and_manifest_source_only",
            "fullTransitiveClosureProven":False},
            "Action source identity/closure drift: "+action)
    gaps=evidence.get("unresolved")
    need(type(gaps) is dict and set(gaps)=={
         "actionBundles","runnerImages","chocolatey","python",
         "syftGrype","signerCheckout","token"} and
         all(type(gaps[k]) is str and len(gaps[k])>30 for k in gaps),
         "unreported runtime dependency gap")
    decision=evidence.get("decision")
    need(type(decision) is dict and decision=={
         "sourceCandidateOnly":True, "actualSignerDeployedHardening":False,
         "runnerIsolationProven":False, "actionExecutableClosureProven":False,
         "writerTokenIsolationProven":False,
         "signedPublisherPositivePrewriteProven":False,
         "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
         "publicationAuthorized":False}, "forged runtime hardening or Publisher acceptance")
    proposed=hardened_signer(signer_bytes)
    return {"decision":"PROPOSED_SIGNER_PATCH_OFFLINE_ONLY",
            "activeSignerBlob":EXPECTED_SIGNER,
            "proposedSignerBlob":blob(proposed),
            "checkoutHardeningProposed":5,"checkoutHardeningDeployed":0,
            "actionRootsObserved":len(ACTIONS), "actionRuntimeDependencyClosure":False,
            "chocolateyDigestsVerified":False,"pythonWheelHashesVerified":False,
            "runnerImageDigestVerified":False,"writerTokenIsolationProven":False,
            "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO","publicationAuthorized":False}
def main():
    try:
        historical = SIGNER.read_bytes()
        result = inspect(record(EVIDENCE.read_bytes()), historical)
        result.update(verify_main_candidate(MAIN_CANDIDATE.read_bytes(), historical))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Deny, OSError, ValueError, TypeError, KeyError, UnicodeError) as e:
        print(json.dumps({"decision":"DENY_SIGNER_HARDENING_PROOF",
                          "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
                          "publicationAuthorized":False},sort_keys=True))
        return 2
if __name__=="__main__":sys.exit(main())
