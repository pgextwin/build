# Candidate Contents transport repair

GitHub's Contents API returns line-wrapped base64. The original protected-main
postmerge observer and scheduled signing-intent adapter used strict base64
decoding without removing wrapping, so a genuine future candidate could be
rejected before signing. A current immutable orafce manifest reproduces this
failure; that source read is not a new candidate or signing receipt.

The native manifest binder, protected-main observer and signing-intent adapter
now share `github_contents.py`. It removes only CR/LF, requires canonical
base64, validates the exact Git blob digest and any supplied byte count, rejects
oversized data, and parses one UTF-8 JSON object without duplicate keys or
nonfinite values. Transport integrity never grants signature or publication
authority. Existing source, origin, PR, App15368, artifact and policy gates
remain mandatory.

The native PR auditor and protected-main observer both read Check Runs. Their
reusable jobs, and the matching caller jobs, explicitly declare checks/read;
all other permissions remain unchanged. This is read access to the public
candidate's required-check evidence, not a new App, Secret, WRITE scope or
branch-protection exception.

Deploy only the two repaired reusable workflow refs to the new protected build
SHA. Preserve the scheduled detector/operator refs, attested builder, candidate
policy, all source manifests, signer/verifier pins and manual-only publication
settings. Genuine signing E2E still requires an actual manifest-only stable
candidate; ordinary pin-update Windows CI cannot stand in for that evidence.
