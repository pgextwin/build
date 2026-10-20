#!/usr/bin/env python3
"""Issue #75: hostile offline classification checks; no PowerShell or installers."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue75_kb_conditional", ROOT / "scripts/issue-75-kb-conditional-inert.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class KBInertFixtures(TestCase):
    def test_literal_os_branches_are_candidates_never_validated_payloads(self):
        script = b"""$msuData = @{
    '6.1-client' = @{
        Url = 'https://download.microsoft.com/download/a/Windows6.1-x86.msu'
        Checksum = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        Url64 = 'https://download.microsoft.com/download/b/Windows6.1-x64.msu'
        Checksum64 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    }
}
Install-WindowsUpdate -Id 'KB3033929' -MsuData $msuData -ChecksumType 'sha256'
"""
        d = p.classify_script(script)
        self.assertEqual(d["osHashtableKeys"], ["6.1-client"])
        self.assertEqual(len(d["externalURLCandidates"]), 2)
        self.assertTrue(all(u["allowlistedHost"] and u["literalAssignment"]
                            and not u["payloadBytesVerified"]
                            for u in d["externalURLCandidates"]))
        self.assertEqual([x["literalSHA256"] for x in d["urlOrChecksumAssignments"]
                          if x["literalSHA256"]], ["a"*64, "b"*64])
        self.assertFalse(d["urlChecksumPairingProven"])
        self.assertFalse(d["osBranchReachabilityProven"])
        self.assertFalse(d["conditionalExternalPayloadBytesVerified"])

    def test_dynamic_and_indirect_downloads_remain_unresolved(self):
        source = b"""$url = $base + '/payload.msu'
$url64 = "https://download.microsoft.com/download/$variant/x.msu"
if ($os) { Invoke-WebRequest $url -OutFile $x }
Install-ChocolateyPackage $packageName 'msu' $args $url
"""
        d = p.classify_script(source)
        self.assertTrue(d["unresolvedDynamicOrIndirectBehavior"])
        self.assertFalse(d["externalURLCandidates"][0]["literalAssignment"])
        self.assertTrue(any(not a["resolved"] and a["property"] == "url"
                            for a in d["urlOrChecksumAssignments"]))
        self.assertTrue(any(z["name"].lower() == "invoke-webrequest"
                            for z in d["downloadOrExecutionHelperMentions"]))

    def test_unapproved_host_and_plain_http_not_promoted(self):
        d = p.classify_script(b"""Url = 'http://download.microsoft.com/foo.msu'
Url64 = 'https://evil.example/evil.msu'
Checksum = 'bad'
""")
        self.assertEqual(len(d["externalURLCandidates"]), 2)
        self.assertFalse(any(u["allowlistedHost"] for u in d["externalURLCandidates"]))
        self.assertFalse(d["urlOrChecksumAssignments"][2]["resolved"])

    def test_comment_urls_are_untrusted_lexical_candidates(self):
        d = p.classify_script(b"# https://download.microsoft.com/comment-only.msu\n")
        self.assertEqual(len(d["externalURLCandidates"]), 1)
        self.assertFalse(d["externalURLCandidates"][0]["literalAssignment"])
        self.assertTrue(d["unresolvedDynamicOrIndirectBehavior"])

    def test_oversized_script_fails_closed(self):
        with self.assertRaises(p.Deny):
            p.classify_script(b"x" * 150_001)

    def test_archive_mutation_denied_before_power_shell_parsing(self):
        def fake_get(*_args):
            return b"forged"
        with self.assertRaisesRegex(p.Deny, "original changed"):
            p.observe(download=fake_get)

    def test_package_allowlist_unique_and_hash_pinned(self):
        self.assertEqual(len(p.PACKAGES), 8)
        self.assertEqual(len(set((name.lower(), version)
                                 for name, version, _ in p.PACKAGES)), 8)
        self.assertTrue(all(len(digest) == 64
                            and all(ch in "0123456789abcdef" for ch in digest)
                            for _, _, digest in p.PACKAGES))

    def test_isolated_pr_and_resolver_wireup_without_publication(self):
        wf = (ROOT/"tests/fixtures/historical-workflows/validate-issue75-pr-oneoffs.yml").read_text(encoding="utf-8")
        self.assertIn("github.head_ref == 'issue-75-kb-conditional-inert'", wf)
        self.assertIn("name: Issue75 KB/MSU inert source inventory", wf)
        self.assertIn("python tests/test-issue-75-kb-conditional-inert.py", wf)
        self.assertIn("python scripts/issue-75-kb-conditional-inert.py --mode static", wf)
        self.assertIn("python scripts/issue-75-kb-conditional-inert.py --mode observe", wf)
        section = wf.split("  issue75_kb_inert:", 1)[1].split(
            "\n  existing_signed_release_readonly:", 1)[0]
        self.assertIn("contents: read", section)
        self.assertIn("persist-credentials: false", section)
        self.assertNotIn("contents: write", section)
        self.assertNotIn("id-token: write", section)
        self.assertNotIn("secrets.", section)
        self.assertNotIn("upload-artifact", section)

if __name__ == "__main__":
    main()
