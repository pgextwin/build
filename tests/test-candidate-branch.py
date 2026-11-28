"""F21-03 branch naming and repository boundaries."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
from unittest import TestCase, main

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from candidate_branch import (ParsedCandidateBranch, branch_style_for_repository,
                              format_branch, parse_branch, validate_extension_name)

ID = "a" * 20
LEGACY = f"auto-candidate/{ID}"
CENTRAL = f"auto-candidate/pg_bigm/{ID}"


class CandidateBranchTests(TestCase):
    def test_tc01_central_round_trip(self):
        self.assertEqual(format_branch("pg_bigm", ID, "central"), CENTRAL)
        parsed = parse_branch(CENTRAL, expected_extension="pg_bigm")
        self.assertEqual(parsed, ParsedCandidateBranch("central", "pg_bigm", ID, CENTRAL))
        with self.assertRaises(FrozenInstanceError):
            parsed.extension = "pgaudit"

    def test_tc02_legacy_round_trip(self):
        self.assertEqual(format_branch("pg_bigm", ID, "legacy"), LEGACY)
        self.assertEqual(parse_branch(LEGACY, expected_extension="pg_bigm"),
                         ParsedCandidateBranch("legacy", None, ID, LEGACY))

    def test_tc03_reject_other_extension_and_invalid_names(self):
        with self.assertRaises(ValueError):
            parse_branch(CENTRAL, expected_extension="pgaudit")
        for name in ("Pg_bigm", ".", "pg_bigm.lock", "con", "prn", "aux", "nul",
                     "com0", "com9", "lpt0", "lpt9", "pg-bigm", "pg bigm",
                     "pg/bigm", "pg\\bigm", "pg\né", "é", "a" * 65, ""):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    parse_branch(f"auto-candidate/{name}/{ID}")
                with self.assertRaises(ValueError):
                    format_branch(name, ID, "legacy")
        validate_extension_name("a" * 64)
        for branch in (None, CENTRAL + "\n", LEGACY + "\n", CENTRAL + "/extra",
                       f"auto-candidate//{ID}", f"auto-candidate/{ID.upper()}",
                       f"auto-candidate/{ID[1:]}", f"auto-candidate/{ID}a"):
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                parse_branch(branch)
        for candidate_id, style in ((ID.upper(), "central"), (ID, "other")):
            with self.subTest(candidate_id=candidate_id, style=style), self.assertRaises(ValueError):
                format_branch("pg_bigm", candidate_id, style)

    def test_tc04_exclusive_formats(self):
        self.assertEqual(parse_branch(CENTRAL, allow_legacy=False).style, "central")
        self.assertEqual(parse_branch(LEGACY, allow_central=False).style, "legacy")
        with self.assertRaises(ValueError):
            parse_branch(LEGACY, allow_legacy=False)
        with self.assertRaises(ValueError):
            parse_branch(CENTRAL, allow_central=False)

    def test_tc05_repository_boundaries(self):
        self.assertEqual(branch_style_for_repository("pgextwin/build", "pg_bigm"), "central")
        self.assertEqual(branch_style_for_repository("pgextwin/pg_bigm", "pg_bigm"), "legacy")
        for repo, extension in (("pgextwin/pg_bigm", "pgaudit"), ("other/build", "pg_bigm"),
                                ("pgextwin/build", "con")):
            with self.subTest(repo=repo, extension=extension), self.assertRaises(ValueError):
                branch_style_for_repository(repo, extension)


if __name__ == "__main__":
    main()
