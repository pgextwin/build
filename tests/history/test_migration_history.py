#!/usr/bin/env python3
"""Re-prove the frozen generated migration review templates, without applying."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence/issue-75/publication-migration"
spec = importlib.util.spec_from_file_location("history_migration_planner", ROOT / "scripts/publication-migration-plan.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MigrationHistory(unittest.TestCase):
    def test_frozen_generated_templates_match(self):
        snapshot = json.loads((EVIDENCE / "extension-snapshot.json").read_text())
        heads = json.loads((EVIDENCE / "observed-heads.json").read_text())
        self.assertEqual(m.plan(snapshot, heads),
                         json.loads((EVIDENCE / "review-templates.json").read_text()))


if __name__ == "__main__":
    unittest.main()
