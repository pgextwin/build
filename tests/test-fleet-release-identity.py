#!/usr/bin/env python3
"""No-network heterogeneous 14-extension manual Release identity denial matrix."""
from datetime import date
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ident",ROOT/"scripts"/"fleet-release-identity.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)

# Real upstream ref conventions, as verified against existing signed GitHub Releases.
SOURCES = {
    "pg_bigm": ("v1.2-20250903", "1.2", "v1.2-20250903-windows.3"),
    "pg_cron": ("v1.6.8", "1.6.8", "v1.6.8-windows.3"),
    "set_user": ("REL4_2_0", "4.2.0", "v4.2.0-windows.3"),
    "pg_repack": ("ver_1.5.3", "1.5.3", "v1.5.3-windows.3"),
    "pg_ivm": ("v1.16", "1.16", "v1.16-windows.3"),
    "pg_qualstats": ("2.1.4", "2.1.4", "v2.1.4-windows.3"),
    "plpgsql_check": ("v2.10.14", "2.10.14", "v2.10.14-windows.2"),
    "hypopg": ("1.4.3", "1.4.3", "v1.4.3-windows.2"),
    "wal2json": ("wal2json_2_6", "2.6", "v2.6-windows.2"),
    "pg_partman": ("v5.5.0", "5.5.0", "v5.5.0-windows.3"),
    "pg_stat_monitor": ("2.4.0", "2.4.0", "v2.4.0-windows.2"),
    "orafce": ("VERSION_4_16_13", "4.16.13", "v4.16.13-windows.2"),
}
PER_MAJOR = {
    "pgaudit": {
        14: ("1.6.3","1.6.3"),15: ("1.7.1","1.7.1"),
        16: ("16.1","16.1"),17: ("17.1","17.1"),18: ("18.0","18.0")
    },
    "pg_hint_plan": {
        14: ("REL14_1_4_4","1.4.4"),15: ("REL15_1_5_3","1.5.3"),
        16: ("REL16_1_6_2","1.6.2"),17: ("REL17_1_7_1","1.7.1"),
        18: ("REL18_1_8_0","1.8.0")
    },
}
TAGS = {"pgaudit":"v18.0-windows.3","pg_hint_plan":"v1.8.0-windows.3"}

def manifest(name):
    obj={"schemaVersion":1,"name":name,
         "upstream":{"repository":lib.UPSTREAMS[name]},
         "postgresql":{"majors":[14,15,16,17,18]}}
    if name in SOURCES:
        ref,version,_=SOURCES[name]
        obj["upstream"].update(ref=ref,version=version,commit="a"*40)
    else:
        obj["upstream"]["perPostgresql"]={
            str(m):{"ref":ref,"version":version,"commit":"b"*40}
            for m,(ref,version) in PER_MAJOR[name].items()
        }
    return obj

class IdentityTests(unittest.TestCase):
    def test_every_fleet_member_has_an_exact_tag_and_fifteen_assets(self):
        self.assertEqual(len(lib.UPSTREAMS),14)
        self.assertEqual(set(lib.UPSTREAMS),set(SOURCES)|set(PER_MAJOR))
        for name in lib.UPSTREAMS:
            with self.subTest(extension=name):
                obj=manifest(name)
                tag=SOURCES[name][2] if name in SOURCES else TAGS[name]
                lib.validate_release_tag(obj,tag)
                self.assertEqual(len(lib.expected_assets(obj,[14,15,16,17,18])),16)
                self.assertEqual(len(lib.sources(obj)),5)
                for m in range(14,19):
                    stem=lib.asset_stem(obj,m)
                    self.assertIn(stem+".zip",lib.expected_assets(obj,[14,15,16,17,18]))

    def test_pg14_lifecycle_eol_is_respected(self):
        data={"schemaVersion":1,"postgresql":[
            {"major":m,"eol":"2026-11-12" if m==14 else "2030-12-31"}
            for m in range(14,19)]}
        ext=manifest("hypopg")
        self.assertEqual(lib.maintained_majors(ext,data,date(2026,10,11)),[14,15,16,17,18])
        self.assertEqual(lib.maintained_majors(ext,data,date(2026,11,13)),[15,16,17,18])

    def test_tampering_and_missing_sha_fail_closed(self):
        x=manifest("wal2json")
        x["upstream"]["commit"]=None
        with self.assertRaises(lib.Denied):lib.sources(x)
        self.assertEqual(len(lib.sources(x,require_pins=False)),5)
        x=manifest("pgaudit")
        x["upstream"]["perPostgresql"].pop("17")
        with self.assertRaises(lib.Denied):lib.sources(x)
        x=manifest("hypopg")
        x["upstream"]["repository"]="attacker/hypopg"
        with self.assertRaises(lib.Denied):lib.sources(x)
        x=manifest("pg_bigm")
        x["upstream"]["ref"]="v1.2-20250903-malicious"
        with self.assertRaises(lib.Denied):lib.tag_stem(x)
        x=manifest("pg_ivm")
        for bad in ("v1.16-windows.0","v1.16-windows.2;evil",
                    "v1.17-windows.1","refs/heads/main","v1.16-windows.01"):
            with self.subTest(tag=bad),self.assertRaises(lib.Denied):
                lib.validate_release_tag(x,bad)
        x=manifest("pg_repack")
        with self.assertRaises(lib.Denied):lib.expected_assets(x,[15,15,16])
        with self.assertRaises(lib.Denied):lib.expected_assets(x,[13,14])
        with self.assertRaises(lib.Denied):lib.asset_stem(x,19)
        x["postgresql"]["majors"]=[14,14,15]
        with self.assertRaises(lib.Denied):lib.configured_majors(x)

if __name__ == "__main__":
    unittest.main()
