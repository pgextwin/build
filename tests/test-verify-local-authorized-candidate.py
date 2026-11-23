#!/usr/bin/env python3
"""Stage-2 verification tests. All signing below is TEST ONLY, never production.

RFC 8032 section 7.1 fixtures are public test data, NOT operational secrets:
https://www.rfc-editor.org/rfc/rfc8032#section-7.1
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-local-authorized-candidate.py"
spec = importlib.util.spec_from_file_location("local_candidate_verifier", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

# Public RFC test fixtures; never use these keys for real authorization.
RFC_VECTORS = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]
TEST_ONLY_RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


def test_only_encode(point):
    """TEST ONLY point encoding for the signing fixture helper."""
    x, y, z, _ = point
    inv_z = pow(z, verifier._P - 2, verifier._P)
    x, y = x * inv_z % verifier._P, y * inv_z % verifier._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def test_only_sign(message):
    """TEST ONLY RFC 8032 signing, using a publicly documented test seed."""
    digest = hashlib.sha512(TEST_ONLY_RFC_SEED).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar = (scalar & ((1 << 254) - 8)) | (1 << 254)
    public = test_only_encode(verifier._scalar_mul(scalar, verifier._BASE))
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % verifier._L
    encoded_r = test_only_encode(verifier._scalar_mul(r, verifier._BASE))
    h = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % verifier._L
    return encoded_r + ((r + h * scalar) % verifier._L).to_bytes(32, "little")


def sign_ticket(ticket):
    unsigned = {key: value for key, value in ticket.items() if key != "signature"}
    ticket["signature"] = test_only_sign(verifier.canonical_json(unsigned)).hex()
    return ticket


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors_pure_and_selected_backend(self):
        for public, message, signature in RFC_VECTORS:
            with self.subTest(message=message):
                args = tuple(bytes.fromhex(value) for value in (public, message, signature))
                self.assertTrue(verifier.verify_ed25519_pure(*args))
                self.assertTrue(verifier.verify_ed25519(*args))
                self.assertFalse(verifier.verify_ed25519_pure(args[0], args[1] + b"tampered", args[2]))

    def test_test_only_signer_matches_rfc8032(self):
        self.assertEqual(test_only_sign(b"").hex(), RFC_VECTORS[0][2])

    def test_reject_malleable_scalar(self):
        public, message, signature = (bytes.fromhex(value) for value in RFC_VECTORS[0])
        s = int.from_bytes(signature[32:], "little") + verifier._L
        bad_signature = signature[:32] + s.to_bytes(32, "little")
        self.assertFalse(verifier.verify_ed25519_pure(public, message, bad_signature))
        self.assertFalse(verifier.verify_ed25519(public, message, bad_signature))

    def test_reject_bad_lengths_and_point_encodings(self):
        public, message, signature = (bytes.fromhex(value) for value in RFC_VECTORS[0])
        identity = b"\x01" + b"\x00" * 31
        bad_points = [
            b"", b"x" * 31, verifier._P.to_bytes(32, "little"),
            identity, b"\x00" * 32,  # identity and order-four point
            (1 + 2**255).to_bytes(32, "little"),  # x=0 with sign bit set
        ]
        for bad in bad_points:
            with self.subTest(point=bad.hex()):
                self.assertFalse(verifier.verify_ed25519_pure(bad, message, signature))
                self.assertFalse(verifier.verify_ed25519_pure(public, message, bad + signature[32:]))
        self.assertFalse(verifier.verify_ed25519_pure(public, message, signature[:-1]))
        self.assertFalse(verifier.verify_ed25519_pure(public, message, signature + b"x"))


class TicketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
        cls.inputs = verifier.canonical_json({
            "operation": "candidate", "extension": "hypopg",
            "upstream": {"repository": "HypoPG/hypopg", "tag": "TEST-v1", "commit": "a" * 40},
            "sources": {"17": {"commit": "a" * 40}},
        })
        cls.template_policy = json.loads((ROOT / "metadata/local-candidate-authority.json").read_text())
        cls.template_policy.update({
            "mode": "OBSERVE", "issuerKeyId": "RFC8032-TEST-ONLY",
            "issuerPublicKey": RFC_VECTORS[0][0],
            "delegationStartsAt": "2026-11-17T00:00:00Z",
            "delegationEndsAt": "2026-11-18T00:00:00Z",
        })
        cls.template_ticket = sign_ticket({
            "schemaVersion": 1, "sourceKind": "LOCAL_AUTH_REQUEST_V1",
            "issuerKeyId": "RFC8032-TEST-ONLY", "policyEpoch": 1,
            "policySha": "1" * 40, "requestId": "2" * 32, "nonce": "3" * 64,
            "issuedAt": "2026-11-17T11:59:00Z", "notBefore": "2026-11-17T11:59:00Z",
            "expiresAt": "2026-11-17T12:14:00Z", "operation": "candidate",
            "repository": "pgextwin/hypopg", "repositoryId": 987654321,
            "targetMainSha": "4" * 40, "centralMainSha": "5" * 40,
            "workflowPath": verifier.WORKFLOW_PATH, "verifierSha": "6" * 40,
            "inputsSha256": hashlib.sha256(cls.inputs).hexdigest(),
            "manifestBlob": "7" * 40, "upstreamSourcesSha256": "8" * 64,
        })

    def setUp(self):
        self.ticket = copy.deepcopy(self.template_ticket)
        self.policy = copy.deepcopy(self.template_policy)
        self.fleet = {"pgextwin/hypopg"}

    def verify(self, **kwargs):
        arguments = dict(ticket_obj=self.ticket, inputs_bytes=self.inputs,
                         policy=self.policy, fleet_repositories=self.fleet, now=self.now)
        arguments.update(kwargs)
        return verifier.verify_ticket(**arguments)

    def assert_rejected(self, code, function=None):
        with self.assertRaises(verifier.TicketRejected) as caught:
            (function or self.verify)()
        self.assertEqual(caught.exception.code, code)

    def test_valid_ticket_has_no_authority_or_side_effects(self):
        before_ticket, before_policy = copy.deepcopy(self.ticket), copy.deepcopy(self.policy)
        for mode in ("OBSERVE", "ENFORCE"):
            self.policy["mode"] = mode
            with self.subTest(mode=mode), patch("socket.socket", side_effect=AssertionError("network")), \
                    patch("subprocess.Popen", side_effect=AssertionError("subprocess")), \
                    patch("builtins.open", side_effect=AssertionError("file access")):
                result = self.verify()
            self.assertEqual(result["status"], "VERIFIED_TICKET_ONLY")
            self.assertFalse(result["authorized"])
            self.assertFalse(result["publication"])
            self.assertEqual(result["requestId"], self.ticket["requestId"])
        self.policy["mode"] = before_policy["mode"]
        self.assertEqual(self.ticket, before_ticket)
        self.assertEqual(self.policy, before_policy)

    def test_forced_pure_python_ticket_verification(self):
        with patch.object(verifier, "Ed25519PublicKey", None):
            self.assertEqual(self.verify()["status"], "VERIFIED_TICKET_ONLY")

    def test_canonical_ticket_round_trip(self):
        text = verifier.canonical_json(self.ticket).decode()
        self.assertEqual(verifier.parse_ticket(text), self.ticket)
        self.assertEqual(self.verify(ticket_obj=verifier.parse_ticket(text))["status"], "VERIFIED_TICKET_ONLY")

    def test_expired(self):
        self.assert_rejected("EXPIRED", lambda: self.verify(now=self.now + timedelta(minutes=14)))

    def test_unknown_fields(self):
        for name in ("extra", "authorizationMode", "candidatePr", "publication"):
            self.ticket[name] = False
            self.assert_rejected("UNKNOWN_FIELD")
            self.assert_rejected("UNKNOWN_FIELD", lambda: verifier.parse_ticket(json.dumps(self.ticket)))
            del self.ticket[name]

    def test_every_field_is_required(self):
        for field in verifier.TICKET_FIELDS:
            with self.subTest(field=field):
                ticket = dict(self.ticket)
                del ticket[field]
                self.assert_rejected("MISSING_FIELD", lambda: self.verify(ticket_obj=ticket))

    def test_duplicate_raw_json_key(self):
        raw = verifier.canonical_json(self.ticket).decode()
        self.assert_rejected("DUPLICATE_KEY", lambda: verifier.parse_ticket('{"nonce":"x",' + raw[1:]))

    def test_nested_duplicate_key(self):
        raw = '{"schemaVersion":{"nested":1,"nested":2}}'
        self.assert_rejected("DUPLICATE_KEY", lambda: verifier.parse_ticket(raw))

    def test_float_values(self):
        self.ticket["policyEpoch"] = 1.5
        self.assert_rejected("FLOAT_NOT_ALLOWED")
        self.assert_rejected("FLOAT_NOT_ALLOWED", lambda: verifier.parse_ticket(json.dumps(self.ticket)))
        for value in ("NaN", "Infinity", "-Infinity", "1e0", "1.0"):
            self.assert_rejected("FLOAT_NOT_ALLOWED", lambda: verifier.parse_ticket('{"x":' + value + '}'))
        self.assert_rejected("FLOAT_NOT_ALLOWED", lambda: verifier.parse_ticket('{"x":[{"a":1.5}]}'))

    def test_non_object_and_malformed_json(self):
        for raw in ("[]", "null", "1", '"text"', "true"):
            self.assert_rejected("NON_OBJECT", lambda: verifier.parse_ticket(raw))
        for raw in ("{", "", "{} {}"):
            self.assert_rejected("INVALID_JSON", lambda: verifier.parse_ticket(raw))

    def test_noncanonical_raw_ticket(self):
        for raw in (json.dumps(self.ticket), verifier.canonical_json(self.ticket).decode() + "\n"):
            self.assert_rejected("NON_CANONICAL_TICKET", lambda: verifier.parse_ticket(raw))

    def test_signature_mismatch_for_signed_field_substitution(self):
        for field in ("targetMainSha", "centralMainSha", "policySha", "verifierSha", "manifestBlob"):
            old = self.ticket[field]
            self.ticket[field] = "f" * 40
            with self.subTest(field=field):
                self.assert_rejected("BAD_SIGNATURE")
            self.ticket[field] = old

    def test_signature_mismatch(self):
        self.ticket["signature"] = "00" * 64
        self.assert_rejected("BAD_SIGNATURE")

    def test_repository_not_in_fleet(self):
        self.ticket["repository"] = "pgextwin/unregistered"
        self.assert_rejected("REPO_NOT_IN_FLEET")

    def test_sha_id_and_signature_formats(self):
        for field, length in verifier.HEX_LENGTHS.items():
            for invalid in ("a" * (length - 1), "g" * length, "A" * length, None, 42):
                with self.subTest(field=field, value=invalid):
                    ticket = dict(self.ticket, **{field: invalid})
                    self.assert_rejected("BAD_FORMAT", lambda: self.verify(ticket_obj=ticket))

    def test_numeric_fields_strict_including_boolean(self):
        for field in ("repositoryId", "policyEpoch"):
            for invalid in (0, -1, True, "1", None):
                with self.subTest(field=field, value=invalid):
                    ticket = dict(self.ticket, **{field: invalid})
                    self.assert_rejected("TYPE_MISMATCH", lambda: self.verify(ticket_obj=ticket))
        self.ticket["repositoryId"] = 2**53
        self.assert_rejected("INTEGER_OUT_OF_RANGE")

    def test_schema_kind_workflow_and_operation(self):
        for field, value, code in (
            ("schemaVersion", True, "SCHEMA_MISMATCH"),
            ("schemaVersion", 2, "SCHEMA_MISMATCH"),
            ("sourceKind", "ORIGINAL_OUTER_ZIP_VERIFIED", "SCHEMA_MISMATCH"),
            ("sourceKind", "LOCAL_AUTH_CANDIDATE_DECISION_V1", "SCHEMA_MISMATCH"),
            ("operation", "requalify", "OPERATION_NOT_ALLOWED"),
            ("operation", "sign", "OPERATION_NOT_ALLOWED"),
            ("operation", "publish", "OPERATION_NOT_ALLOWED"),
            ("workflowPath", ".github/workflows/update-watch.yml", "WORKFLOW_MISMATCH"),
        ):
            with self.subTest(field=field, value=value):
                self.assert_rejected(code, lambda: self.verify(ticket_obj=dict(self.ticket, **{field: value})))

    def test_string_limits(self):
        for field, value in (("issuerKeyId", "x" * 129), ("issuerKeyId", ""),
                             ("repository", "x" * 40 + "/repo"), ("repository", "repo")):
            self.assert_rejected("BAD_FORMAT", lambda: self.verify(ticket_obj=dict(self.ticket, **{field: value})))

    def test_bad_timestamps(self):
        for value in ("2026-11-17T12:00:00+00:00", "2026-11-17T12:00:00",
                      "2026-02-30T12:00:00Z", "2026-11-17T12:00:60Z", None):
            self.assert_rejected("BAD_TIMESTAMP", lambda: self.verify(ticket_obj=dict(self.ticket, issuedAt=value)))

    def test_lifetime_too_long(self):
        self.ticket["expiresAt"] = "2026-11-17T12:14:01Z"
        self.assert_rejected("LIFETIME_TOO_LONG")

    def test_nonpositive_lifetime(self):
        self.ticket["expiresAt"] = self.ticket["issuedAt"]
        self.assert_rejected("INVALID_LIFETIME")

    def test_not_before_too_far_future(self):
        self.ticket["notBefore"] = "2026-11-17T12:01:01Z"
        self.assert_rejected("NOT_YET_VALID")

    def test_sixty_second_future_tolerance(self):
        self.ticket["notBefore"] = "2026-11-17T12:01:00Z"
        sign_ticket(self.ticket)
        self.assertEqual(self.verify()["status"], "VERIFIED_TICKET_ONLY")

    def test_invalid_time_order(self):
        self.ticket["notBefore"] = "2026-11-17T11:58:59Z"
        self.assert_rejected("INVALID_TIME_ORDER")
        self.ticket["notBefore"] = self.ticket["expiresAt"]
        self.assert_rejected("INVALID_TIME_ORDER")

    def test_missing_or_naive_clock(self):
        for invalid in (None, self.now.replace(tzinfo=None), "2026-11-17T12:00:00Z"):
            self.assert_rejected("INVALID_CLOCK", lambda: self.verify(now=invalid))

    def test_policy_epoch_mismatch(self):
        self.policy["policyEpoch"] = 2
        self.assert_rejected("EPOCH_MISMATCH")

    def test_revoked_epoch(self):
        self.policy["revokedPolicyEpochs"] = [1]
        self.assert_rejected("EPOCH_REVOKED")

    def test_issuer_mismatch_and_key_unset(self):
        self.policy["issuerKeyId"] = "different-key"
        self.assert_rejected("ISSUER_MISMATCH")
        self.policy["issuerPublicKey"] = None
        self.assert_rejected("KEY_UNSET")

    def test_invalid_policy_fails_closed(self):
        for field, value in (("schemaVersion", True), ("mode", "UNKNOWN"),
                             ("policyEpoch", True), ("revokedPolicyEpochs", None),
                             ("revokedPolicyEpochs", [True]), ("issuerPublicKey", "x"),
                             ("allowedOperations", ["candidate", "publish"]), ("publication", True)):
            with self.subTest(field=field):
                self.assert_rejected("INVALID_POLICY", lambda: self.verify(policy=dict(self.policy, **{field: value})))

    def test_delegation_window(self):
        self.policy["delegationStartsAt"] = None
        self.assert_rejected("DELEGATION_UNSET")
        self.policy["delegationStartsAt"] = "2026-11-17T12:00:01Z"
        self.assert_rejected("OUTSIDE_DELEGATION")
        self.policy["delegationEndsAt"] = self.policy["delegationStartsAt"]
        self.assert_rejected("INVALID_POLICY")

    def test_inputs_hash_mismatch(self):
        self.assert_rejected("INPUTS_HASH_MISMATCH", lambda: self.verify(inputs_bytes=self.inputs + b" "))

    def test_inputs_are_strict_canonical_json(self):
        for raw, code in ((b'{ "x": 1 }', "NON_CANONICAL_INPUTS"),
                          (b'{"x":1,"x":2}', "DUPLICATE_KEY"),
                          (b'{"x":1.0}', "FLOAT_NOT_ALLOWED"),
                          (b'[]', "INVALID_INPUTS"), (b'\xff', "INVALID_INPUTS")):
            self.ticket["inputsSha256"] = hashlib.sha256(raw).hexdigest()
            with self.subTest(raw=raw):
                self.assert_rejected(code, lambda: self.verify(inputs_bytes=raw))

    def test_integer_only_canonical_golden_bytes(self):
        # Literal golden bytes, independent of json.dumps output in this test.
        self.assertEqual(verifier.canonical_json({"z": [1, True, None], "a": "\n\""}),
                         b'{"a":"\\n\\\"","z":[1,true,null]}')
        # RFC 8785 key sorting uses UTF-16 order, unlike Python codepoint order.
        self.assertEqual(verifier.canonical_json({"\ue000": 2, "\U00010000": 1}),
                         '{"\U00010000":1,"\ue000":2}'.encode())
        self.assert_rejected("INVALID_UNICODE", lambda: verifier.canonical_json({"x": "\ud800"}))

    def test_size_and_depth_limits(self):
        self.assert_rejected("TOO_LARGE", lambda: verifier.parse_ticket(" " * (verifier.MAX_TICKET_BYTES + 1)))
        self.assert_rejected("TOO_LARGE", lambda: self.verify(inputs_bytes=b"x" * (verifier.MAX_INPUTS_BYTES + 1)))
        self.assert_rejected("JSON_TOO_DEEP", lambda: verifier.parse_ticket("[" * 34 + "0" + "]" * 34))

    def test_production_policy_key_and_deny_precedence(self):
        real = json.loads((ROOT / "metadata/local-candidate-authority.json").read_text())
        self.assertEqual(real["issuerKeyId"], "local-auth-prod-1")
        self.assertEqual(real["issuerPublicKey"], "d8aaf19ea48e7ef9ca82dea860a04b5eafad92ff82378b5cd73d2f137b3a727c")
        deny = dict(real, mode="DENY")
        self.assert_rejected("DENY_MODE", lambda: verifier.authorize(self.ticket, self.inputs, deny, self.fleet, self.now))
        # DENY also precedes every other failure, even with malformed evidence.
        self.assert_rejected("DENY_MODE", lambda: verifier.authorize({}, b"", deny, set(), None))
        self.assert_rejected("ISSUER_MISMATCH", lambda: self.verify(policy=real))

    def test_deny_even_when_ticket_could_verify(self):
        self.policy["mode"] = "DENY"
        self.assertEqual(self.verify()["status"], "VERIFIED_TICKET_ONLY")
        self.assert_rejected("DENY_MODE", lambda: verifier.authorize(self.ticket, self.inputs, self.policy, self.fleet, self.now))

    def test_mode_edit_cannot_enable_production(self):
        for mode in ("OBSERVE", "ENFORCE", "UNKNOWN", None):
            self.policy["mode"] = mode
            self.assert_rejected("MODE_NOT_IMPLEMENTED", lambda: verifier.authorize(self.ticket, self.inputs, self.policy, self.fleet, self.now))

    def test_repeat_verification_is_evidence_only_not_a_claim(self):
        first, second = self.verify(), self.verify()
        self.assertEqual(first, second)
        self.assertFalse(second["authorized"])

    def test_cli_deny_read_only_and_load_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            ticket_path, inputs_path = Path(temp) / "ticket.json", Path(temp) / "inputs.json"
            ticket_path.write_bytes(verifier.canonical_json(self.ticket))
            inputs_path.write_bytes(self.inputs)
            before = {p.name: p.read_bytes() for p in Path(temp).iterdir()}
            command = [sys.executable, str(SCRIPT), "--ticket", str(ticket_path), "--inputs", str(inputs_path)]
            result = subprocess.run(command, capture_output=True, text=True, cwd=temp, check=False)
            self.assertEqual(result.returncode, 1)
            policy = json.loads((ROOT / "metadata/local-candidate-authority.json").read_text())
            code = "DENY_MODE" if policy["mode"] == "DENY" else "MODE_NOT_IMPLEMENTED"
            self.assertEqual(json.loads(result.stderr), {"status": "REJECTED", "code": code})
            self.assertEqual(result.stdout, "")
            self.assertEqual(before, {p.name: p.read_bytes() for p in Path(temp).iterdir()})
            inputs_path.unlink()
            result = subprocess.run(command, capture_output=True, text=True, cwd=temp, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stderr)["code"], "LOAD_ERROR")


class PolicySchemaTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "metadata/local-candidate-authority.json").read_text())
        self.schema = json.loads((ROOT / "schema/local-candidate-authority.schema.json").read_text())

    def test_required_shape_without_external_dependencies(self):
        self.assertEqual(set(self.policy), set(self.schema["required"]))
        self.assertEqual(set(self.policy), set(self.schema["properties"]))
        self.assertFalse(self.schema["additionalProperties"])
        self.assertEqual(self.policy["schemaVersion"], 1)
        self.assertEqual(self.policy["policyEpoch"], 1)
        self.assertEqual(self.policy["revokedPolicyEpochs"], [])
        self.assertEqual(self.policy["allowedOperations"], ["candidate", "requalify"])
        self.assertIs(self.policy["publication"], False)
        self.assertEqual(self.policy["issuerKeyId"], "local-auth-prod-1")
        self.assertEqual(self.policy["issuerPublicKey"], "d8aaf19ea48e7ef9ca82dea860a04b5eafad92ff82378b5cd73d2f137b3a727c")
        self.assertIn(self.policy["mode"], ("DENY", "ENFORCE"))
        if self.policy["mode"] == "ENFORCE":
            self.assertLess(verifier._timestamp(self.policy["delegationStartsAt"]),
                            verifier._timestamp(self.policy["delegationEndsAt"]))
        manifest = json.loads((ROOT / "metadata/automation-fleet.json").read_text())
        self.assertEqual(self.policy["targetSet"], {"path": "metadata/automation-fleet.json", "schemaVersion": manifest["schemaVersion"]})
        self.assertNotIn("repositories", self.policy)
        for key in ("candidateManualOnlyInferred", "releaseOptInInferred", "environmentInferred", "admissionInferred"):
            self.assertIs(self.policy["boundaries"][key], False)
        self.assertEqual(self.policy["rateLimits"], {
            "maxUnresolvedCandidatesPerRepository": 1,
            "candidateAuthorizationsPerRepositoryPer15Minutes": 1,
            "candidateAuthorizationsPerRepositoryPerHour": 4,
        })

    def test_jsonschema_validation_when_available(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema unavailable; dependency-free structural checks still run")
        Draft202012Validator.check_schema(self.schema)
        validator = Draft202012Validator(self.schema)
        validator.validate(self.policy)
        for field in self.schema["required"]:
            invalid = copy.deepcopy(self.policy)
            del invalid[field]
            self.assertFalse(validator.is_valid(invalid), field)
        for field, value in (("mode", "OBSERVE"), ("issuerKeyId", "invented"),
                             ("issuerPublicKey", "00" * 32), ("publication", True),
                             ("delegationStartsAt", "invalid"),
                             ("allowedOperations", ["candidate", "publish"]), ("extra", True)):
            self.assertFalse(validator.is_valid(dict(self.policy, **{field: value})), field)
        delegated = dict(self.policy, mode="ENFORCE", delegationStartsAt="2026-11-17T00:00:00Z",
                         delegationEndsAt="2026-11-18T00:00:00Z")
        validator.validate(delegated)
        validator.validate(dict(delegated, mode="DENY"))
        self.assertFalse(validator.is_valid(dict(delegated, delegationEndsAt=None)))


if __name__ == "__main__":
    unittest.main()
