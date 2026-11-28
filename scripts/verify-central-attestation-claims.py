#!/usr/bin/env python3
"""Compare both sets of claims after gh has cryptographically verified the bundles."""

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import sys
import zipfile

auth = importlib.import_module("central-signing-auth")
require = auth.require
obj = auth.object_or_empty
SLSA = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
ENVELOPE = "CLAIMS_ENVELOPE_STRUCTURE_INVALID"
SUBJECT = "CLAIMS_SUBJECT_NOT_SINGLE_ZIP"
SLSA_INVALID = "CLAIMS_SLSA_PREDICATE_INVALID"
SPDX_MISMATCH = "CLAIMS_SPDX_PREDICATE_MISMATCH"
CROSS = "CLAIMS_CROSS_EXTENSION_SWAP"


def same_json(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def certificate_expectations(intent):
    pin = intent["reusable_pin_sha"]
    packaging = intent["head_sha"]
    signer = auth.signer_uri(pin)
    return (
        ("issuer", "https://token.actions.githubusercontent.com", "CLAIMS_ISSUER_MISMATCH"),
        ("buildSignerURI", signer, "CLAIMS_SIGNER_URI_MISMATCH"),
        ("subjectAlternativeName", signer, "CLAIMS_SAN_MISMATCH"),
        ("buildSignerDigest", pin, "CLAIMS_SIGNER_DIGEST_MISMATCH"),
        ("runInvocationURI", intent["run_invocation_uri"], "CLAIMS_RUN_INVOCATION_MISMATCH"),
        ("buildConfigURI", auth.CONFIG_URI, "CLAIMS_BUILD_CONFIG_MISMATCH"),
        ("buildConfigDigest", packaging, "CLAIMS_BUILD_CONFIG_MISMATCH"),
        ("sourceRepositoryURI", auth.REPO_URI, "CLAIMS_SOURCE_REPO_MISMATCH"),
        ("sourceRepositoryDigest", packaging, "CLAIMS_SOURCE_REPO_MISMATCH"),
        ("sourceRepositoryRef", auth.REF, "CLAIMS_SOURCE_REPO_MISMATCH"),
        ("githubWorkflowSHA", packaging, "CLAIMS_WORKFLOW_SHA_REF_MISMATCH"),
        ("githubWorkflowRef", auth.REF, "CLAIMS_WORKFLOW_SHA_REF_MISMATCH"),
        ("buildTrigger", intent["authentic_event"], "CLAIMS_TRIGGER_MISMATCH"),
    )


def zip_json(archive, name):
    entries = [entry for entry in archive.infolist() if entry.filename.casefold() == name.casefold()]
    require(len(entries) == 1 and entries[0].filename == name, CROSS, name)
    require(entries[0].file_size <= 64 * 1024, CROSS, name)
    return auth.parse_json(archive.read(entries[0]).decode("utf-8-sig"))


def verify_package(zip_path, sbom_path, sbom, intent, *, major=None,
                   upstream_repository=None, upstream_commit=None):
    extension = intent["extension_name"]
    require(auth.matches(r"[A-Za-z0-9][A-Za-z0-9._+-]*\.zip", zip_path.name)
            and not zip_path.is_symlink() and not sbom_path.is_symlink()
            and zip_path.stem.startswith(f"{extension}-") and sbom_path.name == f"{zip_path.stem}.spdx.json", CROSS)
    with zip_path.open("rb") as stream:
        zip_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    try:
        with zipfile.ZipFile(zip_path) as archive:
            embedded = auth.validate_intent(zip_json(archive, auth.INTENT_NAME))
            package = obj(zip_json(archive, "PACKAGE-INFO.json"))
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as error:
        raise auth.Denied(CROSS, str(error)) from error
    require(embedded == intent, CROSS, "ZIP intent differs from the independently supplied intent")
    require(package.get("buildMode") == "release-attested"
            and obj(package.get("package")).get("name") == extension, CROSS)
    require(package.get("source") == {
        "packagingRepository": auth.REPOSITORY,
        "packagingCommit": intent["head_sha"],
    } and package.get("buildInfrastructure") == {
        "repository": auth.REPOSITORY, "commit": intent["reusable_pin_sha"],
        "workflow": auth.REUSABLE,
    }, CROSS, "ZIP source/build metadata differs from the intent")
    require(same_json(package.get("workflowRun"), {
        "id": intent["run_id"], "attempt": intent["run_attempt"],
        "url": intent["run_invocation_uri"].rsplit("/attempts/", 1)[0],
        "event": intent["authentic_event"], "ref": auth.REF,
    }), CROSS, "ZIP run metadata differs from the intent")
    if major is not None:
        require(type(obj(package.get("postgresql")).get("major")) is int
                and package["postgresql"]["major"] == major, CROSS, "Wrong PostgreSQL major")
    upstream = obj(package.get("upstream"))
    pg_major = obj(package.get("postgresql")).get("major")
    require(type(pg_major) is int and pg_major > 0
            and zip_path.name == f'{extension}-{upstream.get("ref")}-pg{pg_major}-windows-x64.zip',
            CROSS, "ZIP filename differs from embedded package metadata")
    if upstream_commit is not None:
        require(upstream.get("repository") == upstream_repository
                and upstream.get("commit") == upstream_commit, CROSS, "Wrong upstream pin")

    require(isinstance(sbom, dict) and sbom.get("spdxVersion") == "SPDX-2.3", SPDX_MISMATCH)
    creators = obj(sbom.get("creationInfo")).get("creators")
    require(isinstance(creators, list) and "Tool: syft-1.54.1" in creators, CROSS)
    packages = sbom.get("packages")
    require(isinstance(packages, list), CROSS)
    sources = [item for item in packages if obj(item).get("name") == zip_path.stem]
    require(len(sources) == 1 and sbom.get("name") == zip_path.stem, CROSS)
    source = sources[0]
    source_id = source.get("SPDXID")
    require(isinstance(source_id, str) and source_id.startswith("SPDXRef-")
            and source.get("supplier") == "Organization: pgextwin"
            and isinstance(upstream.get("version"), str)
            and source.get("versionInfo") == upstream["version"], CROSS)
    describes = sbom.get("documentDescribes")
    relationships = sbom.get("relationships")
    require((isinstance(describes, list) and source_id in describes)
            or (isinstance(relationships, list) and any(
                obj(relation).get("spdxElementId") == "SPDXRef-DOCUMENT"
                and obj(relation).get("relationshipType") == "DESCRIBES"
                and obj(relation).get("relatedSpdxElement") == source_id
                for relation in relationships
            )), CROSS)
    checksums = source.get("checksums")
    require(isinstance(checksums, list), CROSS)
    source_digests = [item.get("checksumValue") for item in checksums
                      if obj(item).get("algorithm") == "SHA256"]
    require(len(source_digests) == 1 and auth.matches(r"[a-fA-F0-9]{64}", source_digests[0])
            and source_digests[0].lower() == zip_digest, CROSS)
    return {
        "extension": extension,
        "zip_name": zip_path.name,
        "source_package": source["name"],
        "sha256": zip_digest,
    }


def row(number, claim, expected, actual):
    return {"number": number, "claim": claim, "expected": expected, "actual": actual,
            "status": "match"}


def inapplicable(number):
    return {"number": number, "status": "not_applicable"}


def compare(kind, results, subject, intent, sbom, package_binding):
    require(isinstance(results, list) and len(results) == 1, ENVELOPE)
    entry = obj(results[0])
    shape = sorted(entry)
    require(shape in (["verificationResult"], ["attestation", "verificationResult"])
            and ("attestation" not in entry or isinstance(entry["attestation"], dict)), ENVELOPE)
    result = obj(entry["verificationResult"])
    statement = obj(result.get("statement"))
    cert = obj(obj(result.get("signature")).get("certificate"))
    require(bool(statement) and bool(cert), ENVELOPE)
    timestamps = result.get("verifiedTimestamps")
    require(isinstance(timestamps, list) and timestamps
            and all(isinstance(value, dict) and value for value in timestamps),
            "CLAIMS_TIMESTAMPS_MISSING")
    require("runnerInvocationURI" not in cert, "CLAIMS_LEGACY_RUNNER_URI_FORBIDDEN")
    rows = [
        row(1, "verificationResult envelope", "one verified result, with optional attestation",
            {"count": len(results), "keys": shape}),
        row(2, "verifiedTimestamps", "nonempty array of nonempty objects", timestamps),
        row(3, "signature.certificate", "nonempty object without runnerInvocationURI",
            {"keys": sorted(cert)}),
    ]
    for number, (claim, expected, code) in enumerate(certificate_expectations(intent), start=4):
        actual = cert.get(claim)
        require(actual == expected, code, claim)
        rows.append(row(number, f"certificate.{claim}", expected, actual))
    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1, SUBJECT)
    actual_subject = obj(subjects[0])
    digest = obj(actual_subject.get("digest"))
    require(actual_subject.keys() == {"name", "digest"} and digest.keys() == {"sha256"}
            and actual_subject["name"] == subject["name"]
            and auth.matches(r"[a-fA-F0-9]{64}", digest["sha256"])
            and digest["sha256"].lower() == subject["digest"]["sha256"], SUBJECT)
    rows.append(row(17, "statement.subject", [subject], subjects))

    predicate = obj(statement.get("predicate"))
    if kind == SLSA:
        definition = obj(predicate.get("buildDefinition"))
        require(statement.get("predicateType") == SLSA and bool(definition), SLSA_INVALID)
        expected_workflow = {"repository": auth.REPO_URI, "ref": auth.REF, "path": auth.CALLER}
        if "externalParameters" in definition:
            external = definition["externalParameters"]
            require(isinstance(external, dict), SLSA_INVALID)
            if "workflow" in external:
                workflow = obj(external["workflow"])
                require(all(workflow.get(key) == value for key, value in expected_workflow.items()),
                        SLSA_INVALID, "externalParameters.workflow")
        details = obj(predicate.get("runDetails"))
        invocation = obj(details.get("metadata")).get("invocationId")
        builder = obj(details.get("builder")).get("id")
        require(isinstance(builder, str) and bool(builder.strip()), SLSA_INVALID, "builder.id")
        require(invocation == cert["runInvocationURI"], "CLAIMS_RUN_INVOCATION_MISMATCH",
                "predicate.runDetails.metadata.invocationId")
        rows.extend([
            row(18, "SLSA predicateType and buildDefinition",
                {"predicateType": SLSA, "workflow_if_present": expected_workflow},
                {"predicateType": SLSA, "buildDefinition": definition}),
            row(19, "SLSA runDetails",
                {"invocationId": cert["runInvocationURI"], "builder.id": "nonempty string"},
                {"invocationId": invocation, "builder.id": builder}),
            inapplicable(20), inapplicable(21),
        ])
    else:
        expected_spdx = {"predicateType": SPDX, "spdxVersion": "SPDX-2.3"}
        actual_spdx = {"predicateType": statement.get("predicateType"),
                       "spdxVersion": predicate.get("spdxVersion")}
        require(actual_spdx == expected_spdx and same_json(predicate, sbom), SPDX_MISMATCH)
        sbom_digest = hashlib.sha256(
            json.dumps(sbom, sort_keys=True, allow_nan=False).encode("utf-8")
        ).hexdigest()
        rows.extend([
            inapplicable(18), inapplicable(19),
            row(20, "SPDX predicateType and spdxVersion", expected_spdx, actual_spdx),
            row(21, "SPDX local predicate equality and ZIP binding",
                {"spdx_sha256": sbom_digest, **package_binding},
                {"spdx_sha256": sbom_digest, **package_binding}),
        ])
    return rows


def verify_claims(zip_path, sbom_path, slsa, spdx, intent, expected_event, **target):
    auth.validate_intent(intent)
    require(expected_event == intent["authentic_event"], "CLAIMS_TRIGGER_MISMATCH")
    sbom = auth.read_json(sbom_path, SPDX_MISMATCH)
    package_binding = verify_package(zip_path, sbom_path, sbom, intent, **target)
    subject = {"name": zip_path.name, "digest": {"sha256": package_binding["sha256"]}}
    return {
        "schema_version": 1, "intent": intent, "subject": subject, "verified": True,
        "claims": {
            SLSA: compare(SLSA, slsa, subject, intent, sbom, package_binding),
            SPDX: compare(SPDX, spdx, subject, intent, sbom, package_binding),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("zip", "sbom", "intent"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("slsa-json", "spdx-json", "output-table"):
        parser.add_argument(f"--{name}", type=Path)
    parser.add_argument("--expected-event", required=True)
    parser.add_argument("--major", type=int)
    parser.add_argument("--upstream-repository")
    parser.add_argument("--upstream-commit")
    parser.add_argument("--check-package", action="store_true",
                        help="Validate the ZIP and SBOM before signing")
    args = parser.parse_args()

    try:
        intent = auth.load_intent(args.intent)
        require(args.expected_event == intent["authentic_event"], "CLAIMS_TRIGGER_MISMATCH")
        target = {"major": args.major, "upstream_repository": args.upstream_repository,
                  "upstream_commit": args.upstream_commit}
        if args.check_package:
            sbom = auth.read_json(args.sbom, SPDX_MISMATCH)
            verify_package(args.zip, args.sbom, sbom, intent, **target)
        else:
            slsa = auth.read_json(args.slsa_json, ENVELOPE)
            spdx = auth.read_json(args.spdx_json, ENVELOPE)
            auth.write_json(args.output_table, verify_claims(
                args.zip, args.sbom, slsa, spdx, intent, args.expected_event, **target
            ))
    except (ValueError, OSError, TypeError) as error:
        return auth.report_error(error, ENVELOPE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
