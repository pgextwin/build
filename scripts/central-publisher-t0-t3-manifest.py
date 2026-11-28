#!/usr/bin/env python3
"""Build, attach a Catalog CLI receipt to, or verify a ZIP-wise manifest."""

from copy import deepcopy
from datetime import datetime
from importlib import import_module
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker

contract = import_module("central-publisher-contract")
require = contract.require
package = contract.package
INCOMPLETE = "CPUB_MANIFEST_INCOMPLETE"
MISMATCH = "CPUB_MANIFEST_HASH_MISMATCH"
PENDING = "RELEASE_PUBLISHED_AWAITING_CLI_RECEIPT"
COMPLETE = "COMPLETE_T0_T3"
SCHEMA = contract.ROOT / "schema/central-zip-t0-t3-manifest.schema.json"
RECEIPT_FLAGS = dict.fromkeys((
    "signatureVerified", "provenanceVerified", "publicationAuthorized",
    "distributionAuthorized", "installAuthorized",
), False)
RECEIPT_CONSTANTS = {"source": "SIGSTORE_SIGNED_CATALOG_FEED_ORIGINAL_ZIPS",
                     "verificationLevel": "INTEGRITY_ONLY", **RECEIPT_FLAGS}
HANDOFF_KEYS = {"schemaVersion", "stage", "extension", "pgMajor", "fileName", "sha256",
                "size", "previousStage", "previousSha256"}


def target_key(row):
    if isinstance(row, (list, tuple)):
        require(len(row) == 3, INCOMPLETE)
        extension, major, name = row
    else:
        extension, major, name = (row[key] for key in ("extension", "pgMajor", "fileName"))
    require(contract.auth.matches(contract.EXTENSION, extension) and contract.positive(major)
            and contract.auth.matches(r"[A-Za-z0-9_-][A-Za-z0-9._-]*\.zip", name), INCOMPLETE)
    return extension, major, name


def unique_targets(targets):
    require(isinstance(targets, list) and bool(targets), INCOMPLETE)
    keys = [target_key(row) for row in targets]
    require(len({major for _, major, _ in keys}) == len(keys)
            and len({name.casefold() for _, _, name in keys}) == len(keys), INCOMPLETE)
    return set(keys)


def check_chain(row):
    with contract.reject_as(MISMATCH):
        chain = [row["handoffs"][stage] for stage in ("T0", "T1", "T2")]
        require(all(record.keys() == HANDOFF_KEYS for record in chain), MISMATCH)
        sha, size = row["sha256"], row["size"]
        # The shared utility requires all four stages. The projected fourth
        # record represents Release/receipt identity once available.
        t3 = {**chain[2], "stage": "T3", "previousStage": "T2", "previousSha256": sha}
        release = row.get("release")
        receipt = row.get("cliReceipt")
        if release is not None:
            require(release["assetName"] == row["fileName"] and release["assetSha256"] == sha
                    and type(release["assetSize"]) is int and release["assetSize"] == size, MISMATCH)
            t3.update(fileName=release["assetName"], sha256=release["assetSha256"],
                      size=release["assetSize"])
        if receipt is not None:
            require(receipt["sha256"] == sha and type(receipt["bytes"]) is int
                    and receipt["bytes"] == size, MISMATCH)
            t3.update(sha256=receipt["sha256"], size=receipt["bytes"])
        package.verify_handoff_chain([*chain, t3], expected_sha256=sha, expected_size=size,
                                     expected_extension=row["extension"], expected_pg_major=row["pgMajor"],
                                     expected_file_name=row["fileName"])


def receipt_path(path, extension, major, file_name):
    require(isinstance(path, str), INCOMPLETE)
    parts = path.split("/")
    require(all(contract.auth.matches(r"[A-Za-z0-9_-][A-Za-z0-9._-]*", part) for part in parts)
            and parts[-1] == file_name
            and (len(parts) == 1 or parts[0] in (extension, f"pg{major}")), INCOMPLETE)


def validate(manifest, expected_targets, *, require_complete=False):
    with contract.reject_as(INCOMPLETE):
        schema = contract.read_json(SCHEMA, INCOMPLETE)
        require(Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(manifest), INCOMPLETE)
        rows = manifest["entries"]
        keys = unique_targets(rows)
        require(keys == unique_targets(expected_targets) and len(rows) == manifest["expectedTargetCount"]
                and rows == sorted(rows, key=lambda row: (row["pgMajor"], row["fileName"])), INCOMPLETE)
        complete = manifest["stageStatus"] == COMPLETE
        require(complete or not require_complete, INCOMPLETE)
        extension, tag = manifest["extension"], manifest["od01Tag"]
        contract.tag_suffix(extension, tag)
        seen_assets = set()
        release_identity = None
        catalog_commit = None
        for row in rows:
            require(row["extension"] == extension and row["fileName"].startswith(extension + "-"), INCOMPLETE)
            release = row["release"]
            require(datetime.fromisoformat(release["publishedAt"]).tzinfo is not None, INCOMPLETE)
            identity = tuple(release[key] for key in ("releaseId", "releaseUrl", "publishedAt"))
            if release_identity is None:
                release_identity = identity
            require(release.get("tag") == tag and identity == release_identity
                    and release["assetId"] not in seen_assets, INCOMPLETE)
            seen_assets.add(release["assetId"])
            if complete:
                receipt = row["cliReceipt"]
                if catalog_commit is None:
                    catalog_commit = receipt["catalogCommit"]
                require(receipt["catalogCommit"] == catalog_commit and receipt["zipCount"] == len(rows)
                        and all(receipt[key] is False for key in RECEIPT_FLAGS), INCOMPLETE)
                receipt_path(receipt["relativePath"], extension, row["pgMajor"], row["fileName"])
            check_chain(row)
        for target in expected_targets:
            if isinstance(target, dict) and {"sha256", "size"} & target.keys():
                row = next(row for row in rows if target_key(row) == target_key(target))
                require(contract.comparison_key(row) == contract.comparison_key(target), MISMATCH)
        return manifest


def verify_prepublication(entries, expected_targets):
    with contract.reject_as(INCOMPLETE):
        require(unique_targets(entries) == unique_targets(expected_targets), INCOMPLETE)
        for row in entries:
            check_chain(row)


def build(request, entries, release, expected_targets):
    with contract.reject_as(INCOMPLETE):
        verify_prepublication(entries, expected_targets)
        require(release["draft"] is False and release["tag_name"] == request["tag"], INCOMPLETE)
        assets = release["assets"]
        require(isinstance(assets, list) and all(isinstance(row, dict) and isinstance(row.get("name"), str)
                                                for row in assets), INCOMPLETE)
        by_name = {row["name"]: row for row in assets}
        require(len(by_name) == len(assets) and
                {name for name in by_name if name.lower().endswith(".zip")} ==
                {row["fileName"] for row in entries}, INCOMPLETE)
        output = []
        for row in sorted(entries, key=lambda item: (item["pgMajor"], item["fileName"])):
            asset = by_name[row["fileName"]]
            require(asset.get("state") == "uploaded", INCOMPLETE)
            digest = asset.get("digest")
            require(contract.auth.matches(r"sha256:[0-9a-f]{64}", digest), MISMATCH)
            output.append({
                **row, "release": {
                    "tag": request["tag"], "releaseId": release["id"], "releaseUrl": release["html_url"],
                    "assetId": asset["id"], "assetName": asset["name"], "assetSha256": digest[7:],
                    "assetSize": asset["size"], "publishedAt": release["published_at"],
                }, "cliReceipt": None,
            })
        manifest = {
            "schemaVersion": 1, "extension": request["ext"], "signingRunId": request["run"],
            "signingRunAttempt": request["attempt"], "protectedMainSha": request["sha"],
            "od01Tag": request["tag"], "stageStatus": PENDING, "expectedTargetCount": len(output),
            "entries": output,
        }
        return validate(manifest, expected_targets)


def receipt_major(value):
    if isinstance(value, str) and re.fullmatch(contract.FIELDS["pg"][0], value):
        value = int(value)
    require(contract.positive(value), INCOMPLETE)
    return value


def attach(manifest, receipt, catalog_commit, expected_targets):
    with contract.reject_as(INCOMPLETE):
        validate(manifest, expected_targets)
        require(manifest["stageStatus"] == PENDING and contract.auth.matches(contract.auth.SHA, catalog_commit),
                INCOMPLETE)
        require(all(type(receipt.get(key)) is type(value) and receipt[key] == value
                    for key, value in RECEIPT_CONSTANTS.items()), INCOMPLETE)
        require(receipt.get("schemaVersion") == "pgextwin-cli-batch-download/v1"
                and type(receipt.get("releaseMetadataVerified")) is bool, INCOMPLETE)
        packages = receipt.get("packages")
        count = receipt.get("zipCount")
        require(type(packages) is list and contract.positive(count)
                and count == len(packages) == len(expected_targets), INCOMPLETE)
        output = deepcopy(manifest)
        rows = {(row["extension"], row["pgMajor"]): row for row in output["entries"]}
        repository_id = None
        for item in packages:
            extension = item["extension"]
            require(extension == manifest["extension"], contract.EXT)
            key = (extension, receipt_major(item["pgMajor"]))
            row = rows.pop(key, None)
            require(row is not None, INCOMPLETE)
            path = item["relativePath"]
            receipt_path(path, extension, row["pgMajor"], row["fileName"])
            if repository_id is None:
                repository_id = item["repositoryId"]
            require(contract.positive(item.get("repositoryId")) and item["repositoryId"] == repository_id
                    and item.get("releaseTag") == manifest["od01Tag"]
                    and item.get("catalogCommit") == catalog_commit
                    and contract.positive(item.get("releaseId"))
                    and item["releaseId"] == row["release"]["releaseId"]
                    and contract.positive(item.get("assetId"))
                    and item["assetId"] == row["release"]["assetId"], INCOMPLETE)
            require(contract.positive(item.get("bytes")) and item["bytes"] == row["size"]
                    and item.get("sha256") == row["sha256"], MISMATCH)
            row["cliReceipt"] = {**RECEIPT_CONSTANTS, "catalogCommit": catalog_commit,
                                 "relativePath": path, "bytes": item["bytes"],
                                 "sha256": item["sha256"], "zipCount": count}
        require(not rows, INCOMPLETE)
        output["stageStatus"] = COMPLETE
        return validate(output, expected_targets, require_complete=True)


def verify_sources(args, document):
    request = {"ext": document["extension"], "sha": document["protectedMainSha"],
               "run": document["signingRunId"], "attempt": document["signingRunAttempt"]}
    rows = document["entries"]
    if args.intent_dir:
        request["pg"] = rows[0]["pgMajor"]
        require(set(contract.intent_series(args.intent_dir, request)) == {row["pgMajor"] for row in rows},
                INCOMPLETE)
    if args.signed_dir:
        for row in rows:
            name = contract.artifact_names(row["extension"], row["pgMajor"])[1]
            folder = contract.artifact_folder(args.signed_dir, name, single=len(rows) == 1,
                                              extension=row["extension"])
            path = contract.regular_files(folder).get(row["fileName"])
            require(path is not None, INCOMPLETE)
            require(contract.k3.zip_identity(path) == (row["sha256"], row["size"]), MISMATCH)


def main(argv=None):
    parser = contract.Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", choices=("build", "attach-cli-receipt", "verify"), required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-targets-json", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--trigger-comment")
    parser.add_argument("--catalog-commit")
    for arg in ("intent-dir", "signed-dir", "release-metadata", "handoff-metadata", "cli-receipt"):
        parser.add_argument(f"--{arg}", type=Path)

    def run():
        args = parser.parse_args(argv)
        expected = contract.read_json(args.expected_targets_json, INCOMPLETE)
        if args.mode == "build":
            request = contract.parse_trigger(args.trigger_comment)
            handoffs = contract.read_json(args.handoff_metadata, INCOMPLETE)
            release = contract.read_json(args.release_metadata, INCOMPLETE)
            document = build(request, handoffs, release, expected)
        else:
            document = contract.read_json(args.manifest, INCOMPLETE)
        if args.mode == "attach-cli-receipt":
            document = attach(document, contract.read_json(args.cli_receipt, INCOMPLETE),
                              args.catalog_commit, expected)
        validate(document, expected, require_complete=args.require_complete)
        verify_sources(args, document)
        if args.mode != "verify":
            contract.write_json(args.manifest, document)
        return 0

    return contract.cli(run)


if __name__ == "__main__":
    sys.exit(main())
