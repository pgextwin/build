#!/usr/bin/env python3
"""Independently prepare and publish in the same isolated Publisher job."""

from contextlib import contextmanager
from importlib import import_module
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from urllib.parse import quote

contract = import_module("central-publisher-contract")
intake = import_module("central-publisher-intake")
manifest = import_module("central-publisher-t0-t3-manifest")
writer = import_module("fleet-publish-release")
probe = import_module("probe-publisher-app")
require = contract.require

PLAN = "CPUB_PLAN_MISMATCH"
RECOVERY = "CPUB_RECOVERY_STATE_INVALID"
CREDENTIAL = "CPUB_PUBLISHER_TOKEN_DENIED"
UNKNOWN_STATES = {"WRITE_OUTCOME_UNKNOWN_" + stage for stage in (
    "TAG_RESERVATION", "DRAFT_CREATION", "DRAFT_PUBLICATION",
)}


@contextmanager
def scoped_token(fleet, key, env):
    require(env.get("PUBLISHER_APP_ID") == "5451798"
            and env.get("PUBLISHER_INSTALLATION_ID") == "174720074" and key, CREDENTIAL)
    with contract.reject_as(CREDENTIAL):
        with contract.scope.single_repository_token(
                api=probe.api, jwt=probe.jwt, key=key, app=5451798, installation=174720074,
                repository=contract.REPOSITORY, fleet=fleet,
                release_policy=fleet["releasePolicy"]) as (token, _, _):
            yield token


@contextmanager
def writer_credentials(token):
    previous_token = os.environ.get("GH_TOKEN")
    previous_repo = writer.REPO
    try:
        os.environ["GH_TOKEN"] = token
        writer.REPO = contract.REPOSITORY
        yield
    finally:
        writer.REPO = previous_repo
        if previous_token is None:
            os.environ.pop("GH_TOKEN", None)
        else:
            os.environ["GH_TOKEN"] = previous_token


def record_denial(error, args, api, request, entries, before, now, run_id):
    recovery = args.recovery_file
    if str(error) == "existing tag/release forbidden":
        require(not recovery.exists(), RECOVERY)
        # The writer observed the collision before any writes. Compare the
        # collided ref/Release state around our read-only follow-up probe.
        hit = contract.snapshot(api, request, entries)
        require(hit["releaseByTag"] is not None or hit["gitRefTag"] is not None, contract.READ)
        contract.observe(request, args.out_duplicate_observation, contract.WRITER, hit,
                         contract.snapshot(api, request, entries), now)
        raise contract.Denied(f"CPUB_{contract.WRITER}") from None

    if recovery.is_file():
        state = contract.read_json(recovery, RECOVERY)
        if state.get("state") in UNKNOWN_STATES:
            require(state == {"schemaVersion": 1, "state": state["state"], "tag": request["tag"],
                              "runId": run_id, "commit": request["sha"]}, RECOVERY)
            # Keep the journal intact. A failed diagnostic read must not
            # suppress evidence that the write outcome is unknown.
            try:
                after = contract.snapshot(api, request, entries)
            except contract.Denied:
                after = None
            contract.observe(request, args.out_duplicate_observation, contract.UNKNOWN,
                             before, after, now, recovery=recovery)
            raise contract.Denied(f"CPUB_{contract.UNKNOWN}") from None
    raise contract.Denied("CPUB_RELEASE_WRITER_DENIED") from None


def publish(args, api, request, admitted, expected, before, env, key, now, mint):
    entries = admitted["entries"]
    run_id = env.get("GITHUB_RUN_ID", "")
    require(contract.auth.matches(contract.POSITIVE, run_id), contract.UNAUTHORIZED)
    run_id = int(run_id)
    receipt = {"releaseTag": request["tag"], "majors": [row["pgMajor"] for row in entries]}
    notes = contract.MARKER + json.dumps(contract.provenance(request, entries), sort_keys=True, separators=(",", ":"))
    with mint(admitted["fleet"], key, env) as token:
        try:
            with writer_credentials(token):
                writer.publish_preverified(
                    admitted["dist"], {"name": request["ext"]}, receipt, request["sha"],
                    expected, args.recovery_file, publish_run_id=run_id, extra_notes=notes)
        except writer.Denied as error:
            record_denial(error, args, api, request, entries, before, now, run_id)

    tag = quote(request["tag"], safe="")
    release = api.get(f"{contract.REPO}/releases/tags/{tag}")
    document = manifest.build(request, entries, release, entries)
    if args.cli_receipt:
        document = manifest.attach(document, contract.read_json(args.cli_receipt, manifest.INCOMPLETE),
                                   args.catalog_commit, entries)
    contract.write_json(args.out_manifest, document)
    return document


def run_phase(args, api, issuer_api, env, *, now, attestation_check=contract.verify_attestations,
              mint=scoped_token):
    key = env.pop("PUBLISHER_PRIVATE_KEY", None)
    request = contract.authorized_request(env, api, args.trigger_comment)
    contract.output_extension(env, request["ext"])
    original = contract.read_json(args.plan, PLAN)
    require(isinstance(original, dict) and contract.json_bytes(original.get("request")) ==
            contract.json_bytes(request), PLAN)
    require(bool(args.cli_receipt) == bool(args.catalog_commit) and
            (not args.catalog_commit or contract.auth.matches(contract.auth.SHA, args.catalog_commit)),
            manifest.INCOMPLETE)
    recovery = contract.k3.safe_path(args.recovery_file, RECOVERY)
    require(recovery.parent.is_dir() and not recovery.exists(), RECOVERY)
    with TemporaryDirectory(prefix="central-publisher-run-") as directory:
        admitted = contract.admit(args, request, api, issuer_api, env, Path(directory),
                                  now=now, attestation_check=attestation_check)
        current = intake.plan(request, admitted)
        require(contract.json_bytes(original) == contract.json_bytes(current), PLAN)
        manifest.verify_prepublication(admitted["entries"], original["entries"])
        if args.phase == "publish":
            require(env.get("CENTRAL_PUBLISHER_PREPARED_SHA256") == contract.digest(current), PLAN)
        before = contract.prewrite(api, request, admitted["entries"], args.out_duplicate_observation, now)

        if args.phase == "prepare":
            if env.get("GITHUB_OUTPUT"):
                with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                    output.write(f"prepared_sha256={contract.digest(current)}\n")
            return current
        if args.skip_release_publish:
            return current
        require(contract.authorized_request(env, api, args.trigger_comment) == request, PLAN)
        contract.check_main(request, args.expected_protected_sha, api)
        return publish(args, api, request, admitted, current["uploadSha256"], before, env, key, now, mint)


def main(argv=None):
    parser = contract.Parser(description=__doc__, allow_abbrev=False)
    contract.add_arguments(parser)
    parser.add_argument("--phase", choices=("prepare", "publish"), required=True)
    parser.add_argument("--skip-release-publish", action="store_true")
    parser.add_argument("--catalog-commit")
    for arg in ("plan", "out-manifest", "recovery-file"):
        parser.add_argument(f"--{arg}", type=Path, required=True)
    parser.add_argument("--cli-receipt", type=Path)

    def run():
        args = parser.parse_args(argv)
        if args.phase == "publish" and not args.skip_release_publish:
            # The live writer accepts only the checked-out fleet and direct
            # GitHub downloads. Fixture overrides remain usable for read-only
            # execution or the in-process boundary tests.
            require(args.github_api_base == contract.API
                    and args.fleet_config == contract.ROOT / contract.k3.FLEET_PATH
                    and not any((args.intent_dir, args.unsigned_dir, args.signed_dir, args.claims_dir,
                                 args.ticket, args.inputs, args.issuance_policy)), CREDENTIAL)
        run_phase(args, *contract.runtime(args, os.environ), os.environ, now=contract.utc_now())
        return 0

    return contract.cli(run)


if __name__ == "__main__":
    sys.exit(main())
