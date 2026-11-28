#!/usr/bin/env python3
"""Validate the owner comment, admit the signing run, and write a read-only plan."""

from importlib import import_module
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

contract = import_module("central-publisher-contract")


def plan(request, admitted):
    return {
        "schemaVersion": 1, "request": request, "entries": admitted["entries"],
        "uploadSha256": {path.name: contract.package.sha256_file(path)
                         for path in sorted(admitted["dist"].iterdir())},
    }


def intake(args, api, issuer_api, env, *, now, attestation_check=contract.verify_attestations):
    request = contract.authorized_request(env, api, args.trigger_comment)
    contract.output_extension(env, request["ext"])
    with TemporaryDirectory(prefix="central-publisher-intake-") as directory:
        admitted = contract.admit(args, request, api, issuer_api, env, Path(directory),
                                  now=now, attestation_check=attestation_check)
        contract.prewrite(api, request, admitted["entries"], args.out_duplicate_observation, now)
        document = plan(request, admitted)
        contract.write_json(args.out_plan, document)
        return document


def main(argv=None):
    parser = contract.Parser(description=__doc__, allow_abbrev=False)
    contract.add_arguments(parser)
    parser.add_argument("--out-plan", type=Path, required=True)

    def run():
        args = parser.parse_args(argv)
        intake(args, *contract.runtime(args, os.environ), os.environ, now=contract.utc_now())
        return 0

    return contract.cli(run)


if __name__ == "__main__":
    sys.exit(main())
