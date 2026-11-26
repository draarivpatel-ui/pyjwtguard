"""Command line interface for structural token inspection.

The CLI never accepts a secret and never verifies a signature. It exists to
answer "what is inside this token and is its structure safe to process", which
is the one operation that is useful without key material.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .errors import JwtGuardError
from .jwt import DEFAULT_MAX_TOKEN_SIZE, inspect_token


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="pyjwtguard",
        description="Inspect a JWT or JWS without verifying its signature.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="pyjwtguard {}".format(__version__),
    )
    subparsers = parser.add_subparsers(dest="command")
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="decode header and claims using strict structural checks",
    )
    inspect_parser.add_argument("token", help="compact JWS token")
    inspect_parser.add_argument(
        "--max-token-size",
        type=_positive_int,
        default=DEFAULT_MAX_TOKEN_SIZE,
        help="maximum token size in bytes (default: %(default)s)",
    )
    inspect_parser.add_argument(
        "--allow-remote-headers",
        action="store_true",
        help="permit jku, x5u, jwk, and x5c headers in the report",
    )
    inspect_parser.add_argument(
        "--allow-unencoded-payload",
        action="store_true",
        help="permit RFC 7797 b64 false compact payloads in the report",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "inspect":
        parser.print_help(sys.stderr)
        return 2
    try:
        inspection = inspect_token(
            args.token,
            max_token_size=args.max_token_size,
            allow_remote_headers=args.allow_remote_headers,
            allow_unencoded_payload=args.allow_unencoded_payload,
        )
    except JwtGuardError as exc:
        print("pyjwtguard: error: {}".format(exc), file=sys.stderr)
        return 3
    report = inspection.to_dict()
    report["verified"] = False
    report["note"] = "Signature is not verified. Do not trust these claims."
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


__all__ = ["build_parser", "main"]
