"""Command-line front end for the local Maltego transform server.

Every operation the MCP tools expose is available here, calling the same
:mod:`transformatron.operations` functions, so behaviour and output are identical.
Use this from a terminal, a shell script, or any coding agent that can run commands
but does not speak MCP.

Usage:
    uv run python scripts/transformatron_cli.py status
    uv run python scripts/transformatron_cli.py start --ssl
    uv run python scripts/transformatron_cli.py restart
    uv run python scripts/transformatron_cli.py list
    uv run python scripts/transformatron_cli.py run <id> maltego.IPv4Address 8.8.8.8 [--json]
    uv run python scripts/transformatron_cli.py logs --lines 100
    uv run python scripts/transformatron_cli.py certs
    uv run python scripts/transformatron_cli.py seed-url
    uv run python scripts/transformatron_cli.py scaffold --curl '...' --dry-run
    uv run python scripts/transformatron_cli.py scaffold --openapi spec.yaml --list-operations
    uv run python scripts/transformatron_cli.py remove-scaffold <service>

Exit status is 0 when the operation did what was asked and 1 when it failed: a failed
start, stop, or restart, a server that is unreachable or unhealthy, a transform run that
ended in a state other than success, a failed scaffold, scaffold removal, operation
listing, or certificate generation, or an unusable ``transformatron.toml``. A successful
run that returned zero entities exits 0; read the entity count in the output.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Coroutine
from typing import Any

from transformatron import operations
from transformatron.config import ConfigError, load_config


def _resolve(value: Coroutine[Any, Any, str]) -> str:
    """Run an async operation to completion and return its output."""
    return asyncio.run(value)


def _parse_settings(pairs: list[str] | None) -> dict[str, str] | None:
    """Parse repeated ``KEY=VALUE`` arguments into a settings mapping."""
    if not pairs:
        return None
    settings: dict[str, str] = {}
    for pair in pairs:
        key, separator, value = pair.partition("=")
        if not separator:
            raise SystemExit(f"Invalid --setting {pair!r}: expected KEY=VALUE")
        settings[key] = value
    return settings


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every supported command."""
    parser = argparse.ArgumentParser(
        prog="transformatron_cli",
        description="Control a local Maltego v3 transform server.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Start the server")
    start.add_argument("--ssl", action="store_true", help="Serve over HTTPS")

    sub.add_parser("stop", help="Stop the server")

    restart = sub.add_parser("restart", help="Restart to pick up edited transforms")
    restart.add_argument(
        "--ssl",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Serve over HTTPS (default: keep the scheme the server is running under)",
    )

    sub.add_parser("status", help="Report running state, health, and transform count")
    sub.add_parser("list", help="List advertised transforms with input/output types")
    sub.add_parser("entities", help="List advertised entity types")
    sub.add_parser("seed-url", help="Print the seed URL and registration steps")

    show = sub.add_parser("show", help="Print the detail document for one transform")
    show.add_argument("transform_id")

    logs = sub.add_parser("logs", help="Print recent server log output")
    logs.add_argument("--lines", type=int, default=50)

    certs = sub.add_parser("certs", help="Generate a self-signed certificate for HTTPS")
    certs.add_argument("--force", action="store_true", help="Overwrite an existing pair")

    run = sub.add_parser("run", help="Run one transform against one input entity")
    run.add_argument("transform_id")
    run.add_argument("entity_type", help="e.g. maltego.IPv4Address")
    run.add_argument("entity_value")
    run.add_argument("--setting", action="append", metavar="KEY=VALUE")
    run.add_argument("--timeout", type=float, default=60.0)
    run.add_argument(
        "--json",
        action="store_true",
        help="Print every entity and link as the full JSON the server sent, "
        "instead of one summary line per entity",
    )

    scaffold = sub.add_parser("scaffold", help="Scaffold a new transform from cURL or OpenAPI")
    scaffold.add_argument("--service", help="Service name slug (e.g. greynoise)")
    scaffold.add_argument("--curl", help="cURL command string")
    scaffold.add_argument(
        "--openapi",
        help="OpenAPI/Swagger spec in JSON or YAML: a URL, a file path, or the document itself",
    )
    scaffold.add_argument(
        "--sample-response",
        help="Sample JSON response to map outputs from; with --openapi, select one --operation",
    )
    scaffold.add_argument(
        "--sample-input",
        metavar="VALUE",
        help="An input value the API answers for, e.g. the hash or id the sample response "
        "came from: the transform skips it when the response echoes it, and samples.json "
        "records it for the smoke test (default for --curl: the value in the request)",
    )
    scaffold.add_argument(
        "--operation",
        action="append",
        metavar="OPERATION_ID",
        help="Scaffold only this OpenAPI operation; repeat for more. Required for POST.",
    )
    scaffold.add_argument(
        "--name", help="Transform name for a cURL scaffold (default: <service>_lookup)"
    )
    scaffold.add_argument(
        "--records",
        metavar="PATH",
        help="Dotted path to the list of records in the response, e.g. data or "
        "containers.cna.references",
    )
    scaffold.add_argument(
        "--map",
        action="append",
        dest="mappings",
        metavar="PATH=TYPE",
        help="Map one response field, e.g. 'containers.cna.affected[].vendor=Company'; TYPE "
        "Property attaches it to the record's entity, Drop ignores it. Repeatable.",
    )
    scaffold.add_argument(
        "--primary",
        metavar="PATH",
        help="Field to use as each record's primary entity, the one the other fields attach "
        "to as properties, e.g. 'SHA-1'; it must map to an entity type",
    )
    scaffold.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned transforms, field inventory, and files without writing",
    )
    scaffold.add_argument(
        "--list-operations",
        action="store_true",
        help="List the operations in --openapi and what each would scaffold, then exit",
    )
    scaffold.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing service directory and its project.py imports",
    )

    remove = sub.add_parser(
        "remove-scaffold",
        help="Delete a scaffolded service and its project.py imports (refuses hand-written "
        "services)",
    )
    remove.add_argument("service", help="Service name slug, the directory under transforms/")

    return parser


def dispatch(args: argparse.Namespace) -> str:
    """Route a parsed command to its operation and return the rendered output."""
    config = load_config()
    match args.command:
        case "start":
            return operations.start(config, ssl=args.ssl)
        case "stop":
            return operations.stop(config)
        case "restart":
            return operations.restart(config, ssl=args.ssl)
        case "status":
            return _resolve(operations.status(config))
        case "list":
            return _resolve(operations.list_transforms(config))
        case "entities":
            return _resolve(operations.list_entities(config))
        case "show":
            return _resolve(operations.get_transform(config, args.transform_id))
        case "logs":
            return operations.logs(config, args.lines)
        case "certs":
            return operations.generate_certs(config, force=args.force)
        case "seed-url":
            return operations.seed_url(config)
        case "run":
            return _resolve(
                operations.run_transform(
                    config,
                    args.transform_id,
                    args.entity_type,
                    args.entity_value,
                    _parse_settings(args.setting),
                    args.timeout,
                    full=args.json,
                )
            )
        case "scaffold" if args.list_operations:
            if not args.openapi or args.curl:
                return operations.Failure(
                    "Failed to list operations: --list-operations lists the operations of an "
                    "--openapi spec; pass one, and no --curl."
                )
            return operations.list_operations(config, args.openapi, service=args.service)
        case "scaffold":
            return operations.scaffold(
                config,
                service=args.service,
                curl=args.curl,
                openapi=args.openapi,
                sample_response=args.sample_response,
                operations=args.operation,
                force=args.force,
                name=args.name,
                records=args.records,
                mappings=args.mappings,
                dry_run=args.dry_run,
                sample_input=args.sample_input,
                primary=args.primary,
            )
        case "remove-scaffold":
            return operations.remove_scaffold(config, args.service)
    raise SystemExit(f"Unknown command: {args.command}")


def main() -> int:
    """Run one command, print its output, and return the process exit status."""
    args = build_parser().parse_args()
    try:
        output = dispatch(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 1 if isinstance(output, operations.Failure) else 0


if __name__ == "__main__":
    raise SystemExit(main())
