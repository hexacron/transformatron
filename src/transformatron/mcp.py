"""MCP tools for running and inspecting a local Maltego v3 transform server.

Every tool here is a thin shell over :mod:`transformatron.operations`, which the
CLI in ``scripts/transformatron_cli.py`` also calls. Keep behaviour in that module
so both front ends stay identical.

Authoring transforms is covered by ``docs/transform-authoring.md`` and the SDK
guidance in ``server/.agents/skills/``. These tools cover what those do not: the
server lifecycle and the transform execution cycle.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Concatenate

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from transformatron import operations
from transformatron.config import ConfigError, TransformatronConfig, load_config

server = MCPServer(
    name="transformatron",
    instructions=(
        "Control a local Maltego v3 transform server. Use these tools to start, "
        "stop, and inspect the server and to execute transforms. To write or "
        "modify transform code, read docs/transform-authoring.md first."
    ),
)

log = logging.getLogger(__name__)


# Config is loaded on every call, not once at import, for the same reason the CLI loads it
# per command: an edit to transformatron.toml must apply to the next tool call without
# restarting the MCP client, and a typo in the file must come back to the agent as a
# message it can act on rather than stopping this server from starting at all.


def _crash(exc: Exception) -> ToolError:
    """Return a ToolError naming an operation's unexpected exception, logging its traceback.

    Operations report every failure a caller can act on as text, so an exception reaching
    here is a bug. Since mcp 2.1 an uncaught one reaches the agent only as "Error
    executing tool <name>", with the cause kept on the server (mcp/server/mcpserver/tools/
    base.py: "A crash: the exception's own text stays on the server"). A ToolError is
    passed through with its message, so the agent can see what broke and report it. The
    traceback still goes to this server's stderr, where a ToolError alone would not put it.
    """
    log.exception("Tool operation raised unexpectedly")
    return ToolError(f"{type(exc).__name__}: {exc}")


async def _blocking[**P](
    operation: Callable[Concatenate[TransformatronConfig, P], str],
    *args: P.args,
    **kwargs: P.kwargs,
) -> str:
    """Run a synchronous operation off the event loop with freshly loaded config.

    Starting and stopping the server wait for seconds, and the others touch disk or the
    network. Run on the loop, any of them would stall every other request this server
    is handling.
    """
    try:
        config = load_config()
    except ConfigError as exc:
        return f"Failed: {exc}"
    try:
        output = await asyncio.to_thread(operation, config, *args, **kwargs)
    except Exception as exc:
        raise _crash(exc) from exc
    # str() drops the operations.Failure subtype: MCP tools return plain text.
    return str(output)


async def _async[**P](
    operation: Callable[Concatenate[TransformatronConfig, P], Awaitable[str]],
    *args: P.args,
    **kwargs: P.kwargs,
) -> str:
    """Await an async operation with freshly loaded config."""
    try:
        config = load_config()
    except ConfigError as exc:
        return f"Failed: {exc}"
    try:
        output = await operation(config, *args, **kwargs)
    except Exception as exc:
        raise _crash(exc) from exc
    return str(output)


@server.tool()
async def server_start(ssl: bool = False) -> str:
    """Start the local transform server and wait until it answers.

    Args:
        ssl: Serve over HTTPS. Requires generate_certs first. Both the Maltego
            desktop client and the Graph Browser require it.
    """
    return await _blocking(operations.start, ssl=ssl)


@server.tool()
async def server_stop() -> str:
    """Stop the running transform server."""
    return await _blocking(operations.stop)


@server.tool()
async def server_restart(ssl: bool | None = None) -> str:
    """Restart the server to pick up new or edited transform modules.

    Args:
        ssl: Serve over HTTPS after restarting. Left unset, the scheme the
            server is already running under is preserved, so reloading an
            HTTPS server keeps the Maltego desktop client working.
    """
    return await _blocking(operations.restart, ssl=ssl)


@server.tool()
async def server_status() -> str:
    """Report whether the server is running, healthy, and how many transforms it serves."""
    return await _async(operations.status)


@server.tool()
async def server_logs(lines: int = 50) -> str:
    """Return recent server log output.

    Args:
        lines: Number of trailing log lines to return.
    """
    return await _blocking(operations.logs, lines)


@server.tool()
async def list_transforms() -> str:
    """List every transform the running server advertises, with input and output types.

    An output type of NONE means the transform function is missing a return
    annotation, which stops the Maltego client from routing to it.
    """
    return await _async(operations.list_transforms)


@server.tool()
async def get_transform(transform_id: str) -> str:
    """Return the full detail document for one transform.

    Args:
        transform_id: Fully qualified transform name from list_transforms.
    """
    return await _async(operations.get_transform, transform_id)


@server.tool()
async def list_entities() -> str:
    """List the entity types the running server advertises."""
    return await _async(operations.list_entities)


@server.tool()
async def run_transform(
    transform_id: str,
    entity_type: str,
    entity_value: str,
    settings: dict[str, str] | None = None,
    timeout: float = 60.0,
    full: bool = False,
) -> str:
    """Run a transform against one input entity and return its results.

    The output starts with the run state, then each status message prefixed with its
    severity ([INFO], [WARNING], [ERROR], [DEBUG]), then the entity count and the number
    of distinct (type, value) pairs, one line per entity:
    `type  value  {property=value, ...}  [link label]`, and the link count. A run that
    FAILED also shows the last Python traceback from the server log.

    Check the entity count and the message severities: a transform can report success
    while producing nothing, and an upstream 403 or 500 logged as [ERROR] still ends the
    run in a success state; a run like that with no entities gets a Warning line under
    the state. An unknown transform id comes back with how to find the right one. See
    docs/transform-authoring.md.

    Args:
        transform_id: Fully qualified transform name from list_transforms.
        entity_type: Maltego type of the input entity, e.g. maltego.Domain.
        entity_value: Value carried by the input entity.
        settings: Optional transform settings, keyed by setting name.
        timeout: Seconds to wait before cancelling the run.
        full: Return every entity and link as the full JSON the server sent instead of
            one line each. Use it when a property, display field, or overlay that the
            summary cuts short matters.
    """
    return await _async(
        operations.run_transform,
        transform_id,
        entity_type,
        entity_value,
        settings,
        timeout,
        full=full,
    )


@server.tool()
async def get_seed_url() -> str:
    """Return the seed URL and the steps to register this server with Maltego."""
    return await _blocking(operations.seed_url)


@server.tool()
async def generate_certs(force: bool = False) -> str:
    """Generate a self-signed certificate for serving over HTTPS.

    Args:
        force: Overwrite an existing certificate pair.
    """
    return await _blocking(operations.generate_certs, force=force)


@server.tool()
async def scaffold_transform(
    service: str | None = None,
    curl: str | None = None,
    # Typed to accept a parsed document as well as text: the MCP server decodes any string
    # argument holding JSON unless the parameter is exactly `str`
    # (mcp/server/mcpserver/utilities/func_metadata.py, pre_parse_json), so a sample or spec
    # passed as a JSON string arrives as a dict or list and a plain `str | None` rejected it.
    openapi: str | dict[str, Any] | None = None,
    sample_response: str | dict[str, Any] | list[Any] | None = None,
    operation_ids: list[str] | None = None,
    force: bool = False,
    name: str | None = None,
    records: str | None = None,
    mappings: list[str] | None = None,
    dry_run: bool = False,
    # Not exactly `str`, so the JSON pre-parse noted above applies, but it leaves a value
    # that decodes to a number or string alone (pre_parse_json skips str/int/float), so an
    # id like "1" or a hash arrives as the text sent.
    sample_input: str | None = None,
    primary: str | None = None,
) -> str:
    """Scaffold a new Maltego transform module from a cURL command or OpenAPI specification.

    The output lists each transform by the id the server registers it under, its sample
    input, a ready-made run command, and a field inventory: every leaf path seen in the
    sample response or schema, its sample value, and what happened to it (mapped to an
    entity, attached as a property, or dropped and why). Read the inventory and the notes:
    data an investigator needs is often nested deeper than the scaffolder follows by
    default. Preview with dry_run=True, adjust records/mappings/primary until the inventory
    maps what matters, then call again without dry_run. Restart the server, then call
    run_transform with the transform id exactly as listed (it includes the namespace).

    Args:
        service: Optional service name slug (e.g. 'greynoise', 'threatfox').
        curl: A full cURL command string demonstrating an API request.
        openapi: An OpenAPI/Swagger spec in JSON or YAML: a URL, a file path, or the
            document itself (as text or as an object). Use list_operations first to
            pick operation_ids.
        sample_response: A real JSON response (as text or as the parsed value), to map
            outputs from. Works with curl, and with openapi when exactly one operation
            is scaffolded (name it in operation_ids); without it a spec with no response
            schema maps nothing.
        operation_ids: OpenAPI operation ids to scaffold. Without it every GET operation is
            scaffolded; POST operations are only scaffolded when named here.
        force: Replace an existing service: its whole directory and its project.py imports.
        name: Transform name for a curl scaffold (default '<service>_lookup'), so one
            service can grow endpoint by endpoint.
        records: Dotted path to the list of records in the response, e.g. 'data' or
            'containers.cna.references'. Each element becomes one record to map.
        mappings: Per-field overrides as 'dotted.path[].field=EntityType', e.g.
            'containers.cna.affected[].vendor=Company'. EntityType 'Property' attaches
            the field to the record's entity as a property; 'Drop' ignores it.
        dry_run: Parse and report the plan (transforms, field inventory, notes, auth,
            and the files that would be written) without writing anything.
        sample_input: An input value the API answers for, e.g. the hash or id the
            sample_response came from. The generated transform skips the input when the
            response echoes it back (so the other fields enrich the input instead of a copy
            of it), and samples.json records it so the smoke test sends a value the
            endpoint accepts. A curl scaffold defaults to the value in the request; give it
            for an openapi scaffold, which otherwise only has the spec's example, if any.
        primary: Path of the field to use as each record's primary entity, the one every
            other field attaches to as a property, written like a mappings path (e.g.
            'SHA-1' or 'hits.hits[]._id'). It must map to an entity type; the error names
            the valid candidates.
    """
    return await _blocking(
        operations.scaffold,
        service=service,
        curl=curl,
        openapi=openapi,
        sample_response=sample_response,
        operations=operation_ids,
        force=force,
        name=name,
        records=records,
        mappings=mappings,
        dry_run=dry_run,
        sample_input=sample_input,
        primary=primary,
    )


@server.tool()
async def list_operations(openapi: str, service: str | None = None) -> str:
    """List the operations in an OpenAPI spec and what scaffolding each would produce.

    One row per operation: HTTP method, path, operation id (pass it to
    scaffold_transform's operation_ids), the transform id it would get, the inferred
    input entity, whether the spec has a response schema to map outputs from, and why
    an operation would be skipped. Nothing is written.

    Args:
        openapi: An OpenAPI/Swagger spec in JSON or YAML: a URL, a file path, or the
            document itself.
        service: The service name you will scaffold under, so the transform ids shown
            match the ones scaffold_transform generates.
    """
    return await _blocking(operations.list_operations, openapi, service=service)


@server.tool()
async def remove_scaffold(service: str) -> str:
    """Delete a scaffolded service directory and its imports in project.py.

    Use this to undo a scaffold. Deleting server/transforms/<service>/ by hand leaves
    its imports behind, and the server then fails to start. Restart the server
    afterwards. Only services the scaffolder generated are removed: a hand-written
    service (its api.py lacks the scaffold's generated marker) is refused, and the
    output says so.

    Args:
        service: Service name slug, the directory name under server/transforms/.
    """
    return await _blocking(operations.remove_scaffold, service)


def main() -> None:
    """Run the MCP server over stdio."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
