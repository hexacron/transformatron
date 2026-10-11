"""Server operations shared by every front end.

The MCP tools and the CLI are both thin shells over this module, so an agent using
MCP and a human using the terminal get identical behaviour and identical output.
Add an operation here, not in a front end.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from pathlib import Path
from typing import Any

import httpx

from transformatron import certs, lifecycle
from transformatron.client import TransformClient, TransformNotFoundError, TransformServerError
from transformatron.config import TransformatronConfig
from transformatron.scaffold import (
    FieldReport,
    ScaffoldServiceConfig,
    list_openapi_operations,
    parse_curl_command,
    parse_openapi_spec,
    planned_scaffold_paths,
    write_scaffold,
)
from transformatron.scaffold import remove_scaffold as delete_scaffold
from transformatron.scaffold.schema import qualified_entity_type


class Failure(str):
    """Output of an operation that did not do what it was asked to.

    It is still a ``str``, so the MCP tools hand it to the agent as ordinary text and
    anything that only renders output need not care. The CLI checks
    ``isinstance(output, Failure)`` to choose its exit code. Failure is carried in the type
    rather than read back out of the wording because the wording is not reliable: a
    transform's own status message can say "Failed" on a run that succeeded.
    """

    __slots__ = ()


def format_transform(transform: dict[str, Any]) -> str:
    """Render one transform as id, display name, and input/output types."""
    name = transform.get("name", "<unnamed>")
    display = transform.get("displayName", "")
    input_types = ", ".join(transform.get("input", {}).get("typeIds", [])) or "?"
    output_types = ", ".join(transform.get("output", {}).get("typeIds", [])) or "NONE"
    return f"{name}\n    {display}\n    {input_types} -> {output_types}"


def start(config: TransformatronConfig, ssl: bool = False) -> str:
    """Start the server and report the result."""
    try:
        return lifecycle.start(config, ssl=ssl).detail
    except (lifecycle.ServerLifecycleError, OSError) as exc:
        return Failure(f"Failed to start: {exc}")


def stop(config: TransformatronConfig) -> str:
    """Stop the server and report the result."""
    try:
        return lifecycle.stop(config)
    except (lifecycle.ServerLifecycleError, OSError) as exc:
        return Failure(f"Failed to stop: {exc}")


def restart(config: TransformatronConfig, ssl: bool | None = None) -> str:
    """Restart the server, picking up edited transform modules.

    With ``ssl=None`` the running server's scheme is preserved.
    """
    try:
        return lifecycle.restart(config, ssl=ssl).detail
    except (lifecycle.ServerLifecycleError, OSError) as exc:
        return Failure(f"Failed to restart: {exc}")


async def status(config: TransformatronConfig) -> str:
    """Report whether the server is running, healthy, and how many transforms it serves.

    Reported as a failure unless the server answers and lists its transforms, so a script
    can gate on ``status`` before running anything against the server.
    """
    # The health probe is a blocking HTTP call; running it on the event loop would stall
    # every other MCP request for as long as the probe waits.
    state = await asyncio.to_thread(lifecycle.status, config)
    lines = [state.detail]
    if not state.healthy:
        return Failure("\n".join(lines))
    resolved = lifecycle.resolve_config(config)
    try:
        transforms = await TransformClient(resolved).list_transforms()
    except TransformServerError as exc:
        lines.append(str(exc))
        return Failure("\n".join(lines))
    lines.append(f"Serving {len(transforms)} transforms.")
    lines.append(f"Seed URL: {resolved.seed_url}")
    return "\n".join(lines)


async def list_transforms(config: TransformatronConfig) -> str:
    """List every transform the server advertises."""
    try:
        transforms = await TransformClient(lifecycle.resolve_config(config)).list_transforms()
    except TransformServerError as exc:
        return Failure(str(exc))
    if not transforms:
        return "The server advertises no transforms."
    body = "\n".join(format_transform(t) for t in transforms)
    return f"{len(transforms)} transforms:\n{body}"


async def get_transform(config: TransformatronConfig, transform_id: str) -> str:
    """Return the full detail document for one transform."""
    try:
        detail = await TransformClient(lifecycle.resolve_config(config)).get_transform(transform_id)
    except TransformServerError as exc:
        return Failure(_server_error(config, exc, transform_id))
    return json.dumps(detail, indent=2)


def _server_error(
    config: TransformatronConfig, exc: TransformServerError, transform_id: str
) -> str:
    """Render a server error, with how to find the right id when the id was unknown."""
    if not isinstance(exc, TransformNotFoundError):
        return str(exc)
    lines = [
        str(exc),
        "Run 'transformatron_cli.py list' (the list_transforms tool) to see the registered "
        "transform ids.",
    ]
    # Every registered id carries the server namespace; the short id a module defines
    # (and that a scaffold names its files after) is the most common thing to pass instead.
    if "." not in transform_id:
        lines.append(f"Transform ids carry the namespace: try '{config.namespace}.{transform_id}'.")
    lines.append(
        "A transform added since the server started is only served after "
        "'transformatron_cli.py restart'."
    )
    return "\n".join(lines)


async def list_entities(config: TransformatronConfig) -> str:
    """List the entity types the server advertises."""
    try:
        entities = await TransformClient(lifecycle.resolve_config(config)).list_entities()
    except TransformServerError as exc:
        return Failure(str(exc))
    names = sorted(str(e.get("name") or e.get("id") or e) for e in entities)
    return f"{len(names)} entities:\n" + "\n".join(names)


# Values beyond these widths are cut so one entity stays one readable line. The full form
# (``full=True``) is there for when the cut part matters.
_VALUE_WIDTH = 80
_PROPERTY_WIDTH = 40
_MAX_PROPERTIES = 8
# The property the SDK sends a link's label under (maltego/model/link.py:71).
_LINK_LABEL = "maltego.link.label"


async def run_transform(
    config: TransformatronConfig,
    transform_id: str,
    entity_type: str,
    entity_value: str,
    settings: dict[str, str] | None = None,
    timeout: float = 60.0,
    full: bool = False,
) -> str:
    """Run one transform against one input entity and render the result.

    The rendered output always states the entity count, because a transform can
    report success while producing nothing — see docs/transform-authoring.md.

    By default each entity is one line of type, value, properties, and link label, so an
    author can read a run of a hundred entities at a glance; ``full`` renders every entity
    and link as the JSON the server sent instead. A run that ends FAILED also carries the
    last Python traceback the server logged during it, because the run's own message for a
    crash only says that one happened.

    A run is reported as a failure when the server is unreachable or the run ends in a
    state other than a success state. A successful run that returned zero entities is not
    a failure: finding nothing is a legitimate answer for many inputs, so the count in the
    output is the signal to read, not the exit code. Such a run that also logged an ERROR
    message carries a warning under the state line, because there the success state is
    actively misleading.
    """
    # Taken before the run starts so the traceback search below sees only what this run
    # logged, not a crash from an earlier run still sitting in the tail of the log.
    log_offset = _log_size(config.log_file)
    try:
        result = await TransformClient(lifecycle.resolve_config(config)).run_transform(
            transform_id, entity_type, entity_value, settings, timeout
        )
    except TransformServerError as exc:
        return Failure(_server_error(config, exc, transform_id))

    lines = [f"State: {result.state} ({'success' if result.succeeded else 'failure'})"]
    if result.succeeded and not result.entities and "ERROR" in result.message_levels:
        # A transform that logs a fatal error and returns still ends COMPLETED (see
        # transformatron/client.py), so the state line alone reads as a working run.
        lines.append(
            "Warning: the transform logged an error and returned nothing; the success state "
            "does not mean it worked."
        )
    if result.messages:
        lines.append("Messages:")
        lines += [
            f"  [{level}] {message}"
            for message, level in zip(result.messages, result.message_levels, strict=True)
        ]
    distinct = {(e.get("type"), _entity_value(e)) for e in result.entities}
    lines.append(f"Entities ({len(result.entities)}, {len(distinct)} distinct):")
    if full:
        lines += [f"  {json.dumps(e)}" for e in result.entities]
        lines.append(f"Links ({len(result.links)}):")
        lines += [f"  {json.dumps(link)}" for link in result.links]
    else:
        labels = _link_labels(result.links)
        lines += [_format_entity(e, labels.get(e.get("id"))) for e in result.entities]
        lines.append(f"Links: {len(result.links)}")
    if result.state == "FAILED":
        traceback = _last_traceback(_read_log_from(config.log_file, log_offset))
        if traceback:
            lines.append("Server log traceback (newest):")
            lines += [f"  {line}" for line in traceback]
    rendered = "\n".join(lines)
    return rendered if result.succeeded else Failure(rendered)


def _entity_value(entity: dict[str, Any]) -> str:
    """Return the entity's value: the property its ``valueRef`` names.

    A ``TransformRunEntity`` (maltego/protocol/v3/execution/entity.py) carries no value
    field of its own; the value is whichever property ``valueRef`` points at.
    """
    value_ref = entity.get("valueRef")
    for prop in entity.get("properties") or []:
        if prop.get("name") == value_ref:
            return str(prop.get("value"))
    return str(entity.get("value", ""))


def _link_labels(links: list[dict[str, Any]]) -> dict[Any, str]:
    """Map each link's target entity id to the label on the link."""
    labels: dict[Any, str] = {}
    for link in links:
        for prop in link.get("properties") or []:
            if prop.get("name") == _LINK_LABEL and prop.get("value"):
                labels[link.get("targetId")] = str(prop["value"])
    return labels


def _format_entity(entity: dict[str, Any], label: str | None) -> str:
    """Render one entity as ``type  value  {name=value, ...}  [label]``."""
    parts = [str(entity.get("type", "?")), _clip(_entity_value(entity), _VALUE_WIDTH)]
    value_ref = entity.get("valueRef")
    extra = [
        f"{prop.get('name')}={_clip(str(prop['value']), _PROPERTY_WIDTH)}"
        for prop in entity.get("properties") or []
        if prop.get("name") != value_ref and _shown_value(prop.get("value"))
    ]
    if extra:
        shown = extra[:_MAX_PROPERTIES]
        if len(extra) > _MAX_PROPERTIES:
            shown.append(f"+{len(extra) - _MAX_PROPERTIES} more")
        parts.append("{" + ", ".join(shown) + "}")
    if label:
        parts.append(f"[{_clip(label, _PROPERTY_WIDTH)}]")
    return "  " + "  ".join(parts)


def _shown_value(value: Any) -> bool:
    """Return whether a property value carries anything worth a column in the summary.

    Whitespace counts as empty: some SDK entities default a property to a single space
    (``Port``'s ``properties.port``, maltego/entities/infrastructure.py:482-486), which
    the summary would otherwise show as ``properties.port= `` on every entity.
    """
    if value is None or value == []:
        return False
    return not (isinstance(value, str) and not value.strip())


def _clip(text: str, width: int) -> str:
    """Return ``text`` on one line, cut to ``width`` characters.

    Line breaks are shown escaped rather than removed: a value holding one is usually a
    mapping bug (several names joined in one field), and the author needs to see it.
    """
    flat = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return flat if len(flat) <= width else flat[: width - 3] + "..."


# A record line from the server's log formatter starts with uvicorn's level prefix
# (``ERROR:     | 2026-... | logger | message``, maltego/config.py:48); traceback lines
# never do. Colour codes are allowed for in case the server ever logs to a terminal.
_LOG_RECORD = re.compile(
    r"^(?:\x1b\[[\d;]*m)?(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)(?:\x1b\[[\d;]*m)?:"
)
_TRACEBACK_START = "Traceback (most recent call last):"
_TRACEBACK_MAX_LINES = 30


def _log_size(log_file: Path) -> int:
    """Return the log's current size in bytes, or 0 when the server has not written one."""
    try:
        return log_file.stat().st_size
    except OSError:
        return 0


def _read_log_from(log_file: Path, offset: int) -> str:
    """Return what the server logged after byte ``offset``, or '' when there is no log."""
    try:
        with log_file.open("rb") as handle:
            # A log that shrank was replaced since the offset was taken; all of it is new.
            if handle.seek(0, 2) >= offset:
                handle.seek(offset)
            else:
                handle.seek(0)
            return handle.read().decode(errors="replace")
    except OSError:
        return ""


def _last_traceback(log_text: str) -> list[str]:
    """Return the last logged traceback in ``log_text`` with the record that logged it.

    The SDK logs a transform crash as one record — "Caught unknown internal error while
    running Transform." — followed by the traceback (maltego/runner/
    transform_execution_context.py:360-362). The block runs from that record line to the
    next record line, so a chained exception is kept whole. Long tracebacks keep their end,
    where the transform's own frame and the exception are.
    """
    lines = log_text.splitlines()
    start = next((i for i in range(len(lines) - 1, -1, -1) if _TRACEBACK_START in lines[i]), None)
    if start is None:
        return []
    begin = next((i for i in range(start - 1, -1, -1) if _LOG_RECORD.match(lines[i])), start)
    end = next((i for i in range(start + 1, len(lines)) if _LOG_RECORD.match(lines[i])), len(lines))
    block = lines[begin:end]
    if len(block) <= _TRACEBACK_MAX_LINES:
        return block
    kept = block[-(_TRACEBACK_MAX_LINES - 2) :]
    return [block[0], f"... ({len(block) - len(kept) - 1} lines trimmed)", *kept]


def seed_url(config: TransformatronConfig) -> str:
    """Return the seed URL and the steps to register this server with Maltego."""
    return (
        f"Seed URL: {lifecycle.resolve_config(config).seed_url}\n\n"
        "To register it in the Maltego client:\n"
        "1. Start the server and confirm it is healthy.\n"
        "2. In Maltego, open the Transforms tab and choose Transform Hub.\n"
        "3. Add a local Transform Hub item and paste the seed URL above.\n"
        "4. Install the item, then run a transform from a matching entity.\n\n"
        "The desktop client and the Graph Browser both require HTTPS: generate "
        "certificates and restart with SSL enabled."
    )


def generate_certs(config: TransformatronConfig, force: bool = False) -> str:
    """Generate a self-signed certificate for serving over HTTPS."""
    try:
        pair = certs.generate(config, force=force)
    except certs.CertificateError as exc:
        return Failure(f"Failed to generate certificates: {exc}")
    return (
        f"Certificate: {pair.cert_file}\n"
        f"Private key: {pair.key_file}\n\n"
        "Restart with SSL enabled to serve over HTTPS.\n\n"
        "To trust this certificate, run (changes system trust, so run it yourself):\n"
        f"  {pair.trust_command}"
    )


def logs(config: TransformatronConfig, lines: int = 50) -> str:
    """Return recent server log output."""
    return lifecycle.tail_log(config, lines)


_SPEC_FETCH_TIMEOUT = 30.0


def _load_openapi(openapi: str | dict[str, Any]) -> tuple[str | dict[str, Any], str | None]:
    """Return the spec and, when it was fetched, the URL it came from.

    Accepts a URL, a file path, or the document itself, as text or already parsed: the MCP
    server hands over a JSON document passed as a string already decoded.
    """
    if isinstance(openapi, dict):
        return openapi, None
    if re.match(r"^https?://", openapi.strip()):
        url = openapi.strip()
        try:
            response = httpx.get(url, follow_redirects=True, timeout=_SPEC_FETCH_TIMEOUT)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            # Raised as ValueError so the caller reports it like any other bad spec.
            raise ValueError(f"could not fetch the OpenAPI spec from {url}: {exc}") from exc
        return response.text, str(response.url)
    path = Path(openapi)
    return (path.read_text() if path.is_file() else openapi), None


def scaffold(
    config: TransformatronConfig,
    service: str | None = None,
    curl: str | None = None,
    openapi: str | dict[str, Any] | None = None,
    sample_response: dict[str, Any] | list[Any] | str | None = None,
    operations: list[str] | None = None,
    force: bool = False,
    name: str | None = None,
    records: str | None = None,
    mappings: list[str] | None = None,
    dry_run: bool = False,
    sample_input: str | None = None,
    primary: str | None = None,
) -> str:
    """Scaffold a new Maltego transform module package from a cURL command or OpenAPI spec.

    With ``dry_run`` the request is parsed and the plan reported — transforms, the field
    inventory, notes, and the files that would be written — without touching disk, so the
    ``records``/``mappings``/``primary`` overrides can be tuned before anything is generated.

    ``sample_input`` names an input value the API answers for: it is what the generated
    transform recognises as the input echoed back in the response, and what samples.json
    records for the smoke test. A cURL command supplies one by default; an OpenAPI scaffold
    only has one when it is given here or the spec has an example. ``primary`` is the
    dotted path of the field to use as each record's primary entity.
    """
    if not curl and not openapi:
        return Failure("Failed to scaffold: Provide either a --curl command or an --openapi spec.")
    if curl and openapi:
        return Failure(
            "Failed to scaffold: Provide a --curl command or an --openapi spec, not both."
        )
    if curl and operations:
        return Failure(
            "Failed to scaffold: --operation selects from an OpenAPI spec, not a cURL command."
        )
    if openapi and name:
        return Failure(
            "Failed to scaffold: --name names the transform scaffolded from a cURL command; "
            "OpenAPI transforms are named after their operation ids."
        )

    # Only the failures a caller can act on are caught: a malformed spec, a cURL command
    # with no URL, a bad --records/--map path, or a service that already exists. A bare
    # `except Exception` here would also swallow the FileExistsError guarding hand-written
    # modules and report it as ordinary prose, and would hide genuine bugs in the generator
    # behind a string.
    try:
        if curl:
            scaffold_cfg = parse_curl_command(
                curl_cmd=curl,
                sample_response=sample_response,
                service_name=service,
                transform_name=name,
                records=records,
                mappings=mappings,
                sample_input=sample_input,
                primary=primary,
            )
        else:
            spec, spec_url = _load_openapi(openapi or "")
            scaffold_cfg = parse_openapi_spec(
                spec=spec,
                service_name=service,
                operations=operations,
                spec_url=spec_url,
                sample_response=sample_response,
                records=records,
                mappings=mappings,
                sample_input=sample_input,
                primary=primary,
            )
        if dry_run:
            return _render_scaffold_plan(config, scaffold_cfg, force)
        created_files = write_scaffold(scaffold_cfg, config.project_dir, force=force)
    except ValueError as exc:
        # json.JSONDecodeError subclasses ValueError, so a malformed spec lands here too.
        return Failure(f"Failed to scaffold: {exc}")
    except FileExistsError as exc:
        return Failure(f"Failed to scaffold: {exc}")
    except OSError as exc:
        return Failure(f"Failed to scaffold: could not write to {config.project_dir}: {exc}")

    if (config.project_dir / "project.py").exists():
        import_line = "Imports added to server/project.py."
    else:
        import_line = (
            "No server/project.py found, so nothing was imported; add the imports by hand."
        )
    return "\n".join(
        [
            f"Scaffolded '{scaffold_cfg.display_name}' ({scaffold_cfg.service_id}):",
            "",
            "Created files:",
            *(f"  - {f}" for f in created_files),
            "",
            *_render_scaffold_body(config, scaffold_cfg, dry_run=False),
            import_line,
            "",
            "Next steps:",
            "1. Run 'transformatron_cli.py restart' to load the new transforms.",
            "2. Run each against its sample input and compare the entities with the field "
            "inventory above: the entity count, the types, and the values.",
            *_run_commands(config, scaffold_cfg),
            "3. Add what is missing. A path marked 'dropped' that an investigator needs is "
            "mapped by scaffolding again with --records PATH or --map PATH=EntityType plus "
            "--force (preview with --dry-run first), or by editing the module. Also check the "
            "Notes: request details the scaffolder could not carry over need adding by hand.",
            "4. Remove noise: mapped fields an investigator would not pivot on.",
            "5. Run 'smoke_test_transforms.py' to gate the whole set.",
        ]
    )


def _render_scaffold_plan(
    config: TransformatronConfig, scaffold_cfg: ScaffoldServiceConfig, force: bool
) -> str:
    """Render what a scaffold would generate, without writing anything."""
    # The same checks the real write runs, so the preview predicts its outcome. An existing
    # service the write would refuse is reported rather than raised: an author redoing a
    # scaffold still needs to see the new mapping before choosing --force.
    svc_dir = config.project_dir / "transforms" / scaffold_cfg.service_id
    try:
        paths = planned_scaffold_paths(scaffold_cfg, config.project_dir, force=force)
        refusal = None
    except FileExistsError as exc:
        paths = planned_scaffold_paths(scaffold_cfg, config.project_dir, force=True)
        refusal = str(exc)
    if refusal:
        exists_line = [f"Without --force, writing it would fail: {refusal}", ""]
    elif svc_dir.exists() and force:
        exists_line = [
            f"{svc_dir} already exists; --force replaces the whole directory, including "
            "transforms this scaffold does not generate.",
            "",
        ]
    elif svc_dir.exists():
        exists_line = [f"{svc_dir} already exists; this scaffold adds to it.", ""]
    else:
        exists_line = []
    project_py = config.project_dir / "project.py"
    return "\n".join(
        [
            f"Dry run, nothing written. Scaffolding '{scaffold_cfg.display_name}' "
            f"({scaffold_cfg.service_id}) would write:",
            *(f"  - {path}" for path in paths),
            *([f"  - {project_py} (imports added)"] if project_py.exists() else []),
            "",
            *exists_line,
            *_render_scaffold_body(config, scaffold_cfg, dry_run=True),
            "Next steps:",
            "1. Check the inventory: every path an investigator needs should map to an entity "
            "or a property.",
            "2. Point the transform at the list of records with --records PATH, and map or "
            "drop single fields with --map PATH=EntityType (Property attaches the field to "
            "the record's entity, Drop ignores it). Repeat with --dry-run until it fits.",
            "3. Run the same command without --dry-run to write it, restart the server, and "
            "run each transform against its sample input:",
            *_run_commands(config, scaffold_cfg),
        ]
    )


# The front end the next-steps commands are written for: the run line is copied from the
# output into a terminal at the repository root, so it is spelled out in full.
_CLI = "uv run python scripts/transformatron_cli.py"
# Stands in for the input value of a transform the scaffolder found no sample input for.
_NO_SAMPLE_INPUT = "VALUE"
# Every scaffold note that points at --dry-run ends with a sentence starting with this
# (the convention transformatron/scaffold keeps); a dry run already shows what it offers.
_DRY_RUN_POINTER = re.compile(r"\s*Preview with --dry-run.*\Z", re.DOTALL)


def _registered_id(config: TransformatronConfig, transform_id: str) -> str:
    """Return the id the server registers a scaffolded transform under.

    The server prefixes every transform's own id with the namespace (``MALTEGO_SERVER_NS``,
    set from the config at start), and only the prefixed id is accepted by ``run``.
    """
    return f"{config.namespace}.{transform_id}"


def _run_commands(config: TransformatronConfig, scaffold_cfg: ScaffoldServiceConfig) -> list[str]:
    """Return a copy-pasteable ``run`` command per transform, by its registered id."""
    lines = []
    for t in scaffold_cfg.transforms:
        value = _NO_SAMPLE_INPUT if t.sample_input is None else shlex.quote(t.sample_input)
        lines.append(
            f"     {_CLI} run {_registered_id(config, t.transform_id)} "
            f"{qualified_entity_type(t.input_entity)} {value}"
        )
    if any(t.sample_input is None for t in scaffold_cfg.transforms):
        lines.append(
            f"   {_NO_SAMPLE_INPUT} marks a transform with no sample input: replace it with a "
            "value the API knows, and scaffold again with --sample-input VALUE so samples.json "
            "records it for the smoke test."
        )
    return lines


def _render_scaffold_body(
    config: TransformatronConfig, scaffold_cfg: ScaffoldServiceConfig, dry_run: bool
) -> list[str]:
    """Render the transforms, their field inventories, auth, and notes of a scaffold."""
    lines = ["Transforms:"]
    for t in scaffold_cfg.transforms:
        outputs = ", ".join(t.output_entity_types) or "NONE"
        lines.append(f"  - {_registered_id(config, t.transform_id)}: {t.display_name}")
        lines.append(f"      {t.input_entity} -> {outputs} ({t.http_method} {t.endpoint_path})")
        if t.sample_input is not None:
            lines.append(f"      sample input: {t.sample_input}")
    lines.append("")
    for t in scaffold_cfg.transforms:
        lines.append(
            f"Field inventory, {_registered_id(config, t.transform_id)} (path, sample, outcome):"
        )
        lines += _format_inventory(t.inventory)
        lines.append("")
    if scaffold_cfg.auth_key_name:
        lines.append(
            f"API key setting: {scaffold_cfg.auth_key_name}. Set it in .env, or pass "
            f"--setting {scaffold_cfg.auth_key_name}=... to run."
        )
    else:
        lines.append("No API key: the request showed no authentication.")
    notes = scaffold_cfg.notes
    if dry_run:
        notes = [kept for note in notes if (kept := _DRY_RUN_POINTER.sub("", note))]
    if notes:
        lines += ["", "Notes:", *(f"  - {note}" for note in notes)]
    lines.append("")
    return lines


_INVENTORY_PATH_WIDTH = 48
_INVENTORY_SAMPLE_WIDTH = 32


def _format_inventory(inventory: list[FieldReport]) -> list[str]:
    """Render a field inventory as aligned ``path  sample  outcome`` rows.

    A path longer than the column is printed alone on its line, with its sample and outcome
    on the next line under their columns, so one deep path does not shift every row.
    """
    if not inventory:
        return ["  (no sample response or response schema, so no fields to report)"]
    path_width = min(max(len(row.path) for row in inventory), _INVENTORY_PATH_WIDTH)
    sample_width = min(
        max(len(_clip(row.sample, _INVENTORY_SAMPLE_WIDTH)) for row in inventory),
        _INVENTORY_SAMPLE_WIDTH,
    )
    lines = []
    for row in inventory:
        rest = f"{_clip(row.sample, _INVENTORY_SAMPLE_WIDTH):<{sample_width}}  {row.outcome}"
        if len(row.path) > path_width:
            lines += [f"  {row.path}", f"  {'':<{path_width}}  {rest}"]
        else:
            lines.append(f"  {row.path:<{path_width}}  {rest}")
    return lines


def list_operations(
    config: TransformatronConfig, openapi: str | dict[str, Any], service: str | None = None
) -> str:
    """List the operations of an OpenAPI spec and what scaffolding each would produce.

    ``service`` is the name a scaffold would be given, so the transform ids shown are the
    ones it would generate. ``config`` is unused; it is taken so every operation has the
    same front-end shape.
    """
    try:
        spec, _ = _load_openapi(openapi)
        found = list_openapi_operations(spec, service_name=service)
    except ValueError as exc:
        return Failure(f"Failed to list operations: {exc}")
    except OSError as exc:
        return Failure(f"Failed to list operations: could not read {openapi}: {exc}")
    if not found:
        return "The spec defines no operations."
    rows = [
        [
            op.method,
            op.path,
            f"{op.operation_id}*" if op.duplicate else op.operation_id,
            op.transform_id,
            op.input,
            "yes" if op.has_response_schema else "no",
            op.skipped_reason or "",
        ]
        for op in found
    ]
    table = _table(["METHOD", "PATH", "OPERATION", "TRANSFORM", "INPUT", "SCHEMA", "SKIPPED"], rows)
    usable = sum(1 for op in found if not op.skipped_reason)
    # A spec may reuse one operationId for several paths; the transforms get distinct ids,
    # but the operation id alone no longer names one operation, which the author must see.
    duplicate_note = (
        [
            "* The spec gives this operation id to more than one operation: --operation with "
            "it scaffolds all of them. To pick one, pass its TRANSFORM value to --operation.",
        ]
        if any(op.duplicate for op in found)
        else []
    )
    return "\n".join(
        [
            f"{len(found)} operations, {usable} scaffoldable:",
            *table,
            "",
            *duplicate_note,
            "Scaffold chosen ones with --operation OPERATION (repeatable). SCHEMA 'no' means "
            "the spec has no response schema to map: pass --sample-response with one "
            "--operation, or the transform returns nothing useful.",
        ]
    )


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """Render rows as left-aligned columns under ``headers``."""
    widths = [max(len(cell) for cell in column) for column in zip(headers, *rows, strict=True)]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        for row in [headers, *rows]
    ]


def remove_scaffold(config: TransformatronConfig, service: str) -> str:
    """Delete a scaffolded service directory and its ``project.py`` imports."""
    try:
        removed = delete_scaffold(service, config.project_dir)
    except ValueError as exc:
        return Failure(f"Failed to remove scaffold: {exc}")
    except OSError as exc:
        return Failure(f"Failed to remove scaffold: could not edit {config.project_dir}: {exc}")
    return "\n".join(
        [
            f"Removed '{service}':",
            *(f"  - {item}" for item in removed),
            "",
            "Restart the server ('transformatron_cli.py restart') so it stops serving the "
            "removed transforms.",
        ]
    )
