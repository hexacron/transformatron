"""Tests for the operations shared by the MCP and CLI front ends."""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
import yaml

from transformatron import lifecycle, operations
from transformatron.client import RunResult, TransformNotFoundError, TransformServerError
from transformatron.config import CONFIG_FILE_NAME, TransformatronConfig

CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "transformatron_cli.py"


@pytest.fixture
def config(tmp_path) -> TransformatronConfig:
    project = tmp_path / "server"
    project.mkdir()
    (project / "project.py").write_text("")
    return TransformatronConfig(project_dir=project, state_dir=tmp_path / "state")


@pytest.fixture
def cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The CLI script, loading its config from an empty ``tmp_path`` repository root."""
    monkeypatch.setattr("transformatron.config.REPO_ROOT", tmp_path)
    spec = importlib.util.spec_from_file_location("transformatron_cli", CLI_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cli(monkeypatch: pytest.MonkeyPatch, cli: ModuleType, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["transformatron_cli", *argv])
    return cli.main()


def test_format_transform_renders_input_and_output_types() -> None:
    rendered = operations.format_transform(
        {
            "name": "acme.demo.lookup",
            "displayName": "Lookup",
            "input": {"typeIds": ["maltego.Domain"]},
            "output": {"typeIds": ["maltego.IPv4Address", "maltego.AS"]},
        }
    )

    assert "acme.demo.lookup" in rendered
    assert "maltego.Domain -> maltego.IPv4Address, maltego.AS" in rendered


def test_format_transform_marks_a_missing_output_type_as_none() -> None:
    """An untyped return annotation must be visible, since it breaks client routing."""
    rendered = operations.format_transform(
        {"name": "acme.demo.broken", "input": {"typeIds": ["maltego.Domain"]}, "output": {}}
    )

    assert "-> NONE" in rendered


def _run_result(entities: list[dict[str, Any]], state: str = "COMPLETED") -> RunResult:
    return RunResult(run_id="r1", state=state, entities=entities)


def _entity(entity_id: str, entity_type: str, value: str, **props: str) -> dict[str, Any]:
    """An entity as the server sends it: the value is the property ``valueRef`` names."""
    return {
        "id": entity_id,
        "type": entity_type,
        "valueRef": "fqdn",
        "properties": [
            {"name": "fqdn", "type": "STRING", "value": value},
            *({"name": name, "type": "STRING", "value": v} for name, v in props.items()),
        ],
        "displayInformation": [],
    }


def _link(target_id: str, label: str) -> dict[str, Any]:
    return {
        "id": f"link-{target_id}",
        "sourceId": "0",
        "targetId": target_id,
        "properties": [{"name": "maltego.link.label", "type": "STRING", "value": label}],
    }


def _patch_run(monkeypatch: pytest.MonkeyPatch, result: RunResult) -> None:
    async def fake_run(self, *args: object, **kwargs: object) -> RunResult:
        return result

    monkeypatch.setattr(operations.TransformClient, "run_transform", fake_run)


async def test_run_transform_always_reports_the_entity_count(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count is the only signal that distinguishes a working transform from a silent failure."""
    _patch_run(monkeypatch, _run_result([]))

    rendered = await operations.run_transform(
        config, "acme.demo.lookup", "maltego.Domain", "example.com"
    )

    assert "State: COMPLETED (success)" in rendered
    assert "Entities (0, 0 distinct):" in rendered


async def test_run_transform_summarises_each_entity_on_one_line(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Type, value, properties, and link label per entity; duplicates show in the counts."""
    result = _run_result(
        [
            _entity("e1", "maltego.Domain", "www.example.com", issuer="R3"),
            _entity("e2", "maltego.Domain", "www.example.com"),
            # Two names joined in one value is a mapping bug the author has to see.
            _entity("e3", "maltego.Domain", "a.example.com\nb.example.com"),
            _entity("e4", "maltego.Phrase", "x" * 300),
        ]
    )
    result.links = [_link("e1", "SAN"), _link("e2", "SAN"), _link("e3", "SAN")]
    result.add_message("Upstream API access forbidden (403)", "ERROR")
    result.add_message("Partial results", "WARNING")
    _patch_run(monkeypatch, result)

    rendered = await operations.run_transform(
        config, "acme.demo.lookup", "maltego.Domain", "example.com"
    )
    lines = rendered.splitlines()

    assert "  [ERROR] Upstream API access forbidden (403)" in lines
    assert "  [WARNING] Partial results" in lines
    assert "Entities (4, 3 distinct):" in lines
    assert "  maltego.Domain  www.example.com  {issuer=R3}  [SAN]" in lines
    assert "  maltego.Domain  www.example.com  [SAN]" in lines
    assert "  maltego.Domain  a.example.com\\nb.example.com  [SAN]" in lines
    long_line = next(line for line in lines if "maltego.Phrase" in line)
    assert len(long_line) < 120, "a long value must not flood the output"
    assert "Links: 3" in lines
    assert "valueRef" not in rendered, "the summary is not the raw JSON"


async def test_run_summary_leaves_out_blank_properties(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SDK defaults Port's properties.port to a space; it showed on every Port."""
    port = _entity("e1", "maltego.Port", "443", **{"properties.port": " ", "service": "https"})
    _patch_run(monkeypatch, _run_result([port]))

    rendered = await operations.run_transform(config, "acme.demo.ports", "maltego.Domain", "x")

    assert "  maltego.Port  443  {service=https}" in rendered.splitlines()


@pytest.mark.parametrize(
    ("state", "level", "entities", "warned"),
    [
        ("COMPLETED", "ERROR", [], True),
        # Entities came back, so the run produced something to read despite the error.
        ("COMPLETED", "ERROR", [_entity("e1", "maltego.Domain", "a.example.com")], False),
        # Finding nothing, said with an INFO, is a legitimate answer.
        ("COMPLETED", "INFO", [], False),
        # A failed run already says it failed.
        ("FAILED", "ERROR", [], False),
    ],
)
def test_a_success_state_after_a_logged_error_and_no_entities_carries_a_warning(
    cli: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: str,
    level: str,
    entities: list[dict[str, Any]],
    warned: bool,
) -> None:
    """A transform that logs [ERROR] and returns still ends COMPLETED and exits 0."""
    result = _run_result(entities, state=state)
    result.add_message("Upstream API access forbidden (403)", level)
    _patch_run(monkeypatch, result)

    exit_code = run_cli(monkeypatch, cli, "run", "acme.demo", "maltego.Domain", "x.com")
    lines = capsys.readouterr().out.splitlines()

    assert exit_code == (1 if state == "FAILED" else 0), "the exit code semantics are unchanged"
    assert lines[1].startswith("Warning: ") is warned
    if warned:
        assert "does not mean it worked" in lines[1]


@pytest.mark.parametrize(
    ("transform_id", "suggestion"),
    [
        ("crtsh_lookup", "try 'acme.demo.crtsh_lookup'"),
        # Already namespaced: there is no prefixed form to suggest, only how to look it up.
        ("acme.demo.crtsh_lookup", None),
    ],
)
async def test_an_unknown_transform_id_says_how_to_find_the_registered_one(
    config: TransformatronConfig,
    monkeypatch: pytest.MonkeyPatch,
    transform_id: str,
    suggestion: str | None,
) -> None:
    """A scaffold's short id gave a bare 404 with no way forward."""

    async def not_found(self, transform_id: str, *args: object, **kwargs: object) -> RunResult:
        detail = f'{{"detail":"Transform with id {transform_id} not found"}}'
        raise TransformNotFoundError(f"POST .../run failed with HTTP 404: {detail}", 404)

    monkeypatch.setattr(operations.TransformClient, "run_transform", not_found)
    namespaced = dataclasses.replace(config, namespace="acme.demo")

    rendered = await operations.run_transform(namespaced, transform_id, "maltego.Domain", "x")

    assert isinstance(rendered, operations.Failure)
    assert "HTTP 404" in rendered
    assert "transformatron_cli.py list" in rendered
    assert "restart" in rendered, "a transform scaffolded since the start is not served yet"
    if suggestion:
        assert suggestion in rendered
    else:
        assert "try '" not in rendered


async def test_other_server_errors_carry_no_transform_id_hint(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def server_error(self, *args: object, **kwargs: object) -> RunResult:
        raise TransformServerError("POST .../run failed with HTTP 500: boom", 500)

    monkeypatch.setattr(operations.TransformClient, "run_transform", server_error)

    rendered = await operations.run_transform(config, "crtsh_lookup", "maltego.Domain", "x")

    assert rendered == "POST .../run failed with HTTP 500: boom"


async def test_run_transform_full_renders_the_json_the_server_sent(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    entity = _entity("e1", "maltego.Domain", "www.example.com", issuer="R3")
    link = _link("e1", "SAN")
    result = _run_result([entity])
    result.links = [link]
    _patch_run(monkeypatch, result)

    rendered = await operations.run_transform(
        config, "acme.demo.lookup", "maltego.Domain", "example.com", full=True
    )
    lines = rendered.splitlines()

    entities_at = lines.index("Entities (1, 1 distinct):")
    assert json.loads(lines[entities_at + 1]) == entity
    assert lines[entities_at + 2] == "Links (1):"
    assert json.loads(lines[entities_at + 3]) == link


_CRASH_LOG = """\
ERROR:    | 2026-10-11 10:00:01 |       maltego.runner | Caught unknown internal error while \
running Transform.
Traceback (most recent call last):
  File "/srv/server/transforms/demo/lookup.py", line 12, in lookup
    return [Domain(value=data["name"])]
TypeError: 'NoneType' object is not subscriptable
INFO:     | 2026-10-11 10:00:02 |       uvicorn.access | GET /run/r1/results 200
"""


@pytest.mark.parametrize(("state", "shown"), [("FAILED", True), ("COMPLETED", False)])
async def test_a_failed_run_shows_the_traceback_the_server_logged_during_it(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch, state: str, shown: bool
) -> None:
    """A crash reports only 'Unexpected exception'; the cause is in the server log.

    Only what was logged after the run started counts: an older crash still in the log
    belongs to some other run and would send the author after the wrong bug.
    """
    config.state_dir.mkdir()
    config.log_file.write_text(
        "ERROR:    | 2026-10-11 09:00:00 |       maltego.runner | earlier crash\n"
        "Traceback (most recent call last):\n"
        "OldError: from an earlier run\n"
    )

    async def crashing_run(self, *args: object, **kwargs: object) -> RunResult:
        with config.log_file.open("a") as log:
            log.write(_CRASH_LOG)
        result = _run_result([], state=state)
        result.add_message("Unexpected exception while executing transform Demo", "ERROR")
        return result

    monkeypatch.setattr(operations.TransformClient, "run_transform", crashing_run)

    rendered = await operations.run_transform(config, "acme.demo.lookup", "maltego.Domain", "x")

    assert ("TypeError: 'NoneType' object is not subscriptable" in rendered) is shown
    assert ("Caught unknown internal error" in rendered) is shown
    assert "OldError" not in rendered
    assert "GET /run/r1/results" not in rendered, "the traceback ends at the next log record"


async def test_a_long_traceback_keeps_its_end(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The transform's frame and the exception are at the end; that part must survive."""
    config.state_dir.mkdir()
    frames = "".join(f'  File "/sdk/frame{i}.py", line {i}, in f{i}\n' for i in range(200))

    async def crashing_run(self, *args: object, **kwargs: object) -> RunResult:
        config.log_file.write_text(
            "ERROR:    | 2026-10-11 10:00:01 |       maltego.runner | Caught unknown error\n"
            f"Traceback (most recent call last):\n{frames}KeyError: 'name'\n"
        )
        return _run_result([], state="FAILED")

    monkeypatch.setattr(operations.TransformClient, "run_transform", crashing_run)

    rendered = await operations.run_transform(config, "acme.demo.lookup", "maltego.Domain", "x")

    assert rendered.endswith("KeyError: 'name'")
    assert "frame199.py" in rendered
    assert "frame0.py" not in rendered
    assert len(rendered.splitlines()) < 50


async def test_list_transforms_reports_an_empty_server(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_list(self) -> list[dict[str, Any]]:
        return []

    monkeypatch.setattr(operations.TransformClient, "list_transforms", fake_list)

    assert "no transforms" in await operations.list_transforms(config)


def _server_status(healthy: bool, detail: str) -> Any:
    def fake_status(config: TransformatronConfig) -> lifecycle.ServerStatus:
        return lifecycle.ServerStatus(running=healthy, pid=None, healthy=healthy, detail=detail)

    return fake_status


async def test_status_renders_a_non_json_answer_as_a_failure_message(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Something other than the transform server on the port must not crash status."""
    monkeypatch.setattr(lifecycle, "status", _server_status(True, "Server is running."))
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html>hi</html>"))
    original = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *args, **kwargs: original(*args, **kwargs, transport=transport)
    )

    rendered = await operations.status(config)

    assert isinstance(rendered, operations.Failure)
    assert "not JSON: <html>hi</html>" in rendered


@pytest.mark.parametrize(
    ("state", "entities", "exit_code"),
    [
        ("COMPLETED", [{"id": "e1"}], 0),
        # Finding nothing is a legitimate answer; the output's entity count reports it.
        ("COMPLETED", [], 0),
        ("FINISHED", [], 0),
        ("FAILED", [], 1),
        ("TIMED_OUT", [], 1),
    ],
)
def test_cli_run_exits_nonzero_only_when_the_run_did_not_succeed(
    cli: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    entities: list[dict[str, Any]],
    exit_code: int,
) -> None:
    async def fake_run(self, *args: object, **kwargs: object) -> RunResult:
        return _run_result(entities, state=state)

    monkeypatch.setattr(operations.TransformClient, "run_transform", fake_run)

    assert run_cli(monkeypatch, cli, "run", "acme.demo", "maltego.Domain", "x.com") == exit_code


def test_cli_exits_nonzero_when_the_server_is_unreachable(
    cli: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def unreachable(self) -> list[dict[str, Any]]:
        raise TransformServerError("Could not reach the transform server")

    monkeypatch.setattr(operations.TransformClient, "list_transforms", unreachable)

    assert run_cli(monkeypatch, cli, "list") == 1
    assert "Could not reach" in capsys.readouterr().out


def test_cli_status_exits_nonzero_when_the_server_is_not_running(
    cli: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "status", _server_status(False, "Server is not running."))

    assert run_cli(monkeypatch, cli, "status") == 1


def test_cli_exits_nonzero_when_start_fails(
    cli: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(config: TransformatronConfig, ssl: bool = False) -> lifecycle.ServerStatus:
        raise lifecycle.ServerLifecycleError("port 3000 is already in use")

    monkeypatch.setattr(lifecycle, "start", refuse)

    assert run_cli(monkeypatch, cli, "start") == 1
    assert capsys.readouterr().out.startswith("Failed to start: port 3000 is already in use")


def test_cli_exits_zero_on_success(
    cli: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli(monkeypatch, cli, "seed-url") == 0
    assert "Seed URL:" in capsys.readouterr().out


def test_cli_reports_a_bad_config_file_in_one_line(
    cli: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A typo in transformatron.toml must read as an error message, not a traceback."""
    (tmp_path / CONFIG_FILE_NAME).write_text("[server\n")

    assert run_cli(monkeypatch, cli, "seed-url") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert "not valid TOML" in captured.err
    assert "Traceback" not in captured.err


def test_cli_run_json_prints_the_full_entities(
    cli: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    entity = _entity("e1", "maltego.Domain", "www.example.com")
    _patch_run(monkeypatch, _run_result([entity]))

    assert run_cli(monkeypatch, cli, "run", "acme.demo", "maltego.Domain", "x.com", "--json") == 0
    assert f"  {json.dumps(entity)}" in capsys.readouterr().out.splitlines()


# A real EPSS answer, trimmed: an envelope around `data`, the list of records.
_EPSS_CURL = "curl 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228'"
_EPSS_SAMPLE = json.dumps(
    {
        "status": "OK",
        "status-code": 200,
        "total": 1,
        "data": [{"cve": "CVE-2021-44228", "epss": "0.943580000", "percentile": "0.999610000"}],
    }
)


def _snapshot(directory: Path) -> dict[str, str]:
    return {
        str(path.relative_to(directory)): path.read_text()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def test_scaffold_dry_run_writes_nothing_and_reports_the_plan(
    config: TransformatronConfig,
) -> None:
    """The preview must be safe to repeat while tuning --records/--map."""
    before = _snapshot(config.project_dir)

    rendered = operations.scaffold(
        config,
        service="epss",
        curl=_EPSS_CURL,
        sample_response=_EPSS_SAMPLE,
        records="data",
        dry_run=True,
    )

    assert not isinstance(rendered, operations.Failure), rendered
    assert _snapshot(config.project_dir) == before
    lines = rendered.splitlines()
    epss_row = next(line for line in lines if "epss" in line and "0.94358" in line)
    assert epss_row.startswith("  "), "the inventory lists each field with its sample"
    assert str(config.project_dir / "transforms" / "epss" / "api.py") in rendered
    assert "sample input: CVE-2021-44228" in rendered


def test_scaffold_dry_run_of_an_existing_service_previews_instead_of_failing(
    config: TransformatronConfig,
) -> None:
    """Redoing a scaffold with new --map overrides starts by previewing over the old one."""
    assert not isinstance(
        operations.scaffold(config, service="epss", curl=_EPSS_CURL), operations.Failure
    )
    before = _snapshot(config.project_dir)

    rendered = operations.scaffold(
        config, service="epss", curl=_EPSS_CURL, sample_response=_EPSS_SAMPLE, dry_run=True
    )

    assert not isinstance(rendered, operations.Failure), rendered
    assert "--force" in rendered
    assert _snapshot(config.project_dir) == before


def test_scaffold_reports_a_bad_override_as_a_failure(config: TransformatronConfig) -> None:
    rendered = operations.scaffold(
        config,
        service="epss",
        curl=_EPSS_CURL,
        sample_response=_EPSS_SAMPLE,
        records="no.such.path",
        dry_run=True,
    )

    assert isinstance(rendered, operations.Failure)
    assert rendered.startswith("Failed to scaffold: ")


def _section(rendered: str, header: str) -> list[str]:
    """Return the lines after the line ``header`` up to the next blank line."""
    lines = rendered.splitlines()
    if header not in lines:
        return []
    start = lines.index(header) + 1
    end = next((i for i in range(start, len(lines)) if not lines[i].strip()), len(lines))
    return lines[start:end]


@pytest.mark.parametrize("dry_run", [True, False])
def test_scaffold_names_each_transform_by_its_registered_id_with_a_run_command(
    config: TransformatronConfig, dry_run: bool
) -> None:
    """The short id a scaffold printed was refused by run with a bare 404."""
    namespaced = dataclasses.replace(config, namespace="acme.demo")

    rendered = operations.scaffold(
        namespaced,
        service="epss",
        curl=_EPSS_CURL,
        sample_response=_EPSS_SAMPLE,
        records="data",
        dry_run=dry_run,
    )

    assert not isinstance(rendered, operations.Failure), rendered
    assert _section(rendered, "Transforms:")[0].startswith("  - acme.demo.epss_lookup: ")
    run_line = (
        "uv run python scripts/transformatron_cli.py run acme.demo.epss_lookup maltego.CVE "
        "CVE-2021-44228"
    )
    assert run_line in [line.strip() for line in rendered.splitlines()]


def test_scaffold_dry_run_notes_do_not_point_at_dry_run(config: TransformatronConfig) -> None:
    """A preview telling the author to preview is noise; the rest of each note is kept."""
    written = operations.scaffold(config, service="epss", curl=_EPSS_CURL)
    preview = operations.scaffold(config, service="epss_preview", curl=_EPSS_CURL, dry_run=True)

    preview_notes = _section(preview, "Notes:")
    assert preview_notes, "the placeholder note itself must survive"
    assert not any("--dry-run" in note for note in preview_notes)
    assert any("--dry-run" in note for note in _section(written, "Notes:"))


def test_scaffold_inventory_keeps_columns_aligned_past_a_long_path(
    config: TransformatronConfig,
) -> None:
    """One deep path pushed its own row out of line with every other row."""
    long_key = "x_legacyV4Record_with_an_extremely_long_key_name"
    sample = json.dumps(
        {"data": [{"cve": "CVE-2021-44228", "epss": "0.94358", "meta": {long_key: "hello"}}]}
    )

    rendered = operations.scaffold(
        config, service="epss", curl=_EPSS_CURL, sample_response=sample, dry_run=True
    )

    lines = rendered.splitlines()
    epss_row = next(line for line in lines if "0.94358" in line)
    long_at = next(i for i, line in enumerate(lines) if long_key in line)
    assert lines[long_at].strip().endswith(long_key), "the long path stands on its own line"
    sample_row = lines[long_at + 1]
    assert sample_row.index("hello") == epss_row.index("0.94358")


_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Vulns", "version": "1.0.0"},
    "servers": [{"url": "https://vulns.example"}],
    "paths": {
        "/api/cve/{cve_id}": {
            "get": {
                "operationId": "get_cve",
                "parameters": [
                    {"name": "cve_id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"id": {"type": "string"}},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/api/lookup/md5/{md5}": {
            "get": {
                "operationId": "lookup_md5",
                "parameters": [
                    {"name": "md5", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}


def _row(rendered: str, operation_id: str) -> list[str]:
    """Return the cells of the table row for ``operation_id``."""
    line = next(line for line in rendered.splitlines() if f" {operation_id} " in f" {line} ")
    return re.split(r"\s{2,}", line.strip())


def test_list_operations_shows_each_operation_and_whether_it_can_map_outputs(
    config: TransformatronConfig, tmp_path: Path
) -> None:
    """A YAML spec file, as most published specs are, lists without scaffolding anything."""
    spec_file = tmp_path / "vulns.yaml"
    spec_file.write_text(yaml.safe_dump(_SPEC))
    before = _snapshot(config.project_dir)

    rendered = operations.list_operations(config, str(spec_file), service="vulns")

    assert not isinstance(rendered, operations.Failure), rendered
    cve = _row(rendered, "get_cve")
    # The id shown is the one scaffolding under the same --service generates.
    assert cve[:4] == ["GET", "/api/cve/{cve_id}", "get_cve", "vulns_get_cve"]
    assert "yes" in cve
    md5 = _row(rendered, "lookup_md5")
    assert md5[:3] == ["GET", "/api/lookup/md5/{md5}", "lookup_md5"]
    assert "no" in md5, "an operation with no response schema must say so"
    assert _snapshot(config.project_dir) == before


def test_list_operations_reports_an_unreadable_spec(config: TransformatronConfig) -> None:
    rendered = operations.list_operations(config, "{not a spec")

    assert isinstance(rendered, operations.Failure)
    assert rendered.startswith("Failed to list operations: ")


def test_remove_scaffold_deletes_the_service_and_its_imports(
    config: TransformatronConfig,
) -> None:
    """Deleting only the directory left imports that stopped the server from booting."""
    project_py = config.project_dir / "project.py"
    project_py.write_text("from transforms.other.lookup import *  # noqa: F401,F403\n")
    assert not isinstance(
        operations.scaffold(config, service="epss", curl=_EPSS_CURL), operations.Failure
    )
    assert "transforms.epss" in project_py.read_text()

    rendered = operations.remove_scaffold(config, "epss")

    assert not isinstance(rendered, operations.Failure), rendered
    assert not (config.project_dir / "transforms" / "epss").exists()
    assert project_py.read_text() == "from transforms.other.lookup import *  # noqa: F401,F403\n"
    assert "restart" in rendered.lower()


def test_remove_scaffold_refuses_a_hand_written_service(config: TransformatronConfig) -> None:
    """remove-scaffold deleted a bundled, hand-written, git-tracked service."""
    service_dir = config.project_dir / "transforms" / "rdap"
    service_dir.mkdir(parents=True)
    (service_dir / "__init__.py").write_text("")
    (service_dir / "api.py").write_text('"""RDAP client, written by hand."""\n')
    project_py = config.project_dir / "project.py"
    project_py.write_text("from transforms.rdap.lookup import *  # noqa: F401,F403\n")

    rendered = operations.remove_scaffold(config, "rdap")

    assert isinstance(rendered, operations.Failure)
    assert rendered.startswith("Failed to remove scaffold: ")
    assert "Generated by transformatron scaffold." in rendered, "the refusal names its reason"
    assert (service_dir / "api.py").exists()
    assert project_py.read_text() == "from transforms.rdap.lookup import *  # noqa: F401,F403\n"


def test_remove_scaffold_of_an_unknown_service_is_a_failure(config: TransformatronConfig) -> None:
    rendered = operations.remove_scaffold(config, "nosuch")

    assert isinstance(rendered, operations.Failure)
    assert rendered.startswith("Failed to remove scaffold: ")


@pytest.mark.parametrize(
    ("argv", "exit_code"),
    [
        (["scaffold", "--list-operations"], 1),
        (["scaffold", "--list-operations", "--curl", _EPSS_CURL], 1),
        (["remove-scaffold", "nosuch"], 1),
        (["scaffold", "--curl", _EPSS_CURL, "--sample-response", _EPSS_SAMPLE, "--dry-run"], 0),
        (["scaffold", "--curl", _EPSS_CURL, "--map", "data[].epss", "--dry-run"], 1),
        # A --primary naming no entity field is refused rather than ignored.
        (
            [
                *["scaffold", "--curl", _EPSS_CURL, "--sample-response", _EPSS_SAMPLE],
                *["--primary", "data[].percentile", "--dry-run"],
            ],
            1,
        ),
    ],
)
def test_cli_scaffold_commands_exit_nonzero_only_on_failure(
    cli: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    exit_code: int,
) -> None:
    (tmp_path / "server").mkdir()

    assert run_cli(monkeypatch, cli, *argv) == exit_code
    assert not (tmp_path / "server" / "transforms").exists(), "none of these may write"


def test_cli_list_operations_reads_an_openapi_file(
    cli: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec_file = tmp_path / "vulns.json"
    spec_file.write_text(json.dumps(_SPEC))

    argv = ["scaffold", "--openapi", str(spec_file), "--list-operations"]
    assert run_cli(monkeypatch, cli, *argv) == 0
    assert "lookup_md5" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("extra", "value"),
    [(["--sample-input", "CVE-2024-3094"], "CVE-2024-3094"), ([], "VALUE")],
)
def test_cli_scaffold_sample_input_is_the_value_an_openapi_transform_is_run_with(
    cli: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
    value: str,
) -> None:
    """An OpenAPI scaffold had no way to be told an input the API answers for."""
    (tmp_path / "server").mkdir()
    spec_file = tmp_path / "vulns.json"
    spec_file.write_text(json.dumps(_SPEC))

    argv = ["scaffold", "--openapi", str(spec_file), "--service", "vulns"]
    argv += ["--operation", "get_cve", *extra, "--dry-run"]
    assert run_cli(monkeypatch, cli, *argv) == 0
    lines = [line.strip() for line in capsys.readouterr().out.splitlines()]

    run_line = (
        "uv run python scripts/transformatron_cli.py run "
        f"acme.new_maltego_integration.vulns_get_cve maltego.CVE {value}"
    )
    assert run_line in lines


def test_list_operations_marks_an_operation_id_the_spec_reuses(
    config: TransformatronConfig,
) -> None:
    """Two operations sharing an id scaffolded under ids the listing did not show."""
    spec = json.loads(json.dumps(_SPEC))
    spec["paths"]["/api/lookup/md5/{md5}"]["get"]["operationId"] = "get_cve"

    rendered = operations.list_operations(config, json.dumps(spec), service="vulns")

    assert not isinstance(rendered, operations.Failure), rendered
    first, second = (
        _row(rendered, path) for path in ("/api/cve/{cve_id}", "/api/lookup/md5/{md5}")
    )
    assert first[2] == second[2] == "get_cve*"
    assert first[3] != second[3], "each must scaffold under its own transform id"
    assert any(line.startswith("* ") for line in rendered.splitlines())
