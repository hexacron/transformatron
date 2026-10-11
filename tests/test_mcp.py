"""Tests for the MCP front end, driven through an in-process MCP client."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp import Client

from transformatron import mcp as mcp_front_end
from transformatron import operations
from transformatron.config import TransformatronConfig


@pytest.fixture(autouse=True)
def empty_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Load config from an empty repository root rather than the real checkout."""
    monkeypatch.setattr("transformatron.config.REPO_ROOT", tmp_path)


def _text(result: object) -> str:
    """Return the text a tool call handed back to the agent."""
    return " ".join(getattr(block, "text", "") for block in getattr(result, "content", []))


async def test_an_unexpected_exception_reaches_the_agent_with_its_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """mcp>=2.1 withholds a crash's text from the client; the agent must still see it.

    Without the cause the agent only learns that the tool failed, and cannot tell a bug
    to report from an input to fix.
    """

    async def broken_status(config: TransformatronConfig) -> str:
        raise RuntimeError("boom: the detail the agent needs")

    monkeypatch.setattr(operations, "status", broken_status)

    async with Client(mcp_front_end.server) as client:
        result = await client.call_tool("server_status", {})

    assert result.is_error
    assert "RuntimeError: boom: the detail the agent needs" in _text(result)


async def test_a_blocking_operation_crash_also_reaches_the_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_seed_url(config: TransformatronConfig) -> str:
        raise KeyError("scheme")

    monkeypatch.setattr(operations, "seed_url", broken_seed_url)

    async with Client(mcp_front_end.server) as client:
        result = await client.call_tool("get_seed_url", {})

    assert result.is_error
    assert "KeyError: 'scheme'" in _text(result)


_EPSS_SAMPLE = {
    "status": "OK",
    "data": [{"cve": "CVE-2021-44228", "epss": "0.943580000", "percentile": "0.999610000"}],
}


@pytest.mark.parametrize("sample", [json.dumps(_EPSS_SAMPLE), _EPSS_SAMPLE])
async def test_a_sample_response_is_accepted_as_json_text_or_as_an_object(
    tmp_path: Path, sample: object
) -> None:
    """The MCP server decodes a JSON string argument before validation.

    The parameter was typed `str | None`, so the decoded dict failed validation and every
    sample response an agent passed as text was rejected before the scaffolder saw it.
    """
    async with Client(mcp_front_end.server) as client:
        result = await client.call_tool(
            "scaffold_transform",
            {
                "service": "epss",
                "curl": "curl 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228'",
                "sample_response": sample,
                "dry_run": True,
            },
        )

    assert not result.is_error, _text(result)
    assert "0.94358" in _text(result), "the sample's fields must reach the inventory"
    assert not (tmp_path / "server" / "transforms").exists()


async def test_an_openapi_document_passed_as_json_text_is_accepted(tmp_path: Path) -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Vulns", "version": "1.0.0"},
        "servers": [{"url": "https://vulns.example"}],
        "paths": {
            "/api/cve/{cve_id}": {
                "get": {
                    "operationId": "get_cve",
                    "parameters": [{"name": "cve_id", "in": "path", "required": True}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }

    async with Client(mcp_front_end.server) as client:
        result = await client.call_tool(
            "scaffold_transform",
            {"service": "vulns", "openapi": json.dumps(spec), "dry_run": True},
        )

    assert not result.is_error, _text(result)
    assert "vulns_get_cve" in _text(result)


async def test_a_numeric_sample_input_reaches_the_scaffold_as_text(tmp_path: Path) -> None:
    """An id like a pet number is what an OpenAPI transform has to be smoke-tested with."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Pets", "version": "1.0.0"},
        "servers": [{"url": "https://pets.example"}],
        "paths": {
            "/pet/{petId}": {
                "get": {
                    "operationId": "getPetById",
                    "parameters": [
                        {"name": "petId", "in": "path", "required": True},
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }

    async with Client(mcp_front_end.server) as client:
        result = await client.call_tool(
            "scaffold_transform",
            {"service": "pets", "openapi": spec, "sample_input": "1", "dry_run": True},
        )

    assert not result.is_error, _text(result)
    assert "sample input: 1" in _text(result)
    assert "run acme.new_maltego_integration.pets_get_pet_by_id " in _text(result)


async def test_list_operations_accepts_a_spec_passed_as_an_object() -> None:
    """scaffold_transform takes an object spec; the tool the docs say to call first must too."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Pets", "version": "1.0.0"},
        "servers": [{"url": "https://pets.example"}],
        "paths": {
            "/pet/{petId}": {
                "get": {
                    "operationId": "getPetById",
                    "parameters": [{"name": "petId", "in": "path", "required": True}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }

    async with Client(mcp_front_end.server) as client:
        result = await client.call_tool("list_operations", {"openapi": spec})

    assert not result.is_error, _text(result)
    assert "getPetById" in _text(result)
