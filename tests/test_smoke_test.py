"""Tests for the smoke test's input selection and run classification."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from transformatron.client import RunResult

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "smoke_test_transforms.py"


@pytest.fixture(scope="module")
def smoke() -> ModuleType:
    spec = importlib.util.spec_from_file_location("smoke_test_transforms", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # @dataclass looks its module up in sys.modules while the class is being built.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


class FakeClient:
    """Stands in for the transform server: records each run and answers with ``result``."""

    def __init__(self, result: RunResult) -> None:
        self.result = result
        self.runs: list[tuple[str, str, str]] = []

    async def run_transform(
        self,
        transform_id: str,
        entity_type: str,
        value: str,
        settings: dict[str, str] | None,
        timeout: float,
    ) -> RunResult:
        self.runs.append((transform_id, entity_type, value))
        return self.result


def _transform(name: str, input_type: str = "maltego.Phrase") -> dict[str, Any]:
    """A discovery entry as /api/v3/transforms lists it."""
    return {
        "name": name,
        "input": {"typeIds": [input_type]},
        "output": {"typeIds": ["maltego.Phrase"]},
    }


def _run(*messages: tuple[str, str], entities: int = 0, state: str = "COMPLETED") -> RunResult:
    result = RunResult(run_id="run", state=state)
    result.entities = [{"type": "maltego.Phrase", "value": str(i)} for i in range(entities)]
    for level, text in messages:
        result.add_message(text, level)
    return result


async def _check(
    smoke: ModuleType,
    result: RunResult,
    transform: dict[str, Any] | None = None,
    override: str | None = None,
    file_samples: dict[str, str] | None = None,
) -> tuple[Any, FakeClient]:
    client = FakeClient(result)
    outcome = await smoke.check_transform(
        client,
        transform or _transform("acme.ns.svc_lookup"),
        override,
        5.0,
        None,
        file_samples,
    )
    return outcome, client


def _write_samples(transforms_dir: Path, service: str, samples: dict[str, str]) -> None:
    (transforms_dir / service).mkdir(parents=True)
    (transforms_dir / service / "samples.json").write_text(json.dumps(samples))


async def test_scaffolded_sample_is_used_over_the_type_default(
    smoke: ModuleType, tmp_path: Path
) -> None:
    """A generated transform must run on the input its API answered for, not 'example'."""
    _write_samples(tmp_path, "mitre", {"mitre_lookup": "CVE-2023-4863"})
    samples = smoke.load_transform_samples(tmp_path)

    _, client = await _check(
        smoke,
        _run(entities=1),
        _transform("acme.ns.mitre_lookup", "maltego.CVE"),
        file_samples=samples,
    )

    assert client.runs == [("acme.ns.mitre_lookup", "maltego.CVE", "CVE-2023-4863")]


async def test_scaffolded_sample_outranks_the_curated_table(
    smoke: ModuleType, tmp_path: Path
) -> None:
    """The author's samples.json sits beside the transform, so it wins over the script's pins."""
    _write_samples(tmp_path, "rdap", {"rdap_domain_to_abuse_contact": "gandi.net"})

    _, client = await _check(
        smoke,
        _run(entities=1),
        _transform("acme.ns.rdap_domain_to_abuse_contact", "maltego.Domain"),
        file_samples=smoke.load_transform_samples(tmp_path),
    )

    assert client.runs[0][2] == "gandi.net"


async def test_explicit_value_outranks_samples_json(smoke: ModuleType, tmp_path: Path) -> None:
    _write_samples(tmp_path, "svc", {"svc_lookup": "from-file"})

    _, client = await _check(
        smoke,
        _run(entities=1),
        override="from-cli",
        file_samples=smoke.load_transform_samples(tmp_path),
    )

    assert client.runs[0][2] == "from-cli"


async def test_samples_json_only_matches_whole_transform_ids(
    smoke: ModuleType, tmp_path: Path
) -> None:
    """`lookup` must not hijack `svc_lookup`: ids are matched on their last dotted segment."""
    _write_samples(tmp_path, "other", {"lookup": "wrong"})

    _, client = await _check(
        smoke, _run(entities=1), file_samples=smoke.load_transform_samples(tmp_path)
    )

    assert client.runs[0][2] == smoke.SAMPLE_VALUES["maltego.Phrase"]


def test_an_unreadable_samples_file_costs_only_its_own_samples(
    smoke: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "samples.json").write_text("{not json")
    _write_samples(tmp_path, "good", {"good_lookup": "8.8.4.4"})

    samples = smoke.load_transform_samples(tmp_path)

    assert samples == {"good_lookup": "8.8.4.4"}
    assert "broken" in capsys.readouterr().err


@pytest.mark.parametrize("input_type", ["maltego.CVE", "maltego.Hash"], ids=["cve", "hash"])
async def test_vulnerability_and_hash_inputs_have_defaults(
    smoke: ModuleType, input_type: str
) -> None:
    """Scaffolded CVE and hash lookups must be exercised, not skipped for want of a sample."""
    outcome, client = await _check(smoke, _run(entities=1), _transform("acme.ns.x", input_type))

    assert outcome.status == smoke.PASS
    assert client.runs[0][1:] == (input_type, smoke.SAMPLE_VALUES[input_type])


@pytest.mark.parametrize(
    ("level", "message", "reason"),
    [
        (
            "ERROR",
            "No crtsh API key configured. Enter it in Maltego Graph Desktop.",
            "needs a credential",
        ),
        ("ERROR", "crtsh lookup failed: rate limited (429)", "rate limit"),
        (
            "ERROR",
            "crtsh lookup failed: payment required / credits exhausted (402)",
            "credits exhausted",
        ),
        ("ERROR", "Invalid input: expected a CVE id", "does not fit"),
        ("INFO", "crtsh has no record for the requested input", "no upstream match"),
        ("INFO", "No CTI record for 8.8.8.8", "no upstream match"),
    ],
    ids=["missing-setting", "rate-limit", "credits-402", "invalid-sample", "generator-404", "cti"],
)
async def test_known_causes_of_an_empty_run_are_skips(
    smoke: ModuleType, level: str, message: str, reason: str
) -> None:
    """An empty run that names an environmental cause says nothing about the code."""
    outcome, _ = await _check(smoke, _run((level, message)))

    assert outcome.status == smoke.SKIP
    assert reason in outcome.detail
    assert message in outcome.detail


async def test_an_error_with_no_entities_fails_with_the_error(smoke: ModuleType) -> None:
    """An upstream 403 ends COMPLETED; the gate must surface it, not blame a MaltegoGraph."""
    outcome, _ = await _check(
        smoke,
        _run(
            ("INFO", "Querying SEC EDGAR"),
            ("ERROR", "sec lookup failed: API access forbidden (403)"),
        ),
    )

    assert outcome.status == smoke.FAIL
    assert "API access forbidden (403)" in outcome.detail
    assert "MaltegoGraph" not in outcome.detail


async def test_a_silent_empty_run_gets_the_maltegograph_hint(smoke: ModuleType) -> None:
    outcome, _ = await _check(smoke, _run())

    assert outcome.status == smoke.FAIL
    assert "MaltegoGraph" in outcome.detail


async def test_an_empty_run_with_only_informational_messages_gets_no_hint(
    smoke: ModuleType,
) -> None:
    """The transform spoke, so it did not return a dropped graph; the hint would mislead."""
    message = "svc returned no mapped entities for this input"
    outcome, _ = await _check(smoke, _run(("INFO", message)))

    assert outcome.status == smoke.FAIL
    assert message in outcome.detail
    assert "MaltegoGraph" not in outcome.detail


async def test_a_transform_without_output_types_fails_without_running(
    smoke: ModuleType,
) -> None:
    """The client cannot route an untyped transform's results, whatever a run returns."""
    transform = {"name": "acme.ns.untyped", "input": {"typeIds": ["maltego.Phrase"]}}
    transform["output"] = {"typeIds": []}

    outcome, client = await _check(smoke, _run(entities=3), transform)

    assert outcome.status == smoke.FAIL
    assert "return annotation" in outcome.detail
    assert client.runs == []
