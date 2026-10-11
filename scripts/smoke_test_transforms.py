"""Run every registered transform and fail on the silent-failure cases.

A transform can report ``COMPLETED (success)`` while producing nothing — returning a
``MaltegoGraph`` from an async transform does exactly that, because the SDK drops it.
Transport-level checks (HTTP 200, a run id) do not catch this. This script does, by
asserting that a successful run actually produced entities.

It also flags transforms whose declared output type is empty, which stops the Maltego
client from routing them onto result entities.

Usage:
    uv run python scripts/smoke_test_transforms.py
    uv run python scripts/smoke_test_transforms.py --value 1.1.1.1
    uv run python scripts/smoke_test_transforms.py --transform <fully.qualified.id>
    uv run python scripts/smoke_test_transforms.py --setting API_KEY=xxx

Each transform is run on one sample input. ``--value`` overrides every sample; otherwise a
``samples.json`` beside the transforms (``server/transforms/<service>/samples.json``, a
``{transform_id: input}`` map the scaffolder writes from the request it was given) wins,
then ``TRANSFORM_SAMPLES``, then the per-entity-type ``SAMPLE_VALUES``.

Credentials are read from ``.env`` at the repository root, so a key written there once is
picked up by every run. A key exported in the shell overrides the file, as it does for the
server, and an explicit ``--setting KEY=VALUE`` overrides both for that run. A transform
that still reports a missing setting is recorded as SKIP rather than FAIL, so an
unconfigured credential is never mistaken for broken code.

The server must already be running. Transforms calling third-party APIs make live
network requests, so a failure here can mean an upstream outage rather than broken
transform code — check the reported message before assuming the latter.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from transformatron import lifecycle
from transformatron.client import RunResult, TransformClient, TransformServerError
from transformatron.config import load_config
from transformatron.envfile import load_env_file

# Sample inputs by entity type. Only types with an unambiguous, publicly routable
# sample belong here; anything else is skipped rather than guessed at, so a skip
# never masks itself as a pass.
SAMPLE_VALUES = {
    "maltego.IPv4Address": "8.8.8.8",
    "maltego.IPv6Address": "2001:4860:4860::8888",
    "maltego.Domain": "example.com",
    "maltego.DNSName": "dns.google",
    "maltego.EmailAddress": "test@example.com",
    "maltego.URL": "https://example.com",
    "maltego.Website": "example.com",
    "maltego.Phrase": "example",
    "maltego.AS": "15169",
    "maltego.Netblock": "8.8.8.0/24",
    # Threat-intelligence inputs. A ransomware group name is the closest thing to an
    # unambiguous Malware sample; "lockbit3" is long-established across data sources.
    "maltego.Malware": "lockbit3",
    "maltego.Company": "hospital",
    "maltego.Country": "US",
    # Log4Shell: published, heavily referenced, and scored by every vulnerability feed.
    "maltego.CVE": "CVE-2021-44228",
    # MD5 of the EICAR anti-virus test file, which public hash services all know.
    "maltego.Hash": "44d88612fea8a8f36de82e1278abb02f",
}

# Per-transform input overrides, matched against the end of the transform id.
#
# One sample per entity type cannot suit every transform: a `Company` sample that
# exercises a search is a substring, while a lookup needs a full organisation name,
# and not every ransomware group has every kind of intelligence attached. Without
# these, a transform that works correctly reports FAIL on an unsuitable sample —
# which trains people to ignore the gate.
TRANSFORM_SAMPLES = {
    # These need a group with published TTPs and CVEs; lockbit3 has neither.
    "group_to_cves": "akira",
    "group_to_ttps": "akira",
    # Matches group names as a substring, so the generic Phrase sample finds nothing.
    "list_groups": "lock",
    # CrowdSec only holds attack data for addresses it has seen reported. The generic
    # 8.8.8.8 sample is a resolver with an "unknown" reputation, so the behaviour and
    # target-country transforms legitimately return nothing for it. This address was
    # reported with several behaviours and a full target-country spread; if it ages
    # out of the dataset these turn into no-match SKIPs, so re-pin it from a current
    # CrowdSec listing rather than treating the skip as a defect.
    "crowdsec_ip_reputation": "141.98.11.30",
    "crowdsec_ip_to_behaviour": "141.98.11.30",
    "crowdsec_ip_to_network": "141.98.11.30",
    "crowdsec_ip_to_location": "141.98.11.30",
    "crowdsec_ip_to_targets": "141.98.11.30",
    # GreyNoise returns a verdict for any routable IPv4, so these do not strictly need a
    # sample of their own. This one is pinned to an address confirmed to be actively
    # scanning, so a pass exercises the populated branch — classification, actor and
    # Visualizer link — rather than only the "not observed" path the generic 8.8.8.8
    # sample takes. If it ages out of the dataset the transform still passes on the
    # negative verdict; re-pin from a current GreyNoise listing to keep the coverage.
    "greynoise_ip_reputation": "185.220.101.1",
    # example.com is registered through IANA's reserved-name process and its registrar
    # publishes no abuse contact, so the generic sample makes this transform look broken.
    # python.org is registered through Gandi, which publishes both an abuse address and a
    # phone number, exercising the populated branch of the jCard walk.
    "rdap_domain_to_abuse_contact": "python.org",
}

# A transform reporting one of these is unconfigured, not broken. Matched
# case-insensitively against the run's status messages.
MISSING_SETTING_MARKERS = (
    "api key configured",
    "no api key",
    "api token configured",
    "missing setting",
)

# A transform reporting one of these was throttled by the upstream API before it could
# answer. The gate runs every transform back to back, which trips free-tier quotas that
# ordinary interactive use never would, so this says nothing about the code. Reported
# SKIP rather than FAIL: re-run the affected transform on its own to judge it.
RATE_LIMIT_MARKERS = ("rate limited", "too many requests", "(429)")

# A transform reporting one of these was refused because the account behind its key has
# run out of credits: the SDK's IntegrationClient reports an upstream 402 as "payment
# required / credits exhausted (402)". Like a rate limit, a fact about the account rather
# than the code, so SKIP.
QUOTA_MARKERS = ("(402)", "credits exhausted")

# A transform reporting one of these ran correctly but had nothing to return for the
# sample input. Distinct from a silent failure, which produces no message at all.
NO_MATCH_MARKERS = (
    # What every scaffolded transform reports when its upstream answers 404 (the
    # generator's fetch in transformatron/scaffold/generator.py).
    "has no record for the requested input",
    "no exact victim match",
    "no press coverage",
    "no leak site listing",
    # ransomware.live answers 404 for an input it holds nothing on. The victim transforms
    # now stop at that message instead of adding a "no match" line after it.
    "no ransomware.live record",
    # A private or reserved address has no public routing data to return.
    "bogon",
    # CrowdSec holds data only for addresses it has seen reported. When the pinned
    # TRANSFORM_SAMPLES address ages out, these are what its transforms report.
    "no cti record",
    "no attack behaviour",
    "no targeted countries",
)

# A transform reporting one of these rejected the sample input before making a request.
# Distinct from a no-match: the transform is fine and the *sample* is unsuitable, which
# happens when one entity type covers several input formats — a Phrase sample cannot be
# both a search query and an opaque id. Reported SKIP with a pointer at the sample tables.
INVALID_SAMPLE_MARKERS = ("invalid input",)

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


@dataclass
class Outcome:
    """Result of smoke-testing one transform."""

    transform_id: str
    status: str
    detail: str


# The fix a transform with an empty output type needs. Only a missing return annotation
# registers that way: a bare `-> list` does not register at all, because the SDK rejects
# it while loading the module (blaming input_entity), so the server never starts.
NO_OUTPUT_TYPE_DETAIL = (
    "declares no output type, so the Maltego client cannot route its results — it has no "
    "return annotation; add one naming the entity types, e.g. '-> list[Domain]'"
)


def _type_ids(spec: Any) -> list[str]:
    """Return the entity type ids from a discovery input/output spec."""
    if not isinstance(spec, dict):
        return []
    type_ids = spec.get("typeIds")
    return [str(t) for t in type_ids] if isinstance(type_ids, list) else []


def load_transform_samples(transforms_dir: Path) -> dict[str, str]:
    """Collect the ``{transform_id: input}`` maps from every ``samples.json`` under a tree.

    The scaffolder records the input it saw in the cURL command or spec example there, so
    a generated transform is exercised on a value its API is known to answer for, not on
    a generic sample such as ``example`` that it has no record of. Files are read in path
    order and the first file naming a transform id wins, so the result does not depend on
    directory listing order. A file that cannot be used is reported and skipped: one bad
    file should cost its own samples, not the whole gate.
    """
    samples: dict[str, str] = {}
    for path in sorted(transforms_dir.rglob("samples.json")):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            print(f"Ignoring {path}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            print(f"Ignoring {path}: expected an object of transform id to input", file=sys.stderr)
            continue
        for transform_id, value in data.items():
            if isinstance(value, str) and value:
                samples.setdefault(str(transform_id), value)
    return samples


def _sample_for(transform_id: str, samples: dict[str, str]) -> str | None:
    """Return the sample keyed by `transform_id`'s last segment (or the full id), if any."""
    for suffix, value in samples.items():
        if transform_id.endswith(f".{suffix}") or transform_id == suffix:
            return value
    return None


def pick_input(
    transform: dict[str, Any], override: str | None, file_samples: dict[str, str] | None = None
) -> tuple[str, str] | None:
    """Return the (entity_type, value) to exercise a transform, or None if unknown.

    Precedence: an explicit ``--value``, then the transform's ``samples.json`` entry, then
    ``TRANSFORM_SAMPLES``, then the ``SAMPLE_VALUES`` default for its input type.
    """
    transform_id = str(transform.get("name", ""))
    sample = (
        override
        if override is not None
        else _sample_for(transform_id, file_samples or {})
        or _sample_for(transform_id, TRANSFORM_SAMPLES)
    )
    for type_id in _type_ids(transform.get("input")):
        value = sample if sample is not None else SAMPLE_VALUES.get(type_id)
        if value is not None:
            return type_id, value
    return None


def _matches(messages: list[str], markers: tuple[str, ...]) -> bool:
    """Return True when any marker appears in the run's status messages."""
    joined = " ".join(messages).lower()
    return any(marker in joined for marker in markers)


def classify_run(transform_id: str, entity_type: str, value: str, result: RunResult) -> Outcome:
    """Classify a finished run of `transform_id` on `entity_type`=`value`."""
    messages = "; ".join(result.messages) if result.messages else "no messages"
    if not result.succeeded:
        return Outcome(transform_id, FAIL, f"state {result.state} ({messages})")
    if result.entities:
        return Outcome(transform_id, PASS, f"{len(result.entities)} entities from {value}")

    # An unconfigured credential is a gap in this run, not a defect in the
    # transform. Reporting it as FAIL would train people to ignore failures.
    if _matches(result.messages, MISSING_SETTING_MARKERS):
        return Outcome(
            transform_id,
            SKIP,
            f"needs a credential — pass it with --setting to exercise this ({messages})",
        )
    # Throttled before it could answer. Running every transform back to back trips
    # free-tier quotas that interactive use never would, so this is a fact about
    # the run, not the code.
    if _matches(result.messages, RATE_LIMIT_MARKERS):
        return Outcome(
            transform_id,
            SKIP,
            f"upstream rate limit ({messages}) — re-run this transform on its own to judge it",
        )
    if _matches(result.messages, QUOTA_MARKERS):
        return Outcome(
            transform_id,
            SKIP,
            f"upstream credits exhausted ({messages}) — top up or use another key to judge it",
        )
    # The transform rejected the sample before calling upstream. The code is fine;
    # the sample does not fit this transform's input format.
    if _matches(result.messages, INVALID_SAMPLE_MARKERS):
        return Outcome(
            transform_id,
            SKIP,
            f"sample input does not fit this transform ({messages}) — "
            f"add a samples.json or TRANSFORM_SAMPLES entry to exercise it",
        )
    # The transform ran and said, explicitly, that this input has no results.
    # That is honest behaviour, not the silent empty return this gate hunts for.
    if _matches(result.messages, NO_MATCH_MARKERS):
        return Outcome(
            transform_id,
            SKIP,
            f"no upstream match for the sample input ({messages}) — "
            f"add a samples.json or TRANSFORM_SAMPLES entry to exercise it",
        )
    # A run that logged an error still ends COMPLETED: a transform reporting an upstream
    # 403 or 500 through context.log.fatal returns normally. The error is the finding.
    errors = [
        text
        for text, level in zip(result.messages, result.message_levels, strict=False)
        if level == "ERROR"
    ]
    if errors:
        return Outcome(
            transform_id,
            FAIL,
            f"error with no entities for {entity_type}={value}: {'; '.join(errors)}",
        )
    if not result.messages:
        # Nothing at all: the silent failure this gate exists for. The SDK drops a
        # MaltegoGraph returned from an async transform without a word.
        return Outcome(
            transform_id,
            FAIL,
            f"reported {result.state} but returned no entities and no message for "
            f"{entity_type}={value} — if it returns a MaltegoGraph, return a list instead",
        )
    return Outcome(
        transform_id,
        FAIL,
        f"reported {result.state} but returned no entities for {entity_type}={value} "
        f"({messages}) — no message names an error or a known no-match, so check how the "
        "response is mapped",
    )


async def check_transform(
    client: TransformClient,
    transform: dict[str, Any],
    override: str | None,
    timeout: float,
    settings: dict[str, str] | None = None,
    file_samples: dict[str, str] | None = None,
) -> Outcome:
    """Run one transform and classify the result."""
    transform_id = str(transform.get("name", "<unnamed>"))

    if not _type_ids(transform.get("output")):
        return Outcome(transform_id, FAIL, NO_OUTPUT_TYPE_DETAIL)

    chosen = pick_input(transform, override, file_samples)
    if chosen is None:
        inputs = ", ".join(_type_ids(transform.get("input"))) or "none declared"
        return Outcome(transform_id, SKIP, f"no sample value for input type ({inputs})")

    entity_type, value = chosen
    try:
        result = await client.run_transform(transform_id, entity_type, value, settings, timeout)
    except TransformServerError as exc:
        return Outcome(transform_id, FAIL, f"run failed: {exc}")
    return classify_run(transform_id, entity_type, value, result)


def parse_settings(pairs: list[str] | None) -> dict[str, str] | None:
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


async def run(
    override: str | None,
    only: str | None,
    timeout: float,
    settings: dict[str, str] | None = None,
) -> int:
    """Smoke-test the registered transforms and return a process exit code."""
    config = lifecycle.resolve_config(load_config())
    client = TransformClient(config)

    # Credentials from .env are passed as transform settings so credential-gated
    # transforms are actually exercised rather than reported SKIP. A key exported in the
    # shell beats the file, the same precedence lifecycle.build_server_env gives the
    # server; otherwise a stale .env value would be sent as a setting, which transforms
    # read before the environment. An explicit --setting wins over both.
    merged_settings = {
        key: os.environ.get(key, value) for key, value in load_env_file(config.env_file).items()
    }
    merged_settings.update(settings or {})
    settings = merged_settings or None

    try:
        transforms = await client.list_transforms()
    except TransformServerError as exc:
        print(f"Could not reach the server at {config.base_url}: {exc}", file=sys.stderr)
        print("Start it first (server_start), then re-run.", file=sys.stderr)
        return 2

    if only is not None:
        transforms = [t for t in transforms if t.get("name") == only]
        if not transforms:
            print(f"No transform named {only}.", file=sys.stderr)
            return 2

    if not transforms:
        print("The server advertises no transforms — nothing to check.")
        return 0

    file_samples = load_transform_samples(config.project_dir / "transforms")
    print(f"Checking {len(transforms)} transforms against {config.base_url}\n")
    outcomes = [
        await check_transform(client, t, override, timeout, settings, file_samples)
        for t in transforms
    ]

    for outcome in outcomes:
        print(f"  {outcome.status:<4} {outcome.transform_id}\n       {outcome.detail}")

    failed = [o for o in outcomes if o.status == FAIL]
    skipped = [o for o in outcomes if o.status == SKIP]
    passed = [o for o in outcomes if o.status == PASS]
    print(f"\n{len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--value", help="Input value to use instead of the built-in samples")
    parser.add_argument("--transform", help="Check only this fully qualified transform id")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-run timeout in seconds")
    parser.add_argument(
        "--setting",
        action="append",
        metavar="KEY=VALUE",
        help="Transform setting, e.g. an API key. Repeatable.",
    )
    args = parser.parse_args()
    return asyncio.run(run(args.value, args.transform, args.timeout, parse_settings(args.setting)))


if __name__ == "__main__":
    raise SystemExit(main())
