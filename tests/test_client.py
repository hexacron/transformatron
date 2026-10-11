"""Tests for the v3 protocol client, especially the run/poll state machine."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from transformatron.client import (
    RunResult,
    TransformClient,
    TransformNotFoundError,
    TransformServerError,
    build_run_request,
    collect_events,
)
from transformatron.config import TransformatronConfig


def entity_event(value: str, event_type: str = "ADD") -> dict[str, Any]:
    # The SDK gives every entity an id; the value doubles as one here so each is distinct.
    return {
        "data": {
            "inputType": "ENTITY",
            "eventType": event_type,
            "entity": {"id": value, "type": "maltego.Phrase", "value": value},
        }
    }


def entity_update_event(entity_id: str, **fields: Any) -> dict[str, Any]:
    """An UPDATE as ``to_v3_run_entity_update`` sends it: the id plus only what changed."""
    return {
        "data": {
            "inputType": "ENTITY",
            "eventType": "UPDATE",
            "entity": {"id": entity_id, **fields},
        }
    }


def delete_event(input_type: str, item_id: str) -> dict[str, Any]:
    """A DELETE as the SDK sends it: only the id of the entity or link being retracted."""
    key = "entity" if input_type == "ENTITY" else "link"
    return {"data": {"inputType": input_type, "eventType": "DELETE", key: {"id": item_id}}}


def status_event(text: str, level: str | None = None) -> dict[str, Any]:
    """A status message as ``TransformMessageEvent.to_v3_event`` sends it.

    ``level`` is the StatusMessage ``type``; None leaves it out, as the protocol allows.
    """
    status: dict[str, Any] = {"text": text}
    if level is not None:
        status["type"] = level
    return {
        "data": {
            "inputType": "STATUS_MESSAGE",
            "eventType": "ADD",
            "statusMessage": status,
        }
    }


class FakeServer:
    """Scripts a sequence of poll responses for one transform run.

    Models the real server's two relevant behaviours: it serves events from the
    ``eventPointer`` the client asks for, and it caps a single response at ``page_size``
    events while reporting the true total in ``eventCount``. A fake that ignored the pointer
    let a client that never paged look correct — that is how truncation at 25 entities went
    unnoticed.
    """

    def __init__(
        self,
        poll_responses: list[dict[str, Any]],
        run_id: str = "run-1",
        page_size: int = 50,
    ) -> None:
        self._poll_responses = poll_responses
        self._run_id = run_id
        self._page_size = page_size
        self.polls = 0
        self.cancelled = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/cancel"):
            self.cancelled = True
            return httpx.Response(200, json={})
        if request.method == "POST":
            return httpx.Response(201, json={"result": {"runId": self._run_id, "state": "RUNNING"}})

        index = min(self.polls, len(self._poll_responses) - 1)
        self.polls += 1
        response = self._poll_responses[index]

        run = dict(response.get("result", {}))
        events = list(run.get("events", []) or [])
        pointer = int(request.url.params.get("eventPointer", 0))
        run["eventCount"] = len(events)
        run["events"] = events[pointer : pointer + self._page_size]
        return httpx.Response(201, json={**response, "result": run})


@pytest.fixture
def config(tmp_path) -> TransformatronConfig:
    return TransformatronConfig(project_dir=tmp_path, state_dir=tmp_path / "state")


def patch_handler(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Route the client's httpx calls to ``handler``.

    Binds the original ``AsyncClient`` before patching; referring to
    ``httpx.AsyncClient`` inside the replacement would recurse.
    """
    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient

    def build(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", build)


def patch_transport(monkeypatch: pytest.MonkeyPatch, fake: FakeServer) -> None:
    """Route the client's httpx calls to the fake server."""
    patch_handler(monkeypatch, fake.handler)


def test_build_run_request_carries_entity_and_settings() -> None:
    body = build_run_request("maltego.Domain", "example.com", {"api_key": "secret"})
    entity = body["input"]["graph"]["entities"][0]
    assert entity["type"] == "maltego.Domain"
    assert entity["properties"][0]["value"] == "example.com"
    # valueRef must name a property that actually exists on the entity.
    assert entity["valueRef"] == entity["properties"][0]["name"]
    assert body["transformSettings"] == [{"name": "api_key", "value": "secret"}]
    assert body["input"]["metadata"]["entitiesTypesStat"] == {"maltego.Domain": 1}


def test_collect_events_sorts_by_type() -> None:
    result = RunResult(run_id="r", state="RUNNING")
    collect_events(
        [
            entity_event("keep"),
            {"data": {"inputType": "LINK", "eventType": "ADD", "link": {"id": "l1"}}},
            status_event("working"),
        ],
        result,
    )
    assert [e["value"] for e in result.entities] == ["keep"]
    assert len(result.links) == 1
    assert result.messages == ["working"]


def test_each_message_keeps_its_severity() -> None:
    """An upstream 403 logged with log.fatal must be told apart from an informational note.

    Both runs end COMPLETED, so the severity is the only signal; a message without a type
    is INFO, the protocol's default.
    """
    result = RunResult(run_id="r", state="RUNNING")
    collect_events(
        [
            status_event("API access forbidden (403)", "ERROR"),
            status_event("Only partial results", "WARNING"),
            status_event("No record for this input"),
        ],
        result,
    )

    assert result.messages == [
        "API access forbidden (403)",
        "Only partial results",
        "No record for this input",
    ]
    assert result.message_levels == ["ERROR", "WARNING", "INFO"]


def test_an_event_without_an_event_type_is_an_add() -> None:
    """``eventType`` defaults to ADD in the SDK model, so an omitted one still adds."""
    result = RunResult(run_id="r", state="RUNNING")
    collect_events([{"data": {"inputType": "ENTITY", "entity": {"id": "e1"}}}], result)
    assert result.entities == [{"id": "e1"}]


def test_an_update_edits_the_entity_instead_of_adding_another() -> None:
    """A transform that sets a property after add_entity must still count as one entity."""
    result = RunResult(run_id="r", state="RUNNING")
    added = entity_event("e1")
    added["data"]["entity"]["properties"] = [
        {"name": "value", "type": "STRING", "value": "e1"},
        {"name": "country", "type": "STRING", "value": "??"},
    ]
    collect_events(
        [
            added,
            entity_update_event(
                "e1",
                properties=[
                    {"name": "country", "type": "STRING", "value": "NL"},
                    {"name": "asn", "type": "STRING", "value": "AS1"},
                ],
                note="checked",
                displayInformation=[{"name": "Seen", "value": "today", "type": "text/plain"}],
            ),
        ],
        result,
    )

    assert len(result.entities) == 1
    entity = result.entities[0]
    assert {p["name"]: p["value"] for p in entity["properties"]} == {
        "value": "e1",
        "country": "NL",
        "asn": "AS1",
    }
    assert entity["note"] == "checked"
    assert [d["name"] for d in entity["displayInformation"]] == ["Seen"]
    assert entity["type"] == "maltego.Phrase", "fields the update did not carry must survive"


def test_an_update_for_an_entity_never_added_is_not_output() -> None:
    """Editing the input entity emits an UPDATE for an id this run never returned."""
    result = RunResult(run_id="r", state="RUNNING")
    collect_events([entity_event("e1"), entity_update_event("0", note="input")], result)
    assert [e["id"] for e in result.entities] == ["e1"]


def test_a_delete_retracts_what_an_earlier_poll_collected() -> None:
    result = RunResult(run_id="r", state="RUNNING")
    collect_events(
        [
            entity_event("e1"),
            entity_event("e2"),
            {"data": {"inputType": "LINK", "eventType": "ADD", "link": {"id": "l1"}}},
        ],
        result,
    )
    collect_events([delete_event("ENTITY", "e1"), delete_event("LINK", "l1")], result)

    assert [e["id"] for e in result.entities] == ["e2"]
    assert result.links == []


@pytest.mark.parametrize("terminal_state", ["COMPLETED", "FINISHED"])
async def test_both_success_states_terminate_the_poll_loop(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch, terminal_state: str
) -> None:
    """The SDK reports success as either COMPLETED or FINISHED; both must end polling."""
    fake = FakeServer(
        [
            {"result": {"state": "RUNNING", "events": []}},
            {"result": {"state": terminal_state, "events": [entity_event("found")]}},
        ]
    )
    patch_transport(monkeypatch, fake)

    result = await TransformClient(config).run_transform("t", "maltego.Phrase", "x", timeout=5)

    assert result.state == terminal_state
    assert result.succeeded
    assert [e["value"] for e in result.entities] == ["found"]


async def test_failed_run_surfaces_its_status_message(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeServer(
        [{"result": {"state": "FAILED", "events": [status_event("Invalid input: boom")]}}]
    )
    patch_transport(monkeypatch, fake)

    result = await TransformClient(config).run_transform("t", "maltego.Phrase", "x", timeout=5)

    assert result.state == "FAILED"
    assert not result.succeeded
    assert "Invalid input: boom" in result.messages


async def test_a_message_pushed_just_after_failure_is_still_collected(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SDK sets FAILED before it pushes the message explaining the crash.

    A poll landing between the two saw FAILED with no message, so the run reported a
    failure with no reason at all.
    """
    crash = status_event("Unexpected exception while executing transform Demo", "ERROR")
    fake = FakeServer(
        [
            {"result": {"state": "FAILED", "events": []}},
            {"result": {"state": "FAILED", "events": [crash]}},
        ]
    )
    patch_transport(monkeypatch, fake)

    result = await TransformClient(config).run_transform("t", "maltego.Phrase", "x", timeout=5)

    assert result.messages == ["Unexpected exception while executing transform Demo"]
    assert result.message_levels == ["ERROR"]


async def test_events_are_not_double_counted_across_polls(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server replays the whole event list each poll, so only new events count."""
    first = entity_event("one")
    second = entity_event("two")
    fake = FakeServer(
        [
            {"result": {"state": "RUNNING", "events": [first]}},
            {"result": {"state": "COMPLETED", "events": [first, second]}},
        ]
    )
    patch_transport(monkeypatch, fake)

    result = await TransformClient(config).run_transform("t", "maltego.Phrase", "x", timeout=5)

    assert [e["value"] for e in result.entities] == ["one", "two"]


async def test_a_poll_with_no_new_events_does_not_rewind_the_pointer(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow run that produces nothing between polls must not re-deliver what it already sent.

    `seen` is an absolute offset and the fetch already pages to eventCount, so after a poll
    that returns events the offset and the page length agree — that is why most scenarios
    survive either `seen += len(events)` or `seen = len(events)`. They part company when a
    poll returns *zero* new events, which is the ordinary case for a transform still working:
    the overwriting form resets the pointer to 0 and the next poll re-reads the run from the
    start, duplicating every entity collected so far.
    """
    batch = [entity_event(f"e{i}") for i in range(3)]
    fake = FakeServer(
        [
            {"result": {"state": "RUNNING", "events": batch}},
            # Still working, nothing new since the last poll.
            {"result": {"state": "RUNNING", "events": batch}},
            {"result": {"state": "COMPLETED", "events": batch}},
        ]
    )
    patch_transport(monkeypatch, fake)

    result = await TransformClient(config).run_transform("t", "maltego.Phrase", "x", timeout=5)

    assert [e["value"] for e in result.entities] == ["e0", "e1", "e2"]


async def test_entities_beyond_one_page_are_collected(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run larger than one page is read to the end rather than truncated.

    The results endpoint answers with at most a page of events and reports the true total in
    eventCount. Reading only the first response silently dropped everything past it: a
    transform returning 50 entities was reported as returning 25, with the run still marked
    COMPLETED (success).
    """
    events = [entity_event(f"e{i:03d}") for i in range(120)]
    fake = FakeServer([{"result": {"state": "COMPLETED", "events": events}}], page_size=50)
    patch_transport(monkeypatch, fake)

    result = await TransformClient(config).run_transform("t", "maltego.Phrase", "x", timeout=5)

    assert len(result.entities) == 120
    assert [e["value"] for e in result.entities] == [f"e{i:03d}" for i in range(120)]


async def test_timeout_cancels_the_run_server_side(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeServer([{"result": {"state": "RUNNING", "events": []}}])
    patch_transport(monkeypatch, fake)

    result = await TransformClient(config).run_transform("t", "maltego.Phrase", "x", timeout=0.01)

    assert result.state == "TIMED_OUT"
    assert not result.succeeded
    assert fake.cancelled, "a run abandoned by the client must be cancelled server-side"
    assert result.message_levels == ["ERROR"], "the client's own timeout note is an error"


async def test_missing_run_id_is_an_error(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"result": {}})

    patch_handler(monkeypatch, handler)

    with pytest.raises(TransformServerError, match="no runId"):
        await TransformClient(config).run_transform("t", "maltego.Phrase", "x")


async def test_unreachable_server_explains_how_to_start_it(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    patch_handler(monkeypatch, handler)

    with pytest.raises(TransformServerError, match="server_start"):
        await TransformClient(config).list_transforms()


async def test_http_error_status_is_reported(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="no such transform")

    patch_handler(monkeypatch, handler)

    with pytest.raises(TransformServerError, match="404"):
        await TransformClient(config).get_transform("missing")


@pytest.mark.parametrize("lost", ["transform", "run"])
async def test_an_unknown_transform_id_is_told_apart_from_an_unknown_run(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch, lost: str
) -> None:
    """Only an unknown transform id may earn a 'check the id' hint; a lost run must not."""

    def handler(request: httpx.Request) -> httpx.Response:
        if lost == "run" and request.url.path.endswith("/run"):
            return httpx.Response(201, json={"result": {"runId": "r1"}})
        detail = "Transform with id t not found" if lost == "transform" else "Run not found"
        return httpx.Response(404, json={"detail": detail})

    patch_handler(monkeypatch, handler)

    with pytest.raises(TransformServerError) as raised:
        await TransformClient(config).run_transform("t", "maltego.Phrase", "x")
    assert isinstance(raised.value, TransformNotFoundError) is (lost == "transform")
    assert raised.value.status_code == 404


async def test_a_non_json_response_is_a_server_error(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another service on the port answers with HTML; that must not surface as a traceback."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not a transform server</html>")

    patch_handler(monkeypatch, handler)

    with pytest.raises(TransformServerError, match="not JSON: <html>not a transform server"):
        await TransformClient(config).list_transforms()
