"""Async client for the Maltego v3 transform protocol.

Route and payload shapes are taken from the SDK's own protocol definitions
(``maltego/server/v3/__init__.py``) and the reference documented in the shipped
``maltego-transform-test`` skill.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

import httpx

from transformatron.config import TransformatronConfig

# From maltego/protocol/v3/execution/transform_run.py. The SDK defines both
# COMPLETED and FINISHED as distinct successful end states; treating only one as
# terminal would poll forever against a server that reports the other.
SUCCESS_STATES = frozenset({"COMPLETED", "FINISHED"})
FAILURE_STATES = frozenset({"FAILED", "CANCELED", "TIMED_OUT"})
TERMINAL_STATES = SUCCESS_STATES | FAILURE_STATES

DEFAULT_RUN_TIMEOUT = 60.0
POLL_INTERVAL = 0.5

# A status message's ``type``, per ``StatusMessage`` in
# maltego/protocol/v3/execution/transform_run.py:42-43, is one of INFO, WARNING, ERROR, or
# DEBUG, defaulting to INFO. maltego/model/event.py:60-65 maps the transform's
# ``context.log`` calls onto it (maltego/model/context.py:161-171): ``inform`` -> INFO,
# ``partial`` -> WARNING, ``fatal`` -> ERROR, ``debug`` -> DEBUG. A raised MaltegoException
# is emitted as a FatalError, so ERROR too (maltego/runner/transform_result_set.py:123-124).
# The level is what tells an upstream 403 logged with ``fatal`` apart from an informational
# "no record", since both runs still end COMPLETED.
DEFAULT_MESSAGE_LEVEL = "INFO"


class TransformServerError(RuntimeError):
    """Raised when the transform server is unreachable or returns an error."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        # The HTTP status the server answered with; None when no answer arrived.
        self.status_code = status_code


class TransformNotFoundError(TransformServerError):
    """Raised when the server has no transform with the requested id.

    A separate type so a front end can tell the caller how to find the right id: the most
    common cause is a short id without the namespace, or a transform added since the server
    started.
    """


async def _not_found_as_unknown_transform(request: Coroutine[Any, Any, Any]) -> Any:
    """Await a request on a transform route, raising a 404 as TransformNotFoundError.

    The transform detail and run-start routes answer 404 only for an unknown transform id
    (maltego/server/v3/__init__.py:985-989 and :1343-1347); the run-results routes answer
    404 for an unknown run, which is why this is not applied in ``_request`` itself.
    """
    try:
        return await request
    except TransformServerError as exc:
        if exc.status_code == 404:
            raise TransformNotFoundError(str(exc), exc.status_code) from exc
        raise


@dataclass
class RunResult:
    """Outcome of a single transform run.

    Attributes:
        run_id: Server-assigned identifier for the run.
        state: Terminal run state reported by the server.
        entities: Entities produced by the transform.
        links: Links produced by the transform.
        messages: Status messages emitted during the run.
        message_levels: Severity of each entry in ``messages``, index for index: INFO,
            WARNING, ERROR, or DEBUG.
    """

    run_id: str
    state: str
    entities: list[dict[str, Any]] = field(default_factory=list)
    links: list[dict[str, Any]] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    message_levels: list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.state in SUCCESS_STATES

    def add_message(self, text: str, level: str = DEFAULT_MESSAGE_LEVEL) -> None:
        """Record one status message, keeping ``message_levels`` aligned with ``messages``."""
        self.messages.append(text)
        self.message_levels.append(level)


def build_run_request(
    entity_type: str,
    entity_value: str,
    settings: dict[str, str] | None = None,
    limit: int = 12,
) -> dict[str, Any]:
    """Build the POST body for a transform run from a single input entity.

    The server derives the input entity from ``valueRef``, which must name one of
    the entity's properties.
    """
    value_ref = "value"
    return {
        "input": {
            "metadata": {
                "entitiesTypesStat": {entity_type: 1},
                "entitiesTotalCount": 1,
                "linksTotalCount": 0,
                "rootEntitiesCount": 1,
            },
            "graph": {
                "entities": [
                    {
                        "id": "0",
                        "valueRef": value_ref,
                        "type": entity_type,
                        "properties": [
                            {"name": value_ref, "type": "STRING", "value": entity_value}
                        ],
                        "displayInformation": [],
                    }
                ],
                "links": [],
            },
        },
        "transformSettings": [
            {"name": name, "value": value} for name, value in (settings or {}).items()
        ],
        "limit": limit,
    }


def collect_events(events: list[dict[str, Any]], result: RunResult) -> None:
    """Sort protocol events into entities, links, and status messages.

    Events arrive as ``{"timestamp": ..., "data": {"inputType": ..., "eventType": ...}}``,
    per ``TransformRunEvent`` in maltego/protocol/v3/execution/transform_run.py, where
    ``eventType`` is ADD (the default), UPDATE, or DELETE. Only ADD creates output. The SDK
    emits an UPDATE whenever a transform edits an entity it already returned — setting a
    property, note, or display field after ``add_entity`` — carrying just the entity id and
    the changed fields; a DELETE carries only the id. Appending those as new entities would
    count one entity several times, which misreports the very number an author checks.
    """
    for event in events:
        data = event.get("data", {})
        input_type = data.get("inputType")
        event_type = data.get("eventType", "ADD")
        if input_type == "ENTITY" and "entity" in data:
            _apply_event(result.entities, event_type, data["entity"])
        elif input_type == "LINK" and "link" in data:
            _apply_event(result.links, event_type, data["link"])
        elif input_type == "STATUS_MESSAGE" and event_type == "ADD":
            status = data.get("statusMessage") or {}
            text = status.get("text") or data.get("text")
            if text:
                level = str(status.get("type") or DEFAULT_MESSAGE_LEVEL).upper()
                result.add_message(str(text), level)


def _apply_event(items: list[dict[str, Any]], event_type: str, item: dict[str, Any]) -> None:
    """Apply one ADD/UPDATE/DELETE event for an entity or link to the collected ``items``.

    An UPDATE or DELETE for an id that was never added (the input entity, say) changes
    nothing, because it is not part of this run's output.
    """
    if event_type == "ADD":
        items.append(dict(item))
        return
    item_id = item.get("id")
    if item_id is None:
        return
    index = next((i for i, existing in enumerate(items) if existing.get("id") == item_id), None)
    if index is None:
        return
    if event_type == "DELETE":
        del items[index]
    elif event_type == "UPDATE":
        items[index] = _merge_update(items[index], item)


def _merge_update(current: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    """Return ``current`` with the fields of an UPDATE event applied.

    ``to_v3_run_entity_update`` in the SDK sends only what changed: ``properties`` holds just
    the changed properties, so they replace by name; ``displayInformation`` and ``overlays``
    hold just the items added (the SDK only ever appends to them), so they extend. Any other
    field present replaces the old value.
    """
    merged = dict(current)
    for key, value in update.items():
        if key == "properties" and isinstance(value, list):
            by_name = {prop.get("name"): prop for prop in merged.get("properties") or []}
            by_name.update({prop.get("name"): prop for prop in value})
            merged["properties"] = list(by_name.values())
        elif isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = [*merged[key], *value]
        else:
            merged[key] = value
    return merged


class TransformClient:
    """Talks to a running transform server over the v3 protocol."""

    def __init__(self, config: TransformatronConfig, timeout: float = 15.0) -> None:
        self._config = config
        self._timeout = timeout

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self._config.api_url}/{path.lstrip('/')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
                response = await client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise TransformServerError(
                f"Could not reach the transform server at {url}: {exc}. "
                "Start it with the server_start tool."
            ) from exc
        if response.status_code >= 400:
            raise TransformServerError(
                f"{method} {url} failed with HTTP {response.status_code}: {response.text[:400]}",
                response.status_code,
            )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            # Something other than the transform server answered — another service on the
            # port, or a proxy error page. A bare JSONDecodeError would say nothing about that.
            raise TransformServerError(
                f"{method} {url} returned a response that is not JSON: {response.text[:200]}"
            ) from exc

    async def status(self) -> Any:
        """Return the server status document."""
        return await self._request("GET", "status")

    async def list_transforms(self) -> list[dict[str, Any]]:
        """Return every transform the server advertises."""
        payload = await self._request("GET", "transforms")
        return _unwrap_list(payload, "transforms")

    async def get_transform(self, transform_id: str) -> Any:
        """Return the detail document for a single transform."""
        return await _not_found_as_unknown_transform(
            self._request("GET", f"transforms/{transform_id}")
        )

    async def list_entities(self) -> list[dict[str, Any]]:
        """Return every entity schema the server advertises."""
        payload = await self._request("GET", "assets/entities")
        return _unwrap_list(payload, "entities")

    async def cancel_run(self, transform_id: str, run_id: str) -> None:
        """Ask the server to cancel an in-flight run."""
        await self._request("POST", f"transforms/{transform_id}/run/{run_id}/cancel")

    async def run_transform(
        self,
        transform_id: str,
        entity_type: str,
        entity_value: str,
        settings: dict[str, str] | None = None,
        timeout: float = DEFAULT_RUN_TIMEOUT,
    ) -> RunResult:
        """Run a transform and poll until it reaches a terminal state.

        Args:
            transform_id: Identifier from ``list_transforms``.
            entity_type: Maltego entity type of the input, e.g. ``maltego.Domain``.
            entity_value: Value carried by the input entity.
            settings: Optional transform settings, by setting name.
            timeout: Seconds to wait before cancelling the run.

        Returns:
            The collected entities, links, and messages for the run.

        Raises:
            TransformNotFoundError: If the server has no transform with this id.
            TransformServerError: If the server is unreachable or returns no run id.
        """
        body = build_run_request(entity_type, entity_value, settings)
        started = await _not_found_as_unknown_transform(
            self._request("POST", f"transforms/{transform_id}/run", json=body)
        )
        run_id = (started or {}).get("result", {}).get("runId")
        if not run_id:
            raise TransformServerError(
                f"Server accepted the run for '{transform_id}' but returned no runId: {started!r}"
            )
        return await self._poll_run(transform_id, run_id, timeout)

    async def _poll_run(self, transform_id: str, run_id: str, timeout: float) -> RunResult:
        """Poll a run's results endpoint until terminal, cancelling on timeout."""
        result = RunResult(run_id=run_id, state="RUNNING")
        seen = 0
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        while True:
            run = await self._fetch_events_from(transform_id, run_id, seen)
            result.state = run.get("state", result.state)

            events = run.get("events", []) or []
            # `seen` is an absolute offset into the run's event list, and the request above
            # starts from it, so these events are all new. The server replays from whatever
            # pointer it is given, and pages, so a run is only fully read once the pointer
            # reaches eventCount — see _fetch_events_from.
            collect_events(events, result)
            seen += len(events)

            if result.state in TERMINAL_STATES:
                if result.state in FAILURE_STATES:
                    # The SDK marks a run FAILED before it logs the traceback and pushes the
                    # message saying why (maltego/runner/transform_execution_context.py:
                    # 409-412 sets the state, then __handle_task_exception at :343-371), and
                    # the results endpoint is served from another thread meanwhile. A poll
                    # landing in between sees FAILED and no message, so read once more after
                    # a pause to collect what followed.
                    await asyncio.sleep(POLL_INTERVAL)
                    late = await self._fetch_events_from(transform_id, run_id, seen)
                    collect_events(late.get("events", []) or [], result)
                return result

            if loop.time() >= deadline:
                # Cancel server-side so the run is not left orphaned. A failure
                # here is not worth surfacing: the run is already being abandoned.
                with suppress(TransformServerError):
                    await self.cancel_run(transform_id, run_id)
                result.state = "TIMED_OUT"
                result.add_message(
                    f"Run exceeded the {timeout:g}s client timeout and was cancelled.", "ERROR"
                )
                return result

            await asyncio.sleep(POLL_INTERVAL)

    async def _fetch_events_from(
        self, transform_id: str, run_id: str, pointer: int
    ) -> dict[str, Any]:
        """Return the run document with every event from `pointer` onward.

        The results endpoint pages: it answers with at most ``v3_page_size_max`` events (50 by
        default) however many the run produced, and reports the true total in ``eventCount``.
        Reading a single response therefore truncates any run that emitted more — 50 events is
        25 entities, because each entity arrives as two events, which is why a transform
        returning 50 entities appeared to return exactly 25.

        The pages are concatenated here so the caller sees one continuous event list.
        """
        path = f"transforms/{transform_id}/run/{run_id}/results"
        payload = await self._request("GET", path, params={"eventPointer": pointer})
        run = (payload or {}).get("result", {}) or {}
        events = list(run.get("events", []) or [])

        total = run.get("eventCount")
        if not isinstance(total, int):
            return run

        offset = pointer + len(events)
        while offset < total and events:
            payload = await self._request("GET", path, params={"eventPointer": offset})
            page = (payload or {}).get("result", {}) or {}
            page_events = list(page.get("events", []) or [])
            if not page_events:
                break
            events.extend(page_events)
            offset += len(page_events)
            # A later page carries the newer state and count; keep them so a run that
            # finishes mid-read is not reported with the state it had on the first page.
            run = page

        run["events"] = events
        return run


def _unwrap_list(payload: Any, key: str) -> list[dict[str, Any]]:
    """Return a list from either a bare array or a keyed/``result``-wrapped object."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for candidate in (payload.get(key), payload.get("result")):
            if isinstance(candidate, list):
                return candidate
            if isinstance(candidate, dict) and isinstance(candidate.get(key), list):
                return candidate[key]
    return []
