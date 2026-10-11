# Draft: upstream bug report for the Maltego SDK

Not yet filed. Review and send to Maltego (SDK support or the `maltego-transforms` issue tracker).
Kept in the repo because this defect is the reason `docs/transform-authoring.md` contradicts the
shipped SDK guidance — if it is fixed upstream, that correction can be removed.

---

## Title

Returning a `MaltegoGraph` from an async transform silently produces zero entities

## Versions

- `maltego-transforms` 1.3.0 (first seen on 1.0.1)
- `maltego-transforms-std-entities` 1.0.2
- Python 3.14, macOS

## Summary

A transform that builds a `MaltegoGraph` and returns it emits **no entities**. The run still
reports `COMPLETED`, no exception is raised, and nothing appears in the server log. Because the
failure is silent and reports success, it does not self-correct — transport-level checks
(HTTP 201, a valid run id, a terminal success state) all pass.

The SDK's own shipped agent skills teach this exact pattern, so an agent or developer following
the documentation writes a transform that cannot work.

## Cause

`MaltegoTransform.__handle_async_result`, `maltego/model/transform/__init__.py:651`:

```python
if not isinstance(async_res, (list, tuple, set, MaltegoGraph)):
    await self.__add_entity_result_to_queue(...)  # graph excluded by the tuple
elif not isinstance(async_res, MaltegoGraph):
    for item in async_res:
        ...  # graph excluded again
```

A returned `MaltegoGraph` fails both branches and falls through with no handling. The generator
branch in `__add_async_results` (line 674) also skips graphs, so this affects every async path.

This looks inconsistent with the surrounding code: `__add_entity_result_to_queue` raises
`ValueError` for an unexpected return type (lines 646-647), so an unusable return is normally loud.

## Reproduction

Standalone — no server or network needed:

```python
import asyncio
from queue import Queue

from maltego.entities import Domain, EmailAddress
from maltego.model.graph import MaltegoGraph
from maltego.model.transform import MaltegoTransform

handler = MaltegoTransform._MaltegoTransform__handle_async_result


async def main() -> None:
    graph = MaltegoGraph()
    graph.add_entity(EmailAddress(value="admin@example.com"))

    for label, result in (
        ("returned MaltegoGraph", graph),
        ("returned list", [EmailAddress(value="admin@example.com")]),
    ):
        q: Queue = Queue()
        await handler(
            MaltegoTransform.__new__(MaltegoTransform),
            [Domain(value="example.com")],
            result,
            q,
            False,
        )
        print(f"{label:>22}: {q.qsize()} events queued")


asyncio.run(main())
```

Observed:

```
 returned MaltegoGraph: 0 events queued
         returned list: 1 events queued
```

Same entity, same handler — the graph is dropped.

End to end, a transform annotated `-> MaltegoGraph[...]` returns
`State: COMPLETED (success)` with `Entities (0, 0 distinct)`; switching the body to return
`list[...]` with the same entities returns all of them.

## Documentation defect

These shipped skill files teach the broken pattern:

- `maltego-transform-basics/references/transform-authoring-patterns.md` §3, "Returning a Graph
  (Multiple Entity Types)" — the example builds a graph and returns it.
- `maltego-transform-build/SKILL.md` §5, "Return Entities" — same pattern under "Multiple entity
  types → use MaltegoGraph".

Both should use a union list return (`-> list[EmailAddress | Person]`), which publishes every
output type to `/api/v3/transforms` correctly and actually emits entities.

## Suggested fix

Either:

1. **Handle it** — add a branch that iterates a returned graph's entities onto the output queue,
   matching what the documentation promises; or
2. **Fail loudly** — raise `ValueError` for a returned `MaltegoGraph`, consistent with line 646,
   so the mistake surfaces immediately.

Option 1 makes the shipped examples correct. Option 2 is a smaller change but turns working-looking
code into an error, so it would want a release note.

Either way, the two skill files above need updating.

## Impact

Any transform emitting multiple entity types is likely to hit this, because building a graph is
the documented way to do that. The silent-success behaviour means it can reach production
undetected — a transform appears to run fine and simply never returns results.
