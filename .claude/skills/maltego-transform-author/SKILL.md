---
name: maltego-transform-author
description: "Write or modify a Maltego transform in this repository. Use when adding a transform, integrating an API as transforms, scaffolding from cURL or OpenAPI, or debugging a transform that returns zero entities, does not appear in list_transforms, shows output type NONE, or stops the server starting. Covers the SDK guidance that is wrong and the scaffold/run/read loop."
---

# Authoring Maltego transforms

**Read `docs/transform-authoring.md` before writing code.** It is the canonical guidance and this
skill does not restate it — a second copy would drift. This file exists to make sure the checklist
below is applied every time, because some of the failure modes report success while producing
nothing.

## Non-negotiables

1. **Return a `list`, never a `MaltegoGraph`.** A graph returned from an `async` transform is
   silently discarded: zero entities, run still reports `COMPLETED (success)`. Use
   `-> list[A | B | C]`; the union still publishes every output type to discovery.
2. **Annotate both sides.** Input type comes from the first parameter's annotation, output from
   the return annotation: `-> list[Domain]`. With no return annotation the transform appears with
   output `NONE` and the Maltego client cannot route it. A bare `-> list` stops the server
   starting, with a registration error that blames `input_entity` — fix the return type.
3. **Import the module in `server/project.py`**, with the other imports at the top of the file.
   The server registers only what `project.py` imports — the most common reason a new transform
   never appears. Do not append the import to the end of the file: it lands after the
   `if __name__ == "__main__"` block and registers nothing.
4. **Read the run, not the state.** `run_transform` prints `Entities (N, M distinct)` and each
   message with its level. Confirm N > 0, that M is close to N, and that no `[ERROR]` is hiding in
   a `COMPLETED (success)` run — an upstream 403 logged with `context.log.fatal` looks exactly
   like that. With zero entities a `Warning:` line flags it; the exit code stays 0.
5. **Credentials go in `TransformSetting(auth=True, is_global=True)`**, read at runtime via
   `settings.get(NAME, "")`. Never hardcode a key. Declare the setting name once as a module
   constant and use it on both sides — a literal mistyped on one side silently reads back as the
   default. Pass the list to `register_transform` as `settings=[...]` — **not**
   `transform_settings=`, which raises at import and stops the server booting.

   **Confirm the field actually reaches the client**, or a user cannot enter the credential at
   all. Restart, then check the transform's discovery document carries a `transformSettings`
   array:

   ```bash
   uv run python scripts/transformatron_cli.py show <id>
   ```

   or `get_transform(id)` over MCP. Both use the configured port and the scheme the server was
   started with, so neither depends on HTTPS. An empty `transformSettings` array there means
   Desktop renders no field.
   Restart before believing it — a stale server serves the old registration and makes correct code
   look broken.
6. **Validate `input_entity.value` before interpolating it** into a URL path, query parameter, or
   subprocess call. It is user-controlled.
7. **Never block.** `async def`, awaited I/O only — no `requests`, sync `httpx`, `time.sleep`.
   A blocking call pins the runner thread, and `stop`/`restart` then kill the server after 10s.
8. **`set_property(name, value, display_name=...)`**, never `add_property` — the SDK skills teach
   it, and it does not exist. Assign typed attributes after construction, not in the constructor.

## The loop

```bash
# 1. dry-run a scaffold with a real response, and read the field inventory and Notes
uv run python scripts/transformatron_cli.py scaffold \
  --curl 'curl https://internetdb.shodan.io/8.8.8.8' \
  --sample-response "$(curl -s https://internetdb.shodan.io/8.8.8.8)" --dry-run
#    OpenAPI (URL/path, JSON or YAML): --openapi <spec> --list-operations, then --operation <id>
#    and --sample-input VALUE unless the spec has an example for the input
# 2. fix it: --records PATH, --map PATH=Type|Property|Drop, --primary PATH; repeat --dry-run;
#    then drop --dry-run
uv run python scripts/transformatron_cli.py restart          # 3. reload
uv run python scripts/transformatron_cli.py list             # 4. confirm types
uv run python scripts/transformatron_cli.py run <namespace>.<id> <type> <sample input> --setting KEY=VALUE
# 5. read count, distinct count, [ERROR]s, properties; edit RECORDS in the module; go back to 3
```

`scaffold` prints the `run` command for each transform, with its registered (namespaced) id and
sample input; the input is also kept in `server/transforms/<service>/samples.json`. Correct the
mapping by editing the module's `RECORDS` table (`Records`, `Entity`, `Prop` in the service's
`api.py`) — see `docs/transform-authoring.md`. `--force` replaces the whole service directory,
hand edits included. Undo with `remove-scaffold <service>`, never by deleting the directory (its
imports stay and the server will not start); it refuses hand-written services, which you remove
by hand, directory and imports. Add an endpoint to a service with a new `--name`. The scaffolder
maps JSON only: for CSV or plain text, hand-write the parsing.

With the `transformatron` MCP server available, `list_operations`, `scaffold_transform`
(`dry_run=True`), `server_restart`, `list_transforms`, `run_transform` and `remove_scaffold` do
the same thing. Both front ends call `src/transformatron/operations.py`.

## Verify before saying it works

```bash
uv run python scripts/smoke_test_transforms.py --setting KEY=VALUE
```

Runs every registered transform and fails on zero entities or an output type of `NONE`. Pass each
credential with `--setting`; a transform that reports a missing setting is recorded SKIP, so an
unconfigured key is never mistaken for working code. Inputs come from `samples.json` first; add a
`TRANSFORM_SAMPLES` entry when neither it nor the per-entity-type sample suits a transform.

**A green smoke test does not prove Correction 1 is avoided.** Adding to `context.graph` and
returning it passes the gate while still being the wrong pattern. Return a list.

Project gates:

```bash
uv run ruff check . && uv run ruff format --check .
uv run ty check src tests scripts
uv run pytest -q
```

`server/transforms/` is linted, scaffolded code included. Only `server/.agents/`,
`server/project.py` and `server/__init__.py` are SDK-generated and excluded.

## Routing to the SDK skills

The vendored SDK guidance in `server/.agents/skills/` is the source of truth for API surface —
entity selection, pagination, input constraints, TRX migration. Load one at a time.

| Task | Skill |
|------|-------|
| Entity modeling, transform sets, pagination design | `maltego-transform-design` |
| `@register_transform` functions, HTTP calls, settings | `maltego-transform-build` |
| Parameters, context logging, input constraints | `maltego-transform-basics` |
| Testing a running server | `maltego-transform-test` |
| Inspecting what a server exposes | `maltego-transform-discover` |
| SDK API docs and entity schemas | `maltego-transform-docs` |
| TRX migration | `maltego-trx-migration-planner` → `-implementer` |

**Two places in that guidance are wrong — do not follow them:**

- The graph return: `maltego-transform-build/SKILL.md` §5 "Return Entities" and
  `maltego-transform-basics/references/transform-authoring-patterns.md` §3 "Returning a Graph".
- `entity.add_property(...)`: `maltego-transform-design/references/standard-entity-selection.md`
  and the TRX migration skills. Use `set_property`.

**Port correction:** those skills default to port 8080. This project runs on **3000** unless
`transformatron.toml` sets another.

## Worked examples

| Example | Shows |
|---------|-------|
| `server/transforms/examples/ffraud.py` | Single module, no auth — the minimal shape |
| `server/transforms/ransomwarelive/` | Multi-module, API key, shared client, upstream field drift |

Do not edit anything under `server/.agents/skills/` or `.venv/` — both are upstream-owned and
regenerate. Corrections belong in `docs/transform-authoring.md`.
