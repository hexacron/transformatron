# Agent guide

Instructions for coding agents working in this repository. This is the canonical file —
`CLAUDE.md` points here. It follows the [AGENTS.md](https://agents.md) convention, which Codex,
Gemini CLI, and other agents read directly.

Humans: `README.md` is the friendlier entry point, but nothing here is agent-only.

## What this project is

An MCP server **and CLI** for authoring Maltego v3 transforms against a single local transform
server. It scaffolds a transform module from a cURL command or an OpenAPI spec, then drives the
server — restart, run, read back the entities — so you can check what you wrote against the live
API. The scaffold is a first draft; the verify loop is what makes it correct.

## Before writing a transform

**Read `docs/transform-authoring.md` first.** It corrects the vendored SDK guidance in
`server/.agents/skills/` in two places — one fails silently (code that looks right, runs green,
and produces nothing), one teaches a method the SDK does not have — and says what never to do in
a transform.

Claude Code loads the same checklist automatically from
`.claude/skills/maltego-transform-author/SKILL.md`. That file is a thin pointer to
`docs/transform-authoring.md`, not a second copy, so nothing here is Claude-only. Working through
this file instead gets you the same result.

The short version, in the order these bite:

1. Return a `list`, never a `MaltegoGraph` — a returned graph is silently discarded.
2. Annotate both the first parameter and the return type: `-> list[Domain]`. No return
   annotation publishes output `NONE`; a bare `-> list` stops the server starting, with an error
   that blames `input_entity`.
3. Import the module in `server/project.py`, or it never registers.
4. Read the run, not the state: the entity count, the distinct count, and the message levels. An
   upstream 403 logged with `context.log.fatal` is `[ERROR]` in a `COMPLETED (success)` run.
5. Never block: `async def` and awaited I/O only — no `requests`, sync `httpx` or `time.sleep`. A
   blocking call pins the runner thread and gets the server killed on `stop`/`restart`.
6. `set_property(name, value, display_name=...)`, not `add_property` (it does not exist); assign
   typed attributes after construction.
7. Credentials belong in `TransformSetting(auth=True, is_global=True)`, never hardcoded.
8. Validate `input_entity.value` before putting it in a URL or a subprocess call.

## The loop

1. **Dry-run a scaffold** from a spec, or hand-write a module under `server/transforms/`:

   ```bash
   # From a cURL command, with the response from running that same command.
   uv run python scripts/transformatron_cli.py scaffold \
     --curl 'curl https://internetdb.shodan.io/8.8.8.8' \
     --sample-response "$(curl -s https://internetdb.shodan.io/8.8.8.8)" --dry-run

   # From an OpenAPI spec (URL or path, JSON or YAML): list the operations, then pick.
   uv run python scripts/transformatron_cli.py scaffold --service demo \
     --openapi ./demo-openapi.yaml --list-operations
   uv run python scripts/transformatron_cli.py scaffold --service demo \
     --openapi ./demo-openapi.yaml --operation searchHosts --sample-input 8.8.8.8 --dry-run
   ```

   GETs are scaffolded by default; POST operations, and GETs with a path segment or operationId
   (past a leading `get`/`post`/`api`/`do`) starting with a state-changing verb (`create`,
   `delete`, `start`, …), only when named with `--operation`. A spec with no response schema maps
   nothing: pass `--sample-response` with exactly one `--operation`. Pass `--sample-input` with a
   value the API answers for unless the spec gives the input parameter an example; without one
   there is no `samples.json` entry and a Note says so. JSON samples only: for CSV or plain text,
   hand-write the parsing.
2. **Read the field inventory and the Notes.** Each record becomes one primary entity with the
   record's plain values as properties and its other typed values as entities beside it. Every
   other field says why it was dropped — including typed values deeper than 4 levels and
   properties deeper than 3. Notes list what the request lost and whether it paginates.
3. **Fix it before writing**: `--records PATH` for the list of records, `--map PATH=TYPE`
   (an entity class, `Property` or `Drop`; repeatable) for single fields, `--primary PATH` for
   each record's primary entity (a single-valued entity field). A `--map` that cannot be honoured
   is an error; `Property` inside an entity-less nested list goes on the record's entity, values
   joined with `, `. Repeat with `--dry-run`.
4. **Write it** — the same command without `--dry-run`. This writes the service package, its
   `samples.json` (the sample input per transform) and the `server/project.py` import; a
   hand-written module needs that import added.
5. **Restart** — the server only loads code at startup — and confirm in `list` the input and
   output types you expect.
6. **Run it on the sample input** with the `run` command the scaffold printed (the id carries the
   namespace) and read the output: count against distinct count, `[ERROR]` and `[WARNING]`
   messages, properties, link labels. Compare it with the inventory.
7. **Correct the mapping** by editing the module's `RECORDS` table (`Records`/`Entity`/`Prop`,
   walked by `map_records` in the service's `api.py`), or re-scaffold with `--force`. Repeat 5–7
   until the entities are the ones an investigator wants.
8. Run the smoke test (below) before calling it done.

Scaffolding rules that bite:

- `--force` replaces the whole service directory and its `project.py` imports — hand edits
  included — and refuses a service the scaffolder did not write. Undo a scaffold with
  `remove-scaffold <service>`; never delete a service directory by
  hand, which leaves its imports and stops the server starting. `remove-scaffold` refuses
  hand-written services (no `Generated by transformatron scaffold.` line in `api.py`); remove
  those by hand, directory and `project.py` imports.
- cURL ids are `<service>_<name>` (`--name`, default `lookup`); OpenAPI ids are
  `<service>_<operation>`. Add endpoints to a service with a new `--name`; that is refused unless
  the regenerated `api.py` would be byte-identical (same base URL, auth, headers, no hand edits).
  An operationId the spec reuses gets a distinct id per operation, marked `*` in
  `--list-operations`; pass its TRANSFORM value to `--operation` to pick one.
- An id already defined anywhere under `server/transforms/` is refused before writing. The
  service name `local` is reserved. The server registers each id as `<namespace>.<id>`.

## Driving the server

Two interchangeable front ends over the same `transformatron.operations` module. Use whichever
your tool supports.

**CLI** — works anywhere you can run a command:

```bash
uv run python scripts/transformatron_cli.py status
uv run python scripts/transformatron_cli.py restart
uv run python scripts/transformatron_cli.py list
uv run python scripts/transformatron_cli.py run <id> maltego.IPv4Address 8.8.8.8   # --json for raw
uv run python scripts/transformatron_cli.py show <id>
uv run python scripts/transformatron_cli.py logs --lines 100
uv run python scripts/transformatron_cli.py scaffold ... --dry-run   # --records, --map, --primary, --sample-input, --name
uv run python scripts/transformatron_cli.py scaffold --openapi <spec> --list-operations
uv run python scripts/transformatron_cli.py remove-scaffold <service>
```

`run` prints `Entities (N, M distinct):` and one line per entity —
`type  value  {property=value, ...}  [link label]`, blank properties left out — with each message
prefixed by its level (`[INFO]`, `[WARNING]`, `[ERROR]`, `[DEBUG]`). A `FAILED` run also shows the
traceback the server logged during it. `--json` prints the full JSON of every entity and link. An
unknown id passed to `run` or `show` gets a hint: `list`, the `<namespace>.<id>` form, a restart.

`--help` on any subcommand lists its options. The CLI exits 0 on success and 1 when the operation
failed — a start, stop, restart or certificate generation that failed, a server that could not be
reached (`status` included), a run that did not end in a success state, a refused scaffold or
removal, or an unusable `transformatron.toml`. A run that completes with zero entities, or with
only `[ERROR]` messages, still exits 0: the output is the signal, not the exit code. Zero entities
plus an `[ERROR]` adds a `Warning:` line under the state.

When `stop` or `restart` has to kill the server after 10s, it names the cause from the server
log — usually a transform blocking the runner thread — and nothing is lost by the kill.

**MCP** — for agents that speak it (Claude Code is configured in `.mcp.json`): `server_start`,
`server_stop`, `server_restart`, `server_status`, `server_logs`, `list_transforms`,
`get_transform`, `list_entities`, `run_transform` (`full=True` for the JSON), `get_seed_url`,
`generate_certs`, `scaffold_transform` (`dry_run`, `records`, `mappings`, `primary`,
`sample_input`, `name`), `list_operations`, `remove_scaffold`.

Both produce identical output. If you add an operation, put it in
`src/transformatron/operations.py` so both front ends get it. An unexpected crash in a tool
reaches you as `Error executing tool <name>: <ExceptionType>: <message>`; the traceback is on the
MCP server's stderr. Report it — operations return every failure you can act on as text.

### The MCP tools can hold stale code

The MCP server is one long-lived process. It imports `src/transformatron/` once at startup, so
**editing that code does not change what the MCP tools run** — they keep executing the version
loaded when the session began. The CLI is a fresh process each time and always runs current code.

This applies only to edits under `src/transformatron/`. Editing `server/transforms/` is unaffected:
`server_restart` restarts the transform server subprocess, which does reload your transform
modules. You do not need to relaunch a session after changing a transform.

`transformatron.toml` is not code: every tool reads it afresh on each call, so an edit applies on
the next call without relaunching. The transform server still takes its identity, host and port
at start, so restart it after changing them.

`/clear` does not help — it resets the conversation but keeps the same process, so the MCP server
keeps its loaded modules. Use `/exit` and relaunch.

**If MCP and the CLI disagree about the server, suspect this first and trust the CLI.** That
disagreement is the signature; the stale tools otherwise look like they are working.

## Verifying your work

**A success state is not proof a transform works.** It can report `COMPLETED (success)` while
returning nothing, or while carrying an `[ERROR]` from the upstream. Always read the entity count
and the message levels.

```bash
uv run python scripts/smoke_test_transforms.py
uv run python scripts/smoke_test_transforms.py --setting API_KEY=xxx
```

Runs every registered transform and fails on zero entities or an output type of `NONE`. Run it
after any change under `server/transforms/`. Each transform's input is `--value`, else its entry
in the service's `samples.json` (written by `scaffold`), else `TRANSFORM_SAMPLES`, else the
per-entity-type default.

Pass credentials with repeated `--setting KEY=VALUE`, or write them to `.env` (copy
`.env.example`), which the server and the smoke test both read. An exported shell variable
overrides `.env`, and `--setting` overrides both. A missing setting, a rate limit (429), exhausted
credits (402), a rejected sample or an input with no upstream match is recorded SKIP rather than
FAIL, so an unconfigured key is never mistaken for broken code — but a SKIP is not evidence the
transform works either. Supply the setting to actually exercise it, and add a `samples.json` or
`TRANSFORM_SAMPLES` entry when the per-entity-type sample does not suit a transform.

Project gates:

```bash
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run ty check src tests scripts
```

## Constraints

- **Do not edit anything under `server/.agents/skills/` or `.venv/`.** Both are upstream-owned and
  regenerate; corrections belong in `docs/transform-authoring.md`. See `CONTRIBUTING.md`.
- `server/.agents/`, `server/project.py` and `server/__init__.py` are SDK-generated and excluded
  from linting. `project.py` carries this project's edits — HTTPS by default, local discovery, and
  a 3s bound on uvicorn's graceful shutdown (`GRACEFUL_SHUTDOWN_TIMEOUT`, see
  `docs/upstream-sdk-shutdown-issue.md`); keep them if you regenerate it. The rest of `server/` —
  `transforms/` (scaffolded code included), `middleware.py`, `discovery.py` — is linted like the
  rest of the project.
- The server runs on port **3000** unless `transformatron.toml` sets another. The SDK's own skill
  scripts default to 8080.
- macOS and Linux only. The lifecycle relies on POSIX signals; on Windows `os.kill(pid, 0)`
  terminates the process it is meant to probe.
- The Maltego desktop client requires HTTPS — plain HTTP fails inside the client with nothing in
  the server log.

## Layout

```
src/transformatron/
  operations.py  shared server operations — add new ones here
  config.py      host, port, scheme, derived URLs and state paths; reads transformatron.toml
  client.py      async v3 protocol client
  lifecycle.py   start/stop/restart/status/logs
  certs.py       self-signed certificate generation
  envfile.py     reads .env so headless runs can reach credentials
  scaffold/      spec → module package: parser.py, generator.py, schema.py
  mcp.py         MCP front end
scripts/
  transformatron_cli.py      CLI front end
  smoke_test_transforms.py   zero-entity gate
server/          SDK-generated; project.py imports decide what registers
  transforms/    your transform modules, scaffolded or hand-written
    local/       gitignored; discovered at startup, for integrations you do not publish
docs/            transform-authoring.md — read before writing transforms
CHANGELOG.md     what changed, per release
transformatron.toml  server name, namespace, author, host, port. Gitignored; copy the .example.
.env             API keys for headless runs. Gitignored; copy .env.example.
