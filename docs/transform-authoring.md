# Writing a Maltego transform

Read this before writing or editing a transform. It applies to humans and to coding agents alike;
nothing in it is specific to one tool.

This repository vendors the official Maltego SDK guidance under `server/.agents/skills/`. Those
files are the source of truth for SDK API surface — entity selection, settings, pagination, input
constraints, TRX migration.

**Two of their examples are wrong** — Correction 1 fails silently, Correction 3 raises. Both are
reproduced on `maltego-transforms` 1.3.0 / `maltego-transforms-std-entities` 1.0.2. Correction 2
is not a divergence: the SDK teaches it correctly, and it is repeated here because it is the most
common way a transform lands in the client unusable. Read all three, then use the SDK guidance for
everything else.

## Correction 1: never return a `MaltegoGraph`

A `MaltegoGraph` returned from an `async` transform is **silently discarded**. You get zero
entities and the run still reports `COMPLETED (success)`, so nothing surfaces the mistake.

```python
# WRONG — returns nothing, reports success
async def domain_profile(input_entity: Domain, context: MaltegoContext) -> MaltegoGraph:
    graph = MaltegoGraph()
    graph.add_entity(EmailAddress(value="admin@example.com"))
    return graph


# RIGHT — return a list; the union annotation still publishes every output type
async def domain_profile(
    input_entity: Domain, context: MaltegoContext
) -> list[EmailAddress | Person]:
    return [EmailAddress(value="admin@example.com"), Person(value="Domain Admin")]
```

Mechanism, so you can check it yourself: in `MaltegoTransform.__handle_async_result`
(`maltego/model/transform/__init__.py:651`), `MaltegoGraph` sits in the first `isinstance` tuple
so the first branch is skipped, and the `elif not isinstance(async_res, MaltegoGraph)` excludes it
again. A returned graph falls through both and is dropped. The generator branch in
`__add_async_results` skips graphs too, so this affects **every** async path.

Only a **freshly constructed** graph loses entities. Adding to the context graph and returning it
still publishes them, because they were registered on the context before the return value was
discarded:

```python
# Entities survive — but only by accident; the return value is still dropped
context.graph.add_entity(EmailAddress(value="admin@example.com"))
return context.graph
```

That variant passes `scripts/smoke_test_transforms.py`, so a green smoke test does not prove a
transform avoids this trap. Return a list and the question does not arise.

**These SDK skill sections teach the broken pattern — do not follow them:**

- `maltego-transform-basics/references/transform-authoring-patterns.md` §3 "Returning a Graph
  (Multiple Entity Types)"
- `maltego-transform-build/SKILL.md` §5 "Return Entities"

Use `-> list[A | B | C]` for multiple output types. It is published to `/api/v3/transforms`
identically and it actually works.

## Correction 2: both annotations are load-bearing

Not a divergence from the SDK — it teaches this correctly — but it is the most common way a
transform ends up registered yet unusable, so it is worth repeating.

Input type comes from the **first parameter's** annotation; output type comes from the **return**
annotation. Both are read at registration and published to discovery.

A transform with **no** return annotation still registers, shows output `NONE` in
`list_transforms`, and the Maltego client cannot route it onto result entities.

A **bare `-> list`** is worse: registration raises and the server does not start. The error blames
the wrong parameter —
`ValueError: Failed to register transform 'x' (...): Type annotation for x input_entity <class
'maltego.entities.personal.Phrase'> is not valid` — so fix the return annotation, not the input.

```python
async def my_transform(input_entity: IPv4Address, context: MaltegoContext) -> list[Domain]:
```

## Correction 3: there is no `add_property`; use `set_property`

The SDK guidance sets a property with no typed attribute through `entity.add_property(...)`:

- `maltego-transform-design/references/standard-entity-selection.md:83` and `:107`
  (`person.add_property(name="source_system", ...)`), and the same file under
  `maltego-trx-migration-planner/references/`
- `maltego-trx-migration-implementer/SKILL.md:143` and its `references/trx-to-sdk-mapping.md:59`
- `maltego-trx-migration-planner/references/trx-risk-taxonomy.md:114`

SDK 1.3.0 has no such method; entities define `set_property`
(`maltego/model/entity/__init__.py:1139`). The run ends `FAILED` with
`AttributeError: 'Person' object has no attribute 'add_property'`.

```python
# WRONG — AttributeError
person.add_property(name="source_system", display_name="Source System", value="example-api")

# RIGHT — name, value, then the label the client shows
person.set_property("source_system", "example-api", display_name="Source System")
```

Typed attributes are not constructor arguments either: `CVE(value="CVE-2021-44228", epss=0.9)`
raises `TypeError: MaltegoEntity.__init__() got an unexpected keyword argument 'epss'`. Construct
the entity, then assign:

```python
cve = CVE(value="CVE-2021-44228")
cve.epss = 0.9
```

Scaffolded transforms already do both: the `_set` helper in each generated `api.py` calls
`set_property`.

## Never block in a transform

Write `async def` and await all I/O — the SDK's `IntegrationClient` (as every generated `api.py`
and the samples do), `httpx.AsyncClient`, `asyncio.sleep`. Never `requests`, a synchronous
`httpx.Client`, or `time.sleep`.

A blocking call pins the SDK's runner thread, and the server's shutdown waits for that thread with
no limit. `stop` and `restart` give up after 10s and kill the server, and say why:

```
Server did not exit within 10s and was killed (pid 54095). A transform was blocking the runner
thread, and the SDK waits for it without a limit; ...
```

A synchronous `def` transform is no better: the SDK logs `Transforms should be asynchronous!`, and
one that returns a list is called twice per run (`__add_sync_results`,
`maltego/model/transform/__init__.py:693` and `:698`) — two upstream requests for one result.

## The loop

1. **Scaffold with `--dry-run` first.** `scaffold` (CLI) and `scaffold_transform` (MCP) parse
   the request and print the plan, the field inventory and the Notes without writing anything.
   Give a cURL command the response from running that same command:

   ```bash
   uv run python scripts/transformatron_cli.py scaffold --service epss \
     --curl "curl 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228'" \
     --sample-response "$(curl -s 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228')" \
     --dry-run
   ```

   From an OpenAPI spec (URL, path or the document; JSON or YAML), list the operations, then pick.
   Pass `--sample-input` with a value the API answers for unless the spec gives the input
   parameter a `default`, `enum`, `example`, `x-example` or `examples`: without one there is no
   `samples.json` entry and no echo detection, and a Note says so.

   ```bash
   uv run python scripts/transformatron_cli.py scaffold --service demo \
     --openapi ./demo-openapi.yaml --list-operations
   uv run python scripts/transformatron_cli.py scaffold --service demo \
     --openapi ./demo-openapi.yaml --operation getIp --sample-input 8.8.8.8 \
     --sample-response "$(curl -s https://api.demo.example/ip/8.8.8.8)" --dry-run
   ```

   The sample must be JSON. For a CSV or plain-text API, scaffold without `--sample-response`
   for the request code, then replace `RECORDS` and the `map_records()` call with your own
   parsing, fetched through `api.client` directly — `fetch()` returns decoded JSON only.

2. **Read the field inventory and the Notes.** Every leaf of the sample is listed with its
   outcome:

   ```
   Field inventory, acme.new_maltego_integration.epss_lookup (path, sample, outcome):
     status             OK              dropped: envelope
     ...
     data[].cve         CVE-2021-44228  entity CVE (primary)
     data[].epss        0.999990000     property epss
     data[].percentile  1.000000000     property percentile
   ```

   Each record becomes **one primary entity** — its strongest single-valued typed field —
   carrying the record's plain values as properties; its other typed values become entities
   beside it. Everything else is `dropped:` with a reason. Typed values are followed 4 levels into
   a record and properties 3; deeper ones are dropped and say so. The Notes summarise what was not
   mapped and what the request lost: headers not reproduced, pagination (only the first page is
   read), a placeholder output, a required key, a missing sample input.
3. **Fix it before writing.** `--records PATH` points at the list of records; `--map PATH=TYPE`
   overrides one field, where `TYPE` is an entity class (`Company`, `URL`, ...), `Property` or
   `Drop`; `--primary PATH`, written like a `--map` path, picks each record's primary entity
   among its single-valued entity fields. A `--map` applies to a field empty in the sample or
   inside a metadata block, ignores depth limits, and shows as `(--map)` in the inventory;
   `Property` inside a nested list with no entity of its own lands on the enclosing record's
   entity, values joined with `, `. One that cannot be honoured is an error, as is a `--primary`
   that is not a single-valued entity field (the error lists those that are). Repeat with
   `--dry-run` until the inventory maps what an investigator needs. See
   [the README](../README.md#scaffolding-from-a-spec) for the path syntax and how records are
   found.
4. **Write it**: the same command without `--dry-run`. It writes the service package, its
   `samples.json`, and the import in `server/project.py`. A hand-written module needs that import
   added: `from transforms.my_module import *`, alongside the existing imports at the top of the
   file. The server only registers what `project.py` imports.
5. **Restart** — the reload path — and confirm in `list` that it registered with the input and
   output types you expect.
6. **Run it against the sample input** with the `run` command the scaffold printed, under the
   registered id `<namespace>.<service>_<name>` (the input is also in `samples.json`). Read the
   output (see [Reading a run](#reading-a-run)): the message levels, the count against the
   distinct count, the properties. Compare it with the inventory. An unknown id gets a 404 that
   says how to find the registered one.
7. **Correct the mapping**: edit `RECORDS` in the module (below), or scaffold again with
   `--records`/`--map` and `--force`. Go back to 5.
8. **Smoke test** before calling it done.

`--force` replaces the whole service directory and its `project.py` imports — hand edits and any
other endpoint added to it with `--name` included. Once you have edited a module, edit rather than
re-scaffold. To undo a scaffold, use `remove-scaffold <service>` (`remove_scaffold` over MCP);
never delete the directory by hand — its imports stay in `project.py` and the server no longer
starts. `remove-scaffold` refuses a service whose `api.py` lacks the line
`Generated by transformatron scaffold.`; remove a hand-written one by hand, directory and imports.

Steps 1 and 4–6 work two ways. With an agent that has the `transformatron` MCP server configured
(currently Claude Code — see `AGENTS.md`), use `list_operations`, `scaffold_transform`
(`dry_run=True`), `server_restart`, `list_transforms` and `run_transform`. Otherwise use the CLI,
which calls the same code:

```bash
uv run python scripts/transformatron_cli.py restart
uv run python scripts/transformatron_cli.py list
uv run python scripts/transformatron_cli.py run <transform-id> maltego.CVE CVE-2021-44228
```

The CLI exits 1 when a run does not end in a success state, but a run that completes with zero
entities exits 0, even when it logged an `[ERROR]` and printed a warning — the exit code cannot
stand in for reading the output.

### Editing `RECORDS`

A scaffolded module declares its mapping as data. This is the EPSS module above, as written:

```python
RECORDS = Records(
    ("data",),
    primary=Entity(CVE, ("cve",), "cve"),
    props=[
        Prop("epss", ("epss",), "Epss"),
        Prop("percentile", ("percentile",), "Percentile"),
        Prop("date", ("date",), "Date"),
    ],
    enrich_input=True,
)
```

`Records`, `Entity` and `Prop` are defined in the service's `api.py`, and `map_records` walks the
table. A path is a tuple of keys from the record; a list met along it is iterated.

- `Records(path, primary=, props=, entities=, nested=, enrich_input=)`: where the records sit,
  the entity each one becomes, the properties set on it, the entities emitted beside it, and
  `nested` tables for lists of objects inside each record.
- `Entity(type, path, label, strip="")`: every value at `path` becomes an entity, linked with
  `label`; `strip` removes a prefix (`"AS"` from `AS15169`).
- `Prop(name, path, label)`: a value set on the primary entity with `set_property`. A value a
  typed property rejects is kept as `<name>.text`.

Delete a line to stop mapping a field, change a type, or move a field between `props` and
`entities`. `map_records` returns each (type, value) once, compared case-insensitively: met again
in another record, the entity gains that record's property values, distinct values joined with
`, `. It splits a multi-line value into one entity per line (not for `Phrase`); strips `*.` and a
trailing dot from domains; and skips a value equal to the input — unless `enrich_input` is set and
the primary has properties, in which case returning it adds those properties to the input entity.
`MAX_ITEMS` in `api.py` (20) caps the records read from each list and the values taken from each
field.

## Verification gate

**A success state is not evidence that a transform works.** Correction 1 produces
`State: COMPLETED (success)` with nothing in the graph, and so does a caught upstream error.

### Reading a run

`run` (CLI) and `run_transform` (MCP) print a compact summary:

```
State: COMPLETED (success)
Entities (1, 1 distinct):
  maltego.CVE  CVE-2021-44228  {epss=0.99999, percentile=1.000000000, date=2026-10-11}  [cve]
Links: 1
```

- **`Entities (N, M distinct)`** — check N > 0, and that M is close to N: fewer distinct
  (type, value) pairs means duplicates. If a transform legitimately returns nothing for an input,
  verify with one that should produce results.
- **One line per entity**: `type  value  {property=value, ...}  [link label]`. Values are clipped
  (80 characters, property values 40, eight properties then `+N more`), and blank properties
  (`None`, `[]`, empty or whitespace text) are left out. `run --json` (CLI) or `full=True` (MCP)
  prints every entity and link as the full JSON the server sent.
- **Message levels.** Each message carries the level its `context.log` call gave it: `inform` →
  `[INFO]`, `partial` → `[WARNING]`, `fatal` → `[ERROR]`, `debug` → `[DEBUG]`. `log.fatal` does
  not fail the run. An upstream 403 or 500 caught and logged that way — which is what generated
  `api.py` does — ends `COMPLETED (success)`; with no entities, a warning says so:

  ```
  State: COMPLETED (success)
  Warning: the transform logged an error and returned nothing; the success state does not mean it worked.
  Messages:
    [ERROR] Example lookup failed: API access forbidden (403)
  Entities (0, 0 distinct):
  Links: 0
  ```

- **A crash** ends `FAILED`, and the output appends the traceback the server logged during that
  run, under `Server log traceback (newest):`, ending at the line in your module that raised.

### The smoke test

```bash
uv run python scripts/smoke_test_transforms.py
uv run python scripts/smoke_test_transforms.py --setting RANSOMWARE_LIVE_API_KEY=xxx
```

It runs every registered transform against a sample input and fails on zero entities or an output
type of `NONE`. Use it after any change to `server/transforms/`. The input is `--value` if given,
else the transform's entry in a `samples.json` (the scaffolder writes one per service), else a
`TRANSFORM_SAMPLES` entry, else the per-entity-type default. A zero-entity run that logged an
`[ERROR]` fails with that message.

### Testing transforms that need credentials

Pass each one with a repeated `--setting KEY=VALUE`, the same form the CLI uses. Some outcomes are
deliberately reported as SKIP rather than FAIL, because treating them as failures teaches people
to ignore the gate:

- **A missing credential.** The transform says so explicitly; supply `--setting` to exercise it.
- **An upstream rate limit or exhausted credits** (429, 402). A fact about the account, not the
  code.
- **A sample the transform's own validation rejects.**
- **An input with no upstream match.** One sample per entity type cannot suit every transform — a
  `Company` sample that exercises a search is a substring, while a lookup needs a full
  organisation name. Add a `samples.json` or `TRANSFORM_SAMPLES` entry, keyed by transform id, to
  give a specific transform a better input.

A SKIP is not evidence a transform works. It means the gate could not judge it.

## Routing to the SDK skills

For anything not covered above, load
`server/.agents/skills/maltego-transform-skill-index/SKILL.md` — a routing table pointing to one
focused skill per task. Load one at a time; load its `references/` only when needed.

| Task | Skill |
|------|-------|
| Entity modeling, transform sets, pagination design | `maltego-transform-design` |
| Writing `@register_transform` functions, HTTP calls, settings | `maltego-transform-build` |
| Parameters, context logging, input constraints | `maltego-transform-basics` |
| Testing a running server | `maltego-transform-test` |
| Inspecting what a server exposes | `maltego-transform-discover` |
| SDK API docs and entity schemas | `maltego-transform-docs` |
| TRX migration | `maltego-trx-migration-planner` → `-implementer` |

**Port correction:** those skills default to port **8080** in their curl examples and scripts. This
project runs on **3000** unless `transformatron.toml` sets another. Pass `--port` with your port,
or use the `transformatron` MCP tools, which already target the right port and scheme.

## Worked example

`server/transforms/examples/ffraud.py` is a working reference. It demonstrates the correct
union-list return, validating `input_entity.value` before interpolating it into a URL, catching
`MaltegoException` so an upstream outage degrades to an empty result rather than a crash, and
using `.get()` throughout because the upstream omits fields rather than nulling them.

`server/transforms/ransomwarelive/` is a larger, multi-module set built on an authenticated API —
see `docs/ransomware-live.md`. It shows a shared `api.py` holding the API key setting, input
validation and error handling, so the transform modules stay declarative, plus result caps and a
schema whose field names differ between endpoints. Verify it with the project smoke test and
`--setting RANSOMWARE_LIVE_API_KEY=<key>`.

## API keys and the client re-import trap

Declare a credential as `TransformSetting(auth=True, is_global=True)` and read it with
`settings.get(NAME, "")`. `is_global=True` makes the Maltego client store one value for the whole
namespace, so it is entered once. The SDK publishes the setting to discovery under a namespaced
name (`global#<ns>.<NAME>`) and strips that prefix again before your transform sees it — look it
up by the bare name.

**Re-importing the seed can orphan the stored value.** Symptom: the transform reports the
credential as missing while the client's settings field still looks populated. Re-importing after
the seed URL changes — switching the server between HTTP and HTTPS does this — rewrites the
transform definitions, and the previously stored global value no longer resolves against the new
registration. Clear the field, apply, and re-enter the key.

Be aware this trigger was inferred from the client's on-disk timestamps, not confirmed by
capturing the client's request body; re-entering the key resolves several possible causes. If it
recurs without a scheme change, capture the raw `POST /run` body and check what the
`transformSettings` array actually contains.

For local development, a transform can fall back to an environment variable when the client
setting is empty, as `server/transforms/ransomwarelive/api.py` does:

```python
api_key = settings.get(API_KEY, "") or os.environ.get(API_KEY, "")
```

The server subprocess inherits the parent shell's environment (`lifecycle.build_server_env`), so a
key exported once survives restarts and re-imports. The client setting still wins. This is a
development convenience — it puts the key in the process environment, which is fine for a local
server and not appropriate for a shared deployment.

### Writing keys down: `.env`

Exporting works but is easy to get wrong — an export does not survive between shells, and a key
set after the server started never reaches it. Write the keys to `.env` at the repository root
instead:

```bash
cp .env.example .env   # then fill in the keys you have
```

`build_server_env` merges that file into the server subprocess on every start, and
`scripts/smoke_test_transforms.py` reads it too, so credential-gated transforms are exercised
rather than reported SKIP. **Restart the server after editing it** — the environment is read once
at start. An exported shell variable still overrides the file, and an explicit `--setting` still
overrides both.

`.env` is gitignored; `.env.example` is the committed template and must never hold a real key.

**A wrong key can be worse than no key.** Some APIs reject a key they do not recognise even on
endpoints that work fine anonymously — urlscan, for one, answers HTTP 400 to an unrecognised
`api-key` header — so a placeholder left in `.env` can break a transform that would otherwise
pass. Leave a key blank rather than filling it with something fake.

## Keeping an integration out of the repository

Anything under `server/transforms/local/` is gitignored and discovered at server start by
`discover_local_transforms` in `server/discovery.py`, which `server/project.py` calls. Use it for
integrations that should not be published; the committed packages alongside it are reference
examples and stay imported by name.

```
server/transforms/local/<service>/{__init__,api,<transform>}.py   # a package
server/transforms/local/<transform>.py                            # or a single module
```

Discovery imports every module in each package except `api.py`, plus every single-file module
directly under `local/`. Names starting with `_` are skipped at either level. No `project.py` edit
is needed — which also means the usual "did you add the import?" failure does not apply there.
Instead, the server log records what was loaded at startup (`Local transforms loaded: ...`); a
module missing from that line was not picked up. A clone without private modules still boots, and
only `local/__init__.py` is tracked.

## Security

- Do not log entity values that may contain PII — `context.log.*` messages surface in the Maltego
  client.
- Keep API keys in `TransformSetting(auth=True, is_global=True)`; never hardcode them.
- Validate `input_entity.value` before forwarding it into URLs, query parameters, or subprocess
  calls. It is user-controlled.
