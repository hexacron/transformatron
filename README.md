# transformatron

[![CI](https://github.com/hexacron/transformatron/actions/workflows/ci.yml/badge.svg)](https://github.com/hexacron/transformatron/actions/workflows/ci.yml)

Build [Maltego](https://www.maltego.com/) transforms with a coding agent, against a real server.

Maltego transforms are small functions that take one entity (an IP address, a domain, a person)
and return related entities, building up a graph. This project gives an agent the two halves it
needs to build them: a **local transform server it can drive** — start, reload after an edit, run
a transform and read back what it returned — and the **authoring guidance and scaffolding** to
write the transform in the first place.

That combination is the point. An agent that can only write code guesses at what the API returns;
an agent that can only run a server has nothing to run. Together they close the loop: scaffold from
a spec, restart, run it, see the entities, fix what the spec got wrong.

Everything works two ways: an **MCP server** for agents that speak it, and a **CLI** for humans and
any agent that can run commands. Both call the same code, so they behave identically.

> **Status:** early. Verified on macOS and Linux: CI runs the full suite on Ubuntu and macOS with
> Python 3.13 and 3.14, and a daily job starts a live server on Ubuntu and runs the keyless
> transforms against their real APIs. The Maltego desktop client has been exercised on macOS only.
> **Windows is not supported** — the lifecycle relies on POSIX signals, and its `os.kill(pid, 0)`
> liveness probe would terminate the server there. Not published to PyPI. Expect rough edges.

## Requirements

- **Python 3.13+**
- **[uv](https://docs.astral.sh/uv/)** for dependency management
- **A Maltego client** — [Maltego Desktop](https://www.maltego.com/downloads/) to actually use the
  transforms. Not needed to run the tests.
- **OpenSSL** on `PATH` (ships with macOS and most Linux distributions) — only for HTTPS certs.

## Quick start

```bash
git clone https://github.com/hexacron/transformatron.git
cd transformatron
uv sync
uv run pytest -q
```

That verifies the control plane. Then go to [Build your first
transform](#build-your-first-transform) — with an agent or by hand — and, if you have API keys to
test against, [Credentials](#credentials).

### Connecting to the Maltego desktop client

The desktop client **refuses plain-HTTP transform servers**, so HTTPS is not optional:

```
Only HTTPS (SSL/TLS) Transform Servers are allowed, but found: http://127.0.0.1:3000
```

Note that this failure happens *inside the client* — the request never reaches the server, so
nothing appears in the server log. An empty log alongside a client-side error is the signature of
this problem, not a sign the server is broken.

1. Generate a self-signed certificate (`generate_certs`).
2. Trust it. This changes system trust, so the tool prints the command rather than running it:
   ```bash
   sudo security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain .transformatron/certs/cert.pem
   ```
   That command is macOS-specific; on Linux, install the cert into your distribution's CA store.
3. Start the server with SSL (`server_restart(ssl=True)`).
4. In Maltego: **Transforms → Transform Hub → add a local hub item**, and paste the seed URL
   `https://127.0.0.1:3000/seed`.
5. Install the hub item, then right-click a matching entity to run a transform.

The server binds to `127.0.0.1` by default, which reaches a client on the same machine and nothing
else. `host` and `port` are set in `transformatron.toml` (see [Naming](#naming)). Binding a
non-loopback address such as `0.0.0.0` makes the server reachable from other machines, but two
things do not follow it:

- **The certificate** from `generate_certs` covers only `localhost` and `127.0.0.1`, so a client
  dialling any other address rejects it. A remote client needs a certificate for the address it
  dials, placed at `.transformatron/certs/cert.pem` and `key.pem`.
- **The seed URL** is built from the bind address. With `0.0.0.0` it reads
  `https://0.0.0.0:3000/seed`, which another machine cannot dial — substitute the machine's
  reachable address when registering the hub item.

## Build your first transform

Assumes `uv sync` has run.

### With an agent

Open a coding agent in the clone and start the server:

```bash
uv run python scripts/transformatron_cli.py start
```

Claude Code picks up `.claude/skills/maltego-transform-author/` from the clone; other agents read
[`AGENTS.md`](AGENTS.md). Nothing to invoke — the guidance is already loaded. Then describe what you
want:

> Build a transform for urlscan.io's search endpoint, then run it and show me the entities:
> `curl "https://urlscan.io/api/v1/search/?q=domain:example.com"`

Here is the whole session, run against the live API on 2026-10-11, and what the agent is doing at
each step. urlscan's results change by the minute, so yours will differ.

**1. It reads [`docs/transform-authoring.md`](docs/transform-authoring.md) first.** The SDK's own
guidance is wrong in two places, one of which fails silently — see [Writing
transforms](#writing-transforms) — and the skill treats reading those corrections as a
precondition for writing code.

**2. It fetches a real response and dry-runs the scaffold:**

```bash
uv run python scripts/transformatron_cli.py scaffold \
  --curl 'curl "https://urlscan.io/api/v1/search/?q=domain:example.com"' \
  --sample-response "$(curl -s 'https://urlscan.io/api/v1/search/?q=domain:example.com')" \
  --dry-run
```

```
Transforms:
  - acme.new_maltego_integration.urlscan_lookup: Urlscan: Lookup
      Phrase -> IPv4Address, URL, Domain, AS, Image (GET /api/v1/search/)
      sample input: domain:example.com

Field inventory, acme.new_maltego_integration.urlscan_lookup (path, sample, outcome):
  results[].submitter                {}                                dropped: empty in the sample
  results[].canonical.task.url       secccuurrrreeee.ink               entity URL
  results[].canonical.page.url       example.com                       entity URL
  ...
  results[].page.ip                  172.66.147.243                    entity IPv4Address (primary)
  ...
  results[].page.asn                 AS13335                           entity AS
  ...
  results[].result                   https://urlscan.io/api/v1/res...  entity URL
  results[].screenshot               https://urlscan.io/screenshot...  entity Image
  total                              5605                              dropped: envelope
  took                               2009                              dropped: envelope
  has_more                           False                             dropped: envelope
  search_date_limit_days             30                                dropped: no primary entity (list fields and input echoes are never primary); --map a single field to an entity type, or pick one with --primary
...
Next steps:
...
3. Run the same command without --dry-run to write it, restart the server, and run each transform against its sample input:
     uv run python scripts/transformatron_cli.py run acme.new_maltego_integration.urlscan_lookup maltego.Phrase domain:example.com
```

Nothing is written yet. The input side is right: `q` carries a search query, so the transform
takes a `Phrase`. Each scan becomes one `IPv4Address` carrying the scan's plain fields as
properties, with its domains, URLs and AS beside it. The inventory shows what to fix:
`canonical.*.url` holds bare hostnames typed as URLs, `result` and `screenshot` point at urlscan
itself rather than the scanned site, and `search_date_limit_days` sitting beside `results` made the
whole response one record.

**3. It fixes the mapping and writes it** — `--records` says where the records are, `--map` drops
the noise:

```bash
uv run python scripts/transformatron_cli.py scaffold \
  --curl 'curl "https://urlscan.io/api/v1/search/?q=domain:example.com"' \
  --sample-response "$(curl -s 'https://urlscan.io/api/v1/search/?q=domain:example.com')" \
  --records results --map canonical.page.url=Drop --map canonical.task.url=Drop \
  --map result=Drop --map screenshot=Drop
```

```
Transforms:
  - acme.new_maltego_integration.urlscan_lookup: Urlscan: Lookup
      Phrase -> IPv4Address, Domain, URL, AS (GET /api/v1/search/)
      sample input: domain:example.com
...
Notes:
  ...
  - The request looks paginated (response field(s) total, has_more): the transform reads the first page only, and at most MAX_ITEMS records of it (api.py). Add paging in the module if one page is not enough.

Imports added to server/project.py.

Next steps:
1. Run 'transformatron_cli.py restart' to load the new transforms.
2. Run each against its sample input and compare the entities with the field inventory above: the entity count, the types, and the values.
     uv run python scripts/transformatron_cli.py run acme.new_maltego_integration.urlscan_lookup maltego.Phrase domain:example.com
...
```

The id the server registers carries the namespace, and the printed `run` line is ready to paste.

**4. It restarts and confirms registration** — `restart`, then `list`:

```
acme.new_maltego_integration.urlscan_lookup
    Urlscan: Lookup
    maltego.Phrase -> maltego.AS, maltego.URL, maltego.Domain, maltego.IPv4Address
```

The server only loads code at startup, so an edit without a restart changes nothing. A transform
missing from `list` almost always means a missing import in `project.py`, which `scaffold` writes
for you.

**5. It runs the transform on the sample input and reads the output:**

```
State: COMPLETED (success)
Entities (41, 41 distinct):
  maltego.IPv4Address  172.66.147.243  {task.visibility=public, task.method=api, task.time=2026-10-11T17:38:19.025Z, 2026-10-11T..., task.uuid=01a12c0b-2dc1-722d-b687-4f459ed2d372,..., task.tags=@ecarlesi, possiblethreat, phishing, ..., stats.uniqIPs=2, stats.uniqCountries=2, stats.dataLength=2956, +24 more}  [page.ip]
  maltego.Domain  secccuurrrreeee.ink  [task.domain]
  maltego.URL  https://secccuurrrreeee.ink/  [task.url]
  maltego.URL  https://example.com/  [page.url]
  maltego.Domain  example.com  [page.domain]
  maltego.AS  13335  [page.asn]
  maltego.IPv4Address  2606:4700:3031::ac43:a78e  {task.visibility=public, task.method=api, task.time=2026-10-11T17:32:10.143Z, task.uuid=01a12c05-89d6-7569-b742-80203e916bbb, stats.uniqIPs=6, stats.uniqCountries=4, stats.dataLength=334590, stats.encodedDataLength=212602, +14 more}  [page.ip]
  ...
Links: 41
```

**This is the step that makes the difference.** `COMPLETED (success)` is not the answer — the
entities are. Read the count against the distinct count, the message levels (none here), the
properties and the types. Three things stand out: the properties carry noise nobody pivots on (ids,
byte counts); `page.ip` holds IPv6 addresses as well, typed `IPv4Address` — the scaffolder gives a
field one type; and `172.66.147.243` served 12 of the first 20 scans in the sample, so it is one
entity whose properties hold every scan's values, joined with `, `.

**6. It edits the mapping and goes round again.** The module's `RECORDS` table is the mapping:
deleting the `Prop` lines for `_id`, `_score`, `sort`, `task.uuid` and the two byte counts drops
those properties. Restart, run, read again:

```
  maltego.IPv4Address  2606:4700:3031::ac43:a78e  {task.visibility=public, task.method=api, task.time=2026-10-11T17:32:10.143Z, stats.uniqIPs=6, stats.uniqCountries=4, stats.requests=19, page.server=cloudflare, page.apexDomainAgeDays=61, +9 more}  [page.ip]
```

Two or three passes is normal.

**7. It gates the result:**

```bash
uv run python scripts/smoke_test_transforms.py --transform acme.new_maltego_integration.urlscan_lookup
```

```
  PASS acme.new_maltego_integration.urlscan_lookup
       41 entities from domain:example.com

1 passed, 0 failed, 0 skipped
```

The input came from the `samples.json` the scaffold wrote. Without `--transform` it runs every
registered transform, and fails on zero entities or an output type of `NONE`.

#### What you decide

The agent handles the mechanics. The judgement calls are yours:

- **Which API, and which endpoints deserve transforms.**
- **How responses map to entities.** Is `page.asn` an `AS` entity or a `Phrase`? Should an IPv6
  address in `page.ip` stay an `IPv4Address`, become a property, or get code that types it by
  version? These choices decide whether the graph can pivot on it.
- **When it is actually done.** The agent may accept one entity; you know the query should have
  returned twenty.

One habit is worth more than the rest: **when an agent says a transform works, ask what the entity
count was.** That single question catches the failure mode this project exists to prevent.

#### If the MCP tools are missing

A fresh clone prompts once for approval of the `transformatron` MCP server and needs a session
restart to load it. Until then the agent falls back to the CLI, which does exactly the same things.
Seeing it shell out to `transformatron_cli.py` instead of calling `run_transform` is expected, not
a fault.

### By hand

The same loop, driven yourself. Dry-run a scaffold, read the field inventory, then write it:

```bash
uv run python scripts/transformatron_cli.py scaffold \
  --curl 'curl https://internetdb.shodan.io/8.8.8.8' \
  --sample-response "$(curl -s https://internetdb.shodan.io/8.8.8.8)" \
  --dry-run
```

Or write a module under `server/transforms/` directly — this is the minimal shape:

```python
# server/transforms/hello.py
from maltego.entities import Domain, IPv4Address
from maltego.model.context import MaltegoContext
from maltego.server import register_transform


@register_transform(display_name="Hello: IP to Domain", transform_set="hello")
async def ip_to_domain(input_entity: IPv4Address, context: MaltegoContext) -> list[Domain]:
    """Return a fixed domain, to prove the loop works."""
    return [Domain(value="example.com")]
```

Both annotations matter: `IPv4Address` declares the input type, `list[Domain]` the output. With no
return annotation the transform registers with output `NONE` and the client cannot route it; a bare
`-> list` stops the server starting, with an error that blames `input_entity`.

A hand-written module needs its import in `server/project.py`, next to the existing ones
(`scaffold` does this for you):

```python
from transforms.hello import *  # noqa: F401,F403
```

The server only loads what `project.py` imports, and the import must sit with the others at the
top — appending it to the end of the file puts it after the `if __name__ == "__main__"` block,
where it still runs but registers nothing you can see. A transform that never appears in `list` is
almost always this.

```bash
# Reload and confirm.
uv run python scripts/transformatron_cli.py restart
uv run python scripts/transformatron_cli.py list

# Run it, and read the entity count and message levels — not just the success state.
uv run python scripts/transformatron_cli.py run \
  acme.new_maltego_integration.ip_to_domain maltego.IPv4Address 8.8.8.8

# Gate the whole set.
uv run python scripts/smoke_test_transforms.py
```

Then [connect the desktop client](#connecting-to-the-maltego-desktop-client) and run it on a real
graph.

## Scaffolding from a spec

`scaffold` turns a cURL command or an OpenAPI document into a module package under
`server/transforms/<service>/`: an `api.py` holding the base URL, auth, headers, input validators,
`fetch` and the mapping helpers; one module per transform holding its `RECORDS` table; a
`samples.json`; and the import added to `server/project.py`.

```bash
# From a cURL command, with the response from running it. --dry-run writes nothing.
uv run python scripts/transformatron_cli.py scaffold --service demo \
  --curl 'curl -H "X-API-KEY: k" https://api.demo.com/v1/ip/8.8.8.8' \
  --sample-response "$(curl -s -H 'X-API-KEY: k' https://api.demo.com/v1/ip/8.8.8.8)" \
  --dry-run

# From an OpenAPI spec — a URL, a path, or the document itself, in JSON or YAML.
# List the operations first, then scaffold the ones you want. --sample-input names a value
# the API answers for, when the spec gives the input parameter no example.
uv run python scripts/transformatron_cli.py scaffold --service demo \
  --openapi https://api.demo.com/openapi.yaml --list-operations
uv run python scripts/transformatron_cli.py scaffold --service demo \
  --openapi https://api.demo.com/openapi.yaml --operation searchHosts --sample-input 8.8.8.8
```

What it works out:

- **The input.** Whichever part of the request — a path segment, a query parameter, or a JSON or
  form body field — holds something that looks like an IP, domain, URL, email, hash or CVE, by name
  or by value. Failing that, a `Phrase`: a lone query parameter, or the path segment that looks
  most like a value (`0000-0002-1825-0097`, not `person`). A paging parameter, or an optional one
  in a spec, is never the input. Other query parameters and body fields are kept and sent with
  every request.
- **The method and body.** A cURL command with `-d`, `--json` or `-X POST` scaffolds a POST that
  sends the body with the input substituted in.
- **The request, as given.** Every cURL header is sent, plus `-A`, `-e` and `-b` — except the auth
  header (it becomes the setting) and connection headers (`Host`, `Content-Length`,
  `Accept-Encoding`, …). A cookie is copied verbatim, with a note that it may expire. Repeated
  query parameters stay repeated. What it cannot reproduce — `-u`, a proxy, `-F`, client
  certificates, `-k`, a cookie-jar file — is listed under Notes.
- **Authentication.** A key-like header, a bearer token, or a key-like query parameter
  (`apikey`, `token`, …) becomes a `TransformSetting`. A request with none of these scaffolds a
  client that needs no key. OpenAPI schemes it cannot express (OAuth2, basic) are reported, not
  guessed. Where a spec allows anonymous access — `{}` among an operation's security
  requirements, `security: []`, or no requirement — the key is sent when set and not required.
- **The outputs**, from the sample response (or the OpenAPI response schema or example, with
  `$ref`s resolved). See [The field inventory](#the-field-inventory). JSON only: a CSV or
  plain-text sample is refused. For such an API, scaffold without `--sample-response` for the
  request code, then replace `RECORDS` and the `map_records()` call with your own parsing, fetched
  through `api.client` directly, since `fetch()` returns decoded JSON only.
- **The sample input** — the value the sample response answers. For cURL it is the value in the
  request; for OpenAPI, the input parameter's `default`, first `enum` value, `example`,
  `x-example` or `examples`. `--sample-input VALUE` sets it (one operation at a time). It goes into
  `samples.json` and the printed `run` command, and lets the transform recognise the input echoed
  back in the response. An OpenAPI scaffold with none gets a Note, no `samples.json` entry, and
  `VALUE` in its `run` command; pass `--sample-input` and scaffold again.

Anything it skipped or could not express — an operation with no usable input, a path parameter
with no default, an unsupported auth scheme, pagination, request details it dropped — is listed
under **Notes** in its output. Each transform is printed under the id the server registers
(`<namespace>.<service>_<name>`), with a `run` command to paste.

### The field inventory

`scaffold` prints every leaf of the sample with what happened to it — `entity T (primary)`,
`entity T`, `property NAME`, or `dropped: <reason>`, marked `(--map)` where an override decided
it — and `--dry-run` prints the same without writing. Read it before writing anything.

- **Records.** A top-level list is the records; so is a list of objects that is the only
  substantive key of the response (`data`, `results`), also behind up to two wrapper objects
  (`{"data": {"items": [...]}}`, Elasticsearch's `hits.hits`). Envelope keys, summary keys
  (`_shards`, `aggregations`, `aggs`, `facets`) and, inside a wrapper, a float, boolean or null
  beside the list (`hits.max_score`) do not count. Anything else is one record, and lists of
  objects inside it become nested records. `--records PATH` overrides this.
- **One primary entity per record** — its strongest single-valued typed field (CVE before IP
  before domain …). A list field is never primary. A field echoing the input is primary only when
  the record is about the input (the whole response, or a top-level record whose one typed field
  it is, as in EPSS); the record's properties then enrich the input entity. The record's plain
  values become properties on the primary, and its other typed values become entities beside it,
  linked with a label made from the field's path. A top-level record with no single-valued typed
  field becomes a `Phrase` titled by `name`, `title`, `label`, `displayname`, `fullname`,
  `summary`, `id` or `identifier` (with nothing typed at all, failing those, another readable text
  field). A title must read as one: 4 characters or more, not an `ENUM_CASE` value or
  `true`/`false`/`null`/`none`/`n/a`, and a number only under `id` or `identifier`. With no title
  there is no primary, and the plain fields are dropped.
- **Types from names.** A key such as `name`, `owner`, `contact`, `state`, `region` or `province`
  types its field only from a real value, so a schema-built sample, which has none, types none of
  them (no `Person` from a pet's `name`).
- **Depth.** Typed values are followed 4 levels into a record and properties 3. Deeper fields are
  dropped, and the inventory says so.
- **Dropped**: metadata subtrees (`links`, `meta`, …), fields outside the records, empty values,
  and more than 30 properties. Envelope keys (`status`, `version`, `total`, `limit`, …) are
  dropped beside the records; when the whole response is one record, a top-level one is dropped
  only when another sits beside it — a lone `status` is the record's own field.

Change it with overrides, and repeat with `--dry-run` until it maps what an investigator needs:

- `--records PATH` — the list of records, as a dotted path: `data`, `containers.cna.references`.
- `--map PATH=TYPE` (repeatable) — one field. `TYPE` is an entity class (`Company`, `URL`, …),
  `Property` to attach it to the record's entity, or `Drop`. `PATH` is dotted, from the response
  root or from the records, with optional `[]`: `containers.cna.affected[].vendor=Company`. Depth
  limits and the property cap do not apply, and it works on a field empty in the sample or inside
  a metadata or envelope subtree. `Property` on a field in a nested list with no entity of its own
  puts it on the enclosing record's entity, every value joined with `, `
  (`containers.cna.descriptions[].value=Property` puts the description on the CVE).
- `--primary PATH` — the field that is each record's primary entity, written like a `--map` path.
  It must be a single-valued entity field, inferred or made one by `--map` in the same command;
  the error otherwise lists the fields that can be. Naming an echo of the input enriches the
  input entity with the record's properties.

A path that matches nothing is an error that points back at `--dry-run`, and so is a `--map` that
cannot be honoured (a `Property` with no entity to attach to).

### After writing: `RECORDS`

Each module declares its mapping as a `RECORDS = Records(...)` table — `Entity`, `Prop` and
`map_records` live in the service's `api.py`. **Edit that table by hand** to correct the mapping
after a live run: delete a line to stop mapping a field, change a type, move a field between
`props` and `entities`. [`docs/transform-authoring.md`](docs/transform-authoring.md#editing-records)
describes it. `map_records` returns each (type, value) once: met again in another record, the
entity gains that record's property values, distinct values joined with `, `. It splits multi-line
values, skips the input's own value, and reads at most `MAX_ITEMS` (20) records from each list.

### Services, names and ids

- **cURL transforms** get the id `<service>_<name>` and the module `<name>.py`; `--name` defaults
  to `lookup`. To grow a service endpoint by endpoint, scaffold again with the same `--service`
  and a new `--name`, no `--force`. That is refused unless the regenerated `api.py` would be
  byte-identical to the one on disk — same base URL, auth and headers, and not edited by hand —
  because the existing transforms share it.
- **OpenAPI transforms** get `<service>_<operation>` (`getIp` → `demo_get_ip`) and the module
  `<operation>.py`. GET operations are scaffolded by default; POST only when named with
  `--operation`, as is a GET whose first path-segment word, or first operationId word after a
  leading `get`/`post`/`api`/`do`, is a state-changing verb (`create`, `delete`, `remove`,
  `update`, `edit`, `login`, `logout`, `register`, `reset`, `set`, `add`, `insert`, `upload`,
  `import`, `purge`, `flush`, `revoke`, `subscribe`, `unsubscribe`, `start`, `stop`).
  `--list-operations` shows each operation's method, path, transform id, input, whether it has a
  response schema, and why it would be skipped. Over 20 operations with no `--operation` gets a
  note. A spec with no response schema gives a placeholder output: pass `--sample-response` with
  exactly one `--operation`.
- **An operationId the spec reuses** gets a distinct transform id and display name per operation,
  from the path words or parameters the others lack (`get_last_by_number`, `(by number)`),
  numbered as a last resort. `--list-operations` marks it with `*`; `--operation` with it
  scaffolds all of them, and its TRANSFORM value picks one.
- **The base URL** is the spec's server; a Swagger 2 spec with `basePath` and no `host` resolves
  it against the spec's URL.
- **Ids are global on the server**, and a duplicate stops it starting. A scaffold whose id is
  already defined anywhere under `server/transforms/` is refused before anything is written.
- **`local` is reserved** for [unpublished transforms](#transforms-you-do-not-want-to-publish).
- **An existing service** is never overwritten without `--force`, which replaces the whole service
  directory and its `project.py` imports — hand edits and other `--name` endpoints included. It
  refuses a service the scaffolder did not write (no marker line in `api.py`).
- **`remove-scaffold <service>`** deletes a scaffolded service directory and its imports. Never
  delete the directory by hand: the imports stay and the server no longer starts. It refuses a
  service whose `api.py` lacks the line `Generated by transformatron scaffold.` — a hand-written
  one, such as the bundled samples. Remove those by hand: the directory and its imports in
  `project.py`.
- **`samples.json`** maps each transform id to its sample input. The scaffold prints it, and the
  [smoke test](#smoke-testing-transforms) uses it.

**Treat the result as a first draft.** Expect the live API to disagree with the sample or the spec
about which fields are present, what a 404 means, and how errors are shaped. Run the transform on
the sample input, read the entities, and correct `RECORDS` — the loop above exists for exactly
this.

## Writing transforms

**Start with [`docs/transform-authoring.md`](docs/transform-authoring.md).**

The SDK ships its own authoring guidance in `server/.agents/skills/`, versioned with the package,
and this project does not restate it — a copy would go stale. But two of its examples are wrong:
one fails silently — the code looks right, the run reports success, and no entities come back —
and one teaches a method the SDK does not have. `docs/transform-authoring.md` corrects those, says
what never to do in a transform (block), then routes to the SDK guidance for everything else.

| Need | Use |
|------|-----|
| **Generate a starting point from an API spec** | `scaffold`, then correct it against a live run |
| **Write or change transform code** | `docs/transform-authoring.md`, then the SDK skills |
| **Run, reload, or inspect the server** | The CLI or the MCP tools |

## The loop

1. `scaffold --dry-run` from a spec and read the field inventory and Notes; fix it with
   `--records`/`--map` until it maps what matters, then scaffold for real. Or add or edit a module
   under `server/transforms/` by hand.
2. Import it in `server/project.py` (`from transforms.my_module import *`); `scaffold` does this
   for you. **The server only discovers what `project.py` imports** — this is the most common
   reason a new transform never shows up. (`server/transforms/local/` is the exception; see
   [below](#transforms-you-do-not-want-to-publish).)
3. `server_restart` — this is the reload path. It keeps the scheme the server is already
   running under, so an HTTPS server stays on HTTPS.
4. `list_transforms` to confirm it registered, then `run_transform` on the sample input — and read
   the entity count, the distinct count, the message levels and the properties, not the state.
5. Correct the mapping — edit `RECORDS`, or re-scaffold with `--force` — and go round again.
   Finish with the [smoke test](#smoke-testing-transforms).

## Commands

Every operation is available as a CLI command and as an MCP tool. Both call the same
`transformatron.operations` module, so output is identical.

| Purpose | CLI | MCP tool |
|---|---|---|
| Start the server | `start [--ssl]` | `server_start(ssl=False)` |
| Stop it | `stop` | `server_stop()` |
| Reload after a code change | `restart [--ssl\|--no-ssl]` | `server_restart()` |
| Running, healthy, transform count | `status` | `server_status()` |
| Recent log output | `logs [--lines N]` | `server_logs(lines=50)` |
| Advertised transforms and their types | `list` | `list_transforms()` |
| Detail document for one transform | `show <id>` | `get_transform(id)` |
| Advertised entity types | `entities` | `list_entities()` |
| Run one transform | `run <id> <type> <value> [--json]` | `run_transform(..., full=False)` |
| Seed URL and registration steps | `seed-url` | `get_seed_url()` |
| Self-signed cert for HTTPS | `certs [--force]` | `generate_certs(force=False)` |
| Scaffold from cURL / OpenAPI | `scaffold --curl ...\|--openapi ... [--sample-response JSON] [--sample-input VALUE] [--operation ID] [--name NAME] [--records PATH] [--map PATH=TYPE] [--primary PATH] [--dry-run] [--force]` | `scaffold_transform(..., sample_input=None, primary=None, dry_run=False)` |
| List a spec's operations | `scaffold --openapi ... --list-operations [--service S]` | `list_operations(openapi, service=None)` |
| Undo a scaffold | `remove-scaffold <service>` | `remove_scaffold(service)` |

`run` prints one line per entity — `type  value  {property=value, ...}  [link label]` — under
`Entities (N, M distinct):`, leaving out blank properties (`None`, `[]`, empty or whitespace
text, such as the SDK's default `Port` property), with each message prefixed by its level
(`[INFO]`, `[WARNING]`, `[ERROR]`, `[DEBUG]`). A success state with zero entities and an `[ERROR]`
message adds `Warning: the transform logged an error and returned nothing; the success state does
not mean it worked.` under the state. A run that ends `FAILED` also shows the traceback the server
logged during it. `--json` (`full=True`) prints every entity and link as the full JSON the server
sent. `run` or `show` with an id the server does not know prints the 404 with how to find the
right one: `list`, the `<namespace>.<id>` form when the id has no dot, and a restart for a
transform added since the server started.

CLI commands are prefixed `uv run python scripts/transformatron_cli.py`:

```bash
uv run python scripts/transformatron_cli.py restart
uv run python scripts/transformatron_cli.py list
uv run python scripts/transformatron_cli.py run <id> maltego.IPv4Address 8.8.8.8
```

Pass settings with repeated `--setting KEY=VALUE`. `--help` works on any subcommand.

The CLI exits 0 on success and 1 when the operation failed: a start, stop, restart or certificate
generation that failed, a server it could not reach (so `status` exits 1 when nothing is serving,
and `status || start` works), a run that did not end in a success state, a refused scaffold or
removal, or an unusable `transformatron.toml` (reported as one `error:` line on stderr, without a
traceback). Two outcomes do not count as failure: **a run that completes with zero entities exits
0, and so does one that completes having logged an `[ERROR]`** — the warning line above does not
change that. The output is the signal — for a gate that fails on it, use the
[smoke test](#smoke-testing-transforms).

The MCP tools read `transformatron.toml` on every call, as the CLI does, so an edit applies on the
next tool call with no MCP restart. A malformed file comes back as the tool's result rather than
stopping the MCP server loading. An unexpected crash inside a tool reaches the agent as
`Error executing tool <name>: <ExceptionType>: <message>`; its traceback is on the MCP server's
stderr.

Adding an operation? Put it in `src/transformatron/operations.py` and both front ends get it.

## Credentials

In real use, an API key belongs in the Maltego client's transform settings — declared with
`TransformSetting(auth=True, is_global=True)`, entered once, reused by every transform in the set.
Nothing needs configuring on the server for that path to work.

For headless runs there is no client to enter it into, so transforms fall back to the process
environment. Copy the template and fill in what you have:

```bash
cp .env.example .env
```

`.env` is read when the server starts and merged into its environment, so a key written once
survives restarts. The smoke test reads it too, which is the difference between a credential-gated
transform being exercised and being reported SKIP. In both, an exported shell variable beats the
file, and for the smoke test an explicit `--setting` beats both.

`.env` is gitignored. `.env.example` is the committed template and holds no values. This is a
development convenience: it puts keys in the server process's environment, visible to anyone who
can read `ps`. Restart after editing it — the environment is read once, at start.

## Transforms you do not want to publish

Anything under `server/transforms/local/` is gitignored and discovered automatically when the
server starts. Use it for integrations that should not be committed — an internal API, a
client-specific lookup, work in progress.

Both shapes are picked up: a package (`local/<service>/` with an `__init__.py`), from which every
module except `api.py` is imported, and a single-file module directly under `local/`
(`local/lookup.py`). Names starting with `_` are skipped at either level, so helpers can sit
alongside. The server log records what was loaded at startup — `Local transforms loaded: ...` —
so check `logs` when a local transform is missing from `list`.

It is discovered rather than imported by name, because a clone without the private modules must
still boot, and a static import of a missing module stops the server booting. The committed
examples alongside it keep their explicit imports in `project.py`.

## Using it with a coding agent

An agent working in this repository can scaffold a transform from an API spec, restart the server
to load it, run it against a real input, read back the entities it produced, and gate the whole set
with the smoke test. That is the loop — and because every step reports what actually happened, the
agent can tell a working transform from one that reports success and returns nothing.

What it reads:

| Agent | Entry point |
|---|---|
| **Claude Code** | `.claude/skills/maltego-transform-author/`, which ships with the clone |
| **Codex, Gemini CLI, others** | [`AGENTS.md`](AGENTS.md), per the [AGENTS.md](https://agents.md) convention |

`CLAUDE.md` points at `AGENTS.md` so the two cannot drift. Both route to
`docs/transform-authoring.md` for the SDK corrections.

Any agent that can run shell commands can drive the server through the CLI — no MCP required.

For **Claude Code**, the MCP server is registered at project scope in `.mcp.json`, so a fresh clone
picks it up automatically. It needs a session restart to load and prompts once for approval. That
approval is recorded in `.claude/settings.local.json`, which is per-machine and gitignored, so a
fresh clone prompts again — expected, not a bug. If the tools are unavailable, the CLI does
everything they do.

If you are modifying this project's own code under `src/transformatron/`, note that the MCP tools
run the version loaded when the session started, so your edits will not show up there until you
relaunch. The CLI always runs current code. `AGENTS.md` has the details — this does not affect
editing transforms under `server/transforms/`, nor `transformatron.toml`, which the tools read on
every call.

## Using it from Python

The same operations work directly:

```python
import asyncio
from transformatron import lifecycle
from transformatron.client import TransformClient
from transformatron.config import load_config

config = load_config()
lifecycle.start(config, ssl=True)


async def main() -> None:
    client = TransformClient(lifecycle.resolve_config(config))
    for transform in await client.list_transforms():
        print(transform["name"])


asyncio.run(main())
```

Run it with `uv run python your_script.py`.

## The sample transforms

Several worked examples ship with the project. All are **illustrative samples, not maintained
integrations** — delete whichever you do not need, along with its import in `server/project.py`.

| Example | Shows | Key |
|---|---|---|
| `server/transforms/rdap/` | Registration data, no API key — pivotable output, redirect handling | no |
| `server/transforms/examples/ffraud.py` | Single module, no API key — the minimal shape | no |
| `server/transforms/ransomwarelive/` | Multi-module, shared client, upstream field drift | yes |
| `server/transforms/greynoise/` | 404 as a verdict, silent key acceptance, tight quota | yes |
| `server/transforms/ipinfo/` | Bearer auth, one response fanned out to several entities | yes |
| `server/transforms/crowdsec/` | Minimal authenticated lookup | yes |

Start from `ffraud.py` if you are learning the shape. Start from `ransomwarelive/` if your API
needs a key — it is documented in [`docs/ransomware-live.md`](docs/ransomware-live.md) and shows
the parts the simple example cannot: declaring one credential across a whole transform set,
keeping validation and error handling in a shared `api.py`, capping result sizes so a large
upstream response does not flood the graph, and normalising a schema whose field names differ
between endpoints. It needs a [ransomware.live](https://www.ransomware.live/) API key to run.

`greynoise/` is worth reading for what a spec cannot tell you: an unrecognised key is accepted
silently, so a successful lookup is not evidence the key is valid; HTTP 404 is a real verdict
("never observed scanning") rather than a failure; and the free tier allows roughly 25 lookups a
week, which the smoke test can spend in one pass. Every one of those was found by running it, not
by reading the documentation.

### RDAP

Against [RDAP](https://datatracker.ietf.org/doc/html/rfc9083), the IETF protocol that replaced
WHOIS. Registries serve it themselves, so the data is authoritative rather than scraped, and it
needs **no API key or registration** — these run on a fresh clone.

Three transforms, all taking `maltego.Domain`:

| Transform | Returns |
|---|---|
| RDAP: Domain to Registration | `Phrase` — registration and expiry dates, notable status, registrar |
| RDAP: Domain to Nameservers | `DNSName` — the delegated nameservers |
| RDAP: Domain to Abuse Contact | `EmailAddress`, `PhoneNumber` — the registrar's abuse contacts |

Start here if you are learning the shape. It is the closest of the samples to real investigative
work: nameservers shared across unrelated domains are a standard way to group infrastructure, and
the abuse contact is where a takedown request goes.

Two things it demonstrates that the simpler sample cannot:

- **Following a redirect safely.** `rdap.org` holds no data; it answers with a 302 to whichever
  registry owns the TLD. The SDK's client sets `follow_redirects=False` deliberately, because
  following one silently would send your headers to a host the transform never chose. The hop is
  taken explicitly, once, and only to an `https` target.
- **Reading a response off an exception.** The client returns only 2xx and raises on everything
  else, so that 302 arrives as `MaltegoHTTPDataProviderInvalidResponse` rather than as a response
  you can inspect. Catching and logging it — the natural thing to write — yields zero entities and
  still reports success. The redirect target has to come off the exception's `response`.

Note that `example.com` is registered through IANA's reserved-name process and publishes no abuse
contact, which is why the smoke test pins `python.org` for that transform.

### ffraud

Against [ffraud.com](https://ffraud.com/docs), a third-party IP reputation API this project has no
affiliation with. It needs no API key, so it runs on a fresh clone.

Three transforms, all taking `maltego.IPv4Address`:

| Transform | Returns |
|---|---|
| ffraud: IP Reputation | `Phrase` — fraud score, risk band, detection flags, threat tags |
| ffraud: IP to Network Details | `AS`, `ISP`, `DNSName`, `Location` |
| ffraud: IP to Abuse Contact | `EmailAddress` from WHOIS |

Worth reading for the patterns it demonstrates: validating `input_entity.value` before
interpolating it into a URL, catching `MaltegoException` so an upstream outage degrades to an
empty result instead of a crash, and using `.get()` throughout because the API omits fields rather
than nulling them.

**Caveat on the data:** upstream coverage is uneven. A known Tor exit node returned
`fraud_score: 0, risk: none` with `tor: false` during testing, and sample responses carried
`data_completeness: 0.5`. Treat the scores as illustrative. To delete the sample, remove the
directory and its import in `server/project.py`.

## Layout

```
src/transformatron/
  operations.py  server operations shared by both front ends — add new ones here
  config.py      TransformatronConfig — host, port, scheme, derived URLs and state paths
  client.py      async v3 protocol client; the run→poll→flatten state machine
  lifecycle.py   start/stop/restart/status/logs over a detached subprocess
  certs.py       self-signed certificate generation
  envfile.py     reads .env so headless runs can reach credentials
  scaffold/      spec → module package: parser.py, generator.py, schema.py
  mcp.py         MCP front end
scripts/
  transformatron_cli.py     CLI front end
  smoke_test_transforms.py  runs every transform, fails on zero entities
server/          SDK-generated (`maltego-transforms start server --with-skills`).
                 .agents/, project.py and __init__.py are upstream-owned and excluded from
                 ruff so regeneration does not churn; the rest is linted.
  project.py     entrypoint; imports decide what gets registered. Also bounds HTTPS shutdown
  discovery.py   finds and imports the modules under transforms/local/
  transforms/    your transform modules go here — linted like the rest of the project
    local/       gitignored; packages and single modules discovered at startup
.claude/skills/
  maltego-transform-author/  authoring checklist; points at docs/, not a second copy
docs/
  transform-authoring.md   read before writing a transform
  ransomware-live.md       the authenticated worked example
  ipinfo.md                bearer auth, one response to several entities
  upstream-sdk-issue.md    draft bug report, not yet filed
  upstream-sdk-shutdown-issue.md  draft report on shutdown stalls, not yet filed
CHANGELOG.md     what changed, per release
tests/           unit tests for the control plane and the scaffolder
transformatron.toml  server name, namespace, author, host, port. Gitignored; copy the .example.
.env             API keys for headless runs. Gitignored; .env.example is the template.
.transformatron/ runtime state — PID, log, certs, recorded scheme. Gitignored.
```

## Gotchas

Things that cost real debugging time, recorded so they cost you less:

- **A transform missing from `list_transforms`, or showing output type `NONE`,** almost always
  means a missing import or a missing annotation. Input type comes from the parameter annotation,
  output from the return annotation: with no return annotation the output is `NONE` and the client
  cannot route it. A bare `-> list` is worse — the server does not start, and the registration
  error blames `input_entity` rather than the return type.

- **Returning a `MaltegoGraph` from an `async` transform silently yields zero entities.** The run
  still reports success. In the SDK's `__handle_async_result`, a returned graph fails both
  `isinstance` branches and is dropped; the generator branch skips graphs too, so this affects
  every async path. Return a list — `-> list[AS | ISP]` still publishes every output type to
  discovery. This contradicts the SDK's own shipped guidance, which teaches the broken pattern;
  see `docs/transform-authoring.md` and the draft report in `docs/upstream-sdk-issue.md`.

- **`entity.add_property` does not exist,** though the SDK skills teach it. Use
  `set_property(name, value, display_name=...)`, and assign typed attributes after construction
  (`cve.epss = 0.9`), not as constructor arguments.

- **A success state is not proof a transform works.** Check the entity count and the message
  levels, or run `scripts/smoke_test_transforms.py`. An upstream 403 or 500 caught and logged with
  `context.log.fatal` shows as `[ERROR]` and still ends `COMPLETED (success)`.

- **Never block in a transform** — no `requests`, synchronous `httpx`, or `time.sleep`. A blocking
  call pins the SDK's runner thread, and shutdown waits for it with no limit, so `stop` and
  `restart` give up after 10s and kill the server.

- **When `stop` has to kill the server, it says why** — a transform blocking the runner thread,
  open client connections, a TLS handshake that never finished — read from the server log since
  the stop began. Nothing is lost: the server keeps no state a clean shutdown would save. On HTTPS,
  a connected Maltego Desktop holds keep-alive connections that uvicorn would wait up to 30s for,
  and a connection that never completes its handshake up to 60s. `server/project.py` bounds that
  wait to about 3s (`GRACEFUL_SHUTDOWN_TIMEOUT`), which logs a harmless `ERROR` line from uvicorn,
  `Cancel 0 running task(s), timeout graceful shutdown exceeded`. It is a workaround until the SDK
  exposes the setting — see [`docs/upstream-sdk-shutdown-issue.md`](docs/upstream-sdk-shutdown-issue.md).
  A freshly generated `project.py` does not have it.

- **An API key entered in the client can stop reaching the transform after a seed re-import.**
  The symptom is a transform reporting the key as missing while the client's settings field still
  looks populated. Re-importing after the seed URL changes — switching the server between HTTP and
  HTTPS does this — rewrites the transform definitions and orphans the stored global value. Clear
  the field, apply, then re-enter the key. See
  [`docs/transform-authoring.md`](docs/transform-authoring.md) for the environment-variable
  fallback that avoids this during development.

- **A successful lookup is not proof the API key is valid.** Some upstreams accept an unrecognised
  key and answer normally — GreyNoise does — so there is no auth-failure path to catch and no
  signal that the key is wrong until a quota or a permission boundary exposes it. Verify a key
  against something that requires it, not against a call that happens to succeed.

- **The desktop client requires HTTPS** (see [above](#connecting-to-the-maltego-desktop-client)).

- **The server runs on port 3000** unless `transformatron.toml` sets another. The SDK's own skill
  scripts default to 8080 — pass `--port` with your port if you invoke them directly.

- **`MALTEGO_SERVER_*` environment variables take precedence** over the values hardcoded in
  `project.py`. That is how the lifecycle tools set host, port, and scheme without editing the
  generated file.

- **The scheme is runtime state,** recorded in `.transformatron/server.scheme`. `project.py`
  defaults to `https`, but the lifecycle tools override the scheme per start, so that file is the
  only way the control plane knows which scheme to address a running server over.

## Development

```bash
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run ty check src tests scripts
```

`server/.agents/`, `server/project.py` and `server/__init__.py` are excluded from linting: the SDK
owns them, and regenerating would churn against upstream. The rest of `server/` —
`transforms/`, `middleware.py`, `discovery.py` — is your code and is linted like the rest of the
project, including anything `scaffold` generates.

### Smoke-testing transforms

```bash
uv run python scripts/smoke_test_transforms.py
uv run python scripts/smoke_test_transforms.py --setting API_KEY=xxx
```

Runs every registered transform against a sample input and **fails on zero entities** or an output
type of `NONE` — the failure modes that otherwise report success. Exits non-zero, so it works as a
gate. Run it after any change under `server/transforms/`.

The input is `--value` if given, else the transform's entry in a `samples.json` beside it (the
scaffolder writes one per service), else a `TRANSFORM_SAMPLES` entry in the script, else the
per-entity-type default. A zero-entity run that logged an `[ERROR]` fails with that message.

Transforms needing credentials take them through repeated `--setting KEY=VALUE`, or from `.env`
(see [Credentials](#credentials)). Five outcomes report SKIP rather than FAIL — a missing
credential, an upstream rate limit (429), exhausted credits (402), a sample input the transform's
own validation rejects, and an input the upstream has no match for — so neither an unconfigured
key nor a spent quota is mistaken for broken code. A SKIP is not evidence a transform works; it
means the gate could not judge it. Add a `samples.json` or `TRANSFORM_SAMPLES` entry when the
per-entity-type sample does not suit a transform.

Transforms calling third-party APIs make live network requests, so a failure can mean an upstream
outage rather than broken code; check the reported message. Override the input with `--value`, or
check one transform with `--transform <id>`.

## Naming

A fresh clone runs under the SDK's placeholder identity — `New Maltego Integration`,
`acme.new_maltego_integration`, `Acme Corp`. Change it before publishing anything: the namespace
is part of every transform's fully qualified ID, so two servers that share one collide in the
same client.

Copy the template and edit it:

```bash
cp transformatron.toml.example transformatron.toml
```

```toml
[server]
server_name = "Acme Threat Intel"
namespace   = "acme.threat_intel"
author      = "Acme Corp"
```

`transformatron.toml` is gitignored, so your identity does not travel with a fork. The CLI and
MCP server read it on every command or tool call and pass it to the transform server as
`MALTEGO_SERVER_*` variables, which outrank the values in `server/project.py` — so **you never
edit `project.py` to rename a server**. The same file sets `host` and `port` (see
`transformatron.toml.example`). Nothing needs relaunching to pick up an edit except the transform
server itself, which takes these values at start. Restart it to apply, then confirm:

```bash
uv run python scripts/transformatron_cli.py restart
uv run python scripts/transformatron_cli.py list   # ids now carry your namespace
```

The values in `server/project.py` remain as fallbacks for running that file directly.

## License

MIT — see [LICENSE](LICENSE).

Maltego is a trademark of Maltego Technologies GmbH.
