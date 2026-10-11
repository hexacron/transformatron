"""Parsers for converting cURL commands and OpenAPI specs into a service config."""

from __future__ import annotations

import json
import keyword
import re
import shlex
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, unquote, urljoin, urlparse

import yaml

from transformatron.scaffold.schema import (
    MappingResult,
    ScaffoldServiceConfig,
    ScaffoldTransformConfig,
    humanize,
    infer_input_entity,
    infer_mapping,
    key_tokens,
    looks_like_file_name,
    squash,
)

# Query parameters that carry a credential rather than the thing being looked up.
_AUTH_QUERY_RE = re.compile(
    r"^(api[_-]?key|apikey|key|token|access[_-]?token|auth[_-]?token|auth)$", re.I
)
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_GENERIC_HOST_LABELS = frozenset(
    {"api", "www", "v1", "v2", "v3", "pub", "public", "rest", "services", "gateway"}
)
# Module names a transform may not take: `api` is the shared client, `samples` sits beside
# it as samples.json, and a dunder would shadow the package itself.
_RESERVED_MODULES = frozenset({"api", "samples", "__init__"})

# curl options whose value is irrelevant to what the API returns.
_CURL_IGNORED_VALUE_FLAGS = frozenset(
    {"-o", "--output", "-m", "--max-time", "--connect-timeout", "--retry", "-w", "--write-out"}
)
# curl options with a value the generated client does not reproduce; each is noted.
_CURL_UNSUPPORTED_VALUE_FLAGS = {
    "-x": "a proxy (-x)",
    "--proxy": "a proxy (--proxy)",
    "-F": "multipart form fields (-F)",
    "--form": "multipart form fields (--form)",
    "-E": "a client certificate (-E)",
    "--cert": "a client certificate (--cert)",
    "--key": "a client key (--key)",
}
_CURL_DATA_FLAGS = frozenset(
    {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode"}
)
# Headers that describe the connection rather than the request. httpx sets them itself,
# and a copied `Accept-Encoding: br, zstd` would ask for encodings it may not decode.
_CONNECTION_HEADERS = frozenset(
    {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "te"}
    | {"keep-alive", "upgrade"}
)

_DISPLAY_NAME_LIMIT = 80
_ELLIPSIS = "\u2026"
_SEARCH_FIELD_RE = re.compile(
    r"^(q|query|search|term|keyword|keywords|text|name|username|user|value)$", re.I
)
# Parameters that page or order a result. They are never the thing looked up, and their
# presence means the transform sees one page only.
_PAGING_PARAMS = frozenset(
    {"page", "pagenumber", "limit", "offset", "cursor", "perpage", "pagesize", "size", "sort"}
    | {"order", "orderby", "sortby", "start", "after", "before", "count", "pagetoken"}
)
# A path segment that names the resource or the API version rather than carrying a value.
_RESOURCE_WORDS = frozenset(
    {"api", "rest", "json", "xml", "lookup", "search", "query", "info", "details", "detail"}
    | {"data", "person", "people", "profile", "profiles", "user", "users", "repos", "items"}
    | {"item", "record", "records", "summary", "report", "reports", "latest", "current"}
    | {"public", "v"}
)
_VERSION_SEGMENT_RE = re.compile(r"^(v\d+(\.\d+)*|\d+\.\d+)$", re.I)
# Verbs that mean a GET operation changes state upstream (CIRCL's
# `GET /session/create/{name}`): scaffolding it would make a lookup that writes. They count
# only where a verb sits, the first word of a path segment or of the operationId, so a
# resource named `session` or an id like `getLastUpdate` is not mistaken for one.
_STATE_CHANGING_WORDS = frozenset(
    {"create", "delete", "remove", "update", "edit", "login", "logout", "register", "reset"}
    | {"set", "add", "insert", "upload", "import", "purge", "flush", "revoke", "subscribe"}
    | {"unsubscribe", "start", "stop"}
)
# Words an operationId may start with before its verb: `get_session_create`.
_OPERATION_PREFIXES = frozenset({"get", "post", "api", "do"})
_MANY_OPERATIONS = 20


def _slugify(text: str) -> str:
    """Convert text into an ASCII snake_case slug; ``getPetById`` becomes ``get_pet_by_id``.

    ASCII only, and never ending in an underscore: the SDK rejects transform names outside
    ``[A-Za-z0-9_.-]`` or ending in a separator, and it rejects them when the server
    starts, so a bad name takes every other transform down with it.
    """
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text.strip())
    text = re.sub(r"[^a-z0-9\s_-]", "", text.lower())
    return re.sub(r"[-\s_]+", "_", text).strip("_")


def _is_identifier(name: str) -> bool:
    return name.isidentifier() and not keyword.iskeyword(name)


def _service_id(service_name: str | None, derived: str) -> str:
    """Return the package name for the service, or raise if it cannot be one.

    The id becomes a directory under ``transforms/`` and a dotted import in
    ``project.py``, so anything that is not a Python identifier breaks the server's startup
    import — and a path separator would write outside ``transforms/`` altogether.
    """
    if service_name is not None:
        svc_id = _slugify(service_name)
        if not _SERVICE_NAME_RE.match(service_name) or not _is_identifier(svc_id):
            raise ValueError(
                f"Service name {service_name!r} is not usable as a package name. Use letters, "
                "digits, underscores and hyphens, starting with a letter, and not a Python "
                "keyword."
            )
        return svc_id
    if not _is_identifier(derived):
        raise ValueError(
            f"Could not derive a package name from {derived!r}. Pass a service name, e.g. "
            "--service my_api."
        )
    return derived


def _function_name(text: str) -> str:
    """Return a Python function name for an operation id."""
    slug = _slugify(text)
    if not slug:
        return "operation"
    return slug if _is_identifier(slug) else f"op_{slug}"


def _transform_id(svc_id: str, name: str) -> str:
    """Return the service-prefixed transform id for a name.

    Transform ids are global on the server: two services each defining ``lookup`` would
    stop it from starting, so every id carries its service. A name that already starts
    with the service is not prefixed twice.
    """
    return name if name.startswith(f"{svc_id}_") else f"{svc_id}_{name}"


def _display_name(title: str, summary: str, qualifier: str = "") -> str:
    """Return ``title: summary (qualifier)`` short enough for a Maltego menu and the line limit.

    Measured escaped, because that is how it is written into the generated module: a
    ``display_name=`` argument longer than the line limit fails the project's lint gate.
    A long summary is cut at a word and marked with an ellipsis character (escaped in the
    source, so it stays lint-clean); the qualifier telling duplicates apart is always kept.
    """
    tail = f" ({qualifier})" if qualifier else ""
    name = f"{title}: {' '.join(summary.split())}"

    def fits(text: str) -> bool:
        return len(json.dumps(text + tail)) - 2 <= _DISPLAY_NAME_LIMIT

    if fits(name):
        return name + tail
    words = name.split(" ")
    while len(words) > 1 and not fits(" ".join(words) + _ELLIPSIS):
        words.pop()
    return " ".join(words).rstrip(",;:.-") + _ELLIPSIS + tail


def _load_sample(sample_response: Any) -> Any:
    if isinstance(sample_response, str):
        try:
            return json.loads(sample_response)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"The sample response is not valid JSON ({exc}). The scaffolder maps JSON "
                "responses only; CSV and plain-text responses are not supported. Write the "
                "parsing by hand: scaffold without --sample-response to get the request code, "
                "then in the module replace RECORDS and map_records() with code that parses "
                "the text, requested through api.client directly, since fetch() only returns "
                "decoded JSON."
            ) from exc
    return sample_response


def _multi(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """Collect key/value pairs, keeping a repeated key's values as a list.

    ``expand=dns_names&expand=issuer`` must go out as both values; a plain dict keeps the
    last one, and certspotter then answers without the DNS names asked for.
    """
    collected: dict[str, Any] = {}
    for key, value in pairs:
        if key not in collected:
            collected[key] = value
        elif isinstance(collected[key], list):
            collected[key].append(value)
        else:
            collected[key] = [collected[key], value]
    return collected


def _is_paging(name: str) -> bool:
    return squash(name) in _PAGING_PARAMS


def _pagination_note(where: str, request: list[str], response: list[str]) -> str:
    signals = []
    if request:
        signals.append(f"request parameter(s) {', '.join(request)}")
    if response:
        signals.append(f"response field(s) {', '.join(response)}")
    return (
        f"{where} looks paginated ({' and '.join(signals)}): the transform reads the first "
        "page only, and at most MAX_ITEMS records of it (api.py). Add paging in the module "
        "if one page is not enough."
    )


def _apply_mapping(
    transform: ScaffoldTransformConfig,
    sample: Any,
    records: str | None,
    mappings: list[str] | None,
    primary: str | None,
) -> MappingResult:
    result = infer_mapping(sample, records, mappings, transform.sample_input, primary)
    transform.mapping = result.mapping
    transform.inventory = result.inventory
    return result


# A pointer to --dry-run is always the note's last sentence and starts "Preview with
# --dry-run": a dry-run front end cuts it there rather than tell the author to do what they
# are already doing.
_PLACEHOLDER_NOTE = (
    "reads a placeholder `result` field: nothing showed what the response looks like. "
    "Scaffold again with --sample-response, or edit RECORDS in the module. Preview with "
    "--dry-run to see the field inventory first."
)


# ---------------------------------------------------------------------------------------
# cURL
# ---------------------------------------------------------------------------------------


def _parse_body(raw: str) -> tuple[dict[str, Any], str]:
    """Return a request body and its encoding: a JSON object, or form fields."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
        return _multi(pairs), "form"
    if not isinstance(parsed, dict):
        raise ValueError(
            "The request body is JSON but not an object. Scaffolding supports object bodies "
            "and form fields; write this request by hand."
        )
    return parsed, "json"


def _auth_header(headers: dict[str, str]) -> str | None:
    """Return the header carrying the credential, if any.

    ``Authorization`` first, then a key, then anything auth- or token-like: a browser's
    copied command can carry an ``X-CSRF-Token`` beside the real ``X-Api-Key``.
    """
    names = list(headers)
    for test in (
        lambda n: n.lower() == "authorization",
        lambda n: "key" in n.lower(),
        lambda n: "auth" in n.lower(),
        lambda n: "token" in n.lower(),
    ):
        found = next((name for name in names if test(name)), None)
        if found is not None:
            return found
    return None


def _segment_score(segment: str) -> int:
    """Score how much a path segment looks like a value rather than a resource name.

    ``/v3.0/0000-0002-1825-0097/person`` must template the ORCID id, not ``person``.
    """
    if (
        _VERSION_SEGMENT_RE.match(segment)
        or segment.lower() in _RESOURCE_WORDS
        or looks_like_file_name(segment)
    ):
        return 0
    if any(char.isdigit() for char in segment):
        return 3
    if re.search(r"[-_.@:~]", segment) or (segment not in (segment.lower(), segment.upper())):
        return 2
    return 1


def parse_curl_command(
    curl_cmd: str,
    sample_response: dict[str, Any] | list[Any] | str | None = None,
    service_name: str | None = None,
    transform_name: str | None = None,
    records: str | None = None,
    mappings: list[str] | None = None,
    sample_input: str | None = None,
    primary: str | None = None,
) -> ScaffoldServiceConfig:
    """Parse a cURL command and optional sample JSON response into a service config.

    Args:
        curl_cmd: The command, as copied from a browser or API docs.
        sample_response: The JSON the command returned, to map the output from.
        service_name: Package name for the service; derived from the host if omitted.
        transform_name: Name of this endpoint within the service (``lookup`` by default),
            so one service can grow endpoint by endpoint.
        records: Dotted path to the list of records in the response.
        mappings: ``PATH=TYPE`` overrides of the inferred mapping.
        sample_input: The input value the sample response answers, recorded in
            samples.json and used to tell an echo of the input apart; the value in the
            request by default.
        primary: Dotted path of the field to use as each record's primary entity.

    Raises:
        ValueError: If the command has no URL, the sample is not JSON, a name is unusable,
            or ``records``/``mappings``/``primary`` do not fit the sample.
    """
    tokens = shlex.split(re.sub(r"\\\s*\n", " ", curl_cmd.strip()))

    method: str | None = None
    url = ""
    headers: dict[str, str] = {}
    cookies: list[str] = []
    data_parts: list[str] = []
    data_in_query = False
    notes: list[str] = []
    unsupported: list[str] = []

    i = 0
    while i < len(tokens):
        token = tokens[i]
        value = tokens[i + 1] if i + 1 < len(tokens) else None
        if token in ("-X", "--request") and value is not None:
            method = value.upper()
        elif token in ("-H", "--header") and value is not None:
            key, sep, header_value = value.partition(":")
            if sep and key.strip():
                if key.strip().lower() == "cookie":
                    cookies.append(header_value.strip())
                else:
                    headers[key.strip()] = header_value.strip()
        elif token in ("-A", "--user-agent") and value is not None:
            headers["User-Agent"] = value
        elif token in ("-e", "--referer") and value is not None:
            headers["Referer"] = value.removesuffix(";auto")
        elif token in ("-b", "--cookie") and value is not None:
            if "=" in value:
                cookies.append(value)
            else:
                unsupported.append(f"a cookie jar file (-b {value})")
        elif (token in _CURL_DATA_FLAGS or token == "--json") and value is not None:
            data_parts.append(value)
        elif token == "--url" and value is not None:
            url = value
        elif token in ("-u", "--user") and value is not None:
            unsupported.append("basic authentication (-u)")
        elif token in _CURL_UNSUPPORTED_VALUE_FLAGS and value is not None:
            unsupported.append(_CURL_UNSUPPORTED_VALUE_FLAGS[token])
        elif token in _CURL_IGNORED_VALUE_FLAGS and value is not None:
            pass
        else:
            if token in ("-G", "--get"):
                data_in_query = True
            elif token in ("-k", "--insecure"):
                unsupported.append("skipping TLS verification (-k)")
            elif not url and not token.startswith("-") and re.match(r"^https?://", token):
                url = token
            i += 1
            continue
        i += 2

    if not url:
        raise ValueError("Could not find an http:// or https:// URL in the cURL command.")
    if cookies:
        headers["Cookie"] = "; ".join(cookies)
        notes.append(
            "The Cookie header is copied into api.py as given; if it holds a session, it "
            "will expire. Move it into a setting if the API needs a fresh one."
        )

    parsed_url = urlparse(url)
    host = parsed_url.hostname or ""
    labels = host.split(".")
    derived = _slugify(labels[0]) if labels else "service"
    if derived in _GENERIC_HOST_LABELS and len(labels) >= 2:
        derived = _slugify(labels[-2])
    svc_id = _service_id(service_name, derived)
    svc_title = svc_id.replace("_", " ").title()
    endpoint = _endpoint_name(transform_name)

    # Authentication: a key-like header, or a key-like query parameter. The value itself
    # is never written into the code; the generated client reads it from a setting.
    auth_type = "none"
    auth_header_name = _auth_header(headers)
    auth_query_param: str | None = None
    if auth_header_name is not None:
        auth_value = headers.pop(auth_header_name)
        auth_type = "bearer" if auth_value.lower().startswith("bearer") else "header"

    dropped = [name for name in headers if name.lower() in _CONNECTION_HEADERS]
    for name in dropped:
        del headers[name]

    query = _multi(parse_qsl(parsed_url.query, keep_blank_values=True))
    for q_name in list(query):
        if _AUTH_QUERY_RE.match(q_name):
            del query[q_name]
            if auth_type == "none":
                auth_type = "query"
                auth_query_param = q_name

    body: dict[str, Any] | None = None
    body_encoding = "json"
    if data_parts:
        raw_body = "&".join(data_parts)
        if data_in_query:
            for key, value in _multi(parse_qsl(raw_body, keep_blank_values=True)).items():
                query[key] = value
        else:
            body, body_encoding = _parse_body(raw_body)
    http_method = method or ("POST" if body is not None else "GET")

    path = parsed_url.path or "/"
    segments = [s for s in path.split("/") if s]
    chosen = _curl_input(query, body, segments)
    if chosen is None:
        raise ValueError(
            "Could not tell which part of the request carries the input. Put a real sample "
            "value (an IP, a domain, a username) in the URL, query string, or body."
        )

    location, key, request_value = chosen
    input_entity = infer_input_entity(str(key) if location != "path" else "", request_value)[0]
    endpoint_path = path
    input_param_name = "target"
    if location == "path":
        parts = [seg if idx != key else "{target}" for idx, seg in enumerate(segments)]
        endpoint_path = "/" + "/".join(parts) + ("/" if path.endswith("/") else "")
    else:
        input_param_name = str(key)

    transform = ScaffoldTransformConfig(
        transform_id=_transform_id(svc_id, endpoint),
        display_name=f"{svc_title}: {humanize(endpoint)}",
        input_entity=input_entity,
        endpoint_path=endpoint_path,
        input_param_name=input_param_name,
        input_location=location,
        http_method=http_method,
        description=f"Look up a {input_entity} with {svc_title}.",
        query_params=query,
        request_body=body,
        body_encoding=body_encoding,
        sample_input=_explicit(sample_input) or request_value or None,
    )
    sample = _load_sample(sample_response)
    result = _apply_mapping(transform, sample, records, mappings, primary)

    if unsupported:
        notes.append(
            f"Not reproduced from the cURL command: {', '.join(unsupported)}. Add it to "
            "api.py by hand if the API needs it."
        )
    if dropped:
        notes.append(
            f"Not sent: {', '.join(dropped)} (connection headers httpx sets itself). Every "
            "other header is sent as given (HEADERS in api.py)."
        )
    if result.placeholder:
        notes.append(f"{transform.transform_id} {_PLACEHOLDER_NOTE}")
    notes.extend(result.notes)
    paging_params = [name for name in query if _is_paging(name)]
    if paging_params or result.pagination:
        notes.append(_pagination_note("The request", paging_params, result.pagination))

    return ScaffoldServiceConfig(
        service_id=svc_id,
        display_name=svc_title,
        base_url=f"{parsed_url.scheme}://{parsed_url.netloc}",
        auth_key_name=f"{svc_id.upper()}_API_KEY" if auth_type != "none" else None,
        auth_header_name=auth_header_name,
        auth_query_param=auth_query_param,
        auth_type=auth_type,
        headers=headers,
        transforms=[transform],
        notes=notes,
    )


def _explicit(sample_input: str | None) -> str | None:
    """Return a caller-given sample input, or None when it is absent or blank."""
    text = sample_input.strip() if sample_input is not None else ""
    return text or None


def _endpoint_name(transform_name: str | None) -> str:
    """Return the module and transform name for a cURL endpoint (``lookup`` by default)."""
    if transform_name is None:
        return "lookup"
    name = _slugify(transform_name)
    if not _is_identifier(name) or name in _RESERVED_MODULES:
        raise ValueError(
            f"Transform name {transform_name!r} is not usable as a module name. Use letters, "
            "digits and underscores, starting with a letter; 'api' and 'samples' are taken."
        )
    return name


def _curl_input(
    query: dict[str, Any], body: dict[str, Any] | None, segments: list[str]
) -> tuple[str, str | int, str] | None:
    """Choose the part of a request that carries the input: (location, key, sample value).

    The first part whose name or value looks like an entity wins, with the stronger types
    preferred over a domain-looking value. Failing that the endpoint is free text: a
    field named like a search term, then a lone field, then any non-numeric field, and a
    path segment that looks like a value last, since a path usually names the resource.
    Paging parameters are never the input.
    """
    candidates: list[tuple[str, str | int, str]] = [
        ("query", k, v) for k, v in query.items() if isinstance(v, str) and not _is_paging(k)
    ]
    candidates += [("path", idx, unquote(seg)) for idx, seg in enumerate(segments)]
    if body is not None:
        candidates += [
            ("body", k, v) for k, v in body.items() if isinstance(v, str) and not _is_paging(k)
        ]

    def entity_of(candidate: tuple[str, str | int, str]) -> str:
        location, key, sample = candidate
        return infer_input_entity(str(key) if location != "path" else "", sample)[0]

    typed = [c for c in candidates if entity_of(c) != "Phrase"]
    typed.sort(key=lambda c: entity_of(c) == "Domain")
    if typed:
        return typed[0]

    fields = [c for c in candidates if c[0] != "path"]
    query_fields = [c for c in fields if c[0] == "query"]
    body_fields = [c for c in fields if c[0] == "body"]
    chosen = next((c for c in fields if _SEARCH_FIELD_RE.match(str(c[1]))), None)
    if chosen is None and len(query_fields) == 1:
        chosen = query_fields[0]
    if chosen is None and len(body_fields) == 1:
        chosen = body_fields[0]
    chosen = chosen or next((c for c in fields if c[2] and not c[2].isdigit()), None)
    if chosen is None and segments:
        scored = [(_segment_score(unquote(seg)), idx) for idx, seg in enumerate(segments)]
        _, best = max(scored)
        chosen = ("path", best, unquote(segments[best]))
    return chosen


# ---------------------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------------------

_EXAMPLE_BY_FORMAT = {
    "ipv4": "192.0.2.1",
    "ipv6": "2001:db8::1",
    "email": "user@example.com",
    "uri": "https://example.com",
    "url": "https://example.com",
    "hostname": "example.com",
}
_EXAMPLE_DEPTH_LIMIT = 8
# Nodes a spec may expand to once YAML aliases are followed. Aliases share structure, so a
# small file can expand into billions of nodes ("billion laughs"), and everything after
# loading walks the expanded tree.
_SPEC_NODE_LIMIT = 2_000_000


class _SpecLoader(yaml.SafeLoader):
    """SafeLoader that leaves yes/no/on/off as strings.

    YAML 1.1 reads those as booleans, which turns a property called `on` or `no` into a
    bool key. OpenAPI documents are written to YAML 1.2, where only true/false are.
    """


_SpecLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_SpecLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def _string_keys(node: Any, memo: dict[int, Any]) -> Any:
    """Return ``node`` with every mapping key a string, sharing what aliases shared.

    Keys such as `2021` or `null` load as other types and break code that treats a field
    name as text. ``memo`` keeps an aliased subtree converted once, not once per use.
    """
    if isinstance(node, dict | list) and id(node) in memo:
        return memo[id(node)]
    if isinstance(node, dict):
        converted: dict[str, Any] = {}
        memo[id(node)] = converted
        for key, value in node.items():
            converted[str(key).lower() if isinstance(key, bool) else str(key)] = _string_keys(
                value, memo
            )
        return converted
    if isinstance(node, list):
        items: list[Any] = []
        memo[id(node)] = items
        items.extend(_string_keys(value, memo) for value in node)
        return items
    return node


def _expanded_size(node: Any, memo: dict[int, int]) -> int:
    """Return how many nodes ``node`` has once shared (aliased) subtrees are expanded."""
    if not isinstance(node, dict | list):
        return 1
    if id(node) in memo:
        return memo[id(node)]
    memo[id(node)] = 1  # a self-referencing alias counts once rather than looping
    children = node.values() if isinstance(node, dict) else node
    size = 1 + sum(_expanded_size(child, memo) for child in children)
    memo[id(node)] = size
    return size


def load_spec(text: str) -> dict[str, Any]:
    """Parse an OpenAPI document written as JSON or YAML.

    Raises:
        ValueError: If the text is neither, is not a mapping, or expands to more than
            ``_SPEC_NODE_LIMIT`` nodes.
    """
    stripped = text.strip()
    if not stripped:
        raise ValueError("The OpenAPI spec is empty.")
    try:
        document = json.loads(stripped)
    except json.JSONDecodeError as json_error:
        try:
            # _SpecLoader is a SafeLoader: no YAML tag can construct Python objects.
            document = yaml.load(stripped, Loader=_SpecLoader)
        except yaml.YAMLError as yaml_error:
            raise ValueError(
                f"The OpenAPI spec is neither JSON ({json_error}) nor YAML "
                f"({' '.join(str(yaml_error).split())})."
            ) from None
    if not isinstance(document, dict):
        raise ValueError(
            "The OpenAPI spec is not a JSON or YAML object. Pass the document, a path to "
            "it, or its URL."
        )
    if _expanded_size(document, {}) > _SPEC_NODE_LIMIT:
        raise ValueError(
            f"The OpenAPI spec expands to more than {_SPEC_NODE_LIMIT:,} nodes once its YAML "
            "aliases are followed; it is too large to scaffold from."
        )
    return _string_keys(document, {})


class _Spec:
    """An OpenAPI document with local ``$ref`` resolution."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document

    def resolve(self, node: Any) -> Any:
        """Follow ``$ref`` pointers until reaching a concrete node.

        Only local refs (``#/...``) are followed; a remote or cyclic ref resolves to an
        empty object rather than recursing forever.
        """
        seen: set[str] = set()
        while isinstance(node, dict) and isinstance(node.get("$ref"), str):
            ref = node["$ref"]
            if not ref.startswith("#/") or ref in seen:
                return {}
            seen.add(ref)
            target: Any = self.document
            for part in ref[2:].split("/"):
                part = unquote(part).replace("~1", "/").replace("~0", "~")
                target = target.get(part) if isinstance(target, dict) else None
            node = target if target is not None else {}
        return node

    def example(
        self,
        schema: Any,
        depth: int = 0,
        response: bool = False,
        expanding: frozenset[str] = frozenset(),
    ) -> Any:
        """Build a representative value for a schema, preferring the spec's own examples.

        For a response, a string with no example or format is None rather than the word
        ``"string"``: the mapping judges fields by their values too, and a made-up value
        would only mislead it. ``expanding`` holds the refs already open on this branch;
        schemas that refer back to each other through their properties would otherwise
        expand exponentially before the depth limit stops them.
        """
        ref = schema.get("$ref") if isinstance(schema, dict) else None
        if isinstance(ref, str):
            if ref in expanding:
                return None
            expanding = expanding | {ref}
        schema = self.resolve(schema)
        if not isinstance(schema, dict) or depth > _EXAMPLE_DEPTH_LIMIT:
            return None
        if "example" in schema:
            return schema["example"]
        if "allOf" in schema:
            merged: dict[str, Any] = {}
            for part in schema["allOf"]:
                value = self.example(part, depth + 1, response, expanding)
                if isinstance(value, dict):
                    merged.update(value)
            return merged
        for combinator in ("oneOf", "anyOf"):
            if schema.get(combinator):
                return self.example(schema[combinator][0], depth + 1, response, expanding)

        schema_type = schema.get("type")
        if isinstance(schema_type, list):
            schema_type = next((t for t in schema_type if t != "null"), None)
        if schema_type == "array" or "items" in schema:
            item = self.example(schema.get("items", {}), depth + 1, response, expanding)
            # A response list of plain strings keeps its one unknown element, so the field
            # is still mapped by its name.
            return [item] if item is not None or response else []
        if schema_type == "object" or "properties" in schema:
            properties = schema.get("properties", {}) or {}
            return {
                name: self.example(prop, depth + 1, response, expanding)
                for name, prop in properties.items()
            }
        if schema.get("enum"):
            return schema["enum"][0]
        if "default" in schema:
            return schema["default"]
        if schema_type == "string":
            by_format = _EXAMPLE_BY_FORMAT.get(str(schema.get("format", "")).lower())
            return by_format or (None if response else "string")
        if schema_type in ("integer", "number"):
            return 0
        if schema_type == "boolean":
            return False
        return None


def _json_content(container: dict[str, Any]) -> dict[str, Any]:
    """Return the JSON media type entry of a response or request body, if any."""
    content = container.get("content", {}) or {}
    for media_type, entry in content.items():
        if "json" in str(media_type) and isinstance(entry, dict):
            return entry
    return {}


def _base_url(spec: dict[str, Any], spec_url: str | None, notes: list[str]) -> str:
    """Return the API's base URL: the first server, or a Swagger 2 host and basePath.

    A relative URL is resolved against the spec's own URL, as both versions specify:
    an OpenAPI 3 server such as ``/api/v3``, and a Swagger 2 spec without ``host`` (served
    from the API's host) or without ``schemes`` (served over the API's scheme). Dropping
    the basePath there sends every request to the wrong path, which reads as "no record".
    """
    servers = spec.get("servers") or []
    spec_scheme = urlparse(spec_url).scheme if spec_url else ""
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        server = servers[0]
        url = str(server["url"])
        for name, variable in (server.get("variables") or {}).items():
            url = url.replace("{" + name + "}", str(variable.get("default", "")))
    else:
        base_path = str(spec.get("basePath") or "")
        if base_path and not base_path.startswith("/"):
            base_path = "/" + base_path
        if spec.get("host"):
            schemes = spec.get("schemes") or [spec_scheme or "https"]
            url = f"{schemes[0]}://{spec['host']}{base_path}"
        else:
            url = base_path

    if not urlparse(url).scheme:
        if spec_url:
            url = urljoin(spec_url, url or "/")
        else:
            notes.append(
                "The spec does not give an absolute server URL, so BASE_URL in api.py is a "
                "placeholder. Set it, or scaffold from the spec's URL instead of a file."
            )
            url = "https://api.example.com" + (url if url.startswith("/") else "/" + url)
    return url.rstrip("/")


def _parameter_value(spec: _Spec, param: dict[str, Any]) -> Any:
    """Return a usable value for a parameter the input does not fill, or None.

    Swagger 2 has no ``example`` on a parameter; specs written for it put one under the
    ``x-example`` extension instead.
    """
    schema = spec.resolve(param.get("schema", {})) or {}
    for source in (param, schema):
        if "default" in source:
            return source["default"]
        if source.get("enum"):
            return source["enum"][0]
        for key in ("example", "x-example"):
            if key in source:
                return source[key]
        examples = source.get("examples")
        if isinstance(examples, dict) and examples:
            first = spec.resolve(next(iter(examples.values())))
            if isinstance(first, dict) and "value" in first:
                return first["value"]
    return None


@dataclass
class _Auth:
    auth_type: str = "none"
    header_name: str | None = None
    query_param: str | None = None
    # The key came from a parameter every operation declares, not a security scheme.
    declared_param: bool = False


def _detect_auth(resolver: _Spec, document: dict[str, Any], notes: list[str]) -> _Auth:
    """Return the first authentication scheme the generator can express."""
    auth = _Auth()
    components = document.get("components") or {}
    schemes = components.get("securitySchemes") or document.get("securityDefinitions") or {}
    unsupported: list[str] = []
    for scheme_name, raw_scheme in schemes.items():
        scheme = resolver.resolve(raw_scheme)
        if not isinstance(scheme, dict):
            continue
        scheme_type = str(scheme.get("type", "")).lower()
        location = scheme.get("in")
        if scheme_type == "http" and str(scheme.get("scheme", "")).lower() == "bearer":
            return _Auth("bearer", "Authorization")
        if scheme_type == "apikey" and location in ("header", "query") and scheme.get("name"):
            if location == "header":
                return _Auth("header", header_name=str(scheme["name"]))
            return _Auth("query", query_param=str(scheme["name"]))
        unsupported.append(f"{scheme_name} ({scheme_type or 'unknown'})")
    # Some specs declare no scheme and instead list the key as an ordinary query parameter
    # on every operation. Treated as data, it would be sent as a literal placeholder or
    # even chosen as the input, so it is recognised as auth here.
    declared = _declared_key_param(resolver, document)
    if declared:
        return _Auth("query", query_param=declared, declared_param=True)
    if unsupported:
        notes.append(
            f"The spec's authentication ({', '.join(unsupported)}) is not scaffolded; "
            "requests go out unauthenticated until you add it to api.py."
        )
    return auth


def _key_required(
    document: dict[str, Any], operation: dict[str, Any], auth: _Auth, params: list[Any]
) -> bool:
    """Return whether an operation needs the key, or merely accepts it.

    A security requirement list containing ``{}`` makes authentication optional, an
    operation's ``security: []`` removes it, and a spec that declares schemes without
    requiring any does not require them either. Gating such an API on a key it does not
    need returns nothing from an endpoint that answers anonymously.
    """
    if auth.auth_type == "none":
        return False
    if auth.declared_param:
        return any(
            isinstance(param, dict)
            and param.get("in") == "query"
            and param.get("name") == auth.query_param
            and param.get("required", False)
            for param in params
        )
    security = operation["security"] if "security" in operation else document.get("security")
    if not security:
        return False
    return all(isinstance(requirement, dict) and requirement for requirement in security)


@dataclass
class _Operation:
    op_key: str  # the operationId, or method_path when there is none
    slug: str
    transform_id: str
    method: str
    path: str
    operation: dict[str, Any]
    shared_params: list[Any]
    # Set when another operation has the same operationId (or slug): the words telling
    # this one apart, added to its display name.
    duplicate: bool = False
    qualifier: str = ""

    @property
    def names(self) -> set[str]:
        """The names an --operation argument may use for this operation."""
        return {self.op_key, self.slug, self.transform_id}


def _operations_of(resolver: _Spec, document: dict[str, Any], svc_id: str) -> list[_Operation]:
    found = []
    for path_str, raw_item in (document.get("paths") or {}).items():
        path_item = resolver.resolve(raw_item)
        if not isinstance(path_item, dict):
            continue
        shared_params = path_item.get("parameters") or []
        for http_method in ("get", "post"):
            operation = resolver.resolve(path_item.get(http_method))
            if not isinstance(operation, dict) or not operation:
                continue
            op_key = str(operation.get("operationId") or f"{http_method}_{path_str}")
            slug = _function_name(op_key)
            found.append(
                _Operation(
                    op_key,
                    slug,
                    _transform_id(svc_id, slug),
                    http_method,
                    str(path_str),
                    operation,
                    shared_params,
                )
            )
    _disambiguate(found, svc_id)
    return found


def _path_words(op: _Operation) -> list[str]:
    """Return the words of an operation's path: ``/last/{source}`` → ``last``, ``{source}``."""
    words = []
    for segment in op.path.split("/"):
        param = re.fullmatch(r"\{([^}]+)\}", segment)
        word = _slugify(param.group(1) if param else segment)
        if word:
            words.append("{" + word + "}" if param else word)
    return words


def _disambiguate(ops: list[_Operation], svc_id: str) -> None:
    """Give operations that share an operationId (or its slug) distinct, meaningful ids.

    Specs reuse an operationId across paths (CIRCL's ``get_last`` for
    ``/vulnerability/last/{number}`` and ``/vulnerability/last/{source}``). As one id they
    would make transforms that cannot be told apart in Maltego, and ids that differ from
    the ones the server registers. Each is suffixed with the path words the others lack,
    parameters as ``by_<name>``; what that still leaves equal is numbered.
    """
    groups: dict[str, list[_Operation]] = {}
    for op in ops:
        groups.setdefault(op.slug, []).append(op)
    taken = {slug for slug, group in groups.items() if len(group) == 1}
    for slug, group in groups.items():
        if len(group) == 1:
            continue
        words = [_path_words(op) for op in group]
        common = set.intersection(*(set(op_words) for op_words in words))
        for op, op_words in zip(group, words, strict=True):
            literals = [word for word in op_words if word not in common and word[0] != "{"]
            params = [word[1:-1] for word in op_words if word not in common and word[0] == "{"]
            suffix = "_".join(literals + ([f"by_{'_'.join(params)}"] if params else []))
            qualifier = " ".join(literals + ([f"by {', '.join(params)}"] if params else []))
            if len({o.method for o in group}) > 1:
                suffix, qualifier = f"{suffix}_{op.method}".strip("_"), f"{qualifier} {op.method}"
            candidate, n = f"{slug}_{suffix}" if suffix else slug, 1
            while candidate in taken:
                n += 1
                candidate = f"{slug}_{suffix}_{n}" if suffix else f"{slug}_{n}"
            taken.add(candidate)
            op.slug, op.duplicate = candidate, True
            op.transform_id = _transform_id(svc_id, candidate)
            op.qualifier = (qualifier.strip() + (f" {n}" if n > 1 else "")).strip()


def _changes_state(op: _Operation) -> bool:
    """Return whether a verb in the path or operationId says the operation writes."""
    for segment in op.path.split("/"):
        tokens = key_tokens(segment) if not segment.startswith("{") else []
        if tokens and tokens[0] in _STATE_CHANGING_WORDS:
            return True
    tokens = key_tokens(op.op_key)
    while tokens and tokens[0] in _OPERATION_PREFIXES:
        tokens = tokens[1:]
    return bool(tokens) and tokens[0] in _STATE_CHANGING_WORDS


def _default_skip_reason(op: _Operation) -> str | None:
    """Return why scaffolding every operation would leave this one out, if it would."""
    if op.method == "post":
        return "POST may create or change data upstream; name it with --operation"
    if _changes_state(op):
        return "its path suggests it changes state upstream; name it with --operation"
    return None


@dataclass
class OperationInfo:
    """One operation of a spec, as scaffolding would treat it."""

    operation_id: str
    transform_id: str
    method: str
    path: str
    input: str  # e.g. "IPv4Address (path {ip})", or "-" when it cannot be scaffolded
    has_response_schema: bool
    skipped_reason: str | None
    # The spec gives this operationId to another operation too; transform_id is then
    # suffixed to tell them apart, and --operation with the shared id selects them all.
    duplicate: bool = False


@dataclass
class _Built:
    transform: ScaffoldTransformConfig
    sample: Any  # the spec's response example or schema-built sample; None without one
    input_description: str
    paging_params: list[str]


def list_openapi_operations(
    spec: dict[str, Any] | str, service_name: str | None = None
) -> list[OperationInfo]:
    """List every GET and POST operation of a spec with what scaffolding would make of it.

    Args:
        spec: The document, parsed or as JSON/YAML text.
        service_name: The service name the transform ids would be prefixed with; derived
            from the spec's title when omitted, as scaffolding does.
    """
    document = load_spec(spec) if isinstance(spec, str) else spec
    resolver = _Spec(document)
    title = str((document.get("info") or {}).get("title") or "API Service")
    svc_id = _service_id(service_name, _slugify(title))
    auth = _detect_auth(resolver, document, [])
    infos = []
    for op in _operations_of(resolver, document, svc_id):
        built, reason = _openapi_transform(resolver, document, op, title, auth)
        infos.append(
            OperationInfo(
                operation_id=op.op_key,
                transform_id=op.transform_id,
                method=op.method.upper(),
                path=op.path,
                input=built.input_description if built else "-",
                has_response_schema=built is not None and built.sample is not None,
                skipped_reason=reason or _default_skip_reason(op),
                duplicate=op.duplicate,
            )
        )
    return infos


def parse_openapi_spec(
    spec: dict[str, Any] | str,
    service_name: str | None = None,
    operations: list[str] | None = None,
    spec_url: str | None = None,
    sample_response: dict[str, Any] | list[Any] | str | None = None,
    records: str | None = None,
    mappings: list[str] | None = None,
    sample_input: str | None = None,
    primary: str | None = None,
) -> ScaffoldServiceConfig:
    """Parse an OpenAPI (v3) or Swagger (v2) specification into a service config.

    Args:
        spec: The document, parsed or as JSON/YAML text.
        service_name: Package name for the service; derived from the title if omitted.
        operations: Operation ids to scaffold. Without it every GET operation is
            scaffolded, except those whose path suggests they change state; POST
            operations are skipped, because they may create or change data upstream and
            should be chosen deliberately.
        spec_url: Where the document came from, to resolve a relative server URL.
        sample_response: A real response of the one operation scaffolded, to map the
            output from instead of the spec's schema.
        records: Dotted path to the list of records in the response (one operation only).
        mappings: ``PATH=TYPE`` overrides of the inferred mapping (one operation only).
        sample_input: The input value the sample response answers (one operation only),
            recorded in samples.json and used to tell an echo of the input apart; the
            input parameter's example in the spec by default.
        primary: Dotted path of the field to use as each record's primary entity (one
            operation only).

    Raises:
        ValueError: If the spec is malformed, names nothing to scaffold, an operation in
            ``operations`` does not exist, or a per-operation argument (sample, sample
            input, records, mappings, primary) is given for more than one operation.
    """
    document = load_spec(spec) if isinstance(spec, str) else spec
    if not isinstance(document, dict):
        raise ValueError("The OpenAPI spec is not a JSON or YAML object.")
    resolver = _Spec(document)
    notes: list[str] = []

    title = str((document.get("info") or {}).get("title") or "API Service")
    svc_id = _service_id(service_name, _slugify(title))
    base_url = _base_url(document, spec_url, notes)
    auth = _detect_auth(resolver, document, notes)

    wanted = set(operations or [])
    found: set[str] = set()
    skipped_posts: list[str] = []
    skipped_state: list[str] = []
    built: list[_Built] = []
    all_operations = _operations_of(resolver, document, svc_id)
    for op in all_operations:
        if wanted:
            matches = wanted & op.names
            if not matches:
                continue
            found |= matches
        elif op.method == "post":
            skipped_posts.append(op.slug if op.duplicate else op.op_key)
            continue
        elif _changes_state(op):
            skipped_state.append(op.slug if op.duplicate else op.op_key)
            continue

        result, reason = _openapi_transform(resolver, document, op, title, auth)
        if result is None:
            notes.append(f"Skipped {op.op_key}: {reason}")
            continue
        built.append(result)

    missing = sorted(wanted - found)
    if missing:
        available = ", ".join(op.op_key for op in all_operations[:30])
        more = f" (+{len(all_operations) - 30} more)" if len(all_operations) > 30 else ""
        raise ValueError(
            f"No operation named {', '.join(missing)} in the spec. Operations: "
            f"{available or 'none'}{more}. --list-operations shows them with their inputs."
        )
    explicit_input = _explicit(sample_input)
    per_operation = sample_response is not None or records or mappings or explicit_input or primary
    if per_operation and len(built) != 1:
        raise ValueError(
            f"--sample-response, --sample-input, --records, --map and --primary describe one "
            f"operation, but {len(built)} operations would be scaffolded. Choose one with "
            "--operation (--list-operations shows them)."
        )

    placeholders: list[str] = []
    paginated: list[str] = []
    with_drops = 0
    for item in built:
        if explicit_input:
            _set_sample_input(item.transform, explicit_input)
        sample = _load_sample(sample_response) if sample_response is not None else item.sample
        result = _apply_mapping(item.transform, sample, records, mappings, primary)
        if result.placeholder:
            placeholders.append(item.transform.transform_id)
        if item.paging_params or result.pagination:
            paginated.append(item.transform.transform_id)
        if len(built) == 1:
            notes.extend(result.notes)
            if item.paging_params or result.pagination:
                notes.append(
                    _pagination_note(
                        item.transform.transform_id, item.paging_params, result.pagination
                    )
                )
        elif result.notes:
            with_drops += 1

    if skipped_posts:
        notes.append(
            f"Skipped {len(skipped_posts)} POST operation(s), which may create or change data "
            f"upstream: {', '.join(skipped_posts)}. Name one with --operation to scaffold it."
        )
    if skipped_state:
        notes.append(
            f"Skipped {len(skipped_state)} GET operation(s) whose path suggests they change "
            f"state upstream: {', '.join(skipped_state)}. Name one with --operation to "
            "scaffold it."
        )
    if placeholders:
        notes.append(
            f"{', '.join(placeholders)}: the spec gives no response schema or example, so the "
            "output reads a placeholder `result` field. Scaffold one operation alone "
            "(--operation) with --sample-response, or edit RECORDS in the module. Preview "
            "with --dry-run to see the field inventory first."
        )
    if len(built) > 1 and paginated:
        notes.append(
            f"{len(paginated)} operation(s) look paginated ({', '.join(paginated[:5])}"
            f"{', ...' if len(paginated) > 5 else ''}): each reads the first page only."
        )
    if with_drops:
        notes.append(
            f"{with_drops} operation(s) leave response fields unmapped; each one's field "
            "inventory lists them. To change that, scaffold one alone with --operation and "
            "--records/--map."
        )
    unsampled = [item.transform for item in built if not item.transform.sample_input]
    if unsampled:
        names = ", ".join(t.transform_id for t in unsampled[:5])
        how = (
            "Scaffold again with --sample-input VALUE"
            if len(built) == 1
            else "Scaffold one alone (--operation) with --sample-input VALUE"
        )
        notes.append(
            f"No sample input for {names}{', ...' if len(unsampled) > 5 else ''}: the spec "
            "has no example for the input, so samples.json gets no entry (the smoke test then "
            "sends a stock value the API may reject) and an echo of the input in the response "
            f"is not recognised. {how}, a value the API answers for."
        )
    keyed = [item.transform.transform_id for item in built if item.transform.key_required]
    if keyed:
        notes.append(
            f"The spec requires an API key for {', '.join(keyed[:5])}"
            f"{', ...' if len(keyed) > 5 else ''}: without one configured they stop before "
            "the request. Specs often over-declare this; if the API answers anonymously, pass "
            "key_required=False to fetch() in the module."
        )
    if not wanted and len(built) > _MANY_OPERATIONS:
        notes.append(
            f"Scaffolded {len(built)} operations, one module each. That is usually more than "
            "an investigation needs: --list-operations shows them, and --operation picks some."
        )
    if not built:
        raise ValueError(
            "Nothing to scaffold. " + (" ".join(notes) if notes else "The spec has no operations.")
        )

    return ScaffoldServiceConfig(
        service_id=svc_id,
        display_name=title,
        base_url=base_url,
        auth_key_name=f"{svc_id.upper()}_API_KEY" if auth.auth_type != "none" else None,
        auth_header_name=auth.header_name,
        auth_query_param=auth.query_param,
        auth_type=auth.auth_type,
        transforms=[item.transform for item in built],
        notes=notes,
    )


def _all_operations(
    spec: _Spec, document: dict[str, Any]
) -> list[tuple[list[Any], dict[str, Any]]]:
    """Return (path-level parameters, operation) for every GET and POST operation."""
    found = []
    for raw_item in (document.get("paths") or {}).values():
        path_item = spec.resolve(raw_item)
        if not isinstance(path_item, dict):
            continue
        for http_method in ("get", "post"):
            operation = spec.resolve(path_item.get(http_method))
            if isinstance(operation, dict) and operation:
                found.append((path_item.get("parameters") or [], operation))
    return found


def _declared_key_param(spec: _Spec, document: dict[str, Any]) -> str | None:
    """Return a key-like query parameter every operation declares, if there is one.

    Requiring it on every operation keeps an ordinary field that happens to be called
    ``token`` (a pagination cursor, say) from being mistaken for the credential.
    """
    operations = _all_operations(spec, document)
    if not operations:
        return None
    per_operation = [
        {
            param["name"]
            for raw in [*shared, *(operation.get("parameters") or [])]
            if isinstance(param := spec.resolve(raw), dict)
            and param.get("in") == "query"
            and _AUTH_QUERY_RE.match(str(param.get("name", "")))
        }
        for shared, operation in operations
    ]
    common = set.intersection(*per_operation)
    return min(common) if common else None


def _response_sample(spec: _Spec, operation: dict[str, Any]) -> Any:
    """Return the operation's success response example, or one built from its schema."""
    responses = {str(code): value for code, value in (operation.get("responses") or {}).items()}
    ok_key = next((code for code in ("200", "201") if code in responses), None)
    ok_key = ok_key or next((code for code in responses if code.startswith("2")), None)
    ok_response = spec.resolve(responses.get(ok_key, {})) if ok_key else {}
    if not isinstance(ok_response, dict):
        return None
    json_entry = _json_content(ok_response)
    if "example" in json_entry:
        return json_entry["example"]
    examples = json_entry.get("examples")
    if isinstance(examples, dict) and examples:
        first = spec.resolve(next(iter(examples.values())))
        if isinstance(first, dict) and "value" in first:
            return first["value"]
    swagger_examples = ok_response.get("examples")
    if isinstance(swagger_examples, dict):
        for media_type, example in swagger_examples.items():
            if "json" in str(media_type):
                return example
    schema = json_entry.get("schema") or ok_response.get("schema")
    if not schema:
        return None
    return spec.example(schema, response=True)


def _openapi_transform(
    spec: _Spec,
    document: dict[str, Any],
    op: _Operation,
    title: str,
    auth: _Auth,
) -> tuple[_Built | None, str]:
    """Build one transform from an operation, or return why it cannot be scaffolded."""
    operation = op.operation
    # Operation-level parameters override path-level ones with the same name and location.
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in [*op.shared_params, *(operation.get("parameters") or [])]:
        param = spec.resolve(raw)
        if isinstance(param, dict) and param.get("name") and param.get("in"):
            merged[(str(param["name"]), str(param["in"]))] = param
    # The credential is sent by api.py; as an ordinary parameter it would go out as a
    # placeholder value, or be chosen as the input.
    params = [
        p
        for p in merged.values()
        if p["in"] in ("path", "query")
        and not (p["in"] == "query" and p["name"] == auth.query_param)
    ]

    # The body: an OpenAPI 3 requestBody, or a Swagger 2 `in: body` / `in: formData` param.
    body_schema: dict[str, Any] = {}
    body_encoding = "json"
    body_required: set[str] = set()
    body_example: dict[str, Any] | None = None
    body_examples: dict[str, Any] = {}
    request_body = spec.resolve(operation.get("requestBody") or {})
    swagger_body = next((p for p in merged.values() if p["in"] == "body"), None)
    form_params = [p for p in merged.values() if p["in"] == "formData"]
    if isinstance(request_body, dict) and request_body:
        body_schema = spec.resolve(_json_content(request_body).get("schema", {})) or {}
    elif swagger_body is not None:
        body_schema = spec.resolve(swagger_body.get("schema", {})) or {}
    if body_schema:
        example = spec.example(body_schema)
        body_example = example if isinstance(example, dict) else None
        body_required = set(body_schema.get("required") or [])
        for name, prop in (body_schema.get("properties") or {}).items():
            prop = spec.resolve(prop)
            if isinstance(prop, dict) and "example" in prop:
                body_examples[name] = prop["example"]
    elif form_params:
        body_encoding = "form"
        body_example = {
            p["name"]: _parameter_value(spec, p) or spec.example(p) or "" for p in form_params
        }
        body_required = {p["name"] for p in form_params if p.get("required")}
        body_examples = {
            p["name"]: value
            for p in form_params
            if (value := _parameter_value(spec, p)) is not None
        }

    # Input: an entity-like parameter or body field, then a path parameter, then a
    # required query parameter or body field. An optional untyped parameter or a paging
    # one is never the input: a transform that sends the investigator's entity as `page`
    # asks the API for the wrong thing.
    candidates: list[tuple[str, str, Any]] = [
        (p["in"], p["name"], _parameter_value(spec, p)) for p in params if not _is_paging(p["name"])
    ]
    if body_example:
        candidates += [
            ("body", name, body_examples.get(name)) for name in body_example if not _is_paging(name)
        ]

    def entity_of(candidate: tuple[str, str, Any]) -> str:
        sample = candidate[2] if isinstance(candidate[2], str) else None
        return infer_input_entity(candidate[1], sample)[0]

    required = {(p["in"], p["name"]) for p in params if p.get("required")}
    required |= {("body", name) for name in body_required}
    chosen = next((c for c in candidates if entity_of(c) != "Phrase"), None)
    chosen = chosen or next((c for c in candidates if c[0] == "path"), None)
    chosen = chosen or next((c for c in candidates if (c[0], c[1]) in required), None)
    if chosen is None:
        left_out = sorted({p["name"] for p in params} | set(body_example or {}))
        if left_out:
            return None, (
                "no required parameter can carry the input; only optional or paging ones "
                f"({', '.join(left_out)})."
            )
        return None, "it takes no parameter to carry the input."
    location, input_name, input_sample = chosen

    endpoint_path = op.path
    query: dict[str, Any] = {}
    paging_params: list[str] = []
    for param in params:
        name, where = param["name"], param["in"]
        if where == "query" and _is_paging(name):
            paging_params.append(name)
        if (where, name) == (location, input_name):
            if where == "path":
                endpoint_path = endpoint_path.replace("{" + name + "}", "{target}")
            else:
                query[name] = ""
            continue
        value = _parameter_value(spec, param)
        if where == "path":
            if value is None:
                return None, f"path parameter {{{name}}} has no default to fill it with."
            endpoint_path = endpoint_path.replace("{" + name + "}", str(value))
        elif param.get("required"):
            if value is None:
                return None, f"required query parameter {name!r} has no default."
            query[name] = value

    body: dict[str, Any] | None = None
    if body_example is not None:
        body = {
            name: value
            for name, value in body_example.items()
            if name == input_name or name in body_required
        }

    input_entity = entity_of(chosen)
    where_text = f"path {{{input_name}}}" if location == "path" else f"{location} {input_name}"
    summary = str(operation.get("summary") or humanize(_function_name(op.op_key)))
    # A bool would pass as an int; it is no input value.
    example = None if isinstance(input_sample, bool) else input_sample
    transform = ScaffoldTransformConfig(
        transform_id=op.transform_id,
        display_name=_display_name(title, summary, op.qualifier),
        input_entity=input_entity,
        endpoint_path=endpoint_path,
        input_param_name=input_name if location != "path" else "target",
        input_location=location,
        http_method=op.method.upper(),
        description=str(operation.get("description") or summary),
        query_params=query,
        request_body=body,
        body_encoding=body_encoding,
        key_required=_key_required(document, operation, auth, list(merged.values())),
        sample_input=(str(example) or None) if isinstance(example, str | int) else None,
    )
    sample = _response_sample(spec, operation)
    return _Built(transform, sample, f"{input_entity} ({where_text})", paging_params), ""


def _set_sample_input(transform: ScaffoldTransformConfig, value: str) -> None:
    """Record the caller's sample input, and let it type an input the spec leaves untyped.

    A parameter named ``id`` says nothing, but a sample input of ``8.8.8.8`` does.
    """
    transform.sample_input = value
    if transform.input_entity == "Phrase":
        name = transform.input_param_name if transform.input_location != "path" else ""
        transform.input_entity = infer_input_entity(name, value)[0]
