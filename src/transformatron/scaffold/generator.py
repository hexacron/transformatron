"""Code generator for creating Maltego transform modules and updating server/project.py.

Everything taken from a spec or a sample response — field names, titles, paths, header
names — reaches the generated source only as an escaped string literal, never as an
identifier or raw text. A key like ``as-name`` or a title containing a quote would
otherwise produce a module that fails to import, and because ``project.py`` imports every
module at startup, one bad module takes every transform on the server down with it.

A service is a package under ``transforms/``: ``api.py`` (the HTTP client, the input
validators and the response-mapping helpers), one module per transform, and
``samples.json`` (an input each transform is known to answer for). ``api.py`` depends only
on the service — base URL, authentication, headers — never on its transforms, so a
service can grow one endpoint at a time without rewriting the client the others use.
"""

from __future__ import annotations

import ast
import json
import math
import re
import shutil
import textwrap
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from transformatron.scaffold.schema import (
    EntityField,
    PropertyField,
    RecordMapping,
    ScaffoldServiceConfig,
    ScaffoldTransformConfig,
    placeholder_mapping,
    qualified_entity_type,
)

_LINE_LIMIT = 100

_VALIDATORS = {
    "IPv4Address": ("validate_ip", "return str(ipaddress.ip_address(value.strip()))"),
    "IPv6Address": ("validate_ip", "return str(ipaddress.ip_address(value.strip()))"),
    "Domain": (
        "validate_domain",
        'domain = value.strip().lower().rstrip(".")\n'
        '    if not re.match(r"^[a-z0-9.-]+\\.[a-z]{2,}$", domain):\n'
        '        raise ValueError("expected a valid domain name")\n'
        "    return domain",
    ),
    "URL": (
        "validate_url",
        "url = value.strip()\n"
        '    if not (url.startswith("http://") or url.startswith("https://")):\n'
        '        raise ValueError("expected an http:// or https:// URL")\n'
        "    return url",
    ),
    "EmailAddress": (
        "validate_email",
        "email = value.strip().lower()\n"
        '    if "@" not in email:\n'
        '        raise ValueError("expected a valid email address")\n'
        "    return email",
    ),
    "Hash": (
        "validate_hash",
        "h = value.strip()\n"
        '    if not re.match(r"^[a-fA-F0-9]{32,128}$", h):\n'
        '        raise ValueError("expected a hex hash string")\n'
        "    return h",
    ),
    "CVE": (
        "validate_cve",
        "cve = value.strip().upper()\n"
        '    if not re.match(r"^CVE-\\d{4}-\\d+$", cve):\n'
        '        raise ValueError("expected format CVE-YYYY-NNNN")\n'
        "    return cve",
    ),
    "Phrase": ("validate_phrase", "return value.strip()"),
}

# Inputs whose validator accepts `/`, `?`, `#` or spaces. Interpolated raw into a URL path,
# they would rewrite the request rather than fill one segment of it.
_FREE_TEXT_INPUTS = frozenset({"Phrase", "URL", "EmailAddress"})

# Module names a transform cannot take inside its service package.
_RESERVED_MODULES = frozenset({"api", "samples", "__init__"})
# Service names that would collide with the server's own layout: transforms/local/ holds
# the discovered, gitignored integrations.
_RESERVED_SERVICES = frozenset({"local"})


def _get_validator(entity_type: str) -> tuple[str, str]:
    return _VALIDATORS.get(entity_type, ("validate_phrase", "return value.strip()"))


def _isort_key(name: str) -> tuple[int, str]:
    """Sort imported names the way ruff's isort rule orders a `from` import.

    Ruff orders by type: constants (``TRANSFORM_SET``, and acronyms such as ``AS``, ``CVE``,
    ``URL``), then classes, then everything else, each group case-insensitively — so
    ``Website`` precedes ``WHOISRecord`` and ``Records`` precedes ``fetch``. Sorting by raw
    codepoint instead puts every embedded acronym in the wrong place, and generated code
    that disagrees with ruff lands an I001 violation on a file the author has not touched.
    """
    if name.isupper():
        group = 0
    elif name[:1].isupper():
        group = 1
    else:
        group = 2
    return group, name.lower()


# ---------------------------------------------------------------------------------------
# Source rendering
# ---------------------------------------------------------------------------------------


def _lit(text: str) -> str:
    """Return a Python string literal for ``text``, quoted the way ``ruff format`` would.

    JSON string escaping is valid Python string escaping, so the body is safe for any
    input. Non-ASCII characters are escaped too: a curly apostrophe or an en dash from a
    spec title is a ruff RUF001 violation when written literally, and the escape renders
    the same text at run time. Ruff prefers double quotes unless the text holds more of
    them than single quotes, in which case it switches to avoid escapes — matching that
    keeps ``ruff format --check`` passing on generated code.
    """
    body = json.dumps(text)[1:-1]
    if text.count('"') > text.count("'"):
        body = body.replace('\\"', '"').replace("'", "\\'")
        return f"'{body}'"
    return f'"{body}"'


def _braces(text: str) -> str:
    return text.replace("{", "{{").replace("}", "}}")


def _path_fstring(template: str, expression: str) -> str:
    """Return an f-string for a path template holding one ``{target}`` placeholder."""
    before, _, after = template.partition("{target}")
    return "f" + _lit(_braces(before) + "{" + expression + "}" + _braces(after))


@dataclass(frozen=True)
class _Code:
    """Source text emitted verbatim inside a rendered literal."""

    source: str


@dataclass(frozen=True)
class _Call:
    """A call expression to render, ``name(*args, **kwargs)``.

    ``explode`` writes one argument per line with a trailing comma whatever the width. The
    trailing comma is "magic" to ruff, so it keeps the layout: a mapping table stays one
    field per line, which is what makes it easy to edit.
    """

    name: str
    args: tuple[Any, ...] = ()
    kwargs: tuple[tuple[str, Any], ...] = ()
    explode: bool = False


@dataclass(frozen=True)
class _Rows:
    """A list rendered one element per line, trailing comma included, whatever the width."""

    items: tuple[Any, ...]


def _flat(value: Any) -> str:
    if isinstance(value, _Code):
        return value.source
    if isinstance(value, _Call):
        parts = [_flat(arg) for arg in value.args]
        parts += [f"{key}={_flat(arg)}" for key, arg in value.kwargs]
        return f"{value.name}({', '.join(parts)})"
    if isinstance(value, _Rows):
        return "[" + ", ".join(_flat(v) for v in value.items) + "]"
    if isinstance(value, str):
        return _lit(value)
    if isinstance(value, bool) or value is None:
        return repr(value)
    if isinstance(value, float) and not math.isfinite(value):
        # json.loads accepts NaN and Infinity, whose repr() is a bare name that does not
        # exist at run time; the module would fail to import and take the server down.
        return f'float("{value!r}")'
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, dict):
        inner = ", ".join(f"{_lit(str(k))}: {_flat(v)}" for k, v in value.items())
        return "{" + inner + "}"
    if isinstance(value, tuple):
        inner = ", ".join(_flat(v) for v in value)
        return f"({inner},)" if len(value) == 1 else f"({inner})"
    if isinstance(value, list):
        return "[" + ", ".join(_flat(v) for v in value) + "]"
    return _lit(str(value))


def _render(value: Any, indent: int, head: str, tail: str) -> list[str]:
    """Render ``head + value + tail`` as lines, wrapping the way ``ruff format`` does.

    What fits on its line stays flat. A collection that does not gets one element per
    line with a trailing comma, recursively. A call that does not first tries all its
    arguments on one indented line between the brackets, and only then one per line.
    """
    pad = " " * indent
    flat = f"{pad}{head}{_flat(value)}{tail}"
    forced = isinstance(value, _Rows) or (isinstance(value, _Call) and value.explode)
    if not forced and (len(flat) <= _LINE_LIMIT or not _splittable(value)):
        return [flat]

    if isinstance(value, _Call):
        items = [("", arg) for arg in value.args] + [(f"{k}=", v) for k, v in value.kwargs]
        if not forced:
            body = ", ".join(f"{key}{_flat(arg)}" for key, arg in items)
            if len(f"{pad}    {body}") <= _LINE_LIMIT:
                return [f"{pad}{head}{value.name}(", f"{pad}    {body}", f"{pad}){tail}"]
        lines = [f"{pad}{head}{value.name}("]
        for key, arg in items:
            lines.extend(_render(arg, indent + 4, key, ","))
        lines.append(f"{pad}){tail}")
        return lines

    if isinstance(value, dict):
        opener, closer = "{", "}"
        entries = [(f"{_lit(str(k))}: ", v) for k, v in value.items()]
    else:
        opener, closer = ("(", ")") if isinstance(value, tuple) else ("[", "]")
        elements = value.items if isinstance(value, _Rows) else value
        entries = [("", v) for v in elements]
    lines = [f"{pad}{head}{opener}"]
    for key, item in entries:
        lines.extend(_render(item, indent + 4, key, ","))
    lines.append(f"{pad}{closer}{tail}")
    return lines


def _splittable(value: Any) -> bool:
    if isinstance(value, _Call):
        return bool(value.args or value.kwargs)
    return isinstance(value, dict | list | tuple | _Rows) and bool(value)


# Typographic characters common in spec prose, folded to the ASCII ruff expects in
# docstrings (RUF002). Anything else outside ASCII is dropped from docstrings, which are
# documentation only; literals keep the full text through escapes instead.
_DOCSTRING_FOLD = str.maketrans(
    {"\u2018": "'", "\u2019": "'", "\u201c": "'", "\u201d": "'", "\u2013": "-", "\u2014": "-"}
)


def _docstring(text: str, indent: int, footer: str = "") -> str:
    """Return a docstring holding ``text``, safe for any content and within the line limit.

    ``footer`` is a line of its own after a blank one, never wrapped into the text.
    """
    folded = unicodedata.normalize("NFKD", text.translate(_DOCSTRING_FOLD))
    ascii_text = folded.encode("ascii", "ignore").decode()
    collapsed = " ".join(ascii_text.replace("\\", "/").replace('"', "'").split()) or "Transform."
    pad = " " * indent
    lines = textwrap.wrap(collapsed, width=_LINE_LIMIT - indent - 6)
    if footer:
        lines += ["", footer]
    if len(lines) == 1:
        return f'{pad}"""{lines[0]}"""'
    body = "\n".join(f"{pad}{line}" if line else "" for line in lines[1:])
    return f'{pad}"""{lines[0]}\n{body}\n{pad}"""'


# The line every generated api.py carries. remove_scaffold() deletes only a service that
# has it: a hand-written service holds work no scaffold can recreate.
GENERATED_MARKER = "Generated by transformatron scaffold."


def _api_name(display_name: str) -> str:
    """Return the service's name as an API's: ``Crtsh API``, but ``Vulnerability-Lookup API``
    for a spec title that already says so, not ``Vulnerability-Lookup API API``."""
    name = display_name.strip()
    return name if re.search(r"\bAPI$", name, re.IGNORECASE) else f"{name} API"


# ---------------------------------------------------------------------------------------
# api.py
# ---------------------------------------------------------------------------------------

# The response-mapping helpers every service shares, written into its api.py. Transform
# modules describe their mapping as data (RECORDS) and map_records() walks it, so the
# mapping can be read and edited as a table, and the walking code is written once.
_MAPPING_HELPERS = '''
# ---------------------------------------------------------------------------------------
# Response mapping. Each transform module declares RECORDS: where the records sit in the
# response and what each one becomes. map_records() walks it.
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Entity:
    """A field whose every value becomes an entity of type `entity`.

    `path` holds the keys from the record to the value; a list met along the way is
    iterated, so ("references", "url") reads the url of every reference. `label` labels
    the link, and `strip` is a prefix removed from each value ("AS" from "AS15169").
    """

    entity: type[MaltegoEntity]
    path: tuple[str, ...]
    label: str
    strip: str = ""


@dataclass(frozen=True)
class Prop:
    """A field set on the record's primary entity as the property `name`."""

    name: str
    path: tuple[str, ...]
    label: str


@dataclass(frozen=True)
class Records:
    """Where records sit, and what each one becomes.

    `path` leads to the records from the response, or from the enclosing record for an
    entry of `nested`; an empty path is that object itself. The `primary` entity carries
    the `props`, and `entities` are emitted beside it. `nested` maps a list of objects
    inside each record, element by element. A value equal to the input is skipped, except
    a primary entity with properties when `enrich_input` is set: returned, it adds those
    properties to the input entity.
    """

    path: tuple[str, ...]
    primary: Entity | None = None
    props: Sequence[Prop] = ()
    entities: Sequence[Entity] = ()
    nested: Sequence[Records] = ()
    enrich_input: bool = False


def pluck(node: Any, path: tuple[str, ...]) -> list[Any]:
    """Return every value at `path` under `node`, iterating each list met on the way."""
    values = [node]
    for key in path:
        items = [item for value in values for item in _items(value)]
        values = [item[key] for item in items if isinstance(item, dict) and key in item]
    found = [item for value in values for item in _items(value)]
    return [value for value in found if value is not None and value != ""]


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def map_records(data: Any, records: Records, target: str) -> list[Any]:
    """Return the entities `records` describes in `data`.

    Each type and value is returned once: met again in another record, it gains that
    record's property values too, distinct values joined with ", ". At most MAX_ITEMS
    records are read from each list, and a value equal to the input `target` is skipped
    (see Records).
    """
    results: list[Any] = []
    _map(data, records, target.casefold(), results, {})
    return results


@dataclass
class _Emitted:
    """An entity returned by map_records(), with every value each property was given."""

    entity: MaltegoEntity
    values: dict[str, list[Any]] = field(default_factory=dict)

    def add(self, prop: Prop, values: list[Any]) -> None:
        held = self.values.setdefault(prop.name, [])
        held.extend(value for value in values if value not in held)
        value = held[0] if len(held) == 1 else ", ".join(str(v) for v in held)
        try:
            self.entity.set_property(prop.name, value, display_name=prop.label)
        except (TypeError, ValueError):
            # A typed property (a CVE's epss, say) rejects a value it cannot parse. The
            # text is kept under a name of its own rather than lost.
            self.entity.set_property(f"{prop.name}.text", str(value), display_name=prop.label)


def _map(
    node: Any,
    records: Records,
    target: str,
    results: list[Any],
    seen: dict[tuple[str, str], _Emitted],
) -> None:
    for record in pluck(node, records.path)[:MAX_ITEMS]:
        props = [(prop, values) for prop in records.props if (values := _scalars(record, prop))]
        if records.primary is not None:
            keep = records.enrich_input and bool(props)
            for text in _texts(records.primary, record)[:1]:
                primary = _add(records.primary, text, target, results, seen, keep)
                if primary is not None:
                    for prop, values in props:
                        primary.add(prop, values)
        for spec in records.entities:
            for text in _texts(spec, record)[:MAX_ITEMS]:
                _add(spec, text, target, results, seen, False)
        for nested in records.nested:
            _map(record, nested, target, results, seen)


def _texts(spec: Entity, record: Any) -> list[str]:
    """Return the entity values a field holds: trimmed, and one per line unless a Phrase."""
    texts: list[str] = []
    for value in pluck(record, spec.path):
        if isinstance(value, dict | list):
            continue
        lines = [str(value)] if issubclass(spec.entity, Phrase) else str(value).splitlines()
        for line in lines:
            text = line.strip().removeprefix(spec.strip)
            if spec.entity.TYPE_NAME in ("maltego.Domain", "maltego.DNSName"):
                text = text.removeprefix("*.").rstrip(".")
            if text:
                texts.append(text)
    return texts


def _add(
    spec: Entity,
    text: str,
    target: str,
    results: list[Any],
    seen: dict[tuple[str, str], _Emitted],
    keep_input: bool,
) -> _Emitted | None:
    """Return the entity for a value, made on first sight; None for a skipped echo."""
    key = (spec.entity.TYPE_NAME, text.casefold())
    if key in seen:
        return seen[key]
    if key[1] == target and not keep_input:
        return None
    seen[key] = _Emitted(spec.entity(value=text, link_label=spec.label))
    results.append(seen[key].entity)
    return seen[key]


def _scalars(record: Any, prop: Prop) -> list[Any]:
    """Return the plain values of a property field; an object there is not a property."""
    return [value for value in pluck(record, prop.path) if not isinstance(value, dict | list)]
'''


def generate_api_module(config: ScaffoldServiceConfig) -> str:
    """Generate the api.py client helper for a service.

    Every validator is emitted, whichever input types the transforms use today: api.py
    then depends on the service alone, and a later endpoint with another input type can
    be added without rewriting the client the existing transforms import.
    """
    validators: dict[str, str] = {}
    for name, body in _VALIDATORS.values():
        validators.setdefault(name, body)
    # Two blank lines between top-level defs, or `ruff format --check` reformats the
    # generated file and the project's format gate fails on brand-new code.
    validators_str = "\n\n\n".join(
        f'def {name}(value: str) -> str:\n    """Validate and normalise the input value, or raise'
        f' ValueError."""\n    {body}'
        for name, body in validators.items()
    )

    authed = config.auth_key_name is not None
    header_auth = authed and config.auth_type in ("header", "bearer")
    uses_headers = bool(config.headers) or header_auth

    # Emit each import only where it is used: an unused one fails ruff (F401) on freshly
    # generated code, and server/transforms/ is linted.
    os_import = "import os\n" if authed else ""
    setting_import = "from maltego.server import TransformSetting\n" if authed else ""

    headers_block = ""
    if config.headers:
        headers_block = (
            "# Sent with every request, as in the command this service was scaffolded from:\n"
            "# some APIs answer differently, or refuse, without them.\n"
            + "\n".join(_render(dict(config.headers), 0, "HEADERS = ", ""))
            + "\n"
        )

    setting_code = ""
    key_param = ""
    auth_code = ""
    if authed:
        # Named once, so the setting and the message agree, and named the way the service
        # is: a spec title already ending in "API" gets no second one.
        key_label = f"{_api_name(config.display_name)} Key"
        setting_code = f"""API_KEY = {_lit(config.auth_key_name or "")}
API_KEY_LABEL = {_lit(key_label)}


def api_key_setting() -> TransformSetting:
    \"\"\"Return the shared API key setting declaration.\"\"\"
    return TransformSetting(
        name=API_KEY,
        display_name=API_KEY_LABEL,
        auth=True,
        is_global=True,
    )


"""
        key_param = "    key_required: bool = True,\n"
        auth_code = """    api_key = settings.get(API_KEY, "") or os.environ.get(API_KEY, "")
    if not api_key and key_required:
        context.log.fatal(
            f"No {API_KEY_LABEL} configured. Enter it in Maltego Graph Desktop under the "
            f"transform settings ('{API_KEY_LABEL}'), or export {API_KEY} before starting "
            "the server."
        )
        return None
"""
    if uses_headers:
        auth_code += (
            "    headers = dict(HEADERS)\n"
            if config.headers
            else "    headers: dict[str, str] = {}\n"
        )
    if authed:
        # An operation whose key is optional still sends it when one is configured.
        if config.auth_type == "query":
            query_param = config.auth_query_param or config.auth_header_name or "apikey"
            # params may arrive as None, so it is copied before the key is added.
            auth_code += (
                "    if api_key:\n"
                "        params = dict(params or {})\n"
                f"        params[{_lit(query_param)}] = api_key\n"
            )
        elif config.auth_type == "bearer":
            auth_code += '    if api_key:\n        headers["Authorization"] = f"Bearer {api_key}"\n'
        else:
            header_name = _lit(config.auth_header_name or "X-API-KEY")
            auth_code += f"    if api_key:\n        headers[{header_name}] = api_key\n"
    headers_arg = "            headers=headers,\n" if uses_headers else ""

    module_doc = _docstring(
        f"Shared client helpers for the {_api_name(config.display_name)}.",
        0,
        footer=GENERATED_MARKER,
    )
    return f'''{module_doc}

from __future__ import annotations

import ipaddress
{os_import}import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from maltego.entities import Phrase
from maltego.model.context import MaltegoContext
from maltego.model.entity import MaltegoEntity
from maltego.model.exception import MaltegoException, MaltegoHTTPDataProviderNotFound
{setting_import}from maltego.util import IntegrationClient

BASE_URL = {_lit(config.base_url.rstrip("/"))}
SERVICE_NAME = {_lit(config.display_name)}
TRANSFORM_SET = SERVICE_NAME
# Records read from each list in a response, and values from each field: a cap on what
# one run returns.
MAX_ITEMS = 20
{headers_block}
client = IntegrationClient()


{setting_code}{validators_str}


async def fetch(
    path: str,
    settings: dict[str, Any],
    context: MaltegoContext,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    form: dict[str, Any] | None = None,
{key_param}) -> Any:
    """Request `path` and return the decoded JSON, or None on failure."""
{auth_code}    try:
        response = await client.request(
            method,
            f"{{BASE_URL}}{{path}}",
            context=context,
{headers_arg}            params=params,
            json=json_body,
            data=form,
        )
    except MaltegoHTTPDataProviderNotFound:
        context.log.inform(f"{{SERVICE_NAME}} has no record for the requested input")
        return None
    except MaltegoException as exc:
        context.log.fatal(f"{{SERVICE_NAME}} lookup failed: {{exc.message}}")
        return None

    try:
        return response.json()
    except ValueError:
        context.log.fatal(f"{{SERVICE_NAME}} returned a response that is not JSON")
        return None

{_MAPPING_HELPERS}'''


# ---------------------------------------------------------------------------------------
# Transform modules
# ---------------------------------------------------------------------------------------


def _camel(snake: str) -> str:
    """Convert a snake_case transform id into a CamelCase name for a type alias."""
    return "".join(part.title() for part in snake.split("_") if part)


def _format_import(module: str, names: list[str]) -> str:
    """Render ``from module import ...``, wrapping one name per line when it would be long.

    A response with many mapped fields, or a long service id, pushes the single-line form
    past the project's 100-character limit (E501), and ruff's formatter then rewrites it,
    failing ``ruff format --check`` on freshly generated code.
    """
    single_line = f"from {module} import {', '.join(names)}"
    if len(single_line) <= _LINE_LIMIT:
        return single_line
    joined = "".join(f"    {name},\n" for name in names)
    return f"from {module} import (\n{joined})"


def _entity_expr(entity_field: EntityField) -> _Call:
    kwargs = (("strip", entity_field.strip_prefix),) if entity_field.strip_prefix else ()
    return _Call(
        "Entity",
        (_Code(entity_field.entity_type), tuple(entity_field.path), entity_field.label),
        kwargs,
    )


def _prop_expr(prop: PropertyField) -> _Call:
    return _Call("Prop", (prop.name, tuple(prop.path), prop.label))


def _records_expr(mapping: RecordMapping) -> _Call:
    kwargs: list[tuple[str, Any]] = []
    if mapping.primary is not None:
        kwargs.append(("primary", _entity_expr(mapping.primary)))
    if mapping.properties:
        kwargs.append(("props", _Rows(tuple(_prop_expr(p) for p in mapping.properties))))
    if mapping.entities:
        kwargs.append(("entities", _Rows(tuple(_entity_expr(e) for e in mapping.entities))))
    if mapping.nested:
        kwargs.append(("nested", _Rows(tuple(_records_expr(n) for n in mapping.nested))))
    if mapping.enrich_input:
        kwargs.append(("enrich_input", True))
    return _Call("Records", (tuple(mapping.path),), tuple(kwargs), explode=True)


def _uses_props(mapping: RecordMapping) -> bool:
    return bool(mapping.properties) or any(_uses_props(child) for child in mapping.nested)


def _uses_entities(mapping: RecordMapping) -> bool:
    return (
        mapping.primary is not None
        or bool(mapping.entities)
        or any(_uses_entities(child) for child in mapping.nested)
    )


def _request_lines(transform: ScaffoldTransformConfig) -> tuple[list[str], list[str], bool]:
    """Return the request-building statements, the fetch() keyword args, and whether the
    statements use ``quote``."""
    lines: list[str] = []
    kwargs: list[str] = []
    uses_quote = False
    target = _Code("target")

    if transform.input_location == "path" and "{target}" in transform.endpoint_path:
        expression = "target"
        if transform.input_entity in _FREE_TEXT_INPUTS:
            lines.append('    encoded = quote(target, safe="")')
            expression = "encoded"
            uses_quote = True
        lines.append(f"    path = {_path_fstring(transform.endpoint_path, expression)}")
    else:
        lines.append(f"    path = {_lit(transform.endpoint_path)}")

    query = dict(transform.query_params)
    if transform.input_location == "query":
        query[transform.input_param_name] = target
    if query:
        lines.extend(_render(query, 4, "params = ", ""))
        kwargs.append("params=params")

    if transform.request_body is not None:
        body = dict(transform.request_body)
        if transform.input_location == "body":
            body[transform.input_param_name] = target
        lines.extend(_render(body, 4, "body = ", ""))
        kwargs.append("json_body=body" if transform.body_encoding == "json" else "form=body")

    if transform.http_method != "GET":
        kwargs.insert(0, f"method={_lit(transform.http_method)}")
    return lines, kwargs, uses_quote


_RECORDS_COMMENT = """\
# How the response becomes entities; Records, Entity and Prop are described in api.py. A
# path is a tuple of keys, and a list met along it is iterated. Edit freely: delete a line
# to stop mapping a field, change an entity type, or move a field between props/entities.
"""
_PLACEHOLDER_COMMENT = """\
# PLACEHOLDER: nothing showed what the response looks like, so this reads a `result`
# field. Replace it once you have seen a real response (`scaffold --dry-run` with a
# sample lists every field), or scaffold again with a sample response.
"""


def generate_transform_module(
    config: ScaffoldServiceConfig,
    transform: ScaffoldTransformConfig,
) -> str:
    """Generate a single transform module file."""
    val_func, _ = _get_validator(transform.input_entity)

    output_types = sorted(set(transform.output_entity_types), key=_isort_key)
    needed_entities = {transform.input_entity} | set(output_types)

    # A transform emitting many entity types produces a union too long to inline at the
    # return annotation (E501). Naming it once keeps the signature short whatever the
    # width. Three widths, matching what ruff's formatter would settle on: the bare
    # assignment if it fits, else the body on its own indented line inside parens if
    # *that* fits, else one operand per line.
    alias_name = f"{_camel(transform.transform_id)}Output"
    alias_body = " | ".join(output_types)
    if len(f"{alias_name} = {alias_body}") <= _LINE_LIMIT:
        alias_decl = f"{alias_name} = {alias_body}\n"
    elif len(f"    {alias_body}") <= _LINE_LIMIT:
        alias_decl = f"{alias_name} = (\n    {alias_body}\n)\n"
    else:
        wrapped = "\n    | ".join(output_types)
        alias_decl = f"{alias_name} = (\n    {wrapped}\n)\n"

    settings_arg = "[api_key_setting()]" if config.auth_key_name else "[]"

    # Without an input constraint the Maltego client offers the transform on every entity
    # of its input type. EntityTypeConstraint matches parent types too, so this does not
    # over-narrow subclasses of the declared input.
    constraint_arg = ""
    constraint_import_str = ""
    if transform.emit_input_constraint:
        qualified = _lit(qualified_entity_type(transform.input_entity))
        constraint_arg = f"\n    input_constraint=EntityTypeConstraint(entity_type={qualified}),"
        constraint_import_str = "from maltego.model.input_constraints import EntityTypeConstraint\n"

    request_lines, fetch_kwargs, uses_quote = _request_lines(transform)
    if config.auth_key_name and not transform.key_required:
        fetch_kwargs.append("key_required=False")
    fetch_args = ", ".join(["path", "settings", "context", *fetch_kwargs])
    fetch_call = f"    data = await fetch({fetch_args})"
    if len(fetch_call) > _LINE_LIMIT:
        joined = "".join(f"        {arg},\n" for arg in fetch_args.split(", "))
        fetch_call = f"    data = await fetch(\n{joined}    )"

    mapping = transform.mapping
    api_imports = ["TRANSFORM_SET", "Records", val_func, "fetch", "map_records"]
    if _uses_entities(mapping):
        api_imports.append("Entity")
    if _uses_props(mapping):
        api_imports.append("Prop")
    if config.auth_key_name:
        api_imports.append("api_key_setting")
    quote_import_str = "from urllib.parse import quote\n" if uses_quote else ""

    comment = _PLACEHOLDER_COMMENT if mapping == placeholder_mapping() else _RECORDS_COMMENT
    records_str = "\n".join(_render(_records_expr(mapping), 0, "RECORDS = ", ""))

    signature = (
        f"async def {transform.transform_id}(input_entity: {transform.input_entity}, "
        f"settings: dict[str, Any], context: MaltegoContext) -> list[{alias_name}]:"
    )
    if len(signature) > _LINE_LIMIT:
        signature = (
            f"async def {transform.transform_id}(\n"
            f"    input_entity: {transform.input_entity}, settings: dict[str, Any], "
            f"context: MaltegoContext\n) -> list[{alias_name}]:"
        )

    module_doc = _docstring(f"Transforms for {config.display_name}: {transform.display_name}.", 0)
    request_str = "\n".join(request_lines)

    return f"""{module_doc}

from typing import Any
{quote_import_str}
{_format_import("maltego.entities", sorted(needed_entities, key=_isort_key))}
from maltego.model.context import MaltegoContext
{constraint_import_str}from maltego.server import register_transform
{_format_import(f"transforms.{config.service_id}.api", sorted(api_imports, key=_isort_key))}

{alias_decl}
{comment}{records_str}


@register_transform(
    display_name={_lit(transform.display_name)},
    transform_set=TRANSFORM_SET,
    settings={settings_arg},{constraint_arg}
)
{signature}
{_docstring(transform.description or transform.display_name, 4)}
    try:
        target = {val_func}(input_entity.value)
    except ValueError as exc:
        context.log.fatal(f"Invalid input: {{exc}}")
        return []

{request_str}
{fetch_call}
    if data is None:
        return []

    results = map_records(data, RECORDS, target)
    if not results:
        context.log.inform(f"{{TRANSFORM_SET}} returned no mapped entities for this input")
    return results
"""


def _module_plan(config: ScaffoldServiceConfig) -> list[tuple[str, ScaffoldTransformConfig]]:
    """Return (module name, transform) per transform, with unique module names.

    A module is named after its transform without the service prefix (``lookup.py`` for
    ``ipinfo_lookup``), suffixed where that name is taken (``api``, say).

    Raises:
        ValueError: If two transforms share an id. The parsers give each operation a
            distinct one; renaming here instead would register ids other than the ones
            reported to the author.
    """
    used_modules = set(_RESERVED_MODULES)
    used_ids: set[str] = set()
    plan: list[tuple[str, ScaffoldTransformConfig]] = []
    for transform in config.transforms:
        if transform.transform_id in used_ids:
            raise ValueError(
                f"Two transforms share the id {transform.transform_id!r}; each needs its own, "
                "as the server registers transforms by id."
            )
        used_ids.add(transform.transform_id)
        base = transform.transform_id.removeprefix(f"{config.service_id}_")
        if not base.isidentifier():
            base = transform.transform_id
        module, n = base, 1
        while module in used_modules:
            n += 1
            module = f"{base}_{n}"
        used_modules.add(module)
        plan.append((module, transform))
    return plan


def generate_service_code(config: ScaffoldServiceConfig) -> dict[str, str]:
    """Generate all source files for a service integration (samples.json aside)."""
    files: dict[str, str] = {
        "__init__.py": "",
        "api.py": generate_api_module(config),
    }
    for module, transform in _module_plan(config):
        files[f"{module}.py"] = generate_transform_module(config, transform)
    return files


# ---------------------------------------------------------------------------------------
# Writing and removing
# ---------------------------------------------------------------------------------------


def inject_project_import(project_py_path: Path, module_import: str) -> bool:
    """Inject an import statement at the top of server/project.py."""
    if not project_py_path.exists():
        return False

    content = project_py_path.read_text()
    if module_import in content:
        return False

    lines = content.splitlines()
    insert_idx = 0
    for idx, line in enumerate(lines):
        if (
            line.startswith("from transforms.")
            or line.startswith("import transforms.")
            or (insert_idx == 0 and line.startswith("from maltego."))
        ):
            insert_idx = idx + 1

    lines.insert(insert_idx, module_import)
    project_py_path.write_text("\n".join(lines) + "\n")
    return True


def _import_line(service_id: str, module: str) -> str:
    return f"from transforms.{service_id}.{module} import *  # noqa: F401,F403"


def _remove_project_imports(project_py: Path, service_id: str) -> list[str]:
    """Remove every import of the service from project.py; return the lines removed.

    A service directory deleted without its imports leaves the server unable to start
    (``ModuleNotFoundError`` at the import), so the two always go together.
    """
    if not project_py.exists():
        return []
    pattern = re.compile(
        rf"^\s*(from\s+transforms\.{re.escape(service_id)}(\.|\s)"
        rf"|import\s+transforms\.{re.escape(service_id)}(\.|\s|$))"
    )
    lines = project_py.read_text().splitlines()
    removed = [line for line in lines if pattern.match(line)]
    if removed:
        kept = [line for line in lines if not pattern.match(line)]
        project_py.write_text("\n".join(kept) + "\n")
    return removed


def _registers_transform(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if name == "register_transform":
            return True
    return False


def _defined_transforms(transforms_dir: Path, exclude: Path | None) -> dict[str, Path]:
    """Return {function name: file} for every registered transform under ``transforms_dir``.

    The SDK registers a transform under its function name, server-wide; a second one of
    the same name stops the server from starting.
    """
    defined: dict[str, Path] = {}
    if not transforms_dir.is_dir():
        return defined
    for path in sorted(transforms_dir.rglob("*.py")):
        if "__pycache__" in path.parts or (exclude is not None and path.is_relative_to(exclude)):
            continue
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError, ValueError):
            continue
        for node in tree.body:
            is_function = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            if is_function and _registers_transform(node):
                defined.setdefault(node.name, path)
    return defined


@dataclass
class _Plan:
    svc_dir: Path
    writes: dict[str, str] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)
    replace_existing: bool = False

    @property
    def paths(self) -> list[Path]:
        return [self.svc_dir / name for name in self.writes]


def _plan(config: ScaffoldServiceConfig, project_dir: Path, force: bool) -> _Plan:
    """Work out what writing a scaffold would do, raising if it should not be done."""
    if config.service_id in _RESERVED_SERVICES:
        raise ValueError(
            f"'{config.service_id}' is reserved: transforms/{config.service_id}/ holds the "
            "discovered local integrations. Choose another service name."
        )
    transforms_dir = project_dir / "transforms"
    svc_dir = transforms_dir / config.service_id
    files = generate_service_code(config)
    modules = _module_plan(config)
    existing = svc_dir.exists()

    plan = _Plan(svc_dir, replace_existing=force and existing)
    plan.imports = [_import_line(config.service_id, module) for module, _ in modules]
    samples = {t.transform_id: t.sample_input for _, t in modules if t.sample_input}

    if existing and not force:
        # Scaffolding a service that already exists is nearly always a mistake —
        # hand-written modules accumulate behaviour a generator cannot recover (upstream
        # quirks found by probing the live API), and silently overwriting them destroys
        # that work with no way back. Adding a new module beside them is safe, provided
        # the shared client stays exactly as it is. Checked before id collisions, so a
        # repeated scaffold is reported as the existing service it is.
        clashing = sorted(f"{m}.py" for m, _ in modules if (svc_dir / f"{m}.py").exists())
        if clashing:
            raise FileExistsError(
                f"{config.service_id} already exists at {svc_dir} and already has "
                f"{', '.join(clashing)}; scaffolding would overwrite it. To add another "
                "endpoint to this service, give it a new name (--name). To replace the whole "
                "service, scaffold again with force (--force on the CLI), or remove it first "
                "(remove-scaffold)."
            )
        api_path = svc_dir / "api.py"
        if api_path.exists() and api_path.read_text() != files["api.py"]:
            raise FileExistsError(
                f"{config.service_id} already exists at {svc_dir} with a different api.py: "
                "its base URL, authentication or headers differ from this scaffold, or it "
                "was edited by hand. Adding this endpoint would change how the existing "
                "transforms call the API. Scaffold it as its own service (--service), or "
                "replace the whole service with force (--force on the CLI)."
            )
        for name, code in files.items():
            if name in ("__init__.py", "api.py") and (svc_dir / name).exists():
                continue
            plan.writes[name] = code
        samples = {**_read_samples(svc_dir / "samples.json"), **samples}
    else:
        plan.writes = dict(files)

    # With force the service directory is replaced, so its own transforms do not count;
    # without it they stay, and a new transform must not collide with them either.
    defined = _defined_transforms(transforms_dir, exclude=svc_dir if force else None)
    clashes = [
        f"{transform.transform_id} (in {defined[transform.transform_id]})"
        for _, transform in modules
        if transform.transform_id in defined
    ]
    if clashes:
        raise ValueError(
            f"Transform id already defined: {', '.join(clashes)}. Transform ids are global "
            "on the server, and a duplicate stops it from starting. Choose another service "
            "name (--service), or for a cURL endpoint another --name."
        )

    if samples:
        plan.writes["samples.json"] = json.dumps(samples, indent=2, sort_keys=True) + "\n"
    return plan


def _read_samples(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def planned_scaffold_paths(
    config: ScaffoldServiceConfig, project_dir: Path, force: bool = False
) -> list[Path]:
    """Return the files :func:`write_scaffold` would write, without writing anything.

    Runs the same checks, so a dry run fails exactly where the real run would.

    Raises:
        FileExistsError: If the service exists and ``force`` is False, and this scaffold
            cannot be added to it.
        ValueError: If a transform id collides with one defined elsewhere under
            ``transforms/``, or the service name is reserved.
    """
    return _plan(config, project_dir, force).paths


def write_scaffold(
    config: ScaffoldServiceConfig, project_dir: Path, force: bool = False
) -> list[Path]:
    """Write generated service files to disk and wire imports into project.py.

    Without ``force``, an existing service gains the new modules only if none of them
    exists yet and its api.py is the one this scaffold would write. With ``force`` the
    whole service directory and its project.py imports are replaced, so no stale module
    or import outlives a narrower re-scaffold.

    Args:
        config: The parsed service configuration to generate code from.
        project_dir: Directory holding ``project.py`` and ``transforms/``.
        force: Replace an existing service instead of refusing. Off by default.

    Returns:
        The paths written, in generation order.

    Raises:
        FileExistsError: If the service exists, ``force`` is False, and this scaffold
            cannot be added to it. Nothing is written.
        ValueError: If a transform id collides with one defined elsewhere under
            ``transforms/``, or the service name is reserved. Nothing is written.
    """
    plan = _plan(config, project_dir, force)
    project_py = project_dir / "project.py"
    if plan.replace_existing:
        shutil.rmtree(plan.svc_dir)
    if force:
        _remove_project_imports(project_py, config.service_id)

    plan.svc_dir.mkdir(parents=True, exist_ok=True)
    for name, code in plan.writes.items():
        (plan.svc_dir / name).write_text(code)

    for import_stmt in plan.imports:
        inject_project_import(project_py, import_stmt)
    return plan.paths


def _is_generated(svc_dir: Path) -> bool:
    """Return whether a service directory was written by the scaffolder.

    Whitespace is normalised, so an api.py from before the marker had a line of its own,
    when it could wrap inside the docstring, still counts.
    """
    try:
        text = (svc_dir / "api.py").read_text()
    except (OSError, UnicodeDecodeError):
        return False
    return GENERATED_MARKER in " ".join(text.split())


def remove_scaffold(service_id: str, project_dir: Path) -> list[str]:
    """Delete a scaffolded service's directory and its project.py imports.

    Only a service whose api.py carries the scaffolder's marker line is deleted: a
    hand-written one (the bundled services) holds work no scaffold can recreate.

    Returns:
        What was removed: the directory path, then each import line.

    Raises:
        ValueError: If ``service_id`` is not a service name, is reserved, names no
            service directory and no import, or names a service the scaffolder did not
            write.
    """
    transforms_dir = project_dir / "transforms"
    if not service_id.isidentifier() or service_id.startswith("_"):
        raise ValueError(f"{service_id!r} is not a service name.")
    if service_id in _RESERVED_SERVICES:
        raise ValueError(
            f"'{service_id}' is the directory of discovered local integrations, not a "
            "service; remove those by hand."
        )
    svc_dir = transforms_dir / service_id
    project_py = project_dir / "project.py"
    imported = project_py.exists() and re.search(
        rf"transforms\.{re.escape(service_id)}(\.|\s)", project_py.read_text()
    )
    if not svc_dir.is_dir() and not imported:
        services = sorted(
            path.name
            for path in (transforms_dir.iterdir() if transforms_dir.is_dir() else [])
            if path.is_dir()
            and path.name.isidentifier()
            and not path.name.startswith("_")
            and path.name not in _RESERVED_SERVICES
            and _is_generated(path)
        )
        raise ValueError(
            f"No service named {service_id!r} under {transforms_dir}. Scaffolded services: "
            f"{', '.join(services) or 'none'}."
        )
    if svc_dir.is_dir() and not _is_generated(svc_dir):
        raise ValueError(
            f"{service_id} was not written by the scaffolder: {svc_dir / 'api.py'} lacks the "
            f"line '{GENERATED_MARKER}'. remove-scaffold deletes scaffolded services only, so "
            "hand-written work is never lost; remove this one by hand (its directory and its "
            "imports in project.py) if you mean to."
        )
    removed: list[str] = []
    if svc_dir.is_dir():
        shutil.rmtree(svc_dir)
        removed.append(str(svc_dir))
    removed.extend(_remove_project_imports(project_py, service_id))
    return removed
