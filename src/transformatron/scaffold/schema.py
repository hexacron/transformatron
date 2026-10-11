"""Schema models and entity mapping heuristics for transform scaffolding.

A scaffolded transform turns each *record* of a response into entities. A record is one
element of the list the response is about (EPSS ``data[]``, a top-level array), or the whole
response when it describes a single thing. Within a record:

- fields whose value is something an investigator can pivot on (an address, a domain, a
  CVE, a hash...) become entities, however deep they sit within a bounded depth;
- one of them is the record's *primary* entity, and the record's other plain values
  (scores, dates, flags) become its properties rather than entities of their own;
- a list of objects inside the record is mapped the same way, element by element.

Everything the mapping does not reach is reported in an inventory with the reason, so the
author can see what was left out instead of finding out from an empty graph.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from typing import Any

from maltego import entities

# ---------------------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------------------


@dataclass
class EntityField:
    """A response field whose values become entities.

    ``path`` holds the keys from the record to the value. A list met along the way is
    iterated, so ``("references", "url")`` reads the url of every reference.
    """

    entity_type: str
    path: tuple[str, ...]
    label: str  # the link label
    strip_prefix: str = ""


@dataclass
class PropertyField:
    """A response field set on the record's primary entity as the property ``name``."""

    name: str
    path: tuple[str, ...]
    label: str  # the property's display name


@dataclass
class RecordMapping:
    """Where records sit and how each one becomes entities.

    ``path`` is relative to the parent: to the response for the top level, to the
    enclosing record for an entry of ``nested``. An empty path is the parent itself.
    """

    path: tuple[str, ...] = ()
    primary: EntityField | None = None
    properties: list[PropertyField] = field(default_factory=list)
    entities: list[EntityField] = field(default_factory=list)
    nested: list[RecordMapping] = field(default_factory=list)
    # Whether the primary entity may be the input itself. Where the record is about the
    # input (the whole response, or a record whose one typed field is what was looked
    # up), returning it with its properties enriches the input entity; anywhere else a
    # value equal to the input is an echo, and is skipped.
    enrich_input: bool = False

    def entity_types(self) -> list[str]:
        """Return every entity type this mapping can emit, in first-seen order."""
        types: list[str] = []
        fields = [self.primary] if self.primary else []
        for entity_field in [*fields, *self.entities]:
            if entity_field.entity_type not in types:
                types.append(entity_field.entity_type)
        for child in self.nested:
            types.extend(t for t in child.entity_types() if t not in types)
        return types


def placeholder_mapping() -> RecordMapping:
    """Return the mapping used when nothing is known about the response.

    It reads a ``result`` field as a Phrase: something that generates valid code, which
    the author replaces once they have seen a real response.
    """
    return RecordMapping(primary=EntityField("Phrase", ("result",), "result"), enrich_input=True)


@dataclass
class FieldReport:
    """One leaf path seen in a sample response, and what the mapping did with it."""

    path: str
    sample: str
    outcome: str


@dataclass
class ScaffoldTransformConfig:
    """Configuration for generating a single Maltego transform function."""

    transform_id: str
    display_name: str
    input_entity: str
    endpoint_path: str
    input_param_name: str = "input_val"
    input_location: str = "query"  # "path", "query", or "body"
    http_method: str = "GET"
    mapping: RecordMapping = field(default_factory=placeholder_mapping)
    description: str = ""
    emit_input_constraint: bool = True
    # Sent with every request. The entry named by input_param_name is replaced by the
    # input value at run time when the input travels in that location. A list value is a
    # repeated parameter (`expand=a&expand=b`).
    query_params: dict[str, Any] = field(default_factory=dict)
    request_body: dict[str, Any] | None = None
    body_encoding: str = "json"  # "json" or "form"
    # False when the spec makes authentication optional for this operation: the key is
    # then sent when configured, and the request goes out without it otherwise.
    key_required: bool = True
    # Every leaf of the sample response and what happened to it.
    inventory: list[FieldReport] = field(default_factory=list)
    # The input value seen in the request or spec example: a value the API is known to
    # answer for, recorded in samples.json for the smoke test.
    sample_input: str | None = None

    @property
    def output_entity_types(self) -> list[str]:
        """Return unique output entity types the mapping can emit."""
        return self.mapping.entity_types() or ["Phrase"]


@dataclass
class ScaffoldServiceConfig:
    """Configuration for an entire service integration (module package)."""

    service_id: str
    display_name: str
    base_url: str
    auth_key_name: str | None = None
    auth_header_name: str | None = "X-API-KEY"
    auth_query_param: str | None = None
    auth_type: str = "header"  # "header", "bearer", "query", "none"
    # Sent on every request besides the credential: the Accept, User-Agent, Referer and
    # Cookie headers an API may refuse to answer without.
    headers: dict[str, str] = field(default_factory=dict)
    transforms: list[ScaffoldTransformConfig] = field(default_factory=list)
    # What the scaffolder could not do and the author has to know about: skipped
    # operations, unsupported authentication, fields the mapping does not reach.
    notes: list[str] = field(default_factory=list)


def qualified_entity_type(entity_class_name: str) -> str:
    """Return the Maltego ``TYPE_NAME`` for a std-entities class name.

    Read off the class rather than rebuilt as ``"maltego." + ClassName``: that rule holds
    for most entities but breaks for 72 of the 244 the package exports. Every
    ``Affiliation*`` class maps to ``maltego.affiliation.<Name>``, every ``STIX2*`` class to
    a hyphenated ``maltego.STIX2.<name>`` (``STIX2attackpattern`` →
    ``maltego.STIX2.attack-pattern``), and ``Hashtag`` to a lowercase ``maltego.hashtag``.
    Reconstructing the string emits a constraint naming an entity type that does not exist,
    which the client silently fails to route on.

    Args:
        entity_class_name: Bare class name, e.g. ``"Domain"``.

    Returns:
        The qualified type name, e.g. ``"maltego.Domain"``.

    Raises:
        ValueError: If no such entity class is exported by ``maltego.entities``.
    """
    entity_class = getattr(entities, entity_class_name, None)
    type_name = getattr(entity_class, "TYPE_NAME", None)
    if not isinstance(type_name, str):
        raise ValueError(
            f"'{entity_class_name}' is not an entity class exported by maltego.entities. "
            f"Check the name against `python -c 'import maltego.entities; "
            f"print(dir(maltego.entities))'`."
        )
    return type_name


def entity_property_ids(entity_class_name: str) -> set[str]:
    """Return the ids of the typed properties an entity class declares.

    A dynamic property with one of these names would instead set the typed property, and
    for the property that holds the entity's value (a Domain's ``fqdn``, a Phrase's
    ``text``) it would silently replace the value itself.
    """
    entity_class = getattr(entities, entity_class_name, None)
    definitions = getattr(entity_class, "entity_properties", None) or {}
    return {prop.name for prop in definitions.values() if getattr(prop, "name", None)}


# ---------------------------------------------------------------------------------------
# Key and value heuristics
# ---------------------------------------------------------------------------------------


def key_tokens(key: str) -> list[str]:
    """Split a key into lowercase words: camelCase, kebab-case, snake_case and dots.

    ``cveMetadata.assignerOrgId`` becomes ``["cve", "metadata", "assigner", "org", "id"]``.
    Acronyms split oddly (``IPv4Address`` gives ``["i", "pv4", "address"]``), which is why
    matching joins trailing tokens back together rather than comparing them one by one.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", key)
    return [token.lower() for token in re.split(r"[^A-Za-z0-9]+", spaced) if token]


def squash(key: str) -> str:
    """Return ``key`` lowercased with every separator removed: ``Status-Code`` → ``statuscode``."""
    return "".join(key_tokens(key))


def _key_suffixes(key: str) -> list[str]:
    """Return the joined trailing tokens of a key, longest first.

    ``cert_sha256`` gives ``["certsha256", "sha256"]``: a rule naming ``sha256`` matches
    on a word boundary, where a plain ``endswith`` would also match ``notsha256``.
    """
    tokens = key_tokens(key)
    return ["".join(tokens[i:]) for i in range(len(tokens))]


def humanize(key: str) -> str:
    """Return a readable label for a key: ``cveMetadata.assignerOrgId`` →
    ``Cve Metadata Assigner Org Id``."""
    return " ".join(token.title() for token in key_tokens(key)) or key


_EMAIL_VALUE_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
_CVE_VALUE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_HASH_VALUE_RE = re.compile(r"^[a-fA-F0-9]{32,128}$")
# Exactly the digest lengths of MD5, SHA-1, SHA-256 and SHA-512. On the output side a
# hash is recognised by value alone, so the lengths are kept strict.
_DIGEST_VALUE_RE = re.compile(
    r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$"
)
_DOMAIN_VALUE_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63})\.?$", re.I
)
# File extensions that the domain pattern would otherwise accept as a TLD. A path segment
# like `lookup.json` or a value like `log4j-core.jar` is a file, not a domain to pivot on.
_FILE_EXTENSIONS = frozenset(
    {
        "json",
        "xml",
        "php",
        "html",
        "htm",
        "txt",
        "csv",
        "asp",
        "aspx",
        "jsp",
        "cgi",
        "yaml",
        "yml",
        "jar",
        "war",
        "exe",
        "dll",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "ico",
        "css",
        "js",
        "py",
        "java",
        "class",
        "log",
        "ini",
        "cfg",
        "conf",
        "gz",
        "tgz",
        "tar",
        "rpm",
        "deb",
        "msi",
        "apk",
    }
)


def infer_value_entity(value: Any) -> str | None:
    """Return the entity a value unambiguously looks like, or None.

    Strict on purpose: this decides between entity types from data alone, so a loose
    rule (any string containing ``:`` as IPv6, say) would turn timestamps into addresses.
    Hashes are not recognised here; see :func:`looks_like_digest`.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return "IPv4Address" if address.version == 4 else "IPv6Address"
    if text.startswith(("http://", "https://")):
        return "URL"
    if _EMAIL_VALUE_RE.match(text):
        return "EmailAddress"
    if _CVE_VALUE_RE.match(text):
        return "CVE"
    domain = _DOMAIN_VALUE_RE.match(text.removeprefix("*."))
    if domain and domain.group(1).lower() not in _FILE_EXTENSIONS:
        return "Domain"
    return None


def looks_like_file_name(text: str) -> bool:
    """Return whether ``text`` ends in a file extension: ``lookup.json``, ``log4j-core.jar``."""
    _, dot, extension = text.rpartition(".")
    return bool(dot) and extension.lower() in _FILE_EXTENSIONS


def looks_like_digest(value: Any) -> bool:
    """Return whether ``value`` is an MD5, SHA-1, SHA-256 or SHA-512 hex digest."""
    return isinstance(value, str) and bool(_DIGEST_VALUE_RE.match(value.strip()))


# Input parameter names, matched on trailing words (see _key_suffixes).
_INPUT_RULES: tuple[tuple[str, str, frozenset[str]], ...] = (
    ("IPv6Address", "ip", frozenset({"ipv6", "ip6", "ipv6address"})),
    (
        "IPv4Address",
        "ip",
        frozenset({"ip", "ipv4", "ipaddress", "ipv4address", "address", "hostip"}),
    ),
    ("Domain", "domain", frozenset({"domain", "domainname", "hostname", "host", "fqdn", "site"})),
    ("URL", "url", frozenset({"url", "link", "uri", "targeturl"})),
    ("EmailAddress", "email", frozenset({"email", "mail", "emailaddress"})),
    (
        "Hash",
        "hash",
        frozenset({"hash", "md5", "sha1", "sha256", "sha512", "checksum", "filehash"}),
    ),
    (
        "CVE",
        "cve",
        frozenset({"cve", "cveid", "vulnerability", "vulnerabilityid", "vulnid"}),
    ),
)
_VALIDATOR_KINDS = {
    "IPv4Address": "ip",
    "IPv6Address": "ip",
    "Domain": "domain",
    "URL": "url",
    "EmailAddress": "email",
    "CVE": "cve",
    "Hash": "hash",
}


def infer_input_entity(param_name: str, sample_val: str | None = None) -> tuple[str, str]:
    """Infer the input entity type and validation helper kind from param name and sample value.

    The name is consulted first, matched on its trailing words so ``domainName``,
    ``ip-address`` and ``vulnerability_id`` are recognised, then the value.

    Returns:
        A tuple of (entity_type, validator_kind), e.g. ("IPv4Address", "ip").
    """
    clean_name = param_name.strip("{}<>:")
    by_value = infer_value_entity(sample_val)
    for suffix in _key_suffixes(clean_name):
        for entity_type, kind, names in _INPUT_RULES:
            if suffix not in names:
                continue
            # A vulnerability id may be a GHSA or vendor id; it is only a CVE when the
            # example says so, or when there is no example to contradict it.
            if entity_type == "CVE" and sample_val and by_value != "CVE":
                return "Phrase", "phrase"
            return entity_type, kind

    if by_value:
        return by_value, _VALIDATOR_KINDS[by_value]
    if sample_val and _HASH_VALUE_RE.match(sample_val.strip()):
        return "Hash", "hash"
    return "Phrase", "phrase"


# Output field names. Each rule is (entity type, names, mode): "suffix" rules match the
# key's trailing words (`client_ip`, `cert_sha256`, `emailAddress`); "exact" rules match
# the whole key only, because their words are common inside unrelated names (`name` in
# `file_name`, `state` in `estate`, `cc` in `email_cc`). Longer matches win.
_OUTPUT_RULES: tuple[tuple[str, frozenset[str], str], ...] = (
    (
        "Image",
        frozenset(
            {"image", "imageurl", "avatar", "avatarurl", "photo", "photourl", "thumbnail"}
            | {"screenshot", "screenshoturl", "logo", "logourl", "favicon"}
        ),
        "suffix",
    ),
    ("IPv6Address", frozenset({"ipv6", "ip6", "ipv6address", "ipv6addresses"}), "suffix"),
    (
        "IPv4Address",
        frozenset({"ip", "ips", "ipv4", "ipaddress", "ipaddresses", "ipv4address", "hostip"}),
        "suffix",
    ),
    (
        "Domain",
        frozenset(
            {"domain", "domains", "domainname", "hostname", "hostnames", "fqdn", "subdomain"}
            | {"subdomains", "dnsname", "dnsnames", "san", "sans", "subjectaltname"}
        ),
        "suffix",
    ),
    ("Domain", frozenset({"host"}), "exact"),
    (
        "DNSName",
        frozenset({"dns", "ptr", "rdns", "reversedns", "nameserver", "nameservers"}),
        "suffix",
    ),
    ("URL", frozenset({"url", "urls", "uri", "link", "href", "permalink"}), "suffix"),
    ("EmailAddress", frozenset({"email", "emails", "emailaddress", "mail"}), "suffix"),
    ("CVE", frozenset({"cve", "cves", "cveid", "cveids"}), "suffix"),
    (
        "Hash",
        frozenset(
            {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "hash", "hashes"}
            | {"checksum", "imphash", "ssdeep", "tlsh"}
        ),
        "suffix",
    ),
    (
        "AS",
        frozenset({"asn", "asnumber", "asnum", "autonomoussystem", "autonomoussystemnumber"}),
        "suffix",
    ),
    (
        "ISP",
        frozenset({"isp", "org", "organization", "organisation", "operator", "asname"})
        | frozenset({"carrier", "asorg", "asorganization"}),
        "exact",
    ),
    ("Country", frozenset({"country", "countrycode", "countryname"}), "suffix"),
    ("Country", frozenset({"cc"}), "exact"),
    ("City", frozenset({"city", "cityname", "town"}), "suffix"),
    ("Location", frozenset({"location", "continent", "region", "state", "province"}), "exact"),
    ("Netblock", frozenset({"cidr", "netblock", "subnet", "iprange"}), "suffix"),
    ("Netblock", frozenset({"network"}), "exact"),
    ("Port", frozenset({"port", "ports", "openports", "destport", "srcport", "dstport"}), "suffix"),
    (
        "Person",
        frozenset({"person", "name", "fullname", "owner", "author", "contact", "registrant"}),
        "exact",
    ),
    (
        "Company",
        frozenset({"company", "companyname", "employer", "vendor", "vendorname"})
        | frozenset({"manufacturer"}),
        "exact",
    ),
    ("PhoneNumber", frozenset({"phone", "phonenumber", "telephone"}), "suffix"),
    ("PhoneNumber", frozenset({"tel", "mobile", "fax"}), "exact"),
    (
        "Alias",
        frozenset({"alias", "aliases", "username", "handle", "screenname", "nick", "nickname"})
        | frozenset({"login"}),
        "exact",
    ),
    ("MacAddress", frozenset({"mac", "macaddress", "macaddr", "hardwareaddress"}), "suffix"),
    ("BTCAddress", frozenset({"bitcoin", "bitcoinaddress", "btc", "btcaddress"}), "exact"),
    (
        "CryptocurrencyAddress",
        frozenset({"wallet", "walletaddress", "cryptoaddress", "cryptocurrencyaddress"}),
        "exact",
    ),
    ("Website", frozenset({"website", "site", "homepage"}), "exact"),
    (
        "Malware",
        frozenset({"malware", "malwarename", "family", "malwarefamily", "trojan"}),
        "exact",
    ),
    (
        "X509Certificate",
        frozenset({"certificate", "cert", "sslcert", "x509", "tlscert"}),
        "exact",
    ),
    ("WHOISRecord", frozenset({"whois", "whoisrecord", "whoisdata"}), "exact"),
    (
        "AttackPattern",
        frozenset({"behavior", "behaviors", "technique", "attackpattern", "mitre", "tactic"})
        | frozenset({"threat"}),
        "exact",
    ),
)

# Name matches the value may overrule. `name` maps to Person, but a list of DNS answers
# carries domains and addresses under `name` and `data`; a value that is unambiguously
# an address or domain is better evidence than a generic key.
_WEAK_NAME_MATCHES = frozenset({"Person", "Location", "ISP", "Company", "Alias", "Domain"})
_ADDRESS_TYPES = frozenset({"IPv4Address", "IPv6Address"})
# Keys whose hex values are identifiers or serial numbers rather than content digests.
_ID_TOKENS = frozenset({"id", "uuid", "guid", "key", "token", "serial", "number", "nonce"})
_DN_RE = re.compile(r"^\s*[A-Za-z.]+\s*=.*,\s*[A-Za-z.]+\s*=")
_ENUM_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")


def _name_rule(field_name: str) -> str | None:
    squashed = squash(field_name)
    for suffix in _key_suffixes(field_name):
        for entity_type, names, mode in _OUTPUT_RULES:
            if suffix in names and (mode == "suffix" or suffix == squashed):
                return entity_type
    return None


# Keys too generic to type a field without a value to confirm them: `name` is a pet's, a
# tag's or a file's as often as a person's, and `state` a lifecycle as often as a place.
# A schema without examples gives no value (None), so there the key alone does not decide.
_WEAK_NAMES = frozenset({"name", "owner", "contact", "state", "region", "province"})


def _value_supports(entity_type: str, value: Any) -> bool:
    """Return whether a sample value is plausible for a name-matched entity type."""
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    if entity_type in ("Port", "AS"):
        text = str(value).strip().upper().removeprefix("AS")
        return text.isdigit()
    if not isinstance(value, str):
        return False
    if entity_type == "Person":
        # A certificate issuer is a distinguished name (`C=US, O=..., CN=...`), and a
        # reference's `name` is a one-word title ("advisory"); neither is a person.
        words = value.split()
        return (
            not _DN_RE.match(value)
            and 2 <= len(words) <= 5
            and not any(char.isdigit() for char in value)
        )
    if entity_type == "Location":
        # `state: PUBLISHED` is a lifecycle state, not a place.
        return not _ENUM_RE.match(value.strip())
    return True


def infer_output_entity(field_name: str, sample_val: Any = None) -> str:
    """Return the entity type for a response field, or ``"Phrase"`` when it is untyped.

    ``sample_val`` is one value (for a list, its first element). The name decides first,
    matched on its trailing words; the value can overrule a weak name match, veto one it
    contradicts, and type a field whose name says nothing (a domain under ``common_name``,
    a CVE under ``vulnerability_id``, a SHA-256 under ``fingerprint``).
    """
    by_name = _name_rule(field_name)
    if sample_val is None and squash(field_name) in _WEAK_NAMES:
        by_name = None
    by_value = infer_value_entity(sample_val)
    if by_name is not None:
        if by_name in _ADDRESS_TYPES and by_value in _ADDRESS_TYPES:
            return by_value
        if by_name in _WEAK_NAME_MATCHES and by_value:
            return by_value
        if _value_supports(by_name, sample_val):
            return by_name
    if by_value:
        return by_value
    tokens = set(key_tokens(field_name))
    if looks_like_digest(sample_val) and not tokens & _ID_TOKENS:
        return "Hash"
    return "Phrase"


# ---------------------------------------------------------------------------------------
# Response mapping
# ---------------------------------------------------------------------------------------

# Fields at the top of a response that describe the response rather than the thing looked
# up: status, version, paging. Compared squashed, so `status-code` matches `statusCode`.
_ENVELOPE_KEYS = frozenset(
    {
        "status",
        "statuscode",
        "statusmessage",
        "version",
        "apiversion",
        "access",
        "total",
        "totalcount",
        "totalresults",
        "totalhits",
        "offset",
        "limit",
        "page",
        "pages",
        "pagesize",
        "perpage",
        "pagecount",
        "next",
        "nextpage",
        "nexturl",
        "previous",
        "prev",
        "prevpage",
        "count",
        "path",
        "ok",
        "success",
        "error",
        "errors",
        "message",
        "messages",
        "code",
        "took",
        "timedout",
        "hasmore",
        "cursor",
        "nextcursor",
        "nextpagetoken",
        "iterator",
        "requestid",
        "links",
        "meta",
        "metadata",
        "pagination",
        "query",
        "querytime",
        "elapsed",
        "warnings",
    }
)
# Top-level keys that mean the response is one page of a larger result.
_PAGINATION_KEYS = frozenset(
    {
        "total",
        "totalcount",
        "totalresults",
        "totalhits",
        "next",
        "nextpage",
        "nexturl",
        "cursor",
        "nextcursor",
        "nextpagetoken",
        "hasmore",
        "offset",
        "limit",
        "page",
        "pages",
        "pagesize",
        "perpage",
        "iterator",
    }
)
# Objects that hold bookkeeping about the data rather than the data: provenance,
# hypermedia links, schema markers, visibility flags. Skipped whole, at any depth;
# following them is how an ORCID record yields `source.source-orcid.host` as "data".
_METADATA_KEYS = frozenset(
    {
        "meta",
        "metadata",
        "links",
        "source",
        "provenance",
        "pagination",
        "paging",
        "headers",
        "debug",
        "request",
        "query",
        "schema",
        "lastmodifieddate",
        "createddate",
        "visibility",
        "providermetadata",
        "xgenerator",
    }
)
# Keys whose value usually names the record, in order of preference: the value of the
# Phrase that stands in for a record with no typed field.
_TITLE_KEYS = ("name", "title", "label", "displayname", "fullname", "summary", "id", "identifier")
# Order in which typed fields are preferred as the record's primary entity: the
# identity-like types first, attribute-like ones (a city, a port) last.
_PRIMARY_ORDER = (
    "CVE",
    "IPv4Address",
    "IPv6Address",
    "Domain",
    "URL",
    "EmailAddress",
    "Hash",
    "DNSName",
    "AS",
    "Netblock",
    "Person",
    "Company",
    "Alias",
    "PhoneNumber",
    "BTCAddress",
    "CryptocurrencyAddress",
    "MacAddress",
    "Malware",
    "X509Certificate",
    "Website",
    "AttackPattern",
    "WHOISRecord",
    "ISP",
    "Location",
    "City",
    "Country",
    "Port",
    "Image",
)
# A CVE's typed properties, under the names APIs commonly use for them. The SDK sets a
# typed property when the property name matches it, so these become CVE.epss / CVE.cvss.
_CVE_TYPED_PROPERTIES = {
    "epss": "epss",
    "epssscore": "epss",
    "cvss": "cvss",
    "cvssscore": "cvss",
    "cvss3": "cvss",
    "cvssv3": "cvss",
    "cvss3score": "cvss",
    "cvssv3score": "cvss",
    "basescore": "cvss",
    "cvssbasescore": "cvss",
}
# Leaf keys that say nothing on their own: `{"given-names": {"value": "Josiah"}}` is
# named by its parent.
_GENERIC_LEAF_KEYS = frozenset({"value", "values", "text", "content"})

TYPED_DEPTH = 4
PROPERTY_DEPTH = 3
PROPERTY_LIMIT = 30
_KEY_LIMIT = 80
_SAMPLE_LIMIT = 60
_MERGE_LIMIT = 20

OVERRIDE_PROPERTY = "Property"
OVERRIDE_DROP = "Drop"
_NOT_ENTITIES = frozenset({OVERRIDE_PROPERTY, OVERRIDE_DROP})


def _is_metadata_key(key: str) -> bool:
    # An underscore marks bookkeeping in HAL (`_links`) but the data itself in
    # Elasticsearch (`_source`), so only the HAL names count there.
    if key.startswith("_"):
        return squash(key) in ("links", "meta", "metadata")
    return squash(key) in _METADATA_KEYS


def is_envelope_key(key: str) -> bool:
    """Return whether a top-level response key describes the response, not the data."""
    return squash(key) in _ENVELOPE_KEYS


def pagination_keys(sample: Any) -> list[str]:
    """Return the top-level keys of a sample that signal a paginated response."""
    if not isinstance(sample, dict):
        return []
    return [key for key in sample if squash(key) in _PAGINATION_KEYS]


@dataclass
class MappingResult:
    """The mapping inferred from a sample, with what it left out."""

    mapping: RecordMapping
    inventory: list[FieldReport]
    notes: list[str]
    # Top-level response keys that say the response is one page of many.
    pagination: list[str]
    placeholder: bool = False


@dataclass
class _Leaf:
    rel: tuple[str, ...]  # keys from the record being mapped
    keys: tuple[str, ...]  # keys from the top-level record, for labels and depth
    display: str  # path from the response root, with [] for lists
    value: Any
    multi: bool
    entity_type: str
    forced: str | None  # an override: an entity type or OVERRIDE_PROPERTY


def _short(value: Any) -> str:
    text = str(value)
    text = " ".join(text.split())
    return text if len(text) <= _SAMPLE_LIMIT else text[: _SAMPLE_LIMIT - 3] + "..."


def _merge(elements: list[Any]) -> dict[str, Any]:
    """Merge the first few objects of a list into one sample with every key seen.

    Real lists are ragged: the first element may lack a field, or hold null where a later
    one has a value. Mapping from the first element alone would drop that field.
    """
    merged: dict[str, Any] = {}
    for element in elements[:_MERGE_LIMIT]:
        if not isinstance(element, dict):
            continue
        for key, value in element.items():
            if merged.get(key) in (None, "", [], {}):
                merged[key] = value
    return merged


def _join(display: str, key: str) -> str:
    return f"{display}.{key}" if display else key


def _parse_path(path: str) -> tuple[str, ...]:
    """Return the keys of a dotted path; ``[]`` list markers are optional and ignored."""
    return tuple(part for part in path.replace("[]", "").strip().split(".") if part)


def parse_overrides(mappings: list[str] | None) -> dict[tuple[str, ...], str]:
    """Parse ``PATH=TYPE`` overrides into {keys: type}.

    Raises:
        ValueError: On a malformed override or an unknown entity type.
    """
    overrides: dict[tuple[str, ...], str] = {}
    for raw in mappings or []:
        path, sep, target = raw.rpartition("=")
        keys = _parse_path(path)
        target = target.strip()
        if not sep or not keys or not target:
            raise ValueError(f"--map expects PATH=TYPE, e.g. 'data[].ip=IPv4Address'; got {raw!r}.")
        if target.lower() == OVERRIDE_PROPERTY.lower():
            target = OVERRIDE_PROPERTY
        elif target.lower() == OVERRIDE_DROP.lower():
            target = OVERRIDE_DROP
        else:
            try:
                qualified_entity_type(target)
            except ValueError:
                raise ValueError(
                    f"--map {raw!r}: {target!r} is not an entity class in maltego.entities. "
                    f"Use a class name such as Domain, IPv4Address or Company, or "
                    f"{OVERRIDE_PROPERTY} to attach the field as a property, or "
                    f"{OVERRIDE_DROP} to leave it out."
                ) from None
        overrides[keys] = target
    return overrides


def _resolve(sample: Any, keys: tuple[str, ...]) -> tuple[list[Any], str] | None:
    """Follow ``keys`` through a sample, iterating lists; return the nodes and display path.

    Returns None when the path does not exist in the sample.
    """
    nodes = [sample]
    display = ""
    for key in keys:
        if any(isinstance(node, list) for node in nodes):
            display += "[]"
        items = [item for node in nodes for item in (node if isinstance(node, list) else [node])]
        stepped = [item[key] for item in items if isinstance(item, dict) and key in item]
        if not stepped:
            return None
        display = _join(display, key)
        nodes = stepped
    if any(isinstance(node, list) for node in nodes):
        display += "[]"
    flat = [item for node in nodes for item in (node if isinstance(node, list) else [node])]
    return flat, display


# Keys beside the records that summarise the result rather than holding records of their
# own: Elasticsearch's `_shards` counters and `aggregations` buckets, Solr's `facets`.
_SUMMARY_KEYS = frozenset({"shards", "aggregations", "aggs", "facets"})


def _substantive(key: str, value: Any, wrapped: bool) -> bool:
    """Return whether a key beside a candidate list of records holds data of its own.

    Inside a wrapper object a score or flag is bookkeeping too (Elasticsearch's
    ``hits.max_score``, a float or null); an integer may be an id, and at the top level any
    scalar may be the record's own data.
    """
    if is_envelope_key(key) or squash(key) in _SUMMARY_KEYS:
        return False
    return not (wrapped and (value is None or isinstance(value, bool | float)))


def _auto_records(sample: Any) -> tuple[str, ...]:
    """Find the records in a sample: a top-level list, or the one list in an envelope.

    An envelope is an object whose keys, apart from status, paging and summary fields, are
    a single list of objects (EPSS ``data``, urlscan ``results``), possibly behind wrapper
    objects (``{"data": {"items": [...]}}``, Elasticsearch ``hits.hits``). Anything else
    is one record.
    """
    node, path = sample, ()
    for _ in range(3):
        if not isinstance(node, dict):
            break
        data_keys = [key for key in node if _substantive(key, node[key], bool(path))]
        if len(data_keys) != 1:
            break
        value = node[data_keys[0]]
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            return (*path, data_keys[0])
        if isinstance(value, dict):
            node, path = value, (*path, data_keys[0])
            continue
        break
    return path


def _echo_key(value: Any) -> str:
    """Normalise a value for comparison with the input: ``*.Example.com.`` → ``example.com``."""
    return str(value).strip().removeprefix("*.").rstrip(".").casefold()


class _Mapper:
    """Walks one sample and builds the mapping, recording every leaf's outcome."""

    def __init__(
        self,
        overrides: dict[tuple[str, ...], str],
        input_value: str | None,
        record_keys: tuple[str, ...],
        primary: tuple[str, ...] | None = None,
    ) -> None:
        self.overrides = overrides
        self.used: set[tuple[str, ...]] = set()
        self.input_value = _echo_key(input_value) if input_value else None
        self.record_keys = record_keys
        # The field --primary names, and what became of it: where it was used, or why it
        # could not be; and every field it could have named, for the error otherwise.
        self.primary = primary
        self.primary_found: str | None = None
        self.primary_problem: str | None = None
        self.candidates: list[str] = []
        self.inventory: list[FieldReport] = []
        # Where each path was first met, so the inventory reads in document order even
        # though a record's own fields are decided after the lists nested inside it.
        self.order: dict[str, int] = {}

    def _names(self, wanted: tuple[str, ...], keys: tuple[str, ...]) -> bool:
        """Return whether a path the author wrote, from the record or the root, is ``keys``."""
        return wanted in (keys, (*self.record_keys, *keys))

    def override(self, keys: tuple[str, ...]) -> str | None:
        """Return the override for a node, matched from the record or the response root."""
        for candidate in (keys, (*self.record_keys, *keys)):
            if candidate in self.overrides:
                self.used.add(candidate)
                return self.overrides[candidate]
        return None

    def is_primary(self, keys: tuple[str, ...]) -> bool:
        return self.primary is not None and self._names(self.primary, keys)

    def named_within(self, keys: tuple[str, ...]) -> bool:
        """Return whether an override or --primary names a field inside the node at ``keys``.

        A subtree otherwise skipped whole (metadata, an envelope) is then walked, so the
        field the author asked for is mapped rather than dropped with the rest.
        """
        named = [*self.overrides, *([self.primary] if self.primary else [])]
        for candidate in (keys, (*self.record_keys, *keys)):
            size = len(candidate)
            if any(len(path) > size and path[:size] == candidate for path in named):
                return True
        return False

    def report(self, display: str, value: Any, outcome: str) -> None:
        self.order.setdefault(display, len(self.order))
        self.inventory.append(FieldReport(display, _short(value), outcome))

    def report_tree(self, display: str, value: Any, outcome: str) -> None:
        """Report every leaf under ``value`` with the same outcome."""
        if isinstance(value, dict) and value:
            for key, child in value.items():
                self.report_tree(_join(display, key), child, outcome)
        elif isinstance(value, list) and value:
            objects = [element for element in value if isinstance(element, dict)]
            if objects:
                self.report_tree(display + "[]", _merge(objects), outcome)
            else:
                self.report(display + "[]", value[0], outcome)
        else:
            self.report(display, value, outcome)

    def sorted_inventory(self) -> list[FieldReport]:
        return sorted(self.inventory, key=lambda report: self.order.get(report.path, 0))

    # -- walking ---------------------------------------------------------------------

    def record(
        self,
        node: dict[str, Any],
        keys: tuple[str, ...],
        display: str,
        top: bool,
        envelope_level: bool,
        single: bool,
        skipped: str | None = None,
    ) -> tuple[RecordMapping, list[_Leaf]]:
        """Map one record (a dict); ``keys`` lead from the top-level record to it.

        Returns the mapping, and the ``--map PATH=Property`` fields it had no entity for:
        the enclosing record takes those over (see :meth:`_assign`).
        """
        # A status or version key describes the response only beside another such key
        # (`{"status": "ok", "version": 2, ...}`); alone it is a field of the record, like
        # a Petstore pet's `status`.
        envelope_level = envelope_level and sum(is_envelope_key(key) for key in node) >= 2
        leaves: list[_Leaf] = []
        nested: list[RecordMapping] = []
        for key, value in node.items():
            self._visit(
                key,
                value,
                (key,),
                (*keys, key),
                _join(display, key),
                leaves,
                nested,
                envelope_level,
                skipped,
            )
        mapping = RecordMapping(nested=nested)
        orphans = self._assign(mapping, leaves, top=top, single=single)
        return mapping, orphans

    def _visit(
        self,
        key: str,
        value: Any,
        rel: tuple[str, ...],
        keys: tuple[str, ...],
        display: str,
        leaves: list[_Leaf],
        nested: list[RecordMapping],
        envelope_level: bool,
        skipped: str | None,
    ) -> None:
        """Collect the leaves under one key of a record.

        ``skipped`` is set inside a subtree that is dropped except for the fields the
        author named: every other leaf there is reported with that reason.
        """
        forced = self.override(keys)
        if forced == OVERRIDE_DROP:
            self.report_tree(display, value, "dropped: by --map")
            return
        container = isinstance(value, dict | list)
        if forced is None and skipped is None:
            reason = None
            if envelope_level and len(rel) == 1 and is_envelope_key(key):
                reason = "envelope"
            elif container and _is_metadata_key(key):
                reason = "metadata"
            elif any(len(part) > _KEY_LIMIT or (" " in part and len(part) > 40) for part in rel):
                reason = "key too long to map"
            if reason is not None:
                if not self.named_within(keys):
                    self.report_tree(display, value, f"dropped: {reason}")
                    return
                skipped = reason

        if isinstance(value, dict):
            if forced is not None:
                unknown = "" if value else " (empty in the sample, so its fields are unknown)"
                raise ValueError(
                    f"--map {display}: that is an object{unknown}; map one of its fields "
                    f"instead, or use {OVERRIDE_DROP} to leave it out."
                )
            if not value:
                self.report(display, value, "dropped: empty in the sample")
                return
            for child_key, child in value.items():
                self._visit(
                    child_key,
                    child,
                    (*rel, child_key),
                    (*keys, child_key),
                    _join(display, child_key),
                    leaves,
                    nested,
                    envelope_level,
                    skipped,
                )
            return

        if isinstance(value, list):
            self._visit_list(value, rel, keys, display, leaves, nested, forced, skipped)
            return

        multi = isinstance(value, str) and "\n" in value.strip()
        sample = value.strip().splitlines()[0] if multi else value
        self._collect(leaves, rel, keys, display, sample, multi, forced, skipped)

    def _visit_list(
        self,
        value: list[Any],
        rel: tuple[str, ...],
        keys: tuple[str, ...],
        display: str,
        leaves: list[_Leaf],
        nested: list[RecordMapping],
        forced: str | None,
        skipped: str | None,
    ) -> None:
        elements = [element for element in value if element is not None]
        if not elements:
            if value or forced is not None:
                # Values unknown (a schema without examples), or none in this sample but
                # mapped by the author: the name decides, or the --map does.
                shown = None if value else []
                self._collect(leaves, rel, keys, display + "[]", shown, True, forced, skipped)
            else:
                self.report(display + "[]", value, "dropped: empty in the sample")
            return
        if all(isinstance(element, dict) for element in elements):
            if forced is not None:
                raise ValueError(
                    f"--map {display}: that is a list of objects; map one of their "
                    f"fields instead (e.g. {display}[].<field>), or use --records "
                    f"{display} to make them the records."
                )
            if skipped is not None and not self.named_within(keys):
                self.report_tree(display, value, f"dropped: {skipped}")
                return
            # Each element is a record of its own, mapped where it sits.
            child, orphans = self.record(
                _merge(elements),
                keys,
                display + "[]",
                top=False,
                envelope_level=False,
                single=False,
                skipped=skipped,
            )
            child.path = rel
            if child.primary or child.entities or child.nested:
                nested.append(child)
            # A forced property its elements had no entity for goes on this record's
            # entity, with every element's value: pluck() iterates the list.
            leaves.extend(
                replace(orphan, rel=(*rel, *orphan.rel), multi=True) for orphan in orphans
            )
            return
        if any(isinstance(element, dict | list) for element in elements):
            if forced is not None:
                raise ValueError(
                    f"--map {display}: that list mixes plain values with objects or lists, "
                    f"which the mapping cannot read; use {OVERRIDE_DROP}, or edit RECORDS in "
                    "the module."
                )
            self.report(display + "[]", value, "dropped: list of mixed or nested lists")
            return
        self._collect(leaves, rel, keys, display + "[]", elements[0], True, forced, skipped)

    def _collect(
        self,
        leaves: list[_Leaf],
        rel: tuple[str, ...],
        keys: tuple[str, ...],
        display: str,
        value: Any,
        multi: bool,
        forced: str | None,
        skipped: str | None,
    ) -> None:
        if skipped is not None and forced is None and not self.is_primary(keys):
            self.report(display, value, f"dropped: {skipped}")
            return
        self.order.setdefault(display, len(self.order))
        name = rel[-1]
        if squash(name) in _GENERIC_LEAF_KEYS and len(keys) > 1:
            name = keys[-2]
        entity_type = infer_output_entity(name, value)
        leaves.append(_Leaf(rel, keys, display, value, multi, entity_type, forced))

    # -- deciding ----------------------------------------------------------------------

    def _assign(
        self, mapping: RecordMapping, leaves: list[_Leaf], top: bool, single: bool
    ) -> list[_Leaf]:
        """Decide each leaf of a record; return the forced properties left without an entity.

        A nested record hands those to its enclosing record (MITRE's
        ``containers.cna.descriptions[].value`` goes on the CVE). The top-level record has
        no enclosing one, so there they are an error rather than silently dropped.
        """
        typed: list[tuple[_Leaf, str]] = []
        untyped: list[_Leaf] = []
        explicit: tuple[_Leaf, str] | None = None
        for leaf in leaves:
            if self.is_primary(leaf.keys) and self._primary_usable(leaf):
                explicit = (leaf, leaf.forced or leaf.entity_type)
                typed.append(explicit)
            elif leaf.forced == OVERRIDE_PROPERTY:
                untyped.append(leaf)
            elif leaf.forced is not None:
                typed.append((leaf, leaf.forced))
            elif leaf.entity_type != "Phrase":
                if len(leaf.keys) > TYPED_DEPTH:
                    self.report(
                        leaf.display,
                        leaf.value,
                        f"dropped: deeper than {TYPED_DEPTH}; use --records/--map",
                    )
                else:
                    typed.append((leaf, leaf.entity_type))
            elif len(leaf.rel) > PROPERTY_DEPTH:
                self.report(
                    leaf.display,
                    leaf.value,
                    f"dropped: deeper than {PROPERTY_DEPTH}; use --map PATH=Property",
                )
            else:
                untyped.append(leaf)
        self.candidates.extend(
            leaf.display
            for leaf, _ in typed
            if not leaf.multi and leaf.display not in self.candidates
        )

        # The primary may be the input itself only where the record is about the input:
        # the whole response, a top-level record whose one typed field is what was looked
        # up (EPSS: the CVE scored), or one whose echo of the input the author chose. A
        # nested list is never about the input.
        chosen_echo = explicit is not None and self._is_echo(explicit[0])
        mapping.enrich_input = top and (single or len(typed) == 1 or chosen_echo)
        primary_leaf = explicit or self._choose_primary(typed, mapping.enrich_input)
        if explicit is not None:
            self.primary_found = explicit[0].display
        if primary_leaf is not None:
            leaf, entity_type = primary_leaf
            mapping.primary = self._entity(leaf, entity_type)
            self.report(leaf.display, leaf.value, _outcome(f"entity {entity_type}", leaf, True))
        for leaf, entity_type in typed:
            if primary_leaf is not None and leaf is primary_leaf[0]:
                continue
            mapping.entities.append(self._entity(leaf, entity_type))
            self.report(leaf.display, leaf.value, _outcome(f"entity {entity_type}", leaf))

        single_typed = any(not leaf.multi for leaf, _ in typed)
        if mapping.primary is None and top and not single_typed:
            # A record with no single-valued entity still deserves a node to carry its
            # fields: a Phrase naming it. Beside other entities (EDGAR's filing beside
            # its companies, a pet beside its photo URLs) only a field whose key names
            # the record will do. A record whose single entity field went unused (crt.sh
            # echoing the domain searched for) has its identity already; --primary names it.
            has_entities = bool(typed) or any(child.entity_types() for child in mapping.nested)
            title = _choose_title(untyped, strict=has_entities)
            if title is not None:
                untyped.remove(title)
                mapping.primary = EntityField("Phrase", title.rel, _link_label(title.keys))
                self.report(title.display, title.value, "entity Phrase (primary)")

        if mapping.primary is None:
            forced = [leaf for leaf in untyped if leaf.forced == OVERRIDE_PROPERTY]
            if top and forced:
                raise ValueError(
                    f"--map {', '.join(leaf.display for leaf in forced)}={OVERRIDE_PROPERTY}: "
                    "the record has no primary entity to attach it to (list fields and echoes "
                    "of the input are never primary). Map a single-valued field to an entity "
                    "type (--map PATH=Type), or name one with --primary PATH."
                )
            # The remedy named here must be one that works: a list field the author mapped
            # to an entity cannot be primary, and --records would lose the enclosing record.
            reason = (
                "dropped: no primary entity (list fields and input echoes are never primary); "
                "--map a single field to an entity type, or pick one with --primary"
                if top
                else "dropped: no entity in these list elements; --map PATH=Property moves it "
                "to the record's entity"
            )
            for leaf in untyped:
                if leaf.forced is None:
                    self.report(leaf.display, leaf.value, reason)
            return forced

        taken = entity_property_ids(mapping.primary.entity_type)
        inferred = 0
        for leaf in untyped:
            # The cap keeps a wide record from burying its entity; a field the author
            # asked for is never cut by it.
            if leaf.forced is None:
                inferred += 1
                if inferred > PROPERTY_LIMIT:
                    self.report(
                        leaf.display, leaf.value, f"dropped: over {PROPERTY_LIMIT} properties"
                    )
                    continue
            prop = self._property(leaf, mapping.primary.entity_type, taken)
            mapping.properties.append(prop)
            self.report(leaf.display, leaf.value, _outcome(f"property {prop.name}", leaf))
        return []

    def _primary_usable(self, leaf: _Leaf) -> bool:
        """Return whether the field --primary names can be the primary; note why not."""
        entity_type = leaf.forced or leaf.entity_type
        if entity_type == OVERRIDE_PROPERTY or (entity_type == "Phrase" and not leaf.forced):
            self.primary_problem = (
                f"{leaf.display} is not an entity field; make it one with --map "
                f"{leaf.display}=<EntityType>"
            )
            return False
        if leaf.multi:
            self.primary_problem = (
                f"{leaf.display} holds several values, and a record's primary entity is one"
            )
            return False
        return True

    def _is_echo(self, leaf: _Leaf) -> bool:
        return self.input_value is not None and _echo_key(leaf.value) == self.input_value

    def _choose_primary(
        self, typed: list[tuple[_Leaf, str]], about_input: bool
    ) -> tuple[_Leaf, str] | None:
        """Pick the typed field the record's properties attach to.

        Only a single value near the record's root qualifies. A field echoing the input
        is the primary of a record about the input (``about_input``): its properties then
        enrich the input entity. In a list of records with other typed fields it is only a
        back-reference (crt.sh: the domain searched for), so it is no record's identity.
        """
        eligible = [
            (leaf, entity_type)
            for leaf, entity_type in typed
            if not leaf.multi and len(leaf.rel) <= PROPERTY_DEPTH
        ]
        echoes = [pair for pair in eligible if self._is_echo(pair[0])]
        if echoes and about_input:
            return echoes[0]
        candidates = [pair for pair in eligible if pair not in echoes]
        if not candidates:
            return None

        def rank(pair: tuple[_Leaf, str]) -> tuple[int, int]:
            entity_type = pair[1]
            order = _PRIMARY_ORDER.index(entity_type) if entity_type in _PRIMARY_ORDER else 99
            return order, len(pair[0].rel)

        return min(candidates, key=rank)

    @staticmethod
    def _entity(leaf: _Leaf, entity_type: str) -> EntityField:
        return EntityField(
            entity_type,
            leaf.rel,
            _link_label(leaf.keys),
            strip_prefix="AS" if entity_type == "AS" else "",
        )

    @staticmethod
    def _property(leaf: _Leaf, primary_type: str, taken: set[str]) -> PropertyField:
        name = _property_name(leaf.rel)
        typed_name = _CVE_TYPED_PROPERTIES.get(squash(leaf.rel[-1]))
        if primary_type == "CVE" and typed_name and _numeric(leaf.value):
            name = typed_name
        elif name in taken:
            # Keep a plain field off the entity's own typed properties: a Domain's `fqdn`
            # property *is* its value.
            name = f"field.{name}"
        return PropertyField(name, leaf.rel, _display_label(leaf.rel))


def _outcome(text: str, leaf: _Leaf, primary: bool = False) -> str:
    """Return an inventory outcome, marked where it is the primary or the author's --map."""
    marks = (["primary"] if primary else []) + (["--map"] if leaf.forced else [])
    return f"{text} ({', '.join(marks)})" if marks else text


# Title keys a number may name its record under; any other title has to be text.
_ID_TITLE_KEYS = frozenset({"id", "identifier"})
_NON_TITLES = frozenset({"true", "false", "null", "none", "n/a"})
_TITLE_MIN = 4


def _title_key(leaf: _Leaf) -> str:
    name = leaf.rel[-1]
    if squash(name) in _GENERIC_LEAF_KEYS and len(leaf.rel) > 1:
        name = leaf.rel[-2]
    return squash(name)


def _readable_title(leaf: _Leaf) -> bool:
    """Return whether a field's value could name its record to an investigator.

    Elasticsearch's `hits.total.relation` is `eq`: an enum or a two-letter code names
    nothing. An unknown value (a schema without examples) is judged by its key alone.
    """
    value = leaf.value
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return _title_key(leaf) in _ID_TITLE_KEYS
    if not isinstance(value, str):
        return False
    text = value.strip()
    return (
        len(text) >= _TITLE_MIN and not _ENUM_RE.match(text) and text.casefold() not in _NON_TITLES
    )


def _choose_title(untyped: list[_Leaf], strict: bool) -> _Leaf | None:
    """Pick the field whose value names a record that has no entity of its own.

    A field the author made a property stays one. ``strict`` (the record has entities,
    just none single-valued) admits only a key that names the record (`name`, `title`,
    `id`...); otherwise any readable text will do, so a record of plain fields still
    yields one node.
    """
    pool = [
        leaf for leaf in untyped if leaf.forced is None and not leaf.multi and _readable_title(leaf)
    ]
    for wanted in _TITLE_KEYS:
        for leaf in pool:
            if _title_key(leaf) == wanted:
                return leaf
    if strict:
        return None
    for leaf in pool:
        if _title_key(leaf).endswith(("name", "title")) and isinstance(leaf.value, str):
            return leaf
    return next((leaf for leaf in pool if isinstance(leaf.value, str)), None)


def _property_name(rel: tuple[str, ...]) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", ".".join(rel))


def _numeric(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return True
    try:
        float(str(value))
    except ValueError:
        return False
    return True


def _link_label(keys: tuple[str, ...]) -> str:
    """Return the link label for a field: its last two keys, ``references.url``."""
    return ".".join(keys[-2:]) if len(keys) > 1 else keys[0] if keys else "value"


_LABEL_LIMIT = 40


def _display_label(rel: tuple[str, ...]) -> str:
    """Return a property's display name; a long one is cut, marked with an ellipsis."""
    text = " ".join(humanize(part) for part in rel)
    if len(text) > _LABEL_LIMIT:
        text = text[: _LABEL_LIMIT - 1].rstrip() + "\u2026"
    return text


def infer_mapping(
    sample: Any,
    records: str | None = None,
    mappings: list[str] | None = None,
    input_value: str | None = None,
    primary: str | None = None,
) -> MappingResult:
    """Infer how a response becomes entities, from a sample of it.

    Args:
        sample: A decoded sample response, or None when there is none.
        records: Dotted path to the list of records (``data``,
            ``containers.cna.references``); found automatically when omitted.
        mappings: ``PATH=TYPE`` overrides; TYPE is an entity class name, ``Property``
            or ``Drop``. PATH is dotted, from the response root or the record, with
            optional ``[]`` list markers.
        input_value: The input the sample was fetched for, to tell an echo of it apart.
        primary: Dotted path, written like an override's, of the field to make each
            record's primary entity. It must be a single-valued entity field, inferred or
            made one by an override.

    Raises:
        ValueError: If ``records``, ``primary`` or an override does not match the sample
            or cannot be honoured, or an override is malformed.
    """
    overrides = parse_overrides(mappings)
    record_keys = _parse_path(records) if records else ()
    if records is not None and not record_keys:
        raise ValueError(f"--records {records!r} is not a dotted path, e.g. 'data'.")
    primary_keys = _parse_path(primary) if primary else None
    if primary is not None and not primary_keys:
        raise ValueError(f"--primary {primary!r} is not a dotted path, e.g. 'data[].ip'.")

    if sample is None:
        return _mapping_without_sample(record_keys, overrides, primary_keys)

    if not records:
        record_keys = _auto_records(sample)
    resolved = _resolve(sample, record_keys)
    if resolved is None:
        raise ValueError(
            f"--records {records!r} does not match the sample response. Lists in it: "
            f"{', '.join(_list_paths(sample)) or 'none'}."
        )
    nodes, records_display = resolved
    mapper = _Mapper(overrides, input_value, record_keys, primary_keys)
    _report_outside(mapper, sample, record_keys, "")

    single = len(nodes) == 1 and isinstance(nodes[0], dict) and not records_display.endswith("[]")
    dicts = [node for node in nodes if isinstance(node, dict)]
    if dicts:
        mapping, _ = mapper.record(
            _merge(dicts),
            (),
            records_display,
            top=True,
            envelope_level=not record_keys,
            single=single,
        )
    else:
        mapping = _scalar_records(mapper, nodes, record_keys, records_display)
    mapping.path = record_keys

    unknown = [keys for keys in overrides if keys not in mapper.used]
    if unknown:
        raise ValueError(
            f"--map {', '.join('.'.join(keys) for keys in unknown)} does not match a field "
            f"of the records ({records_display or 'the whole response'}) in the sample "
            "response. Leave it out and preview with --dry-run to list the fields."
        )
    if primary is not None and mapper.primary_found is None:
        problem = mapper.primary_problem or (
            f"does not match a field of the records ({records_display or 'the whole response'})"
        )
        raise ValueError(
            f"--primary {primary}: {problem}. Fields that can be primary: "
            f"{', '.join(mapper.candidates) or 'none'}. A field becomes one with --map "
            "PATH=<EntityType>."
        )

    placeholder = not mapping.entity_types()
    if placeholder:
        mapping = placeholder_mapping()
        mapping.path = record_keys
    inventory = mapper.sorted_inventory()
    notes = _dropped_notes(inventory)
    return MappingResult(mapping, inventory, notes, pagination_keys(sample), placeholder)


def _scalar_records(
    mapper: _Mapper, nodes: list[Any], record_keys: tuple[str, ...], display: str
) -> RecordMapping:
    """Map records that are bare values (a list of domains, say): each value is an entity."""
    values = [node for node in nodes if node is not None and not isinstance(node, list)]
    if not values:
        mapper.report(display or "(response)", nodes, "dropped: no values in the sample")
        return RecordMapping()
    name = record_keys[-1] if record_keys else "value"
    entity_type = infer_output_entity(name, values[0])
    mapping = RecordMapping(primary=EntityField(entity_type, (), name))
    mapper.report(display or "(response)", values[0], f"entity {entity_type} (primary)")
    return mapping


def _report_outside(
    mapper: _Mapper, sample: Any, record_keys: tuple[str, ...], display: str
) -> None:
    """Report the fields outside the records: the envelope around them."""
    if not record_keys or not isinstance(sample, dict):
        return
    head, rest = record_keys[0], record_keys[1:]
    for key, value in sample.items():
        path = _join(display, key)
        if key == head:
            if rest and isinstance(value, dict):
                _report_outside(mapper, value, rest, path)
            continue
        outcome = "dropped: envelope" if is_envelope_key(key) else "dropped: outside the records"
        mapper.report_tree(path, value, outcome)


def _list_paths(sample: Any, display: str = "", depth: int = 0) -> list[str]:
    """Return the dotted paths of the lists of objects in a sample, for error messages."""
    found: list[str] = []
    if depth > TYPED_DEPTH:
        return found
    if isinstance(sample, dict):
        for key, value in sample.items():
            found.extend(_list_paths(value, _join(display, key), depth + 1))
    elif isinstance(sample, list) and sample and isinstance(sample[0], dict):
        found.append(display or "(the response itself)")
        found.extend(_list_paths(_merge(sample), display + "[]", depth + 1))
    return found


def _mapping_without_sample(
    record_keys: tuple[str, ...],
    overrides: dict[tuple[str, ...], str],
    primary: tuple[str, ...] | None,
) -> MappingResult:
    """Build a mapping from overrides alone, or the placeholder, when there is no sample.

    The entity override ``primary`` names, or else the first, becomes the primary entity
    and carries the property overrides; the rest are emitted beside it.

    Raises:
        ValueError: If ``primary`` names no entity override, or property overrides have
            no entity to go on.
    """

    def rel_of(keys: tuple[str, ...]) -> tuple[str, ...]:
        return keys[len(record_keys) :] if keys[: len(record_keys)] == record_keys else keys

    entity_keys = [keys for keys, target in overrides.items() if target not in _NOT_ENTITIES]
    if primary is not None:
        chosen = [keys for keys in entity_keys if primary in (keys, rel_of(keys))]
        if not chosen:
            raise ValueError(
                f"--primary {'.'.join(primary)}: without a sample response the primary must "
                "be a field mapped with --map PATH=<EntityType>. Mapped entity fields: "
                f"{', '.join('.'.join(keys) for keys in entity_keys) or 'none'}."
            )
        entity_keys.remove(chosen[0])
        entity_keys.insert(0, chosen[0])
    mapping = RecordMapping(path=record_keys, enrich_input=True)
    inventory: list[FieldReport] = []
    for keys in entity_keys:
        target, rel = overrides[keys], rel_of(keys)
        entity_field = EntityField(
            target, rel, _link_label(rel), strip_prefix="AS" if target == "AS" else ""
        )
        if mapping.primary is None:
            mapping.primary = entity_field
            inventory.append(FieldReport(".".join(keys), "", f"entity {target} (primary, --map)"))
        else:
            mapping.entities.append(entity_field)
            inventory.append(FieldReport(".".join(keys), "", f"entity {target} (--map)"))
    properties = [keys for keys, target in overrides.items() if target == OVERRIDE_PROPERTY]
    if properties and mapping.primary is None:
        raise ValueError(
            f"--map {', '.join('.'.join(keys) for keys in properties)}={OVERRIDE_PROPERTY}: "
            "there is no entity to attach it to. Also map a field to an entity type "
            "(--map PATH=Type), or scaffold with --sample-response."
        )
    taken = entity_property_ids(mapping.primary.entity_type) if mapping.primary else set()
    for keys in properties:
        rel = rel_of(keys)
        name = _property_name(rel)
        name = f"field.{name}" if name in taken else name
        mapping.properties.append(PropertyField(name, rel, _display_label(rel)))
        inventory.append(FieldReport(".".join(keys), "", f"property {name} (--map)"))
    for keys, target in overrides.items():
        if target == OVERRIDE_DROP:
            inventory.append(FieldReport(".".join(keys), "", "dropped: by --map"))
    placeholder = mapping.primary is None
    if placeholder:
        mapping = placeholder_mapping()
        mapping.path = record_keys
    return MappingResult(mapping, inventory, [], [], placeholder)


_NOTE_EXAMPLES = 3


def _dropped_notes(inventory: list[FieldReport]) -> list[str]:
    """Summarise the dropped fields of an inventory as one note, grouped by reason."""
    by_reason: dict[str, list[str]] = {}
    for report in inventory:
        if report.outcome.startswith("dropped: "):
            reason = report.outcome.removeprefix("dropped: ").split(";")[0]
            by_reason.setdefault(reason, []).append(report.path)
    if not by_reason:
        return []
    parts = []
    for reason, paths in by_reason.items():
        examples = ", ".join(paths[:_NOTE_EXAMPLES])
        more = f", +{len(paths) - _NOTE_EXAMPLES} more" if len(paths) > _NOTE_EXAMPLES else ""
        if reason in ("envelope", "metadata"):
            parts.append(f"{len(paths)} {reason}")
        else:
            parts.append(f"{len(paths)} {reason} ({examples}{more})")
    total = sum(len(paths) for paths in by_reason.values())
    return [
        f"Not mapped: {total} response field(s): {'; '.join(parts)}. The field inventory "
        "lists each with its reason; --records/--map change what is mapped."
    ]
