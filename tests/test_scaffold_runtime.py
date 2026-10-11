"""Scaffolded transforms, imported and run against a recorded HTTP exchange.

Parsing and linting prove a scaffold is well-formed. These prove it does what the request
showed: the right method, path, headers, query and body go out, and the response comes
back as the entities and properties an investigator can use.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from maltego import entities

from transformatron.scaffold import (
    ScaffoldServiceConfig,
    parse_curl_command,
    parse_openapi_spec,
    write_scaffold,
)


@dataclass
class _Response:
    payload: Any

    def json(self) -> Any:
        return self.payload


@dataclass
class _RecordingClient:
    """Stands in for the generated module's IntegrationClient."""

    payload: Any
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def request(self, method: str, url: str, context: Any, **kwargs: Any) -> _Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        return _Response(self.payload)


@dataclass
class _Log:
    messages: list[str] = field(default_factory=list)

    def fatal(self, message: str) -> None:
        self.messages.append(f"FATAL {message}")

    def inform(self, message: str) -> None:
        self.messages.append(message)


@dataclass
class _Loaded:
    transforms: dict[str, Callable[..., Any]]
    client: _RecordingClient

    async def run(
        self, transform_id: str, entity: Any, settings: dict[str, str] | None = None
    ) -> tuple[list[Any], list[str]]:
        log = _Log()
        results = await self.transforms[transform_id](
            entity, settings or {}, SimpleNamespace(log=log)
        )
        return results, log.messages


def _load(
    cfg: ScaffoldServiceConfig, payload: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> _Loaded:
    """Write the scaffold to a scratch project and import it as the server would."""
    project = tmp_path / "server"
    project.mkdir(exist_ok=True)
    written = write_scaffold(cfg, project)

    # Generated code imports `transforms.<service>`; make that resolve to the scratch
    # project rather than anything a previous test left behind.
    for name in [m for m in sys.modules if m == "transforms" or m.startswith("transforms.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.syspath_prepend(str(project))
    importlib.invalidate_caches()

    api = importlib.import_module(f"transforms.{cfg.service_id}.api")
    client = _RecordingClient(payload)
    monkeypatch.setattr(api, "client", client)

    transforms: dict[str, Callable[..., Any]] = {}
    for path in written:
        if path.suffix != ".py" or path.name in ("__init__.py", "api.py"):
            continue
        module = importlib.import_module(f"transforms.{cfg.service_id}.{path.stem}")
        for t in cfg.transforms:
            if hasattr(module, t.transform_id):
                transforms[t.transform_id] = getattr(module, t.transform_id)
    return _Loaded(transforms, client)


def _values(results: list[Any], entity_type: type) -> list[str]:
    return [r.value for r in results if isinstance(r, entity_type)]


def _props(entity: Any) -> dict[str, Any]:
    """Return an entity's set properties by name, its value property excluded."""
    return {
        name: prop.value
        for name, prop in entity.get_properties().items()
        if prop.value is not None and prop.value != entity.value
    }


async def test_keyless_get_fills_the_input_path_segment_and_keeps_other_query_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The input sits in the middle of the path and a fixed query param rides along."""
    cfg = parse_curl_command(
        "curl 'https://ipinfo.io/8.8.8.8/json?fields=org'",
        sample_response={"ip": "8.8.8.8", "hostname": "dns.google", "org": "AS15169 Google"},
    )
    loaded = _load(cfg, {"ip": "1.1.1.1", "hostname": "one.one.one.one"}, tmp_path, monkeypatch)

    results, messages = await loaded.run("ipinfo_lookup", entities.IPv4Address(value="1.1.1.1"))

    [call] = loaded.client.calls
    assert (call["method"], call["url"]) == ("GET", "https://ipinfo.io/1.1.1.1/json")
    assert call["params"] == {"fields": "org"}
    assert "headers" not in call
    # The input address carries no properties here, so it is not echoed back.
    assert [(type(r), r.value) for r in results] == [(entities.Domain, "one.one.one.one")]
    assert results[0].link_label == "hostname"
    assert not any(m.startswith("FATAL") for m in messages)


async def test_curl_headers_user_agent_cookie_and_repeated_params_are_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Everything the command sent goes out on every request, the credential from settings."""
    cfg = parse_curl_command(
        "curl -A 'research bot ops@example.org' -e https://ref.example -b 'sid=1; theme=dark' "
        "-H 'Accept: application/json' -H 'Authorization: Bearer abc' "
        "'https://api.certspotter.com/v1/issuances?domain=example.com"
        "&expand=dns_names&expand=issuer'",
        service_name="spotter",
    )
    loaded = _load(cfg, [], tmp_path, monkeypatch)

    await loaded.run(
        "spotter_lookup", entities.Domain(value="python.org"), {"SPOTTER_API_KEY": "k"}
    )

    [call] = loaded.client.calls
    assert call["headers"] == {
        "User-Agent": "research bot ops@example.org",
        "Referer": "https://ref.example",
        "Accept": "application/json",
        "Cookie": "sid=1; theme=dark",
        "Authorization": "Bearer k",
    }
    assert call["params"] == {"domain": "python.org", "expand": ["dns_names", "issuer"]}


async def test_epss_envelope_yields_one_cve_carrying_its_scores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The envelope is not data, and the scores belong on the CVE, not beside it.

    The first scaffold of this API returned six envelope Phrases and dropped the score.
    """
    envelope = {"status": "OK", "status-code": 200, "version": "1.0", "access": "public"}
    paging = {"total": 1, "offset": 0, "limit": 100}
    sample = {
        **envelope,
        **paging,
        "data": [{"cve": "CVE-2021-44228", "epss": "0.944", "percentile": "0.999"}],
    }
    cfg = parse_curl_command(
        "curl 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228'",
        sample_response=sample,
        service_name="epss",
    )
    payload = {
        **envelope,
        **paging,
        "data": [{"cve": "CVE-2024-3094", "epss": "0.851", "percentile": "0.986"}],
    }
    loaded = _load(cfg, payload, tmp_path, monkeypatch)

    results, _ = await loaded.run("epss_lookup", entities.CVE(value="CVE-2024-3094"))

    [cve] = results
    assert isinstance(cve, entities.CVE)
    assert cve.value == "CVE-2024-3094"
    # The input itself, enriched: Maltego merges it into the input node.
    assert cve.epss == pytest.approx(0.851)
    assert _props(cve)["percentile"] == "0.986"
    assert cve.link_label == "cve"


async def test_unparseable_typed_property_is_kept_as_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typed property that rejects a value must not cost the entity, or the value."""
    sample = {"data": [{"cve": "CVE-2021-44228", "epss": "0.9"}]}
    cfg = parse_curl_command(
        "curl 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228'", sample, "epss"
    )
    loaded = _load(cfg, {"data": [{"cve": "CVE-2021-44228", "epss": "n/a"}]}, tmp_path, monkeypatch)

    [cve], _ = await loaded.run("epss_lookup", entities.CVE(value="CVE-2021-44228"))

    assert cve.epss is None
    assert _props(cve)["epss.text"] == "n/a"


_CVE_RECORD: dict[str, Any] = {
    "dataType": "CVE_RECORD",
    "cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED"},
    "containers": {
        "cna": {
            "title": "Log4Shell",
            "providerMetadata": {"orgId": "f0158376", "shortName": "apache"},
            "affected": [{"vendor": "Apache Software Foundation", "product": "Apache Log4j2"}],
            "references": [
                {"url": "https://logging.apache.org/security.html", "tags": ["vendor-advisory"]},
                {"url": "https://www.kb.cert.org/vuls/id/930724", "name": "VU#930724"},
            ],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-502", "lang": "en"}]}],
        }
    },
}


async def test_deeply_nested_cve_record_reaches_its_typed_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vendors and references sit four levels down; the record's state is not a place."""
    cfg = parse_curl_command(
        "curl https://cveawg.mitre.org/api/cve/CVE-2021-44228", _CVE_RECORD, "mitre"
    )
    loaded = _load(cfg, _CVE_RECORD, tmp_path, monkeypatch)

    results, _ = await loaded.run("mitre_lookup", entities.CVE(value="CVE-2021-44228"))

    assert not any(isinstance(r, entities.Location) for r in results)
    [cve] = [r for r in results if isinstance(r, entities.CVE)]
    assert _props(cve)["cveMetadata.state"] == "PUBLISHED"
    assert _props(cve)["containers.cna.title"] == "Log4Shell"
    assert _values(results, entities.URL) == [
        "https://logging.apache.org/security.html",
        "https://www.kb.cert.org/vuls/id/930724",
    ]
    [vendor] = [r for r in results if isinstance(r, entities.Company)]
    assert vendor.value == "Apache Software Foundation"
    assert _props(vendor)["product"] == "Apache Log4j2"
    assert vendor.link_label == "affected.vendor"


async def test_a_value_met_in_several_records_keeps_every_records_properties(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CVE-2024-3094 lists six Red Hat products; the Company carried the first one only."""
    cfg = parse_curl_command(
        "curl https://cveawg.mitre.org/api/cve/CVE-2021-44228", _CVE_RECORD, "mitre"
    )
    cna = _CVE_RECORD["containers"]["cna"]
    affected = [
        {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 9"},
        {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 10"},
        {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 9"},
        {"vendor": "Apache Software Foundation", "product": "Apache Log4j2"},
    ]
    payload = {**_CVE_RECORD, "containers": {"cna": {**cna, "affected": affected}}}
    loaded = _load(cfg, payload, tmp_path, monkeypatch)

    results, _ = await loaded.run("mitre_lookup", entities.CVE(value="CVE-2021-44228"))

    vendors = {r.value: _props(r)["product"] for r in results if isinstance(r, entities.Company)}
    assert vendors == {
        "Red Hat": "Red Hat Enterprise Linux 9, Red Hat Enterprise Linux 10",
        "Apache Software Foundation": "Apache Log4j2",
    }


async def test_a_property_mapped_inside_a_list_reaches_the_cve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The description and the CVSS score, each inside a list, land on the CVE as asked."""
    record = {
        **_CVE_RECORD,
        "containers": {
            "cna": {
                **_CVE_RECORD["containers"]["cna"],
                "descriptions": [{"lang": "en", "value": "JNDI lookups run attacker code."}],
            },
            "adp": [{"title": "CISA ADP", "metrics": [{"cvssV3_1": {"baseScore": 10.0}}]}],
        },
    }
    cfg = parse_curl_command(
        "curl https://cveawg.mitre.org/api/cve/CVE-2021-44228",
        record,
        "mitre",
        mappings=[
            "containers.cna.descriptions[].value=Property",
            "containers.adp[].metrics[].cvssV3_1.baseScore=Property",
        ],
    )
    loaded = _load(cfg, record, tmp_path, monkeypatch)

    results, _ = await loaded.run("mitre_lookup", entities.CVE(value="CVE-2021-44228"))

    [cve] = [r for r in results if isinstance(r, entities.CVE)]
    assert _props(cve)["containers.cna.descriptions.value"] == "JNDI lookups run attacker code."
    assert cve.cvss == pytest.approx(10.0)


async def test_records_and_map_overrides_reshape_a_deep_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--records picks the references; --map types a field and drops another."""
    cfg = parse_curl_command(
        "curl https://cveawg.mitre.org/api/cve/CVE-2021-44228",
        _CVE_RECORD,
        "refs",
        records="containers.cna.references",
        mappings=["name=Phrase", "containers.cna.references[].tags=Drop"],
    )
    loaded = _load(cfg, _CVE_RECORD, tmp_path, monkeypatch)

    results, _ = await loaded.run("refs_lookup", entities.CVE(value="CVE-2021-44228"))

    assert sorted((type(r).__name__, r.value) for r in results) == [
        ("Phrase", "VU#930724"),
        ("URL", "https://logging.apache.org/security.html"),
        ("URL", "https://www.kb.cert.org/vuls/id/930724"),
    ]
    assert all("tags" not in _props(r) for r in results)


async def test_crtsh_names_are_split_deduplicated_and_skip_the_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """crt.sh packs every certificate name into one newline-separated string."""
    record = {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "hexacron.com",
        "name_value": "hexacron.com\nwww.hexacron.com",
        "id": 1,
        "not_before": "2024-01-01T00:00:00",
    }
    cfg = parse_curl_command("curl 'https://crt.sh/?q=hexacron.com&output=json'", [record], "crtsh")
    payload = [
        {**record, "common_name": "python.org", "name_value": "python.org\n*.python.org"},
        {**record, "common_name": "docs.python.org", "name_value": "docs.python.org\nPYTHON.ORG"},
        {**record, "common_name": "www.python.org", "name_value": "www.python.org"},
    ]
    loaded = _load(cfg, payload, tmp_path, monkeypatch)

    results, _ = await loaded.run("crtsh_lookup", entities.Domain(value="python.org"))

    assert [type(r) for r in results] == [entities.Domain] * 2
    assert sorted(r.value for r in results) == ["docs.python.org", "www.python.org"]
    [call] = loaded.client.calls
    assert call["params"] == {"q": "python.org", "output": "json"}


async def test_certspotter_list_maps_names_hashes_and_issuer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = [
        {
            "id": "12345",
            "tbs_sha256": "a" * 64,
            "cert_sha256": "b" * 64,
            "dns_names": ["example.com", "www.example.com"],
            "issuer": {"friendly_name": "GoDaddy", "name": "C=US, O=GoDaddy.com, CN=Go Daddy"},
            "not_after": "2025-01-01",
        }
    ]
    cfg = parse_curl_command(
        "curl 'https://api.certspotter.com/v1/issuances?domain=example.com"
        "&expand=dns_names&expand=issuer'",
        sample,
        "certspotter",
    )
    loaded = _load(cfg, sample, tmp_path, monkeypatch)

    results, _ = await loaded.run("certspotter_lookup", entities.Domain(value="example.com"))

    [call] = loaded.client.calls
    assert call["params"]["expand"] == ["dns_names", "issuer"]
    assert _values(results, entities.Domain) == ["www.example.com"]
    assert not any(isinstance(r, entities.Person) for r in results)
    hashes = [r for r in results if isinstance(r, entities.Hash)]
    assert sorted(h.value for h in hashes) == ["a" * 64, "b" * 64]
    [primary] = [h for h in hashes if _props(h)]
    assert _props(primary)["issuer.name"] == "C=US, O=GoDaddy.com, CN=Go Daddy"
    assert _props(primary)["not_after"] == "2025-01-01"


async def test_orcid_path_id_is_templated_and_accept_header_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = parse_curl_command(
        "curl -H 'Accept: application/json' https://pub.orcid.org/v3.0/0000-0002-1825-0097/person",
        {"emails": {"email": [{"email": "josiah@example.org"}]}},
    )
    loaded = _load(cfg, {"emails": {"email": [{"email": "j@example.org"}]}}, tmp_path, monkeypatch)

    results, _ = await loaded.run("orcid_lookup", entities.Phrase(value="0000-0001-5109-3700"))

    [call] = loaded.client.calls
    assert call["url"] == "https://pub.orcid.org/v3.0/0000-0001-5109-3700/person"
    assert call["headers"] == {"Accept": "application/json"}
    assert _values(results, entities.EmailAddress) == ["j@example.org"]


async def test_dns_answers_become_addresses_with_their_record_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DNS answers arrive as a list of objects; their addresses must reach the graph."""
    cfg = parse_curl_command(
        "curl 'https://dns.google/resolve?name=python.org&type=A'",
        sample_response={
            "Status": 0,
            "TC": False,
            "Answer": [{"name": "python.org.", "type": 1, "TTL": 300, "data": "151.101.0.223"}],
        },
    )
    payload = {
        "Status": 0,
        "TC": False,
        "Answer": [
            {"name": "example.com.", "type": 1, "TTL": 60, "data": "192.0.2.1"},
            {"name": "example.com.", "type": 1, "TTL": 60, "data": "192.0.2.2"},
        ],
    }
    loaded = _load(cfg, payload, tmp_path, monkeypatch)

    results, _ = await loaded.run("dns_lookup", entities.Domain(value="example.com"))

    [call] = loaded.client.calls
    assert call["params"] == {"name": "example.com", "type": "A"}
    assert _values(results, entities.IPv4Address) == ["192.0.2.1", "192.0.2.2"]
    # The answer's name is the input domain again: not echoed.
    assert _values(results, entities.Domain) == []
    assert _props(results[0])["TTL"] == 60


async def test_post_sends_the_body_with_the_input_and_reads_a_list_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = parse_curl_command(
        "curl -X POST https://api.search.example/v1/search "
        '-H \'Authorization: Bearer abc\' -d \'{"query": "8.8.8.8", "limit": 5}\'',
        sample_response=[{"ip": "8.8.8.8", "country": "US"}],
        service_name="searchy",
    )
    payload = [{"ip": "1.1.1.1", "country": "AU"}, {"ip": "1.0.0.1", "country": "AU"}]
    loaded = _load(cfg, payload, tmp_path, monkeypatch)

    results, _ = await loaded.run(
        "searchy_lookup", entities.IPv4Address(value="1.1.1.1"), {"SEARCHY_API_KEY": "k1"}
    )

    [call] = loaded.client.calls
    assert call["method"] == "POST"
    assert call["url"] == "https://api.search.example/v1/search"
    assert call["json"] == {"query": "1.1.1.1", "limit": 5}
    assert call["headers"] == {"Authorization": "Bearer k1"}
    # The input is not echoed back, and the shared country is returned once.
    assert _values(results, entities.IPv4Address) == ["1.0.0.1"]
    assert _values(results, entities.Country) == ["AU"]


async def test_form_body_is_sent_as_form_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = parse_curl_command(
        "curl https://api.formy.example/lookup -d 'domain=example.com&mode=full'",
        sample_response={"registrar": "Example Registrar"},
    )
    loaded = _load(cfg, {"registrar": "R"}, tmp_path, monkeypatch)

    await loaded.run("formy_lookup", entities.Domain(value="python.org"))

    [call] = loaded.client.calls
    assert call["method"] == "POST"
    assert call["data"] == {"domain": "python.org", "mode": "full"}
    assert call["json"] is None


async def test_missing_key_stops_before_any_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = parse_curl_command(
        "curl -H 'X-Api-Key: abc' https://api.keyed.example/ip/8.8.8.8",
        sample_response={"ip": "8.8.8.8"},
    )
    loaded = _load(cfg, {"ip": "1.1.1.1"}, tmp_path, monkeypatch)
    monkeypatch.delenv("KEYED_API_KEY", raising=False)

    results, messages = await loaded.run("keyed_lookup", entities.IPv4Address(value="1.1.1.1"))

    assert results == []
    assert loaded.client.calls == []
    assert any("KEYED_API_KEY" in m for m in messages)


async def test_field_names_that_are_not_identifiers_still_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hyphens, quotes, braces and keywords in response keys are data, not code."""
    sample = {
        "as-name": "Google",
        'say "hi"': "x",
        "{brace}": "y",
        "class": "z",
        "geo": {"country_code": "US"},
    }
    cfg = parse_curl_command("curl https://api.odd.example/ip/8.8.8.8", sample_response=sample)
    loaded = _load(cfg, sample, tmp_path, monkeypatch)

    results, _ = await loaded.run("odd_lookup", entities.IPv4Address(value="8.8.8.8"))

    [isp] = [r for r in results if isinstance(r, entities.ISP)]
    assert isp.value == "Google"
    assert set(_props(isp).values()) == {"x", "y", "z"}
    assert _values(results, entities.Country) == ["US"]


async def test_openapi_ref_schemas_path_params_and_query_auth_work_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Refs", "version": "1"},
        "servers": [{"url": "/v2"}],
        "components": {
            "securitySchemes": {"key": {"type": "apiKey", "in": "query", "name": "token"}},
            "parameters": {"Ip": {"name": "ip", "in": "path", "required": True}},
            "schemas": {
                "Host": {
                    "type": "object",
                    "properties": {
                        "hostnames": {"type": "array", "items": {"type": "string"}},
                        "asn": {"type": "string"},
                    },
                }
            },
        },
        "security": [{"key": []}],
        "paths": {
            "/host/{ip}": {
                "parameters": [{"$ref": "#/components/parameters/Ip"}],
                "get": {
                    "operationId": "getHost",
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Host"}
                                }
                            }
                        }
                    },
                },
            }
        },
    }
    cfg = parse_openapi_spec(spec, spec_url="https://refs.example/openapi.json")
    payload = {"hostnames": ["a.example", "b.example"], "asn": "AS64500"}
    loaded = _load(cfg, payload, tmp_path, monkeypatch)

    results, _ = await loaded.run(
        "refs_get_host", entities.IPv4Address(value="192.0.2.9"), {"REFS_API_KEY": "t0k"}
    )

    [call] = loaded.client.calls
    assert call["url"] == "https://refs.example/v2/host/192.0.2.9"
    assert call["params"] == {"token": "t0k"}
    assert _values(results, entities.AS) == ["64500"]
    assert sorted(_values(results, entities.Domain)) == ["a.example", "b.example"]


async def test_optional_key_is_sent_when_set_and_not_required_otherwise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anonymous-friendly API must not be gated on a key it does not need."""
    spec = {
        "swagger": "2.0",
        "info": {"title": "Vulns"},
        "host": "vulns.example",
        "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-API-KEY"}},
        "security": [{}, {"key": []}],
        "paths": {
            "/api/vulnerability/{vulnerability_id}": {
                "get": {
                    "operationId": "get_vulnerability",
                    "parameters": [
                        {
                            "name": "vulnerability_id",
                            "in": "path",
                            "required": True,
                            "type": "string",
                        }
                    ],
                    "responses": {"200": {"examples": {"application/json": {"id": "x"}}}},
                }
            }
        },
    }
    cfg = parse_openapi_spec(spec)
    [transform] = cfg.transforms
    assert transform.input_entity == "CVE"
    loaded = _load(cfg, {"id": "CVE-2021-44228"}, tmp_path, monkeypatch)
    monkeypatch.delenv("VULNS_API_KEY", raising=False)
    cve = entities.CVE(value="CVE-2021-44228")

    _, anonymous_messages = await loaded.run("vulns_get_vulnerability", cve)
    await loaded.run("vulns_get_vulnerability", cve, {"VULNS_API_KEY": "k"})

    anonymous, keyed = loaded.client.calls
    assert anonymous["url"] == "https://vulns.example/api/vulnerability/CVE-2021-44228"
    assert anonymous["headers"] == {}
    assert keyed["headers"] == {"X-API-KEY": "k"}
    assert not any("API key" in m for m in anonymous_messages)


async def test_yaml_spec_scaffolds_a_working_transform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yaml_text = """
openapi: 3.0.0
info: {title: Hashy}
servers: [{url: "https://hash.example"}]
paths:
  /lookup/md5/{md5}:
    get:
      operationId: get_lookup_md5
      parameters: [{name: md5, in: path, required: true}]
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  FileName: {type: string}
                  SHA-1: {type: string}
                  SHA-256: {type: string}
"""
    cfg = parse_openapi_spec(yaml_text)
    payload = {"FileName": "putty.exe", "SHA-1": "c" * 40, "SHA-256": "d" * 64}
    loaded = _load(cfg, payload, tmp_path, monkeypatch)

    results, _ = await loaded.run("hashy_get_lookup_md5", entities.Hash(value="e" * 32))

    [call] = loaded.client.calls
    assert call["url"] == f"https://hash.example/lookup/md5/{'e' * 32}"
    assert sorted(_values(results, entities.Hash)) == ["c" * 40, "d" * 64]
    [primary] = [r for r in results if _props(r)]
    assert _props(primary)["FileName"] == "putty.exe"


async def test_second_endpoint_added_to_a_service_runs_beside_the_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Growing a service endpoint by endpoint leaves the first one working."""
    project = tmp_path / "server"
    project.mkdir()
    first = parse_curl_command(
        "curl https://api.svc.example/ip/8.8.8.8", {"hostname": "dns.google"}, "svc"
    )
    write_scaffold(first, project)
    second = parse_curl_command(
        "curl 'https://api.svc.example/domain?name=example.com'",
        {"ip": "192.0.2.1"},
        "svc",
        transform_name="by_domain",
    )
    loaded = _load(second, {"ip": "192.0.2.5", "hostname": "x.example"}, tmp_path, monkeypatch)
    lookup = importlib.import_module("transforms.svc.lookup")

    by_domain, _ = await loaded.run("svc_by_domain", entities.Domain(value="example.com"))
    by_ip = await lookup.svc_lookup(
        entities.IPv4Address(value="192.0.2.5"), {}, SimpleNamespace(log=_Log())
    )

    assert _values(by_domain, entities.IPv4Address) == ["192.0.2.5"]
    assert _values(by_ip, entities.Domain) == ["x.example"]
    assert [c["url"] for c in loaded.client.calls] == [
        "https://api.svc.example/domain",
        "https://api.svc.example/ip/192.0.2.5",
    ]
