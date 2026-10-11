"""Tests for transform scaffolding engine."""

from __future__ import annotations

import json
import keyword
import subprocess
from pathlib import Path
from typing import Any

import pytest

from transformatron import operations
from transformatron.config import TransformatronConfig
from transformatron.scaffold import (
    EntityField,
    PropertyField,
    RecordMapping,
    ScaffoldServiceConfig,
    ScaffoldTransformConfig,
    generate_service_code,
    inject_project_import,
    list_openapi_operations,
    load_spec,
    parse_curl_command,
    parse_openapi_spec,
    planned_scaffold_paths,
    remove_scaffold,
    write_scaffold,
)
from transformatron.scaffold.generator import generate_api_module, generate_transform_module
from transformatron.scaffold.schema import (
    infer_input_entity,
    infer_output_entity,
    qualified_entity_type,
)


def _entities_mapping(*types: str) -> RecordMapping:
    """Return a mapping emitting one entity per type, plus a property, for code-shape tests."""
    fields = [EntityField(t, (f"f{i}",), f"f{i}") for i, t in enumerate(types)]
    return RecordMapping(
        primary=fields[0] if fields else None,
        entities=fields[1:],
        properties=[PropertyField("score", ("score",), "Score")] if fields else [],
    )


def test_infer_input_entity() -> None:
    assert infer_input_entity("ip")[0] == "IPv4Address"
    assert infer_input_entity("ip_address")[0] == "IPv4Address"
    assert infer_input_entity("target", "8.8.8.8")[0] == "IPv4Address"
    assert infer_input_entity("domain")[0] == "Domain"
    assert infer_input_entity("target", "example.com")[0] == "Domain"
    assert infer_input_entity("url")[0] == "URL"
    assert infer_input_entity("email")[0] == "EmailAddress"
    assert infer_input_entity("hash")[0] == "Hash"
    assert infer_input_entity("cve")[0] == "CVE"
    assert infer_input_entity("custom_param")[0] == "Phrase"


@pytest.mark.parametrize(
    ("name", "sample", "expected"),
    [
        ("domainName", None, "Domain"),
        ("ip-address", None, "IPv4Address"),
        ("emailAddress", None, "EmailAddress"),
        ("cveId", None, "CVE"),
        ("file_sha256", None, "Hash"),
        ("vulnerability_id", "CVE-2021-44228", "CVE"),
        # A vulnerability id that is a GHSA advisory is not a CVE.
        ("vulnerability_id", "GHSA-jfh8-c2jp-5v3q", "Phrase"),
    ],
)
def test_input_names_match_on_their_words(name: str, sample: str | None, expected: str) -> None:
    """camelCase, kebab-case and snake_case parameter names are recognised alike."""
    assert infer_input_entity(name, sample)[0] == expected


@pytest.mark.parametrize(
    ("name", "sample", "expected"),
    [
        ("asn", "AS15169", "AS"),
        ("asNumber", 15169, "AS"),
        ("country_code", "US", "Country"),
        ("as_name", "Google", "ISP"),
        ("city", "Paris", "City"),
        ("cves", "CVE-2024-1234", "CVE"),
        ("cveId", "CVE-2024-1234", "CVE"),
        ("domainName", "example.com", "Domain"),
        ("emailAddress", "a@example.com", "EmailAddress"),
        ("ip-address", "192.0.2.1", "IPv4Address"),
        ("cert_sha256", "ab" * 32, "Hash"),
        # A vulnerability id is a CVE when its value is one.
        ("vulnerability_id", "CVE-2021-44228", "CVE"),
        # A digest is recognised by value whatever the key...
        ("fingerprint", "0123456789abcdef" * 4, "Hash"),
        # ...but a hex identifier or serial number is not a hash.
        ("serial_number", "0123456789abcdef" * 2, "Phrase"),
        ("request_id", "0123456789abcdef" * 2, "Phrase"),
        # A lifecycle state is not a place; a two-letter state code is.
        ("state", "PUBLISHED", "Phrase"),
        ("state", "CA", "Location"),
        # A certificate issuer's distinguished name is not a person.
        ("name", "C=US, O=GoDaddy.com, CN=Go Daddy Secure CA", "Phrase"),
        ("name", "Josiah Carberry", "Person"),
        # A value that is plainly an address beats a generic key.
        ("name", "192.0.2.1", "IPv4Address"),
        ("reputation_score", 42, "Phrase"),
    ],
)
def test_infer_output_entity(name: str, sample: Any, expected: str) -> None:
    assert infer_output_entity(name, sample) == expected


def test_parse_curl_command_with_path_and_header() -> None:
    curl = 'curl -H "X-API-KEY: secret123" https://api.greynoise.io/v3/community/8.8.8.8'
    sample = {
        "ip": "8.8.8.8",
        "noise": True,
        "classification": "benign",
        "link": "https://viz.greynoise.io/ip/8.8.8.8",
    }

    cfg = parse_curl_command(curl, sample_response=sample)

    assert cfg.service_id == "greynoise"
    assert cfg.base_url == "https://api.greynoise.io"
    assert cfg.auth_header_name == "X-API-KEY"
    assert cfg.auth_key_name == "GREYNOISE_API_KEY"
    # The credential travels through the key setting, never as a literal header.
    assert cfg.headers == {}
    [t] = cfg.transforms
    assert t.input_entity == "IPv4Address"
    assert t.endpoint_path == "/v3/community/{target}"
    assert t.sample_input == "8.8.8.8"
    # The looked-up address carries the verdict as properties; the link is a pivot.
    assert t.mapping.primary is not None
    assert t.mapping.primary.entity_type == "IPv4Address"
    assert [p.name for p in t.mapping.properties] == ["noise", "classification"]
    assert set(t.output_entity_types) == {"IPv4Address", "URL"}


def test_parse_curl_command_with_bearer_token_and_query_param() -> None:
    curl = 'curl -H "Authorization: Bearer token_xyz" "https://api.example.com/v1/lookup?domain=example.com"'
    cfg = parse_curl_command(curl, service_name="example_svc")

    assert cfg.service_id == "example_svc"
    assert cfg.auth_type == "bearer"
    assert cfg.transforms[0].input_entity == "Domain"
    assert cfg.transforms[0].input_param_name == "domain"


def test_parse_openapi_spec() -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Threat API", "version": "1.0"},
        "servers": [{"url": "https://api.threatservice.com/v1"}],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-Threat-Key"}
            }
        },
        "security": [{"ApiKeyAuth": []}],
        "paths": {
            "/ip/{ip}": {
                "get": {
                    "summary": "Check IP Reputation",
                    "operationId": "check_ip",
                    "parameters": [{"name": "ip", "in": "path", "required": True}],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "asn": {"type": "string"},
                                            "country": {"type": "string"},
                                            "score": {"type": "integer"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            }
        },
    }

    cfg = parse_openapi_spec(spec)

    assert cfg.service_id == "threat_api"
    assert cfg.base_url == "https://api.threatservice.com/v1"
    assert cfg.auth_header_name == "X-Threat-Key"
    assert len(cfg.transforms) == 1

    t = cfg.transforms[0]
    # Prefixed with the service: transform ids are global on the server.
    assert t.transform_id == "threat_api_check_ip"
    assert t.input_entity == "IPv4Address"
    assert t.key_required is True
    assert set(t.output_entity_types) == {"AS", "Country"}
    assert [p.name for p in t.mapping.properties] == ["score"]


def test_generate_service_code() -> None:
    cfg = ScaffoldServiceConfig(
        service_id="test_service",
        display_name="Test Service",
        base_url="https://api.test.com",
        auth_key_name="TEST_SERVICE_API_KEY",
        transforms=[
            ScaffoldTransformConfig(
                transform_id="test_service_lookup",
                display_name="Test Service: Lookup",
                input_entity="IPv4Address",
                endpoint_path="/lookup/{target}",
                mapping=RecordMapping(
                    primary=EntityField("AS", ("asn",), "asn", strip_prefix="AS"),
                    properties=[PropertyField("summary", ("summary",), "Summary")],
                ),
            )
        ],
    )

    files = generate_service_code(cfg)

    assert set(files) == {"__init__.py", "api.py", "lookup.py"}
    assert 'BASE_URL = "https://api.test.com"' in files["api.py"]
    assert 'API_KEY = "TEST_SERVICE_API_KEY"' in files["api.py"]

    lookup_code = files["lookup.py"]
    assert "from maltego.entities import AS, IPv4Address" in lookup_code
    assert "-> list[TestServiceLookupOutput]:" in lookup_code
    assert "target = validate_ip(input_entity.value)" in lookup_code
    assert 'primary=Entity(AS, ("asn",), "asn", strip="AS")' in lookup_code


def test_inject_project_import(tmp_path: Path) -> None:
    project_py = tmp_path / "project.py"
    project_py.write_text("""from maltego.server import run_server

from transforms.examples.ffraud import *  # noqa: F401,F403

if __name__ == "__main__":
    run_server()
""")

    import_stmt = "from transforms.new_svc.lookup import *  # noqa: F401,F403"
    injected = inject_project_import(project_py, import_stmt)
    assert injected is True

    content = project_py.read_text()
    assert import_stmt in content
    # Verify placed before if __name__
    import_pos = content.index(import_stmt)
    main_pos = content.index('if __name__ == "__main__":')
    assert import_pos < main_pos

    # Test idempotency
    assert inject_project_import(project_py, import_stmt) is False


def _service_config(
    service_id: str = "custom_api", sample: str | None = None
) -> ScaffoldServiceConfig:
    """Return a minimal single-transform service config for write tests."""
    return ScaffoldServiceConfig(
        service_id=service_id,
        display_name="Custom API",
        base_url="https://api.custom.com",
        transforms=[
            ScaffoldTransformConfig(
                transform_id=f"{service_id}_lookup",
                display_name="Custom API: Lookup",
                input_entity="Domain",
                endpoint_path="/check",
                mapping=_entities_mapping("Domain"),
                sample_input=sample,
            )
        ],
    )


def _project(tmp_path: Path) -> Path:
    project_dir = tmp_path / "server"
    (project_dir / "transforms").mkdir(parents=True)
    (project_dir / "project.py").write_text(
        "from transforms.examples.ffraud import *  # noqa: F401,F403\n"
    )
    return project_dir


def test_write_scaffold(tmp_path: Path) -> None:
    project_dir = _project(tmp_path)

    created = write_scaffold(_service_config(sample="example.com"), project_dir)

    svc_dir = project_dir / "transforms" / "custom_api"
    assert created == [
        svc_dir / "__init__.py",
        svc_dir / "api.py",
        svc_dir / "lookup.py",
        svc_dir / "samples.json",
    ]
    assert json.loads((svc_dir / "samples.json").read_text()) == {
        "custom_api_lookup": "example.com"
    }
    assert "from transforms.custom_api.lookup import *" in (project_dir / "project.py").read_text()


def test_planned_paths_match_the_write_and_write_nothing(tmp_path: Path) -> None:
    """A dry run reports exactly what the real run writes."""
    project_dir = _project(tmp_path)
    cfg = _service_config(sample="example.com")

    planned = planned_scaffold_paths(cfg, project_dir)

    assert not (project_dir / "transforms" / "custom_api").exists()
    assert write_scaffold(cfg, project_dir) == planned


def test_write_scaffold_refuses_to_overwrite(tmp_path: Path) -> None:
    """A second scaffold of the same service must not clobber the first."""
    project_dir = _project(tmp_path)
    cfg = _service_config()

    write_scaffold(cfg, project_dir)
    hand_edited = project_dir / "transforms" / "custom_api" / "api.py"
    hand_edited.write_text("# hand-written behaviour a generator cannot recover\n")

    with pytest.raises(FileExistsError, match="already exists"):
        write_scaffold(cfg, project_dir)
    with pytest.raises(FileExistsError, match="already exists"):
        planned_scaffold_paths(cfg, project_dir)

    assert hand_edited.read_text().startswith("# hand-written")


def test_write_scaffold_force_overwrites(tmp_path: Path) -> None:
    """`force=True` is the deliberate escape hatch from the overwrite guard."""
    project_dir = _project(tmp_path)
    cfg = _service_config()

    write_scaffold(cfg, project_dir)
    lookup_py = project_dir / "transforms" / "custom_api" / "lookup.py"
    lookup_py.write_text("# stale\n")

    write_scaffold(cfg, project_dir, force=True)

    assert "register_transform" in lookup_py.read_text()


def test_force_replaces_the_whole_service_and_its_imports(tmp_path: Path) -> None:
    """A narrower re-scaffold must not leave the old modules or their imports behind.

    Stale modules kept registering their transforms beside the new ones, and the server
    refused to start on the duplicate names.
    """
    project_dir = _project(tmp_path)
    wide = _service_config()
    wide.transforms.append(
        ScaffoldTransformConfig(
            transform_id="custom_api_other",
            display_name="Custom API: Other",
            input_entity="Domain",
            endpoint_path="/other",
        )
    )
    write_scaffold(wide, project_dir)

    write_scaffold(_service_config(), project_dir, force=True)

    svc_dir = project_dir / "transforms" / "custom_api"
    assert sorted(p.name for p in svc_dir.iterdir()) == ["__init__.py", "api.py", "lookup.py"]
    project_text = (project_dir / "project.py").read_text()
    assert "transforms.custom_api.other" not in project_text
    assert project_text.count("transforms.custom_api.lookup") == 1


def test_write_scaffold_leaves_no_partial_write_on_clash(tmp_path: Path) -> None:
    """A collision on any file aborts before the others are touched."""
    project_dir = _project(tmp_path)
    svc_dir = project_dir / "transforms" / "custom_api"
    svc_dir.mkdir()
    (svc_dir / "lookup.py").write_text("# only this one exists\n")

    with pytest.raises(FileExistsError):
        write_scaffold(_service_config(), project_dir)

    assert not (svc_dir / "api.py").exists()
    assert (svc_dir / "lookup.py").read_text() == "# only this one exists\n"


def test_transform_id_defined_by_another_service_is_refused(tmp_path: Path) -> None:
    """Ids are global on the server: a duplicate anywhere under transforms/ blocks start-up."""
    project_dir = _project(tmp_path)
    other = project_dir / "transforms" / "handmade"
    other.mkdir()
    (other / "mod.py").write_text(
        "from maltego.server import register_transform\n\n\n"
        "@register_transform(display_name='x', transform_set='x', settings=[])\n"
        "async def custom_api_lookup(input_entity, settings, context):\n"
        "    return []\n"
    )

    with pytest.raises(ValueError, match=r"custom_api_lookup .*handmade"):
        write_scaffold(_service_config(), project_dir)
    with pytest.raises(ValueError, match="custom_api_lookup"):
        planned_scaffold_paths(_service_config(), project_dir, force=True)

    assert not (project_dir / "transforms" / "custom_api").exists()


def test_a_second_curl_endpoint_joins_its_service(tmp_path: Path) -> None:
    """A named endpoint is added beside the first, which keeps working unchanged."""
    project_dir = _project(tmp_path)
    first = parse_curl_command("curl https://api.svc.example/ip/8.8.8.8", service_name="svc")
    second = parse_curl_command(
        "curl 'https://api.svc.example/domain?name=example.com'",
        service_name="svc",
        transform_name="by-domain",
    )
    write_scaffold(first, project_dir)
    api_before = (project_dir / "transforms" / "svc" / "api.py").read_text()

    written = write_scaffold(second, project_dir)

    svc_dir = project_dir / "transforms" / "svc"
    assert [p.name for p in written] == ["by_domain.py", "samples.json"]
    assert (svc_dir / "api.py").read_text() == api_before
    assert json.loads((svc_dir / "samples.json").read_text()) == {
        "svc_by_domain": "example.com",
        "svc_lookup": "8.8.8.8",
    }
    assert "async def svc_by_domain(" in (svc_dir / "by_domain.py").read_text()
    project_text = (project_dir / "project.py").read_text()
    assert "transforms.svc.lookup" in project_text
    assert "transforms.svc.by_domain" in project_text


def test_an_endpoint_needing_a_different_client_is_refused(tmp_path: Path) -> None:
    """Rewriting api.py for a new endpoint would change how the existing ones call the API."""
    project_dir = _project(tmp_path)
    write_scaffold(
        parse_curl_command("curl https://api.svc.example/ip/8.8.8.8", service_name="svc"),
        project_dir,
    )
    keyed = parse_curl_command(
        "curl -H 'X-Api-Key: k' 'https://api.svc.example/domain?name=example.com'",
        service_name="svc",
        transform_name="by_domain",
    )

    with pytest.raises(FileExistsError, match=r"different api\.py"):
        write_scaffold(keyed, project_dir)

    assert not (project_dir / "transforms" / "svc" / "by_domain.py").exists()


def test_remove_scaffold_deletes_the_service_and_its_imports(tmp_path: Path) -> None:
    project_dir = _project(tmp_path)
    write_scaffold(_service_config(), project_dir)
    write_scaffold(_service_config("keep_me"), project_dir)

    removed = remove_scaffold("custom_api", project_dir)

    assert removed == [
        str(project_dir / "transforms" / "custom_api"),
        "from transforms.custom_api.lookup import *  # noqa: F401,F403",
    ]
    assert not (project_dir / "transforms" / "custom_api").exists()
    project_text = (project_dir / "project.py").read_text()
    assert "custom_api" not in project_text
    assert "transforms.keep_me.lookup" in project_text
    assert "transforms.examples.ffraud" in project_text


@pytest.mark.parametrize("service", ["nothing_here", "../escape", "local"])
def test_remove_scaffold_refuses_what_is_not_a_service(tmp_path: Path, service: str) -> None:
    project_dir = _project(tmp_path)
    (project_dir / "transforms" / "local").mkdir()

    with pytest.raises(ValueError, match=service.replace(".", r"\.")):
        remove_scaffold(service, project_dir)

    assert (project_dir / "transforms" / "local").is_dir()


def test_remove_scaffold_refuses_a_hand_written_service(tmp_path: Path) -> None:
    """`remove-scaffold rdap` deleted a bundled, hand-written service, with no way back."""
    project_dir = _project(tmp_path)
    handmade = project_dir / "transforms" / "rdap"
    handmade.mkdir()
    (handmade / "api.py").write_text('"""RDAP client, written by hand."""\n')
    write_scaffold(_service_config(), project_dir)

    with pytest.raises(
        ValueError, match=r"lacks the line 'Generated by transformatron scaffold\.'"
    ):
        remove_scaffold("rdap", project_dir)
    with pytest.raises(ValueError, match=r"Scaffolded services: custom_api\.$"):
        remove_scaffold("nothing_here", project_dir)

    assert (handmade / "api.py").exists()


def test_force_refuses_to_replace_a_hand_written_service(tmp_path: Path) -> None:
    """--force deletes the whole directory, so it must spare work the scaffolder never wrote.

    The refusal for an existing service used to point at --force even for hand-written
    ones, and following it deleted their modules and imports.
    """
    project_dir = _project(tmp_path)
    handmade = project_dir / "transforms" / "custom_api"
    handmade.mkdir()
    (handmade / "api.py").write_text('"""Client, written by hand."""\n')
    (handmade / "lookup.py").write_text("# hand-written transform\n")

    with pytest.raises(FileExistsError) as refused:
        write_scaffold(_service_config(), project_dir)
    assert "--force" not in str(refused.value)
    with pytest.raises(ValueError, match=r"so --force will not replace it"):
        write_scaffold(_service_config(), project_dir, force=True)

    assert (handmade / "lookup.py").read_text() == "# hand-written transform\n"


def test_openapi_search_param_falls_back_to_real_name() -> None:
    """An endpoint with no entity-like parameter still uses its real query param name.

    Leaving the "input_val" placeholder builds a query string the upstream rejects, and
    it only fails at runtime against the live API.
    """
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Searchy", "version": "1.0.0"},
        "servers": [{"url": "https://searchy.example"}],
        "paths": {
            "/api/v1/search": {
                "get": {
                    "operationId": "searchdatasource",
                    "summary": "Search",
                    "parameters": [
                        {"name": "q", "in": "query", "required": True},
                        {"name": "size", "in": "query"},
                    ],
                    "responses": {"200": {"content": {"application/json": {"schema": {}}}}},
                }
            }
        },
    }

    cfg = parse_openapi_spec(spec, service_name="searchy")
    transform = cfg.transforms[0]

    assert transform.input_param_name == "q"
    assert transform.input_entity == "Phrase"
    assert "input_val" not in generate_transform_module(cfg, transform)


def test_openapi_path_parameter_is_not_turned_into_a_query_param() -> None:
    """A templated path keeps interpolating {target} rather than gaining a query string."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Pathy", "version": "1.0.0"},
        "servers": [{"url": "https://pathy.example"}],
        "paths": {
            "/api/v1/hostname/{hostname}": {
                "get": {
                    "operationId": "gethostname",
                    "summary": "Hostname",
                    "parameters": [{"name": "hostname", "in": "path", "required": True}],
                    "responses": {"200": {"content": {"application/json": {"schema": {}}}}},
                }
            }
        },
    }

    cfg = parse_openapi_spec(spec, service_name="pathy")
    code = generate_transform_module(cfg, cfg.transforms[0])

    assert 'path = f"/api/v1/hostname/{target}"' in code
    assert "params=" not in code


def test_generated_entity_imports_are_isort_ordered() -> None:
    """Acronym entities sort before CamelCase ones, matching ruff's isort rule."""
    cfg = _service_config()
    cfg.transforms[0].mapping = _entities_mapping("Phrase", "URL", "IPv4Address")

    code = generate_transform_module(cfg, cfg.transforms[0])

    assert "from maltego.entities import URL, Domain, IPv4Address, Phrase" in code


@pytest.mark.parametrize(
    "input_entity",
    ["IPv4Address", "IPv6Address", "Domain", "URL", "EmailAddress", "Hash", "CVE", "Phrase"],
)
def test_input_constraint_matches_the_input_entity(input_entity: str) -> None:
    """Every scaffolded transform constrains itself to its own input type.

    Without the constraint the Maltego client offers the transform on every entity of the
    type, including ones the endpoint cannot serve.
    """
    cfg = _service_config()
    cfg.transforms[0].input_entity = input_entity

    code = generate_transform_module(cfg, cfg.transforms[0])

    assert f'input_constraint=EntityTypeConstraint(entity_type="maltego.{input_entity}"),' in code
    assert "from maltego.model.input_constraints import EntityTypeConstraint" in code


def test_input_constraint_can_be_suppressed() -> None:
    """Opting out emits neither the argument nor its import.

    A leftover import would be an F401 failure on freshly generated code.
    """
    cfg = _service_config()
    cfg.transforms[0].emit_input_constraint = False

    code = generate_transform_module(cfg, cfg.transforms[0])

    assert "input_constraint" not in code
    assert "EntityTypeConstraint" not in code


def _ruff_gate(directory: Path) -> None:
    for args in (["check"], ["format", "--check"]):
        result = subprocess.run(
            ["uv", "run", "ruff", *args, str(directory)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0, f"ruff {args[0]} failed:\n{result.stdout}\n{result.stderr}"


def _write_all(directory: Path, configs: list[ScaffoldServiceConfig]) -> None:
    for index, cfg in enumerate(configs):
        for name, code in generate_service_code(cfg).items():
            compile(code, name, "exec")
            (directory / f"c{index}_{cfg.service_id}_{name}").write_text(code)


def test_generated_code_passes_the_project_lint_gate(tmp_path: Path) -> None:
    """Generated modules must survive `ruff check` and `ruff format --check`.

    `server/transforms/` is linted, so a scaffold that emits misordered imports, unused
    imports or wrong blank-line spacing hands the author a failing gate on code they have
    not touched. Covered: keyless, keyed and query-keyed clients, extra headers, an
    optional key, a placeholder mapping, and mappings with nested records and many types.
    """
    wide = _service_config(service_id="wide")
    wide.transforms[0].mapping = RecordMapping(
        path=("data",),
        primary=EntityField("WHOISRecord", ("whois",), "whois"),
        entities=[
            EntityField(t, (f"f{i}", "deeper"), f"f{i}")
            for i, t in enumerate(["Website", "X509Certificate", "BTCAddress", "MacAddress"])
        ],
        nested=[
            RecordMapping(
                path=("containers", "cna", "references"),
                primary=EntityField("URL", ("url",), "references.url"),
                properties=[PropertyField("tags", ("tags",), "Tags")],
            )
        ],
        enrich_input=True,
    )
    authed = _service_config(service_id="authed")
    authed.auth_key_name = "AUTHED_API_KEY"
    authed.auth_type = "header"
    authed.headers = {"Accept": "application/json", "User-Agent": "research"}
    optional = _service_config(service_id="optional")
    optional.auth_key_name = "OPTIONAL_API_KEY"
    optional.auth_type = "query"
    optional.auth_query_param = "key"
    optional.transforms[0].key_required = False
    placeholder = _service_config(service_id="placeholder")
    placeholder.transforms[0].mapping = ScaffoldTransformConfig("x", "x", "Domain", "/").mapping

    _write_all(tmp_path, [_service_config(), authed, optional, placeholder, wide])
    _ruff_gate(tmp_path)


@pytest.mark.parametrize(
    ("class_name", "expected"),
    [
        ("Domain", "maltego.Domain"),
        ("IPv4Address", "maltego.IPv4Address"),
        # The "maltego." + ClassName rule breaks for 72 of the 244 exported entities.
        ("AffiliationTwitter", "maltego.affiliation.Twitter"),
        ("STIX2attackpattern", "maltego.STIX2.attack-pattern"),
        ("Hashtag", "maltego.hashtag"),
    ],
)
def test_qualified_entity_type_reads_the_class(class_name: str, expected: str) -> None:
    """TYPE_NAME comes off the class, because it is not always derivable from the name."""
    assert qualified_entity_type(class_name) == expected


def test_qualified_entity_type_rejects_unknown_names() -> None:
    """A name that is not an entity class fails loudly rather than emitting a bad type."""
    with pytest.raises(ValueError, match="not an entity class"):
        qualified_entity_type("NotAnEntity")


@pytest.mark.parametrize(
    ("field_name", "entity_type"),
    [
        ("full_name", "Person"),
        ("company", "Company"),
        ("phone", "PhoneNumber"),
        ("username", "Alias"),
        ("avatar", "Image"),
        ("mac_address", "MacAddress"),
        ("port", "Port"),
        ("bitcoin", "BTCAddress"),
        ("wallet", "CryptocurrencyAddress"),
        ("website", "Website"),
        ("malware", "Malware"),
        ("certificate", "X509Certificate"),
        ("whois", "WHOISRecord"),
    ],
)
def test_widened_output_entities(field_name: str, entity_type: str) -> None:
    """Common response fields map to pivotable entities rather than falling back to Phrase.

    A Phrase renders as text an investigator cannot pivot from, so every field left
    unmapped is a dead end in the graph.
    """
    assert infer_output_entity(field_name) == entity_type


def test_org_still_maps_to_isp() -> None:
    """`org` stays with ISP: on IP-lookup APIs it is the network operator, not a company."""
    assert infer_output_entity("org") == "ISP"


_TYPE_POOL = [
    "URL",
    "Alias",
    "BTCAddress",
    "City",
    "Company",
    "CryptocurrencyAddress",
    "Image",
    "MacAddress",
    "Malware",
    "Person",
    "PhoneNumber",
    "Port",
    "WHOISRecord",
    "X509Certificate",
]


def test_many_output_entities_stay_within_the_line_limit() -> None:
    """A response mapping many entity types must not emit over-long imports or unions.

    Both the entity import and the output union grow with the number of mapped fields, and
    either one crossing 100 characters fails E501 on freshly generated code.
    """
    cfg = _service_config()
    cfg.transforms[0].mapping = _entities_mapping(*_TYPE_POOL)

    code = generate_transform_module(cfg, cfg.transforms[0])

    assert all(len(line) <= 100 for line in code.splitlines())
    # The union is named once rather than inlined in the signature.
    assert "CustomApiLookupOutput = (" in code
    assert "-> list[CustomApiLookupOutput]:" in code


@pytest.mark.parametrize("count", range(1, 15))
def test_output_alias_matches_ruff_at_every_width(count: int, tmp_path: Path) -> None:
    """The alias must be formatted the way ruff would at any number of output types.

    Wrapping earlier or later than the formatter is not cosmetic: ruff rewrites the file
    and `ruff format --check` then fails on code the author has not touched. The boundary
    between the three layouts is the part worth pinning.
    """
    cfg = _service_config(service_id=f"w{count}")
    cfg.transforms[0].mapping = _entities_mapping(*_TYPE_POOL[:count])

    for name, code in generate_service_code(cfg).items():
        (tmp_path / name).write_text(code)

    result = subprocess.run(
        ["uv", "run", "ruff", "format", "--check", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0, f"{count} output types:\n{result.stdout}"


def test_operations_scaffold_validation(tmp_path: Path) -> None:
    config = TransformatronConfig(project_dir=tmp_path / "server", state_dir=tmp_path / "state")
    config.project_dir.mkdir(parents=True)
    (config.project_dir / "project.py").write_text("")

    res_missing = operations.scaffold(config)
    assert "Failed to scaffold" in res_missing

    curl = "curl https://api.threat.com/v1/domain/example.com"
    res_success = operations.scaffold(
        config,
        service="threat",
        curl=curl,
        sample_response=json.dumps({"risk": "high"}),
    )
    assert "Scaffolded 'Threat'" in res_success
    assert (config.project_dir / "transforms" / "threat" / "api.py").exists()


def _query_auth_spec() -> dict[str, object]:
    """Return a spec whose API key travels in the query string, not a header."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "Queryauth", "version": "1.0.0"},
        "servers": [{"url": "https://qa.example"}],
        "components": {
            "securitySchemes": {"apiKey": {"type": "apiKey", "in": "query", "name": "apikey"}}
        },
        "security": [{"apiKey": []}],
        "paths": {
            "/lookup": {
                "get": {
                    "operationId": "lookup",
                    "summary": "Lookup",
                    "parameters": [{"name": "ip", "in": "query", "required": True}],
                    "responses": {"200": {"content": {"application/json": {"schema": {}}}}},
                }
            }
        },
    }


def test_query_auth_scheme_is_recorded_by_the_parser() -> None:
    """An `in: query` apiKey scheme records the parameter name it must be sent under."""
    cfg = parse_openapi_spec(_query_auth_spec(), service_name="qa")

    assert cfg.auth_type == "query"
    assert cfg.auth_query_param == "apikey"
    assert cfg.transforms[0].key_required is True


def test_colliding_transform_ids_are_all_generated() -> None:
    """Operations that slugify to the same id each get a module, under the id reported.

    "do scan" and "do-scan" both slugify to do_scan. Keying the output dict on that
    dropped every colliding transform but the last; numbering them only in the generator
    registered ids other than the ones the scaffold printed.
    """
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Dup", "version": "1.0.0"},
        "servers": [{"url": "https://dup.example"}],
        "paths": {
            "/a/scan": {
                "get": {
                    "operationId": "do scan",
                    "parameters": [{"name": "q", "in": "query", "required": True}],
                    "responses": {},
                }
            },
            "/b/scan": {
                "get": {
                    "operationId": "do-scan",
                    "parameters": [{"name": "q", "in": "query", "required": True}],
                    "responses": {},
                }
            },
        },
    }

    cfg = parse_openapi_spec(spec, service_name="dup")
    files = generate_service_code(cfg)

    assert [t.transform_id for t in cfg.transforms] == ["dup_do_scan_a", "dup_do_scan_b"]
    module_files = sorted(n for n in files if n not in ("__init__.py", "api.py"))
    assert module_files == ["do_scan_a.py", "do_scan_b.py"]
    assert "async def dup_do_scan_a(" in files["do_scan_a.py"]
    assert "async def dup_do_scan_b(" in files["do_scan_b.py"]


_QUERY_Q = {"name": "q", "in": "query", "required": True}


def test_shared_operation_ids_get_distinct_ids_and_names() -> None:
    """CIRCL reuses `get_last` for four paths; each becomes its own, recognisable transform.

    They were scaffolded as identical modules with one display name, and the ids printed
    differed from those the server registered.
    """
    ok = {"200": {"description": "ok"}}
    by_number = {"name": "number", "in": "path", "required": True}
    by_source = {"name": "source", "in": "path", "required": True}
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Vulns"},
        "servers": [{"url": "https://vulns.example/api"}],
        "paths": {
            "/vulnerability/last/{number}": {
                "get": {"operationId": "get_last", "summary": "Latest", "parameters": [by_number]}
                | {"responses": ok}
            },
            "/vulnerability/last/{source}": {
                "get": {"operationId": "get_last", "summary": "Latest", "parameters": [by_source]}
                | {"responses": ok}
            },
            "/kev": {"get": {"operationId": "get_kev", "parameters": [_QUERY_Q], "responses": ok}},
            "/kev/": {"get": {"operationId": "get_kev", "parameters": [_QUERY_Q], "responses": ok}},
        },
    }

    cfg = parse_openapi_spec(spec, operations=["get_last"])
    infos = {info.transform_id: info for info in list_openapi_operations(spec)}

    ids = [t.transform_id for t in cfg.transforms]
    assert ids == ["vulns_get_last_by_number", "vulns_get_last_by_source"]
    assert [t.display_name for t in cfg.transforms] == [
        "Vulns: Latest (by number)",
        "Vulns: Latest (by source)",
    ]
    assert sorted(infos) == sorted([*ids, "vulns_get_kev", "vulns_get_kev_2"])
    assert all(info.duplicate for info in infos.values())
    # The generated functions are registered under exactly the ids reported.
    files = generate_service_code(cfg)
    assert "async def vulns_get_last_by_number(" in files["get_last_by_number.py"]
    # One of them alone, by the id --list-operations shows.
    [one] = parse_openapi_spec(spec, operations=["vulns_get_last_by_source"]).transforms
    assert one.endpoint_path == "/vulnerability/last/{target}"


def test_a_config_with_duplicate_transform_ids_is_refused() -> None:
    """Renaming one quietly would register an id other than the one the author was shown."""
    cfg = _service_config()
    cfg.transforms.append(cfg.transforms[0])

    with pytest.raises(ValueError, match="share the id 'custom_api_lookup'"):
        generate_service_code(cfg)


def test_scaffold_reports_existing_service_instead_of_overwriting(tmp_path: Path) -> None:
    """The FileExistsError guard reaches the caller as a message, not a traceback."""
    config = TransformatronConfig(project_dir=tmp_path / "server", state_dir=tmp_path / "state")
    config.project_dir.mkdir(parents=True)
    (config.project_dir / "project.py").write_text("")

    curl = "curl https://api.threat.com/v1/domain/example.com"
    first = operations.scaffold(config, service="threat", curl=curl)
    assert "Scaffolded" in first

    second = operations.scaffold(config, service="threat", curl=curl)
    assert "Failed to scaffold" in second
    assert "already exists" in second


def test_scaffold_reports_malformed_openapi_spec(tmp_path: Path) -> None:
    """A spec that is neither JSON nor YAML is a caller error, reported rather than raised."""
    config = TransformatronConfig(project_dir=tmp_path / "server", state_dir=tmp_path / "state")
    config.project_dir.mkdir(parents=True)

    result = operations.scaffold(config, service="broken", openapi="{not json at all")

    assert "Failed to scaffold" in result


def test_scaffold_force_overwrites_an_existing_service(tmp_path: Path) -> None:
    """The overwrite escape hatch the clash message points at is reachable from the front end."""
    config = TransformatronConfig(project_dir=tmp_path / "server", state_dir=tmp_path / "state")
    config.project_dir.mkdir(parents=True)
    curl = "curl https://api.threat.com/v1/domain/example.com"
    operations.scaffold(config, service="threat", curl=curl)
    lookup = config.project_dir / "transforms" / "threat" / "lookup.py"
    lookup.write_text("# hand-written\n")

    result = operations.scaffold(config, service="threat", curl=curl, force=True)

    assert "Scaffolded" in result
    assert not lookup.read_text().startswith("# hand-written")


@pytest.mark.parametrize("name", ["../escape", "a/b", "1abc", "class", "with space"])
def test_service_names_that_cannot_be_packages_are_rejected(name: str) -> None:
    """The service id becomes a directory and a dotted import; a bad one breaks startup."""
    with pytest.raises(ValueError, match=r"not usable|Could not derive"):
        parse_curl_command("curl https://api.x.example/ip/8.8.8.8", service_name=name)


@pytest.mark.parametrize("name", ["api", "samples", "1st", "class"])
def test_endpoint_names_that_cannot_be_modules_are_rejected(name: str) -> None:
    """`api` would replace the shared client; the rest would not import."""
    with pytest.raises(ValueError, match="not usable as a module name"):
        parse_curl_command("curl https://api.x.example/ip/8.8.8.8", transform_name=name)


def test_hyphenated_service_name_becomes_a_package_name() -> None:
    cfg = parse_curl_command("curl https://api.x.example/ip/8.8.8.8", service_name="my-svc")

    assert cfg.service_id == "my_svc"


def test_curl_without_credentials_scaffolds_a_keyless_client() -> None:
    """A public API must not be gated on a key the request never sent."""
    cfg = parse_curl_command("curl https://internetdb.shodan.io/8.8.8.8")

    assert cfg.auth_key_name is None
    assert "API_KEY" not in generate_api_module(cfg)


def test_key_in_the_query_string_is_auth_not_input() -> None:
    cfg = parse_curl_command("curl 'https://api.q.example/lookup?apikey=abc&ip=1.1.1.1'")
    transform = cfg.transforms[0]

    assert (cfg.auth_type, cfg.auth_query_param) == ("query", "apikey")
    assert (transform.input_location, transform.input_param_name) == ("query", "ip")
    assert "apikey" not in transform.query_params


def test_resource_names_in_the_path_are_not_taken_for_domains() -> None:
    """`lookup.json` matches the domain pattern but is the endpoint, not the input."""
    cfg = parse_curl_command("curl https://api.x.example/v2/lookup.json/8.8.8.8")

    assert cfg.transforms[0].endpoint_path == "/v2/lookup.json/{target}"
    assert cfg.transforms[0].input_entity == "IPv4Address"


def test_path_segment_that_looks_like_a_value_is_the_input() -> None:
    """ORCID's `/v3.0/<id>/person` must template the id, not the resource word."""
    cfg = parse_curl_command("curl https://pub.orcid.org/v3.0/0000-0002-1825-0097/person")
    [transform] = cfg.transforms

    assert transform.endpoint_path == "/v3.0/{target}/person"
    assert transform.sample_input == "0000-0002-1825-0097"


def test_sample_response_that_is_not_json_is_reported_as_unsupported() -> None:
    """HackerTarget answers CSV; the error says that is unsupported and what to do instead."""
    with pytest.raises(ValueError, match="not valid JSON") as raised:
        parse_curl_command(
            "curl 'https://api.hackertarget.example/hostsearch/?q=python.org'",
            sample_response="www.python.org,151.101.0.223\nmail.python.org,188.166.95.178\n",
        )

    message = str(raised.value)
    assert "CSV and plain-text responses are not supported" in message
    assert "replace RECORDS and map_records()" in message


def test_curl_keeps_request_details_and_notes_what_it_drops() -> None:
    """Headers, the user agent, the referer and cookies are part of the request.

    ORCID answers XML without `Accept: application/json`, and SEC EDGAR refuses a request
    with no User-Agent, so dropping them zeroed both live.
    """
    cfg = parse_curl_command(
        "curl -sS --compressed -A 'research bot ops@example.org' -e https://ref.example "
        "-b 'session=abc' -H 'Accept: application/json' -H 'Accept-Encoding: br' "
        "-H 'X-Api-Key: secret' -x http://proxy:8080 "
        "'https://api.x.example/v1/issuances?domain=example.com&expand=a&expand=b'"
    )

    assert cfg.headers == {
        "User-Agent": "research bot ops@example.org",
        "Referer": "https://ref.example",
        "Accept": "application/json",
        "Cookie": "session=abc",
    }
    assert cfg.auth_header_name == "X-Api-Key"
    assert cfg.transforms[0].query_params == {"domain": "example.com", "expand": ["a", "b"]}
    notes = " ".join(cfg.notes)
    assert "proxy" in notes
    assert "Accept-Encoding" in notes
    assert "Cookie" in notes


def test_curl_without_a_sample_notes_the_placeholder_output() -> None:
    cfg = parse_curl_command("curl https://api.x.example/ip/8.8.8.8")

    assert any("placeholder" in note for note in cfg.notes)


def test_notes_point_at_dry_run_only_in_a_trailing_sentence() -> None:
    """A dry run cuts each note at "Preview with --dry-run", so it never tells the author to
    do what they are doing; any other mention would survive the cut."""
    spec = _two_operation_spec()
    spec["paths"]["/things/{id}"]["get"]["responses"] = {"200": {"description": "ok"}}
    notes = [
        *parse_curl_command("curl https://api.x.example/ip/8.8.8.8").notes,
        *parse_openapi_spec(spec).notes,
        *parse_curl_command("curl https://api.x.example/ip/8.8.8.8", {"a": [{"b": 1}]}).notes,
    ]

    pointing = [note for note in notes if "--dry-run" in note]
    assert pointing, "the placeholder notes point at a preview"
    for note in pointing:
        kept, _, cut = note.partition(" Preview with --dry-run")
        assert cut and "--dry-run" not in kept, note


def _two_operation_spec() -> dict[str, Any]:
    ok = {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}}
    return {
        "openapi": "3.0.0",
        "info": {"title": "Two", "version": "1"},
        "servers": [{"url": "https://two.example"}],
        "paths": {
            "/things/{id}": {
                "get": {
                    "operationId": "getThing",
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "responses": ok,
                }
            },
            "/things": {
                "post": {
                    "operationId": "createThing",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["owner"],
                                    "properties": {
                                        "domain": {"type": "string"},
                                        "owner": {"type": "string", "example": "me"},
                                        "note": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": ok,
                }
            },
        },
    }


def test_post_operations_are_skipped_unless_named() -> None:
    """A POST may create or change data upstream, so scaffolding one is a deliberate choice."""
    cfg = parse_openapi_spec(_two_operation_spec())

    assert [t.transform_id for t in cfg.transforms] == ["two_get_thing"]
    assert any("createThing" in note for note in cfg.notes)


def test_named_post_operation_is_scaffolded_with_its_body() -> None:
    cfg = parse_openapi_spec(_two_operation_spec(), operations=["createThing"])
    [transform] = cfg.transforms

    assert transform.http_method == "POST"
    assert (transform.input_location, transform.input_param_name) == ("body", "domain")
    # Required fields ride along with their example; optional ones are left out.
    assert transform.request_body is not None
    assert set(transform.request_body) == {"domain", "owner"}
    assert transform.request_body["owner"] == "me"


def test_unknown_operation_name_is_an_error_listing_the_real_ones() -> None:
    with pytest.raises(ValueError, match=r"deleteEverything.*getThing, createThing"):
        parse_openapi_spec(_two_operation_spec(), operations=["deleteEverything"])


def test_operation_whose_path_cannot_be_filled_is_skipped_with_a_reason() -> None:
    spec = _two_operation_spec()
    spec["paths"]["/zones/{zone}/hosts"] = {
        "get": {
            "operationId": "listHosts",
            "parameters": [
                {"name": "zone", "in": "path", "required": True},
                {"name": "ip", "in": "query", "required": True},
            ],
        }
    }

    cfg = parse_openapi_spec(spec)

    assert "two_list_hosts" not in [t.transform_id for t in cfg.transforms]
    assert any("listHosts" in note and "{zone}" in note for note in cfg.notes)


def test_unsupported_auth_is_reported_instead_of_guessed() -> None:
    spec = _two_operation_spec()
    spec["components"] = {"securitySchemes": {"oauth": {"type": "oauth2"}}}

    cfg = parse_openapi_spec(spec)

    assert cfg.auth_key_name is None
    assert any("oauth2" in note for note in cfg.notes)


def test_paging_parameters_are_never_the_input() -> None:
    """An operation whose only parameters page the result is skipped, not keyed on `page`."""
    spec = _two_operation_spec()
    spec["paths"]["/users"] = {
        "get": {
            "operationId": "listUsers",
            "parameters": [
                {"name": "page", "in": "query"},
                {"name": "per_page", "in": "query"},
            ],
        }
    }
    spec["paths"]["/search"] = {
        "get": {
            "operationId": "search",
            "parameters": [
                {"name": "page", "in": "query"},
                {"name": "q", "in": "query", "required": True},
            ],
        }
    }

    cfg = parse_openapi_spec(spec)
    by_id = {t.transform_id: t for t in cfg.transforms}

    assert "two_list_users" not in by_id
    assert any("listUsers" in note and "page" in note for note in cfg.notes)
    assert by_id["two_search"].input_param_name == "q"
    assert "page" not in by_id["two_search"].query_params


def test_state_changing_get_operations_are_skipped_unless_named() -> None:
    """`GET /session/create/{name}` creates state upstream; it is no lookup."""
    spec = _two_operation_spec()
    spec["paths"]["/session/create/{name}"] = {
        "get": {
            "operationId": "createSession",
            "parameters": [{"name": "name", "in": "path", "required": True}],
        }
    }

    default = parse_openapi_spec(spec)
    named = parse_openapi_spec(spec, operations=["createSession"])

    assert "two_create_session" not in [t.transform_id for t in default.transforms]
    assert any("createSession" in note and "state" in note for note in default.notes)
    assert [t.transform_id for t in named.transforms] == ["two_create_session"]


@pytest.mark.parametrize(
    ("path", "operation_id", "writes"),
    [
        ("/session/get/{name}", "get_session_matches", False),
        ("/sessions/{id}", "getSession", False),
        ("/vulnerability/last-update/{id}", "getLastUpdate", False),
        ("/session/create/{name}", "get_session_create", True),
        ("/users/{id}/reset-password", "getUser", True),
        ("/things/{id}", "deleteThing", True),
    ],
)
def test_only_a_verb_marks_a_get_operation_as_changing_state(
    path: str, operation_id: str, writes: bool
) -> None:
    """CIRCL's `GET /session/get/{name}` reads a session; only `/session/create` makes one."""
    spec = _two_operation_spec()
    spec["paths"][path] = {
        "get": {
            "operationId": operation_id,
            "parameters": [{"name": path.rsplit("{")[-1].strip("}"), "in": "path"}],
        }
    }

    [info] = [i for i in list_openapi_operations(spec) if i.operation_id == operation_id]

    assert ("changes state" in (info.skipped_reason or "")) is writes


@pytest.mark.parametrize(
    ("document", "spec_url", "base_url"),
    [
        # CIRCL vulnerability-lookup: Swagger 2, basePath, no host.
        (
            {"swagger": "2.0", "basePath": "/api"},
            "https://vulnerability.circl.lu/api/swagger.json",
            "https://vulnerability.circl.lu/api",
        ),
        (
            {"swagger": "2.0", "host": "api.x.example", "basePath": "/v1"},
            "http://docs.x.example/swagger.json",
            "http://api.x.example/v1",
        ),
        (
            {"swagger": "2.0", "host": "api.x.example", "schemes": ["https"], "basePath": "/"},
            None,
            "https://api.x.example",
        ),
        # Petstore: an OpenAPI 3 server relative to the spec's URL.
        (
            {"openapi": "3.0.0", "servers": [{"url": "/api/v3"}]},
            "https://petstore3.swagger.io/api/v3/openapi.json",
            "https://petstore3.swagger.io/api/v3",
        ),
    ],
)
def test_base_url_keeps_the_spec_base_path(
    document: dict[str, Any], spec_url: str | None, base_url: str
) -> None:
    """Dropping `/api` sent every request to the wrong path, reported as "no record"."""
    spec = {
        **document,
        "info": {"title": "Base"},
        "paths": {"/vulnerability/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}}},
    }

    assert parse_openapi_spec(spec, spec_url=spec_url).base_url == base_url


def _hash_spec(sha1_param: dict[str, Any]) -> dict[str, Any]:
    """CIRCL hashlookup's sha1 lookup: Swagger 2, no example for the hash."""
    return {
        "swagger": "2.0",
        "host": "hashlookup.example",
        "info": {"title": "hashlookup"},
        "paths": {
            "/lookup/sha1/{sha1}": {
                "get": {
                    "operationId": "get_lookup_sha1",
                    "parameters": [{"name": "sha1", "in": "path", "required": True, **sha1_param}],
                }
            }
        },
    }


_SHA1 = "732458574c63c3790cad093a36eadfb990d11ee6"
_HASH_RESPONSE = {
    "MD5": "E7793F15C2FF7E747B4BC7079F5CD4E7",
    "SHA-1": _SHA1.upper(),
    "FileName": "./bin/ls",
}


def test_openapi_sample_input_is_recorded_and_recognised_as_the_input(tmp_path: Path) -> None:
    """Without it no samples.json was written, the smoke test sent an MD5 to the sha1 lookup,
    and the MD5 became the record's entity instead of enriching the input SHA-1."""
    cfg = parse_openapi_spec(
        _hash_spec({}), sample_response=_HASH_RESPONSE, sample_input=f" {_SHA1} "
    )
    [transform] = cfg.transforms

    assert transform.sample_input == _SHA1
    assert transform.mapping.primary is not None
    assert transform.mapping.primary.path == ("SHA-1",)
    assert transform.mapping.enrich_input is True
    project_dir = _project(tmp_path)
    write_scaffold(cfg, project_dir)
    samples = json.loads((project_dir / "transforms" / "hashlookup" / "samples.json").read_text())
    assert samples == {"hashlookup_get_lookup_sha1": _SHA1}


@pytest.mark.parametrize("example_key", ["example", "x-example"])
def test_openapi_parameter_example_is_the_sample_input(example_key: str) -> None:
    cfg = parse_openapi_spec(_hash_spec({example_key: _SHA1}))

    assert cfg.transforms[0].sample_input == _SHA1
    assert not any("No sample input" in note for note in cfg.notes)


def test_openapi_without_a_sample_input_says_how_to_give_one() -> None:
    cfg = parse_openapi_spec(_hash_spec({}))

    assert cfg.transforms[0].sample_input is None
    assert any("No sample input" in note and "--sample-input" in note for note in cfg.notes)


def test_sample_input_for_several_operations_is_refused() -> None:
    spec = _two_operation_spec()
    spec["paths"]["/other/{id}"] = {
        "get": {"operationId": "other", "parameters": [{"name": "id", "in": "path"}]}
    }

    with pytest.raises(ValueError, match="--sample-input"):
        parse_openapi_spec(spec, sample_input="x")


@pytest.mark.parametrize(
    ("title", "label"),
    [("Vulnerability-Lookup API", "Vulnerability-Lookup API Key"), ("Crtsh", "Crtsh API Key")],
)
def test_key_messages_name_the_api_once(title: str, label: str) -> None:
    """A spec titled "... API" read "No Vulnerability-Lookup API API key configured"."""
    cfg = _service_config()
    cfg.display_name, cfg.auth_key_name = title, "SVC_API_KEY"

    api = generate_api_module(cfg)

    assert f'API_KEY_LABEL = "{label}"' in api
    assert "display_name=API_KEY_LABEL" in api
    assert 'f"No {API_KEY_LABEL} configured.' in api
    assert "API API" not in api


def test_a_long_summary_is_cut_at_a_word_without_three_dots(tmp_path: Path) -> None:
    """A literal '...' ended Maltego menu names; the ellipsis character reads as one."""
    spec = _two_operation_spec()
    spec["paths"]["/things/{id}"]["get"]["summary"] = (
        "Retrieve the latest vulnerabilities, with optional filters for the source and the "
        "number of results"
    )

    cfg = parse_openapi_spec(spec, operations=["getThing"])
    [transform] = cfg.transforms

    assert "..." not in transform.display_name
    assert transform.display_name.endswith("\u2026")
    assert len(transform.display_name) <= 80
    assert transform.display_name.startswith("Two: Retrieve the latest vulnerabilities")
    _write_all(tmp_path, [cfg])
    _ruff_gate(tmp_path)


def test_optional_security_makes_the_key_optional() -> None:
    """`{}` among the requirements, or `security: []`, means the API answers without a key."""
    spec = _two_operation_spec()
    spec["components"] = {
        "securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-Key"}}
    }
    spec["security"] = [{"key": []}]
    spec["paths"]["/things/{id}"]["get"]["security"] = []
    spec["paths"]["/open/{ip}"] = {
        "get": {
            "operationId": "open",
            "security": [{}, {"key": []}],
            "parameters": [{"name": "ip", "in": "path", "required": True}],
        }
    }
    spec["paths"]["/closed/{ip}"] = {
        "get": {
            "operationId": "closed",
            "parameters": [{"name": "ip", "in": "path", "required": True}],
        }
    }

    by_id = {t.transform_id: t for t in parse_openapi_spec(spec).transforms}

    assert by_id["two_get_thing"].key_required is False
    assert by_id["two_open"].key_required is False
    assert by_id["two_closed"].key_required is True


def test_yaml_spec_is_parsed_like_json() -> None:
    yaml_text = """
openapi: 3.0.0
info: {title: Yammy}
servers: [{url: "https://yam.example"}]
paths:
  /ip/{ip}:
    get:
      operationId: getIp
      parameters: [{name: ip, in: path, required: true, example: 192.0.2.7}]
      responses:
        200:
          content:
            application/json:
              example: {ip: 192.0.2.7, hostname: host.example}
"""
    cfg = parse_openapi_spec(yaml_text)
    [transform] = cfg.transforms

    assert transform.transform_id == "yammy_get_ip"
    assert transform.sample_input == "192.0.2.7"
    assert set(transform.output_entity_types) == {"IPv4Address", "Domain"}


@pytest.mark.parametrize("text", ["", "{not json at all", "just a sentence", "- a\n- list\n"])
def test_load_spec_rejects_what_is_not_a_spec(text: str) -> None:
    with pytest.raises(ValueError, match="OpenAPI spec"):
        load_spec(text)


def test_yaml_keys_that_yaml_1_1_would_type_stay_field_names() -> None:
    """`on`, `no` and `2021` load as a bool and an int, which broke the mapping with a TypeError."""
    yaml_text = """
openapi: 3.0.0
info: {title: Yammy}
servers: [{url: "https://yammy.example"}]
paths:
  /item/{ip}:
    get:
      operationId: getItem
      parameters: [{name: ip, in: path, required: true}]
      responses:
        "200":
          content:
            application/json:
              example: {on: "a.example", no: 1, 2021: "b.example"}
"""
    spec = load_spec(yaml_text)
    [transform] = parse_openapi_spec(spec).transforms

    paths = {report.path for report in transform.inventory}
    assert {"on", "no", "2021"} <= paths


def test_a_spec_that_expands_into_a_billion_nodes_is_refused() -> None:
    """Aliases make a tiny file expand exponentially, and mapping walks the expanded tree."""
    levels = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    levels += [f"a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 10)}]" for i in range(1, 8)]

    with pytest.raises(ValueError, match="too large to scaffold"):
        load_spec("\n".join(levels))


def test_schemas_that_refer_to_each_other_do_not_expand_exponentially() -> None:
    """Five schemas each referring to all five took 20s to scaffold before refs were tracked."""
    names = [f"S{i}" for i in range(5)]
    schemas = {
        name: {
            "type": "object",
            "properties": {
                other.lower(): {"$ref": f"#/components/schemas/{other}"} for other in names
            },
        }
        for name in names
    }
    ok = {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/S0"}}}}
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Loops"},
        "servers": [{"url": "https://loops.example"}],
        "components": {"schemas": schemas},
        "paths": {
            "/thing/{ip}": {
                "get": {
                    "operationId": "getThing",
                    "parameters": [{"name": "ip", "in": "path", "required": True}],
                    "responses": {"200": ok},
                }
            }
        },
    }

    [transform] = parse_openapi_spec(spec).transforms

    assert transform.transform_id == "loops_get_thing"


def test_an_operation_named_like_a_keyword_gets_an_importable_module(tmp_path: Path) -> None:
    """`files_global` under service `files` became `global.py`, a SyntaxError in project.py."""
    project_dir = _project(tmp_path)
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Files"},
        "servers": [{"url": "https://files.example"}],
        "paths": {
            "/global/{ip}": {
                "get": {
                    "operationId": "files_global",
                    "parameters": [{"name": "ip", "in": "path", "required": True}],
                }
            }
        },
    }

    written = write_scaffold(parse_openapi_spec(spec), project_dir)

    assert all(not keyword.iskeyword(path.stem) for path in written)
    compile((project_dir / "project.py").read_text(), "project.py", "exec")


def test_a_hand_written_service_without_api_py_is_not_added_to(tmp_path: Path) -> None:
    """A marked api.py written beside hand-written modules made remove-scaffold delete them."""
    project_dir = _project(tmp_path)
    handmade = project_dir / "transforms" / "custom_api"
    handmade.mkdir()
    (handmade / "ffraud.py").write_text("# hand-written transform\n")

    with pytest.raises(FileExistsError, match="not written by the scaffolder"):
        write_scaffold(_service_config(), project_dir)

    assert sorted(p.name for p in handmade.iterdir()) == ["ffraud.py"]


def test_remove_scaffold_needs_the_service_name_exactly(tmp_path: Path) -> None:
    """On a case-insensitive filesystem `Demo` deleted `demo/` and left its imports behind."""
    project_dir = _project(tmp_path)
    write_scaffold(_service_config("demo"), project_dir)

    with pytest.raises(ValueError, match="'Demo'"):
        remove_scaffold("Demo", project_dir)

    assert (project_dir / "transforms" / "demo").is_dir()
    assert "transforms.demo." in (project_dir / "project.py").read_text()


def test_list_operations_shows_every_operation_and_why_it_would_be_skipped() -> None:
    spec = _two_operation_spec()
    spec["paths"]["/users"] = {
        "get": {"operationId": "listUsers", "parameters": [{"name": "page", "in": "query"}]}
    }

    infos = {info.operation_id: info for info in list_openapi_operations(spec)}

    assert set(infos) == {"getThing", "createThing", "listUsers"}
    thing = infos["getThing"]
    assert (thing.transform_id, thing.method, thing.path) == (
        "two_get_thing",
        "GET",
        "/things/{id}",
    )
    assert thing.input == "Phrase (path {id})"
    assert thing.has_response_schema is True
    assert thing.skipped_reason is None
    assert "POST" in (infos["createThing"].skipped_reason or "")
    assert infos["listUsers"].input == "-"
    assert "paging" in (infos["listUsers"].skipped_reason or "")


def test_openapi_sample_response_is_used_for_a_single_operation() -> None:
    """A real response beats a schema-less spec's placeholder output."""
    cfg = parse_openapi_spec(
        _two_operation_spec(),
        operations=["getThing"],
        sample_response={"domain": "a.example", "risk": "high"},
    )
    [transform] = cfg.transforms

    assert transform.output_entity_types == ["Domain"]
    assert [p.name for p in transform.mapping.properties] == ["risk"]


def test_openapi_sample_response_for_several_operations_is_refused() -> None:
    spec = _two_operation_spec()
    spec["paths"]["/other/{id}"] = {
        "get": {"operationId": "other", "parameters": [{"name": "id", "in": "path"}]}
    }

    with pytest.raises(ValueError, match="--operation"):
        parse_openapi_spec(spec, sample_response={"a": 1})


def test_operation_without_a_response_schema_notes_its_placeholder() -> None:
    spec = _two_operation_spec()
    spec["paths"]["/things/{id}"]["get"]["responses"] = {"200": {"description": "ok"}}

    cfg = parse_openapi_spec(spec)

    assert any("two_get_thing" in note and "placeholder" in note for note in cfg.notes)


def test_many_operations_without_a_choice_are_flagged() -> None:
    spec = _two_operation_spec()
    for index in range(25):
        spec["paths"][f"/r{index}/{{id}}"] = {
            "get": {"operationId": f"r{index}", "parameters": [{"name": "id", "in": "path"}]}
        }

    cfg = parse_openapi_spec(spec)

    assert len(cfg.transforms) == 26
    assert any("--operation" in note and "26 operations" in note for note in cfg.notes)


def test_generated_code_from_hostile_spec_text_passes_the_lint_gate(tmp_path: Path) -> None:
    """Quotes, braces, backslashes and docstring terminators in a spec stay inert.

    Each of these once went into the generated source verbatim, where it either broke the
    module (and with it the server's startup import) or ran as code.
    """
    spec = {
        "openapi": "3.0.0",
        "info": {"title": 'Evil "API" {x}', "version": "1"},
        "servers": [{"url": "https://evil.example"}],
        "paths": {
            "/a": {
                "get": {
                    "operationId": "lookUp",
                    "summary": "Say \"hi\" \\ {braces} ''' and more text that runs on for a while",
                    "description": 'Ends with a quote """ and a backslash \\',
                    "parameters": [{"name": "q", "in": "query", "required": True}],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "example": {"a-b": 1, 'c"d': "x", "{e}": [{"f-g": "h"}]}
                                }
                            }
                        }
                    },
                }
            }
        },
    }
    cfg = parse_openapi_spec(spec, service_name="evil")
    _write_all(tmp_path, [cfg])
    _ruff_gate(tmp_path)


def test_generated_code_passes_the_lint_gate_at_the_edges(tmp_path: Path) -> None:
    """Long names, long keys, deep paths, non-finite numbers and typographic text all stay
    lint-clean.

    Each of these once produced a module that failed `ruff check` or `ruff format --check`,
    and the non-finite float one a module that could not even be imported.
    """
    long_key = "an_unusually_long_response_field_name_that_real_apis_do_sometimes_return"
    deep = {
        "containers": {
            "cna": {
                "references": [{"url": "https://a.example", long_key: "x", "tags": ["a"]}],
                "affected": [{"vendor": "Acme Corp", "product": "Widget"}],
                "title": "A rather long title",
            }
        },
        "cveMetadata": {"cveId": "CVE-2021-44228", "assignerOrgIdentifierLongName": "x"},
    }
    configs = [
        # A long service id overflows the `from transforms.<svc>.api import ...` line.
        parse_curl_command(
            "curl -H 'X-Api-Key: abc' -A 'agent' 'https://api.x.example/v2/lookup/8.8.8.8'",
            {"ip": "8.8.8.8", "tags": ["a"], long_key: "x", "nested": {long_key: "y"}},
            service_name="a_rather_long_service_identifier",
        ),
        parse_curl_command("curl https://cveawg.example/api/cve/CVE-2021-44228", deep),
        parse_curl_command(
            "curl https://cveawg.example/api/cve/CVE-2021-44228",
            deep,
            service_name="cve_refs",
            records="containers.cna.references",
            mappings=[f"{long_key}=Phrase"],
        ),
        # NaN and Infinity are accepted by json.loads and must not become bare names.
        parse_curl_command(
            'curl https://api.nums.example/q -d \'{"ip": "8.8.8.8", "n": NaN, "big": 1e999}\''
        ),
        parse_openapi_spec(
            {
                "openapi": "3.0.0",
                "info": {"title": "Acme\u2019s Threat Intelligence Platform \u2013 v1"},
                "servers": [{"url": "https://acme.example"}],
                "paths": {
                    "/ports": {
                        "get": {
                            "operationId": "listPorts",
                            "summary": "List all ports that the platform is crawling on the "
                            "Internet \u2013 the user\u2019s view",
                            "parameters": [{"name": "q", "in": "query", "required": True}],
                        }
                    }
                },
            }
        ),
        # A long keyed title pushes API_KEY_LABEL and SERVICE_NAME past the line limit.
        parse_openapi_spec(
            {
                "openapi": "3.0.0",
                "info": {
                    "title": "Cybersecurity and Infrastructure Security Agency Known Exploited "
                    "Vulnerabilities Catalogue"
                },
                "servers": [{"url": "https://kev.example"}],
                "components": {
                    "securitySchemes": {"k": {"type": "apiKey", "in": "header", "name": "X-Key"}}
                },
                "security": [{"k": []}],
                "paths": {
                    "/cve/{cve}": {
                        "get": {
                            "operationId": "getKev",
                            "parameters": [{"name": "cve", "in": "path", "required": True}],
                        }
                    }
                },
            },
            service_name="kev",
        ),
    ]
    _write_all(tmp_path, configs)
    _ruff_gate(tmp_path)


def test_non_finite_body_values_survive_as_floats(tmp_path: Path) -> None:
    cfg = parse_curl_command(
        'curl https://api.nums.example/q -d \'{"ip": "8.8.8.8", "n": NaN, "big": 1e999}\''
    )
    namespace: dict[str, object] = {}
    body_line = next(
        line.strip()
        for line in generate_service_code(cfg)["lookup.py"].splitlines()
        if line.strip().startswith("body = ")
    )

    exec(body_line, {"target": "1.1.1.1"}, namespace)

    body = namespace["body"]
    assert isinstance(body, dict)
    assert body["big"] == float("inf")
    assert body["n"] != body["n"]  # NaN


def _shodan_like_spec(**extra: Any) -> dict[str, Any]:
    """A spec that declares no scheme and lists its key as a query param on every operation."""
    key = {"name": "key", "in": "query", "required": True, "example": "YOUR_API_KEY"}
    return {
        "openapi": "3.0.0",
        "info": {"title": "Shodanish"},
        "servers": [{"url": "https://api.shodanish.example"}],
        "paths": {
            "/host/{ip}": {
                "get": {
                    "operationId": "hostInformation",
                    "parameters": [key, {"name": "ip", "in": "path", "required": True}],
                }
            },
            "/host/search": {
                "get": {
                    "operationId": "searchHost",
                    "parameters": [
                        key,
                        {"name": "query", "in": "query", "required": True, "example": "port:22"},
                    ],
                }
            },
        },
        **extra,
    }


def test_key_declared_as_a_query_parameter_is_treated_as_auth() -> None:
    """Otherwise the placeholder key is sent verbatim, or the key becomes the input."""
    cfg = parse_openapi_spec(_shodan_like_spec())
    by_id = {t.transform_id: t for t in cfg.transforms}

    assert (cfg.auth_type, cfg.auth_query_param) == ("query", "key")
    assert cfg.auth_key_name == "SHODANISH_API_KEY"
    assert "key" not in by_id["shodanish_host_information"].query_params
    assert by_id["shodanish_host_information"].key_required is True
    assert by_id["shodanish_search_host"].input_param_name == "query"
    assert "key" not in by_id["shodanish_search_host"].query_params


def test_key_like_parameter_on_only_some_operations_stays_data() -> None:
    """A pagination `token` on one endpoint is not the credential."""
    spec = _shodan_like_spec()
    for item in spec["paths"].values():
        item["get"]["parameters"] = item["get"]["parameters"][1:]
    spec["paths"]["/host/search"]["get"]["parameters"].append({"name": "token", "in": "query"})

    cfg = parse_openapi_spec(spec)

    assert cfg.auth_key_name is None


def test_operation_named_api_does_not_replace_the_shared_client() -> None:
    spec = _two_operation_spec()
    spec["paths"]["/other"] = {"get": {"operationId": "API", "parameters": [_QUERY_Q]}}

    files = generate_service_code(parse_openapi_spec(spec, operations=["API", "getThing"]))

    assert "async def fetch(" in files["api.py"]
    assert "async def two_api(" in files["api_2.py"]


def test_search_term_beats_the_resource_path_segment() -> None:
    """`/search?q=hello&limit=5` searches for the input, not for "hello" at /{input}."""
    transform = parse_curl_command(
        "curl 'https://api.x.example/search?q=hello&limit=5'"
    ).transforms[0]

    assert (transform.input_location, transform.input_param_name) == ("query", "q")
    assert transform.endpoint_path == "/search"


def test_lone_numeric_query_parameter_is_still_the_input() -> None:
    transform = parse_curl_command("curl 'https://api.x.example/lookup?id=12345'").transforms[0]

    assert (transform.input_location, transform.input_param_name) == ("query", "id")


def test_swagger2_body_and_form_parameters_carry_the_input() -> None:
    ok = {"200": {"schema": {"type": "object"}}}
    spec = {
        "swagger": "2.0",
        "info": {"title": "Old"},
        "host": "old.example",
        "paths": {
            "/scan": {
                "post": {
                    "operationId": "scan",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "schema": {
                                "type": "object",
                                "required": ["ip"],
                                "properties": {"ip": {"type": "string"}},
                            },
                        }
                    ],
                    "responses": ok,
                }
            },
            "/lookup": {
                "post": {
                    "operationId": "lookup",
                    "parameters": [
                        {"name": "domain", "in": "formData", "type": "string", "required": True}
                    ],
                    "responses": ok,
                }
            },
        },
    }

    by_id = {
        t.transform_id: t
        for t in parse_openapi_spec(spec, operations=["scan", "lookup"]).transforms
    }

    scan, lookup = by_id["old_scan"], by_id["old_lookup"]
    assert (scan.input_location, scan.input_param_name, scan.body_encoding) == (
        "body",
        "ip",
        "json",
    )
    assert (lookup.input_location, lookup.input_param_name, lookup.body_encoding) == (
        "body",
        "domain",
        "form",
    )


def test_rejected_service_name_is_the_one_the_caller_passed() -> None:
    with pytest.raises(ValueError, match="'class'"):
        parse_curl_command("curl https://api.x.example/ip/8.8.8.8", service_name="class")
