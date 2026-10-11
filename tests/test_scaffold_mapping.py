"""What a scaffold maps from a sample response, and what it reports leaving out.

The field inventory is what `scaffold --dry-run` shows an author before anything is
written, so its outcomes are the contract: every leaf of the sample appears once, with
the entity, property or reason it was dropped.
"""

from __future__ import annotations

from typing import Any

import pytest

from transformatron.scaffold import ScaffoldTransformConfig, parse_curl_command, parse_openapi_spec


def _inventory(transform: ScaffoldTransformConfig) -> dict[str, str]:
    return {report.path: report.outcome for report in transform.inventory}


_EPSS = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 1,
    "offset": 0,
    "limit": 100,
    "data": [{"cve": "CVE-2021-44228", "epss": "0.944", "percentile": "0.999"}],
}


def test_epss_inventory_finds_the_records_and_drops_the_envelope() -> None:
    cfg = parse_curl_command(
        "curl 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228'", _EPSS, "epss"
    )
    [transform] = cfg.transforms

    assert _inventory(transform) == {
        "status": "dropped: envelope",
        "status-code": "dropped: envelope",
        "version": "dropped: envelope",
        "access": "dropped: envelope",
        "total": "dropped: envelope",
        "offset": "dropped: envelope",
        "limit": "dropped: envelope",
        "data[].cve": "entity CVE (primary)",
        "data[].epss": "property epss",
        "data[].percentile": "property percentile",
    }
    assert transform.mapping.path == ("data",)
    notes = " ".join(cfg.notes)
    assert "7 envelope" in notes
    assert "paginated" in notes and "total" in notes


def _cve_record(**cna: Any) -> dict[str, Any]:
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": "f0158376"},
                "references": [{"url": "https://a.example/advisory", "name": "advisory"}],
                **cna,
            }
        },
    }


def test_deep_typed_values_are_reached_and_deeper_ones_reported() -> None:
    """Four levels down is mapped; five is reported with the way to reach it."""
    sample = _cve_record(
        problemTypes=[{"descriptions": [{"reference": {"url": "https://cwe.example/502"}}]}]
    )
    cfg = parse_curl_command("curl https://cveawg.example/api/cve/CVE-2021-44228", sample, "cve")
    inventory = _inventory(cfg.transforms[0])

    assert inventory["cveMetadata.cveId"] == "entity CVE (primary)"
    assert inventory["cveMetadata.state"] == "property cveMetadata.state"
    labels = {prop.name: prop.label for prop in cfg.transforms[0].mapping.properties}
    assert labels["cveMetadata.state"] == "Cve Metadata State"
    assert inventory["containers.cna.references[].url"] == "entity URL (primary)"
    assert inventory["containers.cna.providerMetadata.orgId"] == "dropped: metadata"
    assert inventory["containers.cna.problemTypes[].descriptions[].reference.url"].startswith(
        "dropped: deeper than 4; use --records/--map"
    )
    assert any("deeper than 4" in note and "problemTypes" in note for note in cfg.notes), cfg.notes


def test_records_override_moves_the_record_and_reports_the_rest() -> None:
    cfg = parse_curl_command(
        "curl https://cveawg.example/api/cve/CVE-2021-44228",
        _cve_record(),
        "cve",
        records="containers.cna.references",
    )
    [transform] = cfg.transforms
    inventory = _inventory(transform)

    assert transform.mapping.path == ("containers", "cna", "references")
    assert inventory["containers.cna.references[].url"] == "entity URL (primary)"
    assert inventory["containers.cna.references[].name"] == "property name"
    assert inventory["cveMetadata.cveId"] == "dropped: outside the records"


def test_map_overrides_type_attach_and_drop_fields() -> None:
    cfg = parse_curl_command(
        "curl https://cveawg.example/api/cve/CVE-2021-44228",
        _cve_record(affected=[{"vendor": "Apache", "product": "Log4j2"}]),
        "cve",
        mappings=[
            "containers.cna.affected[].product=Phrase",
            "containers.cna.references[].name=Drop",
            "dataType=Property",
        ],
    )
    inventory = _inventory(cfg.transforms[0])

    assert inventory["containers.cna.affected[].product"] == "entity Phrase (--map)"
    assert inventory["containers.cna.references[].name"] == "dropped: by --map"
    assert inventory["dataType"] == "property dataType (--map)"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"records": "nowhere"}, r"--records 'nowhere' does not match.*containers\.cna"),
        ({"mappings": ["no.such.field=Domain"]}, "does not match a field"),
        ({"mappings": ["dataType=NotAType"]}, "not an entity class"),
        ({"mappings": ["dataType"]}, "PATH=TYPE"),
        ({"mappings": ["containers.cna.references=URL"]}, "list of objects"),
    ],
)
def test_overrides_that_do_not_fit_the_sample_are_errors(
    kwargs: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_curl_command(
            "curl https://cveawg.example/api/cve/CVE-2021-44228", _cve_record(), "cve", **kwargs
        )


def test_a_record_with_nothing_typed_becomes_one_phrase_with_properties() -> None:
    sample = {"results": [{"title": "Quarterly report", "snippet": "text", "id": 7}], "total": 1}
    cfg = parse_curl_command("curl 'https://search.example/find?q=report'", sample, "finder")
    [transform] = cfg.transforms

    assert _inventory(transform) == {
        "total": "dropped: envelope",
        "results[].title": "entity Phrase (primary)",
        "results[].snippet": "property snippet",
        "results[].id": "property id",
    }


def test_untyped_fields_with_no_entity_to_carry_them_are_reported() -> None:
    """crt.sh records name the domain searched for and its siblings; neither is the record."""
    sample = [
        {
            "common_name": "hexacron.com",
            "name_value": "hexacron.com\nwww.hexacron.com",
            "serial_number": "0123456789abcdef0123456789abcdef",
        }
    ]
    cfg = parse_curl_command("curl 'https://crt.sh/?q=hexacron.com&output=json'", sample, "crt")
    inventory = _inventory(cfg.transforms[0])

    assert inventory["[].common_name"] == "entity Domain"
    assert inventory["[].name_value"] == "entity Domain"
    assert inventory["[].serial_number"].startswith("dropped: no primary entity")


def test_metadata_subtrees_are_skipped_whole() -> None:
    """ORCID's `source` blocks hold provenance, including a host that looks like a domain."""
    sample = {
        "emails": {
            "email": [{"email": "j@example.org", "source": {"source-orcid": {"host": "orcid.org"}}}]
        }
    }
    cfg = parse_curl_command(
        "curl https://pub.orcid.org/v3.0/0000-0002-1825-0097/person", sample, "orcid"
    )
    inventory = _inventory(cfg.transforms[0])

    assert inventory["emails.email[].email"] == "entity EmailAddress (primary)"
    assert inventory["emails.email[].source.source-orcid.host"] == "dropped: metadata"
    assert "Domain" not in cfg.transforms[0].output_entity_types


def test_a_field_inside_a_metadata_block_can_be_mapped() -> None:
    """The block is skipped whole except for the field the author names."""
    sample = {
        "emails": {
            "email": [{"email": "j@example.org", "source": {"source-orcid": {"host": "orcid.org"}}}]
        }
    }
    cfg = parse_curl_command(
        "curl https://pub.orcid.org/v3.0/0000-0002-1825-0097/person",
        sample,
        "orcid",
        mappings=["emails.email[].source.source-orcid.host=Property"],
    )
    inventory = _inventory(cfg.transforms[0])

    assert inventory["emails.email[].source.source-orcid.host"] == (
        "property source.source-orcid.host (--map)"
    )


def test_a_property_mapped_inside_an_entityless_list_goes_on_the_record_entity() -> None:
    """MITRE's description and CVSS sit in lists of plain objects.

    `--map ...=Property` there was accepted and then silently dropped, because the list's
    elements have no entity of their own. It now lands on the CVE the record is about,
    however many lists down.
    """
    sample = _cve_record(descriptions=[{"lang": "en", "value": "JNDI lookups run code"}])
    sample["containers"]["adp"] = [{"metrics": [{"cvssV3_1": {"baseScore": 10.0}}]}]
    cfg = parse_curl_command(
        "curl https://cveawg.example/api/cve/CVE-2021-44228",
        sample,
        "cve",
        mappings=[
            "containers.cna.descriptions[].value=Property",
            "containers.adp[].metrics[].cvssV3_1.baseScore=Property",
        ],
    )
    [transform] = cfg.transforms
    inventory = _inventory(transform)

    assert inventory["containers.cna.descriptions[].value"] == (
        "property containers.cna.descriptions.value (--map)"
    )
    assert inventory["containers.adp[].metrics[].cvssV3_1.baseScore"] == "property cvss (--map)"
    assert inventory["containers.cna.descriptions[].lang"].startswith(
        "dropped: no entity in these list elements; --map PATH=Property"
    )
    assert transform.mapping.primary is not None
    assert transform.mapping.primary.entity_type == "CVE"
    assert [p.path for p in transform.mapping.properties][-2:] == [
        ("containers", "cna", "descriptions", "value"),
        ("containers", "adp", "metrics", "cvssV3_1", "baseScore"),
    ]


def test_a_property_mapping_with_no_entity_to_go_on_is_an_error() -> None:
    """A --map that cannot be honoured says why instead of vanishing from the output."""
    sample = [{"name_value": "a.example\nb.example", "serial": "0a1b"}]

    with pytest.raises(ValueError, match=r"serial=Property: the record has no primary entity"):
        parse_curl_command(
            "curl 'https://crt.example/?q=a.example'", sample, "crt", mappings=["serial=Property"]
        )


def test_a_field_empty_in_the_sample_can_still_be_mapped() -> None:
    """InternetDB's `vulns` is empty for 8.8.8.8; --map still makes it a CVE field."""
    sample = {"ip": "8.8.8.8", "ports": [53], "vulns": [], "cpes": [], "tags": []}
    cfg = parse_curl_command(
        "curl https://internetdb.shodan.io/8.8.8.8",
        sample,
        "internetdb",
        mappings=["vulns[]=CVE", "tags[]=Property"],
    )
    [transform] = cfg.transforms
    inventory = _inventory(transform)

    assert inventory["vulns[]"] == "entity CVE (--map)"
    assert inventory["tags[]"] == "property tags (--map)"
    assert inventory["cpes[]"] == "dropped: empty in the sample"
    assert "CVE" in transform.output_entity_types


def _pet_spec() -> dict[str, Any]:
    """Petstore's getPetById: a schema whose tag names have no example."""
    tag = {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}}
    pet = {
        "type": "object",
        "properties": {
            "id": {"type": "integer", "example": 10},
            "name": {"type": "string", "example": "doggie"},
            "photoUrls": {"type": "array", "items": {"type": "string"}},
            "tags": {"type": "array", "items": tag},
            "status": {"type": "string", "enum": ["available", "pending", "sold"]},
        },
    }
    get = {
        "operationId": "getPetById",
        "parameters": [{"name": "petId", "in": "path", "required": True}],
        "responses": {"200": {"content": {"application/json": {"schema": pet}}}},
    }
    return {
        "openapi": "3.0.0",
        "info": {"title": "Petstore"},
        "servers": [{"url": "https://pets.example/api/v3"}],
        "paths": {"/pet/{petId}": {"get": get}},
    }


def test_a_schema_built_sample_names_no_people_and_keeps_the_record_status() -> None:
    """A tag's unknown `name` was planned as a Person, and the pet's `status` as envelope."""
    [transform] = parse_openapi_spec(_pet_spec(), service_name="pets").transforms
    inventory = _inventory(transform)

    assert "Person" not in transform.output_entity_types
    assert inventory["tags[].name"].startswith("dropped: no entity in these list elements")
    assert inventory["name"] == "entity Phrase (primary)"
    assert inventory["status"] == "property status"
    assert inventory["photoUrls[]"] == "entity URL"


def test_status_beside_another_envelope_key_is_still_envelope() -> None:
    sample = {"status": "success", "query": "8.8.8.8", "country": "United States"}

    cfg = parse_curl_command("curl http://ip-api.example/json/8.8.8.8", sample, "ipapi")
    inventory = _inventory(cfg.transforms[0])

    assert inventory["status"] == inventory["query"] == "dropped: envelope"


_HITS = {
    "took": 24,
    "timed_out": False,
    "_shards": {"total": 50, "failed": 0},
    "hits": {
        "total": {"value": 4659, "relation": "eq"},
        "max_score": 12.8,
        "hits": [
            {
                "_id": "0001104659-21-143758:tm2133976d1_ex99-1.htm",
                "_source": {"display_names": ["Supernus (SUPN)"], "form": "8-K"},
            }
        ],
    },
    "aggregations": {"form_filter": {"buckets": [{"key": "8-K", "doc_count": 4659}]}},
}
_EDGAR = "curl 'https://efts.example/LATEST/search-index?q=ransomware&forms=8-K'"


def test_elasticsearch_hits_are_the_records() -> None:
    """EDGAR's filings sit in `hits.hits`; the whole response was one record titled 'eq'."""
    [transform] = parse_curl_command(_EDGAR, _HITS, "edgar").transforms
    inventory = _inventory(transform)

    assert transform.mapping.path == ("hits", "hits")
    assert inventory["hits.hits[]._id"] == "entity Phrase (primary)"
    assert inventory["hits.total.relation"] == "dropped: envelope"
    assert inventory["aggregations.form_filter.buckets[].key"] == "dropped: outside the records"


@pytest.mark.parametrize(
    ("record", "title"),
    [
        ({"relation": "eq", "summary_text": "Quarterly filing"}, "summary_text"),
        ({"kind": "PUBLISHED", "note": "Filed late"}, "note"),
        ({"relation": "eq", "flag": True}, "result"),
    ],
)
def test_a_junk_value_never_titles_a_record(record: dict[str, Any], title: str) -> None:
    """A two-letter code or an enum names nothing: the Phrase takes readable text, or the
    record is left to the placeholder `result` field."""
    [transform] = parse_curl_command("curl 'https://x.example/find?q=a+b'", record, "x").transforms

    assert transform.mapping.primary is not None
    assert transform.mapping.primary.path == (title,)


def test_a_list_field_mapped_to_an_entity_leaves_the_record_its_primary() -> None:
    """Mapping EDGAR's company names made every filing field 'dropped: no primary entity'."""
    [transform] = parse_curl_command(
        _EDGAR, _HITS, "edgar", mappings=["_source.display_names[]=Company"]
    ).transforms
    inventory = _inventory(transform)

    assert inventory["hits.hits[]._source.display_names[]"] == "entity Company (--map)"
    assert inventory["hits.hits[]._id"] == "entity Phrase (primary)"
    assert inventory["hits.hits[]._source.form"] == "property _source.form"


def test_primary_names_the_record_entity() -> None:
    """--primary picks the entity, even the echo of the input a record list would skip."""
    sample = [
        {
            "common_name": "hexacron.com",
            "name_value": "hexacron.com\nwww.hexacron.com",
            "serial_number": "0123456789abcdef0123456789abcdef",
        }
    ]
    curl = "curl 'https://crt.sh/?q=hexacron.com&output=json'"

    [transform] = parse_curl_command(curl, sample, "crt", primary="[].common_name").transforms
    inventory = _inventory(transform)

    assert inventory["[].common_name"] == "entity Domain (primary)"
    assert inventory["[].serial_number"] == "property serial_number"
    # It is the input echoed: returned as the enriched input rather than skipped.
    assert transform.mapping.enrich_input is True


@pytest.mark.parametrize(
    ("primary", "message"),
    [
        ("_source.form", r"_source\.form is not an entity field; make it one with --map"),
        ("_source.display_names", "holds several values"),
        ("nowhere", r"does not match a field of the records \(hits\.hits\[\]\)"),
    ],
)
def test_a_primary_that_cannot_be_used_is_an_error_naming_the_candidates(
    primary: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message) as raised:
        parse_curl_command(
            _EDGAR,
            _HITS,
            "edgar",
            mappings=["_source.display_names[]=Company", "_id=Phrase"],
            primary=primary,
        )

    assert "Fields that can be primary: hits.hits[]._id." in str(raised.value)
