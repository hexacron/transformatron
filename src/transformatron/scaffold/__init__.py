"""Spec-to-Transform Scaffolder package."""

from __future__ import annotations

from transformatron.scaffold.generator import (
    generate_service_code,
    inject_project_import,
    planned_scaffold_paths,
    remove_scaffold,
    write_scaffold,
)
from transformatron.scaffold.parser import (
    OperationInfo,
    list_openapi_operations,
    load_spec,
    parse_curl_command,
    parse_openapi_spec,
)
from transformatron.scaffold.schema import (
    EntityField,
    FieldReport,
    PropertyField,
    RecordMapping,
    ScaffoldServiceConfig,
    ScaffoldTransformConfig,
)

__all__ = [
    "EntityField",
    "FieldReport",
    "OperationInfo",
    "PropertyField",
    "RecordMapping",
    "ScaffoldServiceConfig",
    "ScaffoldTransformConfig",
    "generate_service_code",
    "inject_project_import",
    "list_openapi_operations",
    "load_spec",
    "parse_curl_command",
    "parse_openapi_spec",
    "planned_scaffold_paths",
    "remove_scaffold",
    "write_scaffold",
]
