import json
from copy import deepcopy
from importlib.resources import files

import pytest

from forgejo_api_mcp.catalog import CatalogError, OperationCatalog


def test_bundled_spec_indexes_every_unique_operation() -> None:
    catalog = OperationCatalog.bundled()

    assert catalog.version == "1.25.4"
    assert len(catalog) == 467
    assert len({operation.operation_id for operation in catalog.list()}) == 467


@pytest.mark.parametrize(
    ("operation_id", "method", "path", "tag"),
    [
        ("repoGet", "GET", "/repos/{owner}/{repo}", "repository"),
        (
            "ActionsDispatchWorkflow",
            "POST",
            "/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
            "repository",
        ),
        ("adminCreateUser", "POST", "/admin/users", "admin"),
    ],
)
def test_catalog_exposes_representative_operation_contracts(
    operation_id: str, method: str, path: str, tag: str
) -> None:
    operation = OperationCatalog.bundled().get(operation_id)

    assert operation.method == method
    assert operation.path == path
    assert tag in operation.tags
    assert operation.parameters
    assert operation.produces
    assert operation.is_mutating is (method not in {"GET", "HEAD", "OPTIONS"})


def test_catalog_resolves_body_schema_and_additional_properties() -> None:
    operation = OperationCatalog.bundled().get("ActionsDispatchWorkflow")

    assert not operation.request_body_required
    assert operation.request_body_schema is not None
    assert operation.request_body_schema["required"] == ["ref"]
    assert operation.request_body_schema["properties"]["inputs"]["additionalProperties"] == {
        "type": "string"
    }
    assert "$ref" not in operation.request_body_schema


def test_catalog_exposes_parameter_validation_and_array_serialization_metadata() -> None:
    operation = OperationCatalog.bundled().get("notifyGetList")
    parameters = {parameter["name"]: parameter for parameter in operation.parameters}

    assert parameters["status-types"]["type"] == "array"
    assert parameters["status-types"]["collectionFormat"] == "multi"
    assert parameters["subject-type"]["items"]["enum"] == [
        "issue",
        "pull",
        "commit",
        "repository",
    ]
    assert parameters["since"]["format"] == "date-time"


def test_effective_media_types_use_operation_values_then_root_inheritance() -> None:
    catalog = OperationCatalog.bundled()

    inherited_consumes = catalog.get("activitypubPersonInbox")
    inherited_produces = catalog.get("notifyNewAvailable")
    overridden = catalog.get("renderMarkdownRaw")
    binary = catalog.get("repoGetRawFile")

    assert inherited_consumes.consumes == ("application/json", "text/plain")
    assert inherited_produces.produces == ("application/json", "text/html")
    assert overridden.consumes == ("text/plain",)
    assert overridden.produces == ("text/html",)
    assert binary.response_content_types == ("application/octet-stream",)


def test_catalog_can_filter_by_query_and_tag_case_insensitively() -> None:
    catalog = OperationCatalog.bundled()
    operations = catalog.list(query="workflow", tag="Repository")

    assert operations
    assert all("repository" in {tag.casefold() for tag in operation.tags} for operation in operations)
    assert all(
        "workflow" in f"{operation.operation_id} {operation.summary} {operation.description}".casefold()
        for operation in operations
    )


def test_unknown_and_duplicate_operation_ids_raise_clear_errors() -> None:
    catalog = OperationCatalog.bundled()
    with pytest.raises(CatalogError, match="Unknown Forgejo operation_id"):
        catalog.get("notAnOperation")

    raw = files("forgejo_api_mcp").joinpath("openapi.json").read_text(encoding="utf-8")
    document = json.loads(raw)
    duplicate = deepcopy(next(iter(document["paths"].values())))
    duplicate_operation = next(
        value for key, value in duplicate.items() if key in {"get", "post", "put", "delete"}
    )
    duplicate_operation["operationId"] = "repoGet"
    document["paths"]["/duplicate-test"] = duplicate

    with pytest.raises(CatalogError, match="Duplicate operationId: repoGet"):
        OperationCatalog(document)


def test_path_parameter_is_overridden_by_operation_parameter() -> None:
    document = {
        "swagger": "2.0",
        "info": {"version": "test"},
        "basePath": "/api/v1",
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "paths": {
            "/items/{item}": {
                "parameters": [
                    {"name": "item", "in": "path", "required": True, "type": "string"}
                ],
                "get": {
                    "operationId": "getItem",
                    "parameters": [
                        {
                            "name": "item",
                            "in": "path",
                            "required": True,
                            "type": "integer",
                            "minimum": 1,
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }

    parameter = OperationCatalog(document).get("getItem").parameters[0]
    assert parameter["type"] == "integer"
    assert parameter["minimum"] == 1
