"""Immutable operation catalog built from the bundled Forgejo Swagger document."""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from importlib.resources import files
from types import MappingProxyType
from typing import Any

HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put"})
READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
DESTRUCTIVE_METHODS = frozenset({"DELETE"})


class CatalogError(ValueError):
    """Raised when the Swagger catalog is invalid or an operation is unknown."""


@dataclass(frozen=True, slots=True)
class Operation:
    """Normalized invocation contract for one Forgejo operation."""

    operation_id: str
    method: str
    path: str
    summary: str
    description: str
    parameters: tuple[Mapping[str, Any], ...]
    tags: tuple[str, ...]
    request_body_schema: Mapping[str, Any] | None
    request_body_required: bool
    consumes: tuple[str, ...]
    produces: tuple[str, ...]
    responses: Mapping[str, Mapping[str, Any]]

    @property
    def parameter_names(self) -> dict[str, frozenset[str]]:
        names: dict[str, set[str]] = {}
        for parameter in self.parameters:
            names.setdefault(str(parameter["in"]), set()).add(str(parameter["name"]))
        return {location: frozenset(values) for location, values in names.items()}

    @property
    def required_parameters(self) -> dict[str, frozenset[str]]:
        names: dict[str, set[str]] = {}
        for parameter in self.parameters:
            if parameter.get("required"):
                names.setdefault(str(parameter["in"]), set()).add(str(parameter["name"]))
        return {location: frozenset(values) for location, values in names.items()}

    @property
    def response_content_types(self) -> tuple[str, ...]:
        """Effective Swagger ``produces`` values for this operation."""

        return self.produces

    @property
    def is_mutating(self) -> bool:
        return self.method not in READ_ONLY_METHODS

    @property
    def is_destructive(self) -> bool:
        return self.method in DESTRUCTIVE_METHODS

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe copy suitable for MCP discovery responses."""

        return {
            "operation_id": self.operation_id,
            "method": self.method,
            "path": self.path,
            "summary": self.summary,
            "description": self.description,
            "tags": list(self.tags),
            "parameters": [deepcopy(dict(parameter)) for parameter in self.parameters],
            "required_parameters": {
                location: sorted(names) for location, names in self.required_parameters.items()
            },
            "request_body_schema": deepcopy(dict(self.request_body_schema))
            if self.request_body_schema is not None
            else None,
            "request_body_required": self.request_body_required,
            "consumes": list(self.consumes),
            "produces": list(self.produces),
            "response_content_types": list(self.response_content_types),
            "responses": {
                status: deepcopy(dict(response)) for status, response in self.responses.items()
            },
            "is_mutating": self.is_mutating,
            "is_destructive": self.is_destructive,
        }


class _ReferenceResolver:
    """Resolve local JSON pointers while retaining a marker at recursive cycles."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        self._document = document
        self._cache: dict[str, Any] = {}

    def resolve(self, value: Any, seen: frozenset[str] = frozenset()) -> Any:
        if isinstance(value, list):
            return [self.resolve(item, seen) for item in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                raise CatalogError(f"Unsupported Swagger reference: {ref!r}")
            if ref in seen:
                return {"$ref": ref}
            if not seen and ref in self._cache:
                resolved = deepcopy(self._cache[ref])
            else:
                resolved = self.resolve(self._lookup(ref), seen | {ref})
                if not seen:
                    self._cache[ref] = deepcopy(resolved)
            siblings = {key: item for key, item in value.items() if key != "$ref"}
            if siblings:
                if not isinstance(resolved, dict):
                    raise CatalogError(f"Swagger reference {ref!r} cannot have sibling fields")
                resolved.update(self.resolve(siblings, seen))
            return resolved
        return {key: self.resolve(item, seen) for key, item in value.items()}

    def _lookup(self, ref: str) -> Any:
        value: Any = self._document
        try:
            for encoded_part in ref[2:].split("/"):
                part = encoded_part.replace("~1", "/").replace("~0", "~")
                value = value[part]
        except (KeyError, TypeError) as error:
            raise CatalogError(f"Unresolvable Swagger reference: {ref}") from error
        return value


class OperationCatalog:
    """An immutable, searchable index of operations from one Swagger snapshot."""

    def __init__(self, document: dict[str, Any]) -> None:
        if document.get("swagger") != "2.0":
            raise CatalogError("The operation catalog requires a Swagger 2.0 document")
        self.version = str(document.get("info", {}).get("version", "unknown"))
        self.base_path = self._normalize_base_path(document.get("basePath", "/api/v1"))
        self._resolver = _ReferenceResolver(document)
        self._operations = MappingProxyType(self._build_operations(document))

    @classmethod
    def bundled(cls) -> OperationCatalog:
        raw = files("forgejo_api_mcp").joinpath("openapi.json").read_text(encoding="utf-8")
        return cls(json.loads(raw))

    @staticmethod
    def _normalize_base_path(value: Any) -> str:
        path = str(value or "/api/v1").strip()
        if not path.startswith("/"):
            path = f"/{path}"
        return path.rstrip("/") or "/"

    def _build_operations(self, document: dict[str, Any]) -> dict[str, Operation]:
        operations: dict[str, Operation] = {}
        root_consumes = tuple(document.get("consumes", ()))
        root_produces = tuple(document.get("produces", ()))
        paths = document.get("paths", {})
        if not isinstance(paths, dict):
            raise CatalogError("Swagger paths must be an object")

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                raise CatalogError(f"Swagger path item must be an object: {path!r}")
            inherited = path_item.get("parameters", [])
            for method, raw_operation in path_item.items():
                if method.casefold() not in HTTP_METHODS:
                    continue
                if not isinstance(raw_operation, dict):
                    raise CatalogError(f"Swagger operation must be an object: {method} {path}")
                operation_id = raw_operation.get("operationId")
                if not isinstance(operation_id, str) or not operation_id.strip():
                    raise CatalogError(f"Missing operationId for {method.upper()} {path}")
                if operation_id in operations:
                    raise CatalogError(f"Duplicate operationId: {operation_id}")

                parameters = self._merge_parameters(inherited, raw_operation.get("parameters", []))
                body_parameter = next(
                    (parameter for parameter in parameters if parameter["in"] == "body"), None
                )
                responses = self._normalize_responses(raw_operation.get("responses", {}))
                consumes = tuple(raw_operation.get("consumes", root_consumes))
                produces = tuple(raw_operation.get("produces", root_produces))
                operations[operation_id] = Operation(
                    operation_id=operation_id,
                    method=method.upper(),
                    path=str(path),
                    summary=str(raw_operation.get("summary", "")),
                    description=str(raw_operation.get("description", "")),
                    parameters=tuple(MappingProxyType(parameter) for parameter in parameters),
                    tags=tuple(str(tag) for tag in raw_operation.get("tags", [])),
                    request_body_schema=MappingProxyType(body_parameter["schema"])
                    if body_parameter is not None
                    else None,
                    request_body_required=bool(body_parameter and body_parameter["required"]),
                    consumes=consumes,
                    produces=produces,
                    responses=MappingProxyType(
                        {
                            status: MappingProxyType(response)
                            for status, response in responses.items()
                        }
                    ),
                )
        return operations

    def _merge_parameters(self, inherited: Any, declared: Any) -> list[dict[str, Any]]:
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for raw_parameter in [*(inherited or []), *(declared or [])]:
            parameter = self._resolver.resolve(raw_parameter)
            if not isinstance(parameter, dict):
                raise CatalogError("Swagger parameter must resolve to an object")
            name = parameter.get("name")
            location = parameter.get("in")
            if not isinstance(name, str) or not isinstance(location, str):
                raise CatalogError(f"Invalid Swagger parameter: {parameter!r}")
            descriptor = {
                "name": name,
                "in": location,
                "description": str(parameter.get("description", "")),
                "required": bool(parameter.get("required", False)),
            }
            if location == "body":
                schema = parameter.get("schema", {})
                descriptor["schema"] = self._resolver.resolve(schema)
            else:
                for key in (
                    "type",
                    "format",
                    "enum",
                    "items",
                    "default",
                    "minimum",
                    "maximum",
                    "exclusiveMinimum",
                    "exclusiveMaximum",
                    "minLength",
                    "maxLength",
                    "pattern",
                    "minItems",
                    "maxItems",
                    "uniqueItems",
                    "multipleOf",
                    "collectionFormat",
                ):
                    if key in parameter:
                        descriptor[key] = self._resolver.resolve(parameter[key])
            merged[(location, name)] = descriptor
        return list(merged.values())

    def _normalize_responses(self, raw_responses: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(raw_responses, dict):
            raise CatalogError("Swagger responses must be an object")
        responses: dict[str, dict[str, Any]] = {}
        for status, raw_response in raw_responses.items():
            response = self._resolver.resolve(raw_response)
            if not isinstance(response, dict):
                raise CatalogError(f"Swagger response {status!r} must resolve to an object")
            responses[str(status)] = response
        return responses

    def __len__(self) -> int:
        return len(self._operations)

    def get(self, operation_id: str) -> Operation:
        try:
            return self._operations[operation_id]
        except KeyError as error:
            raise CatalogError(f"Unknown Forgejo operation_id: {operation_id}") from error

    def list(self, query: str | None = None, tag: str | None = None) -> list[Operation]:
        needle = query.casefold() if query else None
        tag_needle = tag.casefold() if tag else None
        return [
            operation
            for operation in self._operations.values()
            if (not tag_needle or any(tag_needle == item.casefold() for item in operation.tags))
            and (
                not needle
                or needle in operation.operation_id.casefold()
                or needle in operation.summary.casefold()
                or needle in operation.description.casefold()
                or any(needle in operation_tag.casefold() for operation_tag in operation.tags)
            )
        ]
