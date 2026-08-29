"""Secure, validated asynchronous HTTP adapter for Forgejo operations."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import math
import os
import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID

import httpx

from .catalog import Operation, OperationCatalog
from .errors import ConfigurationError, InputValidationError
from .provider_auth import classify_token

DEFAULT_BASE_URL = "https://forgejo.invalid"
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 30.0
MAX_TEXT_RESPONSE_BYTES = 1_000_000
MAX_BINARY_RESPONSE_BYTES = 10_000_000
MAX_FILE_UPLOAD_BYTES = 10_000_000
MAX_BASE64_FILE_UPLOAD_CHARS = 4 * ((MAX_FILE_UPLOAD_BYTES + 2) // 3)
MAX_TOTAL_FILE_UPLOAD_BYTES = 10_000_000
MAX_PARAMETER_INPUT_BYTES = 1_000_000
MAX_REQUEST_BODY_BYTES = 1_000_000
MAX_HTTPX_URL_LENGTH = 65_536
TRUNCATION_MARKER = "\n...[truncated]"
EMAIL_DOT_ATOM = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")
EMAIL_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
HTTP_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
STRICT_MEDIA_TYPE = re.compile(
    rf"""
    {HTTP_TOKEN}/{HTTP_TOKEN}
    (?:
        [ ]*;[ ]*{HTTP_TOKEN}[ ]*=[ ]*
        (?:{HTTP_TOKEN}|"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e])*")
    )*
    """,
    re.VERBOSE,
)
FULL_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
RFC3339_DATE_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})"
)
FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "transfer-encoding",
    }
)


class ForgejoClient:
    """Translate validated operation contracts into bounded Forgejo requests."""

    def __init__(
        self,
        catalog: OperationCatalog,
        base_url: str,
        token: str | None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_text_bytes: int = MAX_TEXT_RESPONSE_BYTES,
        max_binary_bytes: int = MAX_BINARY_RESPONSE_BYTES,
        transport: httpx.AsyncBaseTransport | None = None,
        allow_insecure_localhost: bool | None = None,
    ) -> None:
        self.catalog = catalog
        allow_insecure = (
            os.getenv("FORGEJO_ALLOW_INSECURE_HTTP") == "1"
            if allow_insecure_localhost is None
            else allow_insecure_localhost
        )
        self.base_url = self._normalize_base_url(base_url, catalog.base_path, allow_insecure)
        if token is not None and not isinstance(token, str):
            raise ConfigurationError("FORGEJO_ACCESS_TOKEN must be a string")
        if token and ("\r" in token or "\n" in token):
            raise ConfigurationError("FORGEJO_ACCESS_TOKEN contains invalid characters")
        self._token = token or None
        self._token_bytes = self._token.encode("utf-8") if self._token else None
        self.timeout = self._bounded_number(
            "timeout", timeout, minimum=0.001, maximum=MAX_TIMEOUT_SECONDS
        )
        self.max_text_bytes = self._bounded_integer(
            "max_text_bytes", max_text_bytes, MAX_TEXT_RESPONSE_BYTES
        )
        self.max_binary_bytes = self._bounded_integer(
            "max_binary_bytes", max_binary_bytes, MAX_BINARY_RESPONSE_BYTES
        )
        self._transport = transport

    @classmethod
    def from_environment(cls, catalog: OperationCatalog) -> ForgejoClient:
        return cls(
            catalog,
            os.getenv("FORGEJO_BASE_URL", DEFAULT_BASE_URL),
            os.getenv("FORGEJO_ACCESS_TOKEN"),
        )

    @staticmethod
    def _bounded_number(name: str, value: float, *, minimum: float, maximum: float) -> float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigurationError(f"{name} must be a number")
        result = float(value)
        if not math.isfinite(result) or not minimum <= result <= maximum:
            raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
        return result

    @staticmethod
    def _bounded_integer(name: str, value: int, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
            raise ConfigurationError(f"{name} must be between 1 and {maximum}")
        return value

    @staticmethod
    def _normalize_base_url(base_url: str, base_path: str, allow_insecure: bool) -> str:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ConfigurationError("FORGEJO_BASE_URL must be a non-empty URL")
        parsed = urlsplit(base_url.strip())
        if not parsed.scheme or not parsed.hostname:
            raise ConfigurationError("FORGEJO_BASE_URL must be an absolute URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ConfigurationError(
                "FORGEJO_BASE_URL cannot contain credentials, a query, or a fragment"
            )
        hostname = parsed.hostname.casefold()
        is_localhost = hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme.casefold() != "https" and not (
            parsed.scheme.casefold() == "http" and allow_insecure and is_localhost
        ):
            raise ConfigurationError(
                "FORGEJO_BASE_URL must use HTTPS; insecure HTTP is allowed only for "
                "localhost with FORGEJO_ALLOW_INSECURE_HTTP=1"
            )
        if parsed.scheme.casefold() not in {"http", "https"}:
            raise ConfigurationError("FORGEJO_BASE_URL must use HTTP or HTTPS")

        configured_path = parsed.path.rstrip("/")
        normalized_suffix = "/" + base_path.strip("/")
        while configured_path.endswith(f"{normalized_suffix}{normalized_suffix}"):
            configured_path = configured_path[: -len(normalized_suffix)]
        if configured_path == normalized_suffix or configured_path.endswith(normalized_suffix):
            api_path = configured_path
        else:
            api_path = f"{configured_path}{normalized_suffix}"
        return urlunsplit((parsed.scheme.casefold(), parsed.netloc, api_path, "", ""))

    async def invoke(
        self,
        operation_id: str,
        path_params: dict[str, Any] | None = None,
        query_params: dict[str, Any] | None = None,
        header_params: dict[str, Any] | None = None,
        body: Any = None,
        form_params: dict[str, Any] | None = None,
        file_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        operation = self.catalog.get(operation_id)
        groups = {
            "path": self._require_mapping("path_params", path_params),
            "query": self._require_mapping("query_params", query_params),
            "header": self._require_mapping("header_params", header_params),
            "formData": self._require_mapping("form_params", form_params),
        }
        files_input = self._require_mapping("file_params", file_params)
        self._validate_invocation(operation, groups, files_input, body)
        self._validate_aggregate_parameter_sizes(operation, groups, files_input)

        url_path = self._serialize_path(operation, groups["path"])
        query = self._serialize_query(operation, groups["query"])
        request_url = self._build_request_url(url_path, query)
        headers = self._serialize_headers(operation, groups["header"])
        headers["Accept-Encoding"] = "identity"
        if operation.produces:
            headers["Accept"] = operation.produces[0]
        if self._token:
            headers["Authorization"] = f"token {self._token}"

        request_kwargs: dict[str, Any] = {"headers": headers}
        if files_input or groups["formData"]:
            data, files = self._serialize_multipart(operation, groups["formData"], files_input)
            request_kwargs["files"] = [
                *((name, (None, value)) for name, value in data),
                *files,
            ]
        elif body is not None:
            if operation.consumes == ("text/plain",):
                headers["Content-Type"] = "text/plain"
                request_kwargs["content"] = self._bounded_request_body(body.encode("utf-8"))
            else:
                headers["Content-Type"] = "application/json"
                request_kwargs["content"] = self._serialize_json_body(body)

        try:
            async with asyncio.timeout(self.timeout):
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(self.timeout),
                    follow_redirects=False,
                    transport=self._transport,
                    trust_env=False,
                ) as http_client, http_client.stream(
                    operation.method,
                    request_url,
                    **request_kwargs,
                ) as response:
                    return await self._format_response(operation, response)
        except (TimeoutError, httpx.TimeoutException):
            return self._failure(operation_id, "timeout", "Forgejo request timed out")
        except httpx.TransportError:
            return self._failure(
                operation_id, "transport", "Forgejo request failed before receiving a response"
            )

    @staticmethod
    def _require_mapping(name: str, value: dict[str, Any] | None) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
            raise InputValidationError(f"{name} must be an object with string keys")
        return value

    def _validate_invocation(
        self,
        operation: Operation,
        groups: dict[str, dict[str, Any]],
        file_params: dict[str, Any],
        body: Any,
    ) -> None:
        descriptors = {
            location: {
                str(parameter["name"]): parameter
                for parameter in operation.parameters
                if parameter["in"] == location
            }
            for location in ("path", "query", "header", "formData")
        }
        for location, values in groups.items():
            allowed = descriptors[location]
            invalid = sorted(set(values).difference(allowed))
            if invalid:
                label = "form" if location == "formData" else location
                raise InputValidationError(
                    f"{operation.operation_id} does not accept {label} parameters: {invalid}"
                )
            for name, value in values.items():
                descriptor = allowed[name]
                if location == "formData" and descriptor.get("type") == "file":
                    raise InputValidationError(f"File parameter {name!r} must be in file_params")
                self._validate_schema(value, dict(descriptor), f"{location}.{name}")

        declared_files = {
            name: descriptor
            for name, descriptor in descriptors["formData"].items()
            if descriptor.get("type") == "file"
        }
        invalid_files = sorted(set(file_params).difference(declared_files))
        if invalid_files:
            raise InputValidationError(
                f"{operation.operation_id} does not accept file parameters: {invalid_files}"
            )
        for name, descriptor in descriptors["formData"].items():
            supplied = name in (file_params if descriptor.get("type") == "file" else groups["formData"])
            if descriptor.get("required") and not supplied:
                raise InputValidationError(
                    f"{operation.operation_id} requires formData parameter: {name}"
                )
        for name, value in file_params.items():
            self._decode_file(value, f"file_params.{name}")

        for location in ("path", "query", "header"):
            missing = sorted(
                name
                for name, descriptor in descriptors[location].items()
                if descriptor.get("required") and name not in groups[location]
            )
            if missing:
                raise InputValidationError(
                    f"{operation.operation_id} requires {location} parameters: {missing}"
                )

        forbidden = sorted(name for name in groups["header"] if name.casefold() in FORBIDDEN_HEADERS)
        if forbidden:
            raise InputValidationError(f"Protected request headers cannot be overridden: {forbidden}")
        if operation.request_body_schema is None:
            if body is not None:
                raise InputValidationError(f"{operation.operation_id} does not accept a request body")
        elif body is None:
            if operation.request_body_required:
                raise InputValidationError(f"{operation.operation_id} requires a request body")
        else:
            self._validate_schema(body, dict(operation.request_body_schema), "body")
        if body is not None and (groups["formData"] or file_params):
            raise InputValidationError("body cannot be combined with form_params or file_params")

    def _validate_schema(self, value: Any, schema: dict[str, Any], location: str) -> None:
        schema_type = schema.get("type")
        if schema_type is None and ("properties" in schema or "additionalProperties" in schema):
            schema_type = "object"
        if schema_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                self._invalid(location, "must be an integer")
            self._validate_integer_format(value, schema.get("format"), location)
            self._validate_number_constraints(value, schema, location)
        elif schema_type == "number":
            if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
                self._invalid(location, "must be a finite number")
            self._validate_number_constraints(value, schema, location)
        elif schema_type == "boolean":
            if not isinstance(value, bool):
                self._invalid(location, "must be a boolean")
        elif schema_type == "string":
            if not isinstance(value, str):
                self._invalid(location, "must be a string")
            self._validate_string(value, schema, location)
        elif schema_type == "array":
            if not isinstance(value, list | tuple):
                self._invalid(location, "must be an array")
            self._validate_array(value, schema, location)
        elif schema_type == "object":
            if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
                self._invalid(location, "must be an object with string keys")
            self._validate_object(value, schema, location)
        elif schema_type == "file":
            self._decode_file(value, location)
        elif schema_type is not None:
            self._invalid(location, f"uses unsupported Swagger type {schema_type!r}")

        if "enum" in schema and value not in schema["enum"]:
            self._invalid(location, f"must be one of {schema['enum']!r}")

    def _validate_integer_format(self, value: int, value_format: Any, location: str) -> None:
        if value_format == "int32" and not -(2**31) <= value < 2**31:
            self._invalid(location, "must fit the int32 range")
        if value_format == "int64" and not -(2**63) <= value < 2**63:
            self._invalid(location, "must fit the int64 range")

    def _validate_number_constraints(
        self, value: float, schema: dict[str, Any], location: str
    ) -> None:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and (
            value <= minimum if schema.get("exclusiveMinimum") else value < minimum
        ):
            operator = "greater than" if schema.get("exclusiveMinimum") else "at least"
            self._invalid(location, f"must be {operator} {minimum}")
        if maximum is not None and (
            value >= maximum if schema.get("exclusiveMaximum") else value > maximum
        ):
            operator = "less than" if schema.get("exclusiveMaximum") else "at most"
            self._invalid(location, f"must be {operator} {maximum}")
        if "multipleOf" in schema:
            try:
                quotient = Decimal(str(value)) / Decimal(str(schema["multipleOf"]))
            except (InvalidOperation, ZeroDivisionError) as error:
                raise InputValidationError(f"Invalid multipleOf schema at {location}") from error
            if quotient != quotient.to_integral_value():
                self._invalid(location, f"must be a multiple of {schema['multipleOf']}")

    def _validate_string(self, value: str, schema: dict[str, Any], location: str) -> None:
        if "minLength" in schema and len(value) < schema["minLength"]:
            self._invalid(location, f"must contain at least {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            self._invalid(location, f"must contain at most {schema['maxLength']} characters")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            self._invalid(location, f"must match pattern {schema['pattern']!r}")
        value_format = schema.get("format")
        try:
            if value_format == "date":
                if FULL_DATE.fullmatch(value) is None:
                    raise ValueError
                date.fromisoformat(value)
            elif value_format == "date-time":
                if RFC3339_DATE_TIME.fullmatch(value) is None:
                    raise ValueError
                normalized = f"{value[:-1]}Z" if value.endswith("z") else value
                parsed = datetime.fromisoformat(normalized)
                if parsed.tzinfo is None:
                    raise ValueError
            elif value_format == "uuid":
                UUID(value)
            elif value_format == "email":
                if not self._is_valid_email(value):
                    raise ValueError
            elif value_format in {"uri", "url"}:
                if not urlsplit(value).scheme:
                    raise ValueError
            elif value_format == "byte":
                base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            self._invalid(location, f"must be a valid {value_format}")

    @staticmethod
    def _is_valid_email(value: str) -> bool:
        """Validate practical RFC 5321 mailbox syntax without accepting empty atoms."""

        if not value or len(value.encode("utf-8")) > 254 or value.count("@") != 1:
            return False
        if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
            return False
        local, domain = value.rsplit("@", 1)
        if not local or not domain or len(local.encode("utf-8")) > 64:
            return False

        if local.startswith('"') and local.endswith('"'):
            quoted = local[1:-1]
            if not quoted:
                return False
            escaped = False
            for character in quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    return False
            if escaped:
                return False
        elif (
            EMAIL_DOT_ATOM.fullmatch(local) is None
            or local.startswith(".")
            or local.endswith(".")
            or ".." in local
        ):
            return False

        if domain.startswith("[") and domain.endswith("]"):
            literal = domain[1:-1]
            if literal.casefold().startswith("ipv6:"):
                literal = literal[5:]
            try:
                ip_address(literal)
            except ValueError:
                return False
            return True

        try:
            ascii_domain = domain.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            return False
        if not ascii_domain or len(ascii_domain) > 253:
            return False
        return all(EMAIL_DOMAIN_LABEL.fullmatch(label) for label in ascii_domain.split("."))

    def _validate_array(self, value: list[Any] | tuple[Any, ...], schema: dict[str, Any], location: str) -> None:
        if "minItems" in schema and len(value) < schema["minItems"]:
            self._invalid(location, f"must contain at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            self._invalid(location, f"must contain at most {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            serialized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(serialized) != len(set(serialized)):
                self._invalid(location, "must contain unique items")
        item_schema = schema.get("items", {})
        for index, item in enumerate(value):
            self._validate_schema(item, item_schema, f"{location}[{index}]")

    def _validate_object(self, value: dict[str, Any], schema: dict[str, Any], location: str) -> None:
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = sorted(set(required).difference(value))
        if missing:
            self._invalid(location, f"requires properties {missing}")
        unknown = set(value).difference(properties)
        additional = schema.get("additionalProperties", True)
        if additional is False and unknown:
            self._invalid(location, f"does not allow properties {sorted(unknown)}")
        for name, item in value.items():
            if name in properties:
                self._validate_schema(item, properties[name], f"{location}.{name}")
            elif isinstance(additional, dict):
                self._validate_schema(item, additional, f"{location}.{name}")

    @staticmethod
    def _invalid(location: str, message: str) -> None:
        raise InputValidationError(f"Invalid {location}: {message}")

    @staticmethod
    def _serialize_scalar(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    def _serialize_array(self, value: Any, collection_format: str | None) -> list[str] | str:
        if not isinstance(value, list | tuple):
            return self._serialize_scalar(value)
        serialized = [self._serialize_scalar(item) for item in value]
        if collection_format == "multi":
            return serialized
        separator = {"ssv": " ", "tsv": "\t", "pipes": "|"}.get(collection_format, ",")
        return separator.join(serialized)

    def _serialize_path(self, operation: Operation, values: dict[str, Any]) -> str:
        path = operation.path
        descriptors = {
            parameter["name"]: parameter
            for parameter in operation.parameters
            if parameter["in"] == "path"
        }
        for name, value in values.items():
            serialized = self._serialize_array(value, descriptors[name].get("collectionFormat"))
            if isinstance(serialized, list):
                serialized = ",".join(serialized)
            path = path.replace(f"{{{name}}}", quote(serialized, safe=""))
        if "{" in path or "}" in path:
            raise InputValidationError(f"Unresolved path template for {operation.operation_id}")
        return path

    def _serialize_query(self, operation: Operation, values: dict[str, Any]) -> list[tuple[str, str]]:
        descriptors = {
            parameter["name"]: parameter
            for parameter in operation.parameters
            if parameter["in"] == "query"
        }
        query: list[tuple[str, str]] = []
        for name, value in values.items():
            serialized = self._serialize_array(value, descriptors[name].get("collectionFormat"))
            if isinstance(serialized, list):
                query.extend((name, item) for item in serialized)
            else:
                query.append((name, serialized))
        return query

    def _build_request_url(
        self, url_path: str, query: list[tuple[str, str]]
    ) -> httpx.URL:
        query_string = str(httpx.QueryParams(query))
        serialized_url = f"{self.base_url}{url_path}"
        if query_string:
            serialized_url = f"{serialized_url}?{query_string}"
        if len(serialized_url) > MAX_HTTPX_URL_LENGTH:
            raise InputValidationError(
                "Serialized request URL exceeds the "
                f"{MAX_HTTPX_URL_LENGTH}-character HTTPX limit"
            )
        try:
            return httpx.URL(serialized_url)
        except httpx.InvalidURL as error:
            raise InputValidationError("Serialized request URL is invalid") from error

    def _serialize_headers(self, operation: Operation, values: dict[str, Any]) -> dict[str, str]:
        descriptors = {
            parameter["name"]: parameter
            for parameter in operation.parameters
            if parameter["in"] == "header"
        }
        headers: dict[str, str] = {}
        for name, value in values.items():
            serialized = self._serialize_array(value, descriptors[name].get("collectionFormat"))
            headers[name] = ",".join(serialized) if isinstance(serialized, list) else serialized
        return headers

    def _serialize_multipart(
        self,
        operation: Operation,
        form_params: dict[str, Any],
        file_params: dict[str, Any],
    ) -> tuple[list[tuple[str, str]], list[tuple[str, tuple[str, bytes, str]]]]:
        if "multipart/form-data" not in operation.consumes:
            raise InputValidationError(
                f"{operation.operation_id} does not declare multipart/form-data"
            )
        descriptors = {
            parameter["name"]: parameter
            for parameter in operation.parameters
            if parameter["in"] == "formData"
        }
        data: list[tuple[str, str]] = []
        for name, value in form_params.items():
            serialized = self._serialize_array(value, descriptors[name].get("collectionFormat"))
            if isinstance(serialized, list):
                data.extend((name, item) for item in serialized)
            else:
                data.append((name, serialized))
        files = []
        for name, value in file_params.items():
            content, filename, content_type = self._decode_file(value, f"file_params.{name}")
            files.append((name, (filename, content, content_type)))
        return data, files

    def _validate_aggregate_parameter_sizes(
        self,
        operation: Operation,
        groups: dict[str, dict[str, Any]],
        file_params: dict[str, Any],
    ) -> None:
        descriptors = {
            location: {
                str(parameter["name"]): parameter
                for parameter in operation.parameters
                if parameter["in"] == location
            }
            for location in ("path", "query", "header", "formData")
        }
        parameter_bytes = 0
        for location, values in groups.items():
            for name, value in values.items():
                serialized = self._serialize_array(
                    value, descriptors[location][name].get("collectionFormat")
                )
                items = serialized if isinstance(serialized, list) else [serialized]
                name_repetitions = (
                    len(items) if location == "query" and isinstance(serialized, list) else 1
                )
                parameter_bytes += name_repetitions * len(name.encode("utf-8"))
                parameter_bytes += sum(len(item.encode("utf-8")) for item in items)
                if parameter_bytes > MAX_PARAMETER_INPUT_BYTES:
                    raise InputValidationError(
                        "Aggregate parameter input exceeds the "
                        f"{MAX_PARAMETER_INPUT_BYTES}-byte limit"
                    )

        total_file_bytes = 0
        for name, value in file_params.items():
            content, filename, content_type = self._decode_file(value, f"file_params.{name}")
            total_file_bytes += len(content)
            parameter_bytes += sum(
                len(item.encode("utf-8")) for item in (name, filename, content_type)
            )
            if parameter_bytes > MAX_PARAMETER_INPUT_BYTES:
                raise InputValidationError(
                    "Aggregate parameter input exceeds the "
                    f"{MAX_PARAMETER_INPUT_BYTES}-byte limit"
                )
            if total_file_bytes > MAX_TOTAL_FILE_UPLOAD_BYTES:
                raise InputValidationError(
                    "Aggregate file input exceeds the "
                    f"{MAX_TOTAL_FILE_UPLOAD_BYTES}-byte upload limit"
                )

    @staticmethod
    def _serialize_json_body(body: Any) -> bytes:
        try:
            content = json.dumps(
                body,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise InputValidationError("Request body must be JSON serializable") from error
        return ForgejoClient._bounded_request_body(content)

    @staticmethod
    def _bounded_request_body(content: bytes) -> bytes:
        if len(content) > MAX_REQUEST_BODY_BYTES:
            raise InputValidationError(
                f"Serialized request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit"
            )
        return content

    def _decode_file(self, value: Any, location: str) -> tuple[bytes, str, str]:
        if isinstance(value, bytes):
            content, filename, content_type = value, "upload.bin", "application/octet-stream"
        elif isinstance(value, dict):
            allowed = {"content_base64", "filename", "content_type"}
            unknown = sorted(set(value).difference(allowed))
            if unknown:
                self._invalid(location, f"contains unsupported fields {unknown}")
            encoded = value.get("content_base64")
            filename = value.get("filename", "upload.bin")
            content_type = value.get("content_type", "application/octet-stream")
            if not isinstance(encoded, str):
                self._invalid(location, "requires a base64 string in content_base64")
            if not isinstance(filename, str) or not filename:
                self._invalid(location, "filename must be a safe non-empty string")
            if self._contains_c0_or_del(filename):
                self._invalid(location, "filename cannot contain C0 or DEL control characters")
            if not isinstance(content_type, str) or not content_type:
                self._invalid(location, "content_type must be a safe non-empty string")
            if self._contains_c0_or_del(content_type):
                self._invalid(location, "content_type cannot contain C0 or DEL control characters")
            if STRICT_MEDIA_TYPE.fullmatch(content_type) is None:
                self._invalid(location, "content_type must be a valid media type")
            if len(encoded) > MAX_BASE64_FILE_UPLOAD_CHARS:
                self._invalid(location, f"exceeds the {MAX_FILE_UPLOAD_BYTES}-byte upload limit")
            try:
                content = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                self._invalid(location, "content_base64 must be valid base64")
        else:
            self._invalid(location, "must be bytes or a file descriptor object")
        if len(content) > MAX_FILE_UPLOAD_BYTES:
            self._invalid(location, f"exceeds the {MAX_FILE_UPLOAD_BYTES}-byte upload limit")
        return content, filename, content_type

    @staticmethod
    def _contains_c0_or_del(value: str) -> bool:
        return any(ord(character) < 32 or ord(character) == 127 for character in value)

    async def _format_response(
        self, operation: Operation, response: httpx.Response
    ) -> dict[str, Any]:
        if not response.is_success:
            return {
                "operation_id": operation.operation_id,
                "status_code": response.status_code,
                "ok": False,
                "error": {
                    "kind": "http",
                    "message": f"Forgejo returned HTTP {response.status_code}",
                },
            }

        raw_content_type = response.headers.get("content-type", "").split(";", 1)[0].casefold()
        if not raw_content_type and operation.response_content_types:
            raw_content_type = operation.response_content_types[0].casefold()
        is_json = raw_content_type == "application/json" or raw_content_type.endswith("+json")
        is_text = is_json or raw_content_type.startswith("text/")
        safe_content_type = self._redact_response_value(
            raw_content_type or "application/octet-stream"
        )
        limit = self.max_text_bytes if is_text else self.max_binary_bytes
        secrets = self._response_secret_variants()
        inspection_tail = max((len(secret) for secret in secrets), default=1) - 1
        content, truncated = await self._read_bounded(response, limit, inspection_tail)
        content = self._redact_response_bytes(content)[:limit]
        result: dict[str, Any] = {
            "operation_id": operation.operation_id,
            "status_code": response.status_code,
            "ok": True,
            "content_type": safe_content_type,
        }
        if is_text:
            if is_json and not truncated:
                try:
                    result["body"] = self._redact_response_value(json.loads(content))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    result["body"] = self._decode_text(
                        content, response.encoding, truncated
                    )
            else:
                result["body"] = self._decode_text(
                    content, response.encoding, truncated
                )
        else:
            result["body"] = {
                "data": base64.b64encode(content).decode("ascii"),
                "content_type": safe_content_type,
                "encoding": "base64",
                "bytes_included": len(content),
                "truncated": truncated,
            }
        if truncated:
            result["truncated"] = True
        return result

    def _response_secret_variants(self) -> tuple[bytes, ...]:
        if not self._token_bytes:
            return ()
        assert self._token is not None
        variants = (
            self._token_bytes,
            base64.b64encode(self._token_bytes),
            json.dumps(self._token, ensure_ascii=True)[1:-1].encode("ascii"),
            json.dumps(self._token, ensure_ascii=False)[1:-1].encode("utf-8"),
        )
        return tuple(dict.fromkeys(variant for variant in variants if variant))

    def _redact_response_bytes(self, content: bytes) -> bytes:
        """Remove an echoed access token without changing the response byte bound."""

        for secret in self._response_secret_variants():
            content = content.replace(secret, b"*" * len(secret))
        return content

    def _redact_response_value(self, value: Any) -> Any:
        """Recursively redact tokens from decoded JSON, including escaped strings and keys."""

        if not self._token:
            return value
        if isinstance(value, str):
            for secret in (
                self._token,
                base64.b64encode(self._token_bytes).decode("ascii"),
            ):
                value = value.replace(secret, "*" * len(secret))
            return value
        if isinstance(value, list):
            return [self._redact_response_value(item) for item in value]
        if isinstance(value, dict):
            return {
                self._redact_response_value(key): self._redact_response_value(item)
                for key, item in value.items()
            }
        return value

    @staticmethod
    async def _read_bounded(
        response: httpx.Response, limit: int, inspection_tail: int = 0
    ) -> tuple[bytes, bool]:
        read_limit = limit + inspection_tail
        content = bytearray()
        truncated = False
        async for chunk in response.aiter_bytes(chunk_size=65_536):
            remaining = read_limit - len(content)
            if len(chunk) > remaining:
                content.extend(chunk[:remaining])
                truncated = True
                break
            content.extend(chunk)
        if len(content) > limit:
            truncated = True
        content_length = response.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > limit:
            truncated = True
        return bytes(content), truncated

    @staticmethod
    def _decode_text(content: bytes, encoding: str | None, truncated: bool) -> str:
        marker = TRUNCATION_MARKER if truncated else ""
        if truncated:
            content = content[: max(0, len(content) - len(marker.encode("utf-8")))]
        return content.decode(encoding or "utf-8", "replace") + marker

    @staticmethod
    def _failure(operation_id: str, kind: str, message: str) -> dict[str, Any]:
        return {
            "operation_id": operation_id,
            "status_code": 0,
            "ok": False,
            "error": {"kind": kind, "message": message},
        }

    async def probe_auth(self) -> dict[str, Any]:
        """Probe the STARTUP-snapshotted credential with ``GET /api/v1/user`` and return a redacted status.

        The output exposes constant ``usesStartupSnapshot`` and ``restartRequiredAfterRotation``
        booleans plus a ``snapshotStatus`` reflecting only the current probe of the token captured
        once at server import. It deliberately never infers that a restart is unnecessary from a
        current HTTP 200. Classifies a 401 as ``credential_rejected``. Never returns the token,
        the ``Authorization`` header value, or the response body. The probe reuses this client's
        process snapshot; it never re-reads the environment or the platform credential store
        (Windows Credential Manager or Linux Secret Service).
        """

        if not self._token:
            return {
                "usesStartupSnapshot": True,
                "restartRequiredAfterRotation": True,
                "snapshotStatus": "unconfigured",
                "status_code": 0,
                "detail": "No FORGEJO_ACCESS_TOKEN was configured at process start; rotation always requires a restart.",
            }
        classification = await classify_token(
            self._token,
            base_url=self.base_url,
            transport=self._transport,
            timeout=self.timeout,
        )
        return {
            "usesStartupSnapshot": True,
            "restartRequiredAfterRotation": True,
            "snapshotStatus": classification.status,
            "status_code": classification.status_code,
            "detail": classification.detail,
        }
