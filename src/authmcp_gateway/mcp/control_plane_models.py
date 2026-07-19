"""Typed descriptor and envelope models for the admin-only control plane."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from .control_plane_contract import (
    CONTROL_PLANE_ENTITY_OPS,
    CONTROL_PLANE_EXTENSION,
    CONTROL_PLANE_ACTION_ICONS,
    CONTROL_PLANE_COLUMN_KINDS,
    CONTROL_PLANE_MAX_ACTIONS,
    CONTROL_PLANE_MAX_COLUMNS_PER_ENTITY,
    CONTROL_PLANE_MAX_ENTITY_TYPES,
    CONTROL_PLANE_MAX_ERROR_TEXT_CHARS,
    CONTROL_PLANE_MAX_LABEL_CHARS,
    CONTROL_PLANE_MAX_SCHEMA_PROPERTIES,
    CONTROL_PLANE_MAX_STATUS_FIELDS,
    CONTROL_PLANE_MAX_VALUE_CHARS,
    normalize_page_size,
    validate_idempotency_key,
)


class ControlPlaneFieldError(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(..., min_length=1, max_length=64)
    message: str = Field(..., min_length=1, max_length=CONTROL_PLANE_MAX_LABEL_CHARS)


class ControlPlaneError(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Literal["CONFLICT", "VALIDATION_FAILED", "UNSUPPORTED", "UNAVAILABLE", "INTERNAL"]
    message: str = Field(..., min_length=1, max_length=CONTROL_PLANE_MAX_ERROR_TEXT_CHARS)
    field_errors: list[ControlPlaneFieldError] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def validate_field_errors(self) -> "ControlPlaneError":
        if self.code == "VALIDATION_FAILED" and not self.field_errors:
            raise ValueError("VALIDATION_FAILED errors must include field_errors")
        if self.code != "VALIDATION_FAILED" and self.field_errors:
            raise ValueError("field_errors are only allowed for VALIDATION_FAILED")
        return self


class ControlPlaneListRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cursor: str | None = Field(default=None, max_length=512)
    page_size: int = Field(default=50)

    @field_validator("page_size")
    @classmethod
    def validate_page_size(cls, value: int) -> int:
        return normalize_page_size(value)


class ControlPlaneMutationContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(..., min_length=1, max_length=120)
    idempotency_key: str
    revision: str | None = Field(default=None, max_length=512)

    @field_validator("idempotency_key")
    @classmethod
    def validate_uuid_key(cls, value: str) -> str:
        return validate_idempotency_key(value)


class ControlPlaneSchemaProperty(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    type: Literal["string", "number", "integer", "boolean"]
    max_length: int | None = Field(default=None, alias="maxLength", ge=1, le=8192)
    pattern: str | None = Field(default=None, max_length=256)
    enum: list[str] | None = Field(default=None, max_length=64)
    minimum: float | int | None = Field(default=None, validation_alias=AliasChoices("min", "minimum"))
    maximum: float | int | None = Field(default=None, validation_alias=AliasChoices("max", "maximum"))
    default: bool | None = None

    @model_validator(mode="after")
    def validate_subset(self) -> "ControlPlaneSchemaProperty":
        if self.type == "string":
            if self.minimum is not None or self.maximum is not None or self.default is not None:
                raise ValueError("string properties only allow maxLength, pattern, and enum")
        elif self.type in {"number", "integer"}:
            if self.max_length is not None or self.pattern or self.enum or self.default is not None:
                raise ValueError("numeric properties only allow min/max")
            if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
                raise ValueError("min cannot be greater than max")
        elif self.max_length is not None or self.pattern or self.enum or self.minimum is not None or self.maximum is not None:
            raise ValueError("boolean properties only allow default")
        return self

    @field_validator("enum")
    @classmethod
    def validate_enum_values(cls, value: list[str] | None) -> list[str] | None:
        if value and any(len(item) > CONTROL_PLANE_MAX_VALUE_CHARS for item in value):
            raise ValueError("enum values must be bounded")
        return value


class ControlPlaneObjectSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["object"]
    properties: dict[str, ControlPlaneSchemaProperty] = Field(default_factory=dict, max_length=64)
    required: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def validate_schema(self) -> "ControlPlaneObjectSchema":
        if len(self.properties) > CONTROL_PLANE_MAX_SCHEMA_PROPERTIES:
            raise ValueError("schema property limit exceeded")
        missing = set(self.required) - set(self.properties)
        if missing:
            raise ValueError(f"required properties missing from schema: {sorted(missing)}")
        return self

    @field_validator("properties")
    @classmethod
    def validate_property_names(
        cls, value: dict[str, ControlPlaneSchemaProperty]
    ) -> dict[str, ControlPlaneSchemaProperty]:
        if any(len(name) > CONTROL_PLANE_MAX_VALUE_CHARS for name in value):
            raise ValueError("schema property names must be bounded")
        return value

    @field_validator("required")
    @classmethod
    def validate_required_names(cls, value: list[str]) -> list[str]:
        if any(len(name) > CONTROL_PLANE_MAX_VALUE_CHARS for name in value):
            raise ValueError("required property names must be bounded")
        return value


class ControlPlaneColumnDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(..., min_length=1, max_length=64)
    kind: Literal["text", "code", "path", "badge", "number", "datetime", "bool"]
    map: dict[str, str] | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def validate_kind(self) -> "ControlPlaneColumnDescriptor":
        if self.kind not in CONTROL_PLANE_COLUMN_KINDS:
            raise ValueError("unsupported column kind")
        return self

    @field_validator("map")
    @classmethod
    def validate_badge_map(
        cls, value: dict[str, str] | None
    ) -> dict[str, str] | None:
        if value and any(
            len(key) > CONTROL_PLANE_MAX_VALUE_CHARS
            or len(label) > CONTROL_PLANE_MAX_VALUE_CHARS
            for key, label in value.items()
        ):
            raise ValueError("badge map entries must be bounded")
        return value


class ControlPlaneEntityDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(..., min_length=1, max_length=64)
    label: str = Field(..., min_length=1, max_length=CONTROL_PLANE_MAX_LABEL_CHARS)
    id_field: str = Field(..., min_length=1, max_length=64)
    columns: list[ControlPlaneColumnDescriptor] = Field(..., min_length=1, max_length=24)
    schema_definition: ControlPlaneObjectSchema = Field(alias="schema", serialization_alias="schema")
    ops: list[Literal["list", "create", "update", "delete"]] = Field(
        ..., min_length=1, max_length=4
    )

    @model_validator(mode="after")
    def validate_entity(self) -> "ControlPlaneEntityDescriptor":
        if len(self.columns) > CONTROL_PLANE_MAX_COLUMNS_PER_ENTITY:
            raise ValueError("column limit exceeded")
        if self.id_field not in self.schema_definition.properties:
            raise ValueError("id_field must be declared in schema.properties")
        if len(set(self.ops)) != len(self.ops) or not set(self.ops).issubset(CONTROL_PLANE_ENTITY_OPS):
            raise ValueError("ops must be unique and use the fixed CRUD subset")
        return self


class ControlPlaneActionDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    id: str = Field(..., min_length=1, max_length=64)
    label: str = Field(..., min_length=1, max_length=CONTROL_PLANE_MAX_LABEL_CHARS)
    icon: str | None = Field(default=None, max_length=32)
    target: str = Field(..., min_length=1, max_length=64)
    risk: Literal["safe", "mutating", "destructive"]
    async_operation: bool = Field(..., alias="async")
    params_schema: ControlPlaneObjectSchema | None = None

    @field_validator("icon")
    @classmethod
    def validate_icon(cls, value: str | None) -> str | None:
        if value is not None and value not in CONTROL_PLANE_ACTION_ICONS:
            raise ValueError("action icon is not supported")
        return value


class ControlPlaneStatusFieldDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(..., min_length=1, max_length=64)
    kind: Literal["text", "code", "path", "badge", "number", "datetime", "bool"]


class ControlPlaneDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    extension: Literal["com.authmcp/control-plane-v1"]
    revision: str = Field(..., min_length=1, max_length=512)
    entities: list[ControlPlaneEntityDescriptor] = Field(default_factory=list, max_length=32)
    actions: list[ControlPlaneActionDescriptor] = Field(default_factory=list, max_length=32)
    status_fields: list[ControlPlaneStatusFieldDescriptor] = Field(
        default_factory=list, max_length=64
    )

    @model_validator(mode="after")
    def validate_descriptor(self) -> "ControlPlaneDescriptor":
        if self.extension not in {CONTROL_PLANE_EXTENSION}:
            raise ValueError("unsupported control-plane extension identifier")
        if len(self.entities) > CONTROL_PLANE_MAX_ENTITY_TYPES:
            raise ValueError("entity type limit exceeded")
        if len(self.actions) > CONTROL_PLANE_MAX_ACTIONS:
            raise ValueError("action limit exceeded")
        if len(self.status_fields) > CONTROL_PLANE_MAX_STATUS_FIELDS:
            raise ValueError("status field limit exceeded")
        if len({item.type for item in self.entities}) != len(self.entities):
            raise ValueError("entity types must be unique")
        if len({item.id for item in self.actions}) != len(self.actions):
            raise ValueError("action ids must be unique")
        return self
