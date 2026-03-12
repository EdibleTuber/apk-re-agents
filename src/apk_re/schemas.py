from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


# --- Job lifecycle ---

class JobRequest(BaseModel):
    apk_path: str
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class JobStatus(BaseModel):
    job_id: str
    state: str  # "pending", "running", "completed", "failed"
    current_stage: str | None = None
    results: dict[str, str] | None = None  # agent_name -> findings file path


# --- Manifest ---

class Permission(BaseModel):
    name: str
    dangerous: bool = False


class Component(BaseModel):
    name: str
    exported: bool = False
    intent_filters: list[str] = Field(default_factory=list)


class ManifestFindings(BaseModel):
    permissions: list[Permission] = Field(default_factory=list)
    activities: list[Component] = Field(default_factory=list)
    services: list[Component] = Field(default_factory=list)
    receivers: list[Component] = Field(default_factory=list)


# --- Strings & Secrets ---

class StringFinding(BaseModel):
    value: str
    category: str  # "api_key", "url", "token", "encoded_blob", "other"
    source_file: str
    line_number: int | None = None
    entropy: float | None = None


# --- API Endpoints ---

class EndpointFinding(BaseModel):
    url: str
    http_method: str | None = None
    source_class: str
    base_url: str | None = None          # resolved base URL if known
    headers: dict[str, str] = Field(default_factory=dict)   # @Header annotations
    path_params: list[str] = Field(default_factory=list)    # @Path parameter names
    query_params: list[str] = Field(default_factory=list)   # @Query parameter names
    request_fields: dict[str, str] = Field(default_factory=dict)
    response_fields: dict[str, str] = Field(default_factory=dict)


# --- Code Analysis ---

class CodeAnalysisSummary(BaseModel):
    class_name: str
    relevance_score: float  # 0.0 to 1.0
    summary: str
    flags: list[str] = Field(default_factory=list)  # "network", "crypto", "storage", etc.


# --- Network ---

class NetworkFinding(BaseModel):
    endpoint: str
    protocol: str  # "https", "http", "wss", etc.
    source_class: str
    cert_pinning: bool = False
    notes: str | None = None


# --- Generic agent result wrapper ---

class AgentResult(BaseModel):
    agent_name: str
    job_id: str
    status: str  # "success", "error"
    error: str | None = None
    findings: dict[str, Any] = Field(default_factory=dict)
