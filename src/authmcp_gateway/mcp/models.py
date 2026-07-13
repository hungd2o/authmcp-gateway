"""Pydantic models for MCP server management."""

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator


class McpServerBase(BaseModel):
    """Base MCP server model."""

    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    url: Optional[str] = Field(
        None, description="Backend MCP server URL (e.g., http://rag-mcp:8001/mcp)"
    )
    tool_prefix: Optional[str] = Field(
        None, description="Tool prefix for routing (e.g., 'rag_', 'ha_')"
    )
    transport_type: Literal["http", "stdio", "pipe"] = Field(
        "http", description="Backend transport type"
    )
    command: Optional[str] = Field(
        None, description="Command to execute for STDIO transport"
    )
    command_args: Optional[List[str]] = Field(
        default=None, description="Command arguments for STDIO transport"
    )
    pipe_path: Optional[str] = Field(None, description="Pipe/socket path for pipe transport")
    expose_port: Optional[int] = Field(
        None, ge=1, le=65535, description="Optional HTTP bridge port"
    )
    working_dir: Optional[str] = Field(None, description="Working directory for STDIO process")
    env_vars: Optional[Dict[str, str]] = Field(
        default=None, description="Environment variables for STDIO process"
    )

    # Status
    enabled: bool = Field(True, description="Whether this MCP server is active")

    # Auth to backend MCP
    auth_type: Literal["none", "bearer", "basic"] = Field(
        "none", description="Auth method for backend MCP"
    )
    auth_token: Optional[str] = Field(None, description="Token for backend MCP authentication")

    # Refresh token support (NEW)
    refresh_token: Optional[str] = Field(
        None, description="OAuth2 refresh token (will be hashed in storage)"
    )
    token_expires_at: Optional[datetime] = Field(None, description="Access token expiration time")
    refresh_endpoint: Optional[str] = Field(
        default="/oauth/token", description="OAuth2 token endpoint URL"
    )

    # Routing
    routing_strategy: Literal["prefix", "explicit", "auto"] = Field(
        "prefix", description="How to route tools to this server"
    )

    @model_validator(mode="after")
    def validate_transport_config(self):
        """Validate required fields per transport type."""
        if self.transport_type == "http" and not self.url:
            raise ValueError("url is required when transport_type is 'http'")
        if self.transport_type == "stdio" and not self.command:
            raise ValueError("command is required when transport_type is 'stdio'")
        if self.transport_type == "pipe" and not self.pipe_path:
            raise ValueError("pipe_path is required when transport_type is 'pipe'")
        return self


class McpServerCreate(McpServerBase):
    """Create MCP server request."""

    pass


class McpServerUpdate(BaseModel):
    """Update MCP server request (all fields optional)."""

    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    url: Optional[str] = None
    tool_prefix: Optional[str] = None
    enabled: Optional[bool] = None
    auth_type: Optional[Literal["none", "bearer", "basic"]] = None
    auth_token: Optional[str] = None
    # Refresh token support (NEW)
    refresh_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    refresh_endpoint: Optional[str] = None
    routing_strategy: Optional[Literal["prefix", "explicit", "auto"]] = None
    transport_type: Optional[Literal["http", "stdio", "pipe"]] = None
    command: Optional[str] = None
    command_args: Optional[List[str]] = None
    pipe_path: Optional[str] = None
    expose_port: Optional[int] = Field(default=None, ge=1, le=65535)
    working_dir: Optional[str] = None
    env_vars: Optional[Dict[str, str]] = None


class McpServerResponse(McpServerBase):
    """MCP server response."""

    id: int
    status: Literal["unknown", "online", "offline", "error"] = "unknown"
    last_health_check: Optional[datetime] = None
    last_error: Optional[str] = None
    tools_count: int = 0
    token_last_refreshed: Optional[datetime] = None  # NEW
    process_status: Literal["running", "stopped", "error", "n/a"] = "n/a"
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class McpServerHealth(BaseModel):
    """MCP server health check result."""

    server_id: int
    server_name: str
    status: Literal["online", "offline", "error"]
    response_time_ms: Optional[float] = None
    tools_count: Optional[int] = None
    error: Optional[str] = None
    checked_at: datetime


class ToolMapping(BaseModel):
    """Explicit tool to MCP server mapping."""

    tool_name: str
    mcp_server_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ToolMappingCreate(BaseModel):
    """Create tool mapping request."""

    tool_name: str = Field(..., min_length=1)
    mcp_server_id: int = Field(..., gt=0)


class UserMcpPermission(BaseModel):
    """User permission for MCP server."""

    id: int
    user_id: int
    mcp_server_id: int
    can_access: bool = True
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserMcpPermissionCreate(BaseModel):
    """Create user MCP permission."""

    user_id: int = Field(..., gt=0)
    mcp_server_id: int = Field(..., gt=0)
    can_access: bool = True


class UserMcpPermissionUpdate(BaseModel):
    """Update user MCP permission."""

    can_access: bool


# MCP Protocol models
class McpToolInfo(BaseModel):
    """MCP tool information from backend server."""

    name: str
    description: Optional[str] = None
    inputSchema: dict


class McpToolsListResponse(BaseModel):
    """Aggregated tools list from all backend servers."""

    tools: List[McpToolInfo]
    _meta: Optional[dict] = Field(default=None, description="Metadata about servers and routing")


class McpToolCallRequest(BaseModel):
    """Tool call request (MCP protocol)."""

    name: str
    arguments: Optional[dict] = None


class McpToolCallResponse(BaseModel):
    """Tool call response (MCP protocol)."""

    content: List[dict]
    isError: bool = False
    _meta: Optional[dict] = Field(
        default=None, description="Metadata about which server handled the request"
    )


# Token Management Models (NEW)
class McpServerTokenStatus(BaseModel):
    """Token status for backend MCP server (admin UI)."""

    server_id: int
    server_name: str
    auth_type: str
    has_refresh_token: bool
    token_expires_at: Optional[datetime] = None
    token_expired: bool = False
    time_until_expiry_seconds: Optional[int] = None
    last_refreshed: Optional[datetime] = None
    can_auto_refresh: bool = False  # True if has refresh_token and endpoint


class TokenAuditLog(BaseModel):
    """Token audit log entry."""

    id: int
    mcp_server_id: int
    server_name: Optional[str] = None  # Joined from mcp_servers
    event_type: str
    success: bool
    error_message: Optional[str] = None
    old_expires_at: Optional[datetime] = None
    new_expires_at: Optional[datetime] = None
    triggered_by: str
    timestamp: datetime

    class Config:
        from_attributes = True
