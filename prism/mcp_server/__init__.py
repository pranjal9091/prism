"""PRism Model Context Protocol (MCP) server package."""

from prism.mcp_server.security import (
    Capability,
    InputValidationError,
    PermissionDeniedError,
    PermissionFirewall,
)
from prism.mcp_server.server import create_mcp_server
from prism.mcp_server.tools import register_github_tools

__all__ = [
    "Capability",
    "InputValidationError",
    "PermissionDeniedError",
    "PermissionFirewall",
    "create_mcp_server",
    "register_github_tools",
]
