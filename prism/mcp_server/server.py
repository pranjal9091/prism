"""PRism GitHub MCP Server initialization and runner."""

import argparse
import logging
import sys

from mcp.server.mcpserver import MCPServer

from prism.config import Settings, get_settings
from prism.github.client import GitHubClientProtocol
from prism.mcp_server.tools import register_github_tools

logger = logging.getLogger(__name__)


def create_mcp_server(
    client: GitHubClientProtocol | None = None,
    settings: Settings | None = None,
) -> MCPServer:
    """Factory creating and configuring the PRism GitHub MCP server.

    Attaches only whitelisted, least-privilege tools protected by
    the PermissionFirewall.
    """
    app_settings = settings or get_settings()
    server = MCPServer(
        name=app_settings.mcp_server_name,
        version=app_settings.mcp_server_version,
        instructions=(
            "PRism GitHub MCP Server. Provides read-only repository inspection "
            "and pull-request review commenting tools. Strictly enforces "
            "read/comment-only boundaries; code modification, branch creation, "
            "and merging are prohibited."
        ),
    )

    # Register whitelisted tools
    register_github_tools(server=server, client=client)

    return server


def main() -> None:
    """CLI entrypoint for running the PRism MCP server."""
    parser = argparse.ArgumentParser(description="Run the PRism GitHub MCP server.")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol to use (default: stdio)",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override logging level",
    )
    args = parser.parse_args()

    settings = get_settings()
    log_level = args.log_level or settings.mcp_log_level
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,  # Never pollute stdout in stdio mode
    )

    logger.info(
        "Starting %s v%s (transport=%s)",
        settings.mcp_server_name,
        settings.mcp_server_version,
        args.transport,
    )

    server = create_mcp_server(settings=settings)
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
