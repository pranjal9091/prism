"""Safe GitHub MCP tool definitions enforcing least-privilege security boundaries."""

from typing import Any

from mcp.server.mcpserver import MCPServer

from prism.github.client import GitHubClient, GitHubClientProtocol
from prism.mcp_server.security import PermissionFirewall


def register_github_tools(
    server: MCPServer,
    client: GitHubClientProtocol | None = None,
) -> None:
    """Register safe GitHub tools to an MCPServer instance.

    Every tool strictly executes under the PermissionFirewall and rejects any
    action exceeding READ or COMMENT capabilities.
    """
    github_client: GitHubClientProtocol = client or GitHubClient()

    @server.tool(
        name="get_pr",
        description="Retrieve pull request metadata including title, description, state, author, branch, and change counts.",
    )
    async def get_pr(owner: str, repo: str, pull_number: int) -> dict[str, Any]:
        PermissionFirewall.validate_operation("get_pr")
        PermissionFirewall.validate_repo_identifier(owner, repo)
        PermissionFirewall.validate_pull_number(pull_number)

        metadata = await github_client.get_pr_metadata(owner, repo, pull_number)
        return metadata.model_dump()

    @server.tool(
        name="get_pr_diff",
        description="Retrieve the unified git diff for a pull request, bounded by safety limits to prevent memory exhaustion.",
    )
    async def get_pr_diff(owner: str, repo: str, pull_number: int) -> str:
        PermissionFirewall.validate_operation("get_pr_diff")
        PermissionFirewall.validate_repo_identifier(owner, repo)
        PermissionFirewall.validate_pull_number(pull_number)

        diff = await github_client.get_pr_diff(owner, repo, pull_number)
        return diff

    @server.tool(
        name="get_changed_files",
        description="List all files modified in the pull request with line additions, deletions, change status, and patches.",
    )
    async def get_changed_files(owner: str, repo: str, pull_number: int) -> list[dict[str, Any]]:
        PermissionFirewall.validate_operation("get_changed_files")
        PermissionFirewall.validate_repo_identifier(owner, repo)
        PermissionFirewall.validate_pull_number(pull_number)

        files = await github_client.get_changed_files(owner, repo, pull_number)
        return [f.model_dump() for f in files]

    @server.tool(
        name="get_pr_comments",
        description="Retrieve existing discussion and inline review comments for the specified pull request.",
    )
    async def get_pr_comments(owner: str, repo: str, pull_number: int) -> list[dict[str, Any]]:
        PermissionFirewall.validate_operation("get_pr_comments")
        PermissionFirewall.validate_repo_identifier(owner, repo)
        PermissionFirewall.validate_pull_number(pull_number)

        comments = await github_client.get_pr_comments(owner, repo, pull_number)
        return [c.model_dump() for c in comments]

    @server.tool(
        name="get_repo_file",
        description="Read the UTF-8 text content of a repository file at a given commit SHA or branch ref.",
    )
    async def get_repo_file(
        owner: str,
        repo: str,
        path: str,
        ref: str | None = None,
    ) -> str:
        PermissionFirewall.validate_operation("get_repo_file")
        PermissionFirewall.validate_repo_identifier(owner, repo)
        PermissionFirewall.validate_file_path(path)

        content = await github_client.read_repo_file(owner, repo, path, ref=ref)
        return content

    @server.tool(
        name="post_review_comment",
        description="Post a review comment to GitHub. If path, line, and commit_id are provided, posts an inline diff comment. Otherwise posts a summary comment.",
    )
    async def post_review_comment(
        owner: str,
        repo: str,
        pull_number: int,
        body: str,
        commit_id: str | None = None,
        path: str | None = None,
        line: int | None = None,
    ) -> dict[str, Any]:
        PermissionFirewall.validate_operation("post_review_comment")
        PermissionFirewall.validate_repo_identifier(owner, repo)
        PermissionFirewall.validate_pull_number(pull_number)
        PermissionFirewall.validate_comment_body(body)

        if path:
            PermissionFirewall.validate_file_path(path)

        result = await github_client.post_review_comment(
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            body=body,
            commit_id=commit_id,
            path=path,
            line=line,
        )
        return result.model_dump()
