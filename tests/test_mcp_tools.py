"""Tests for PRism MCP Server tool registration, execution, and boundary enforcement."""

import json

import pytest
from mcp.server.mcpserver.exceptions import UnexpectedToolError

from prism.github.client import GitHubClientProtocol
from prism.github.exceptions import GitHubNotFoundError
from prism.github.models import ChangedFile, PRComment, PRMetadata, ReviewCommentResult
from prism.mcp_server.server import create_mcp_server


class MockGitHubClient(GitHubClientProtocol):
    """Mock client for verifying MCP tool handlers."""

    def __init__(self):
        self.posted_comments: list[dict] = []

    async def get_pr_metadata(self, owner: str, repo: str, pull_number: int) -> PRMetadata:
        if pull_number == 9999:
            raise GitHubNotFoundError(f"PR #{pull_number} not found.")
        return PRMetadata(
            number=pull_number,
            title="Refactor auth token parser",
            body="Safe refactor of token claims parsing.",
            state="open",
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}",
            head_sha="deadbeef12345678",
            head_branch="refactor/token",
            base_branch="main",
            author="bob",
            draft=False,
            created_at="2026-10-08T08:00:00Z",
            updated_at="2026-10-08T08:30:00Z",
            additions=15,
            deletions=4,
            changed_files_count=1,
        )

    async def get_pr_diff(self, owner: str, repo: str, pull_number: int) -> str:
        if pull_number == 9999:
            raise GitHubNotFoundError(f"PR #{pull_number} not found.")
        return "diff --git a/jwt.py b/jwt.py\n+claims = parse(token)"

    async def get_changed_files(self, owner: str, repo: str, pull_number: int) -> list[ChangedFile]:
        if pull_number == 9999:
            raise GitHubNotFoundError(f"PR #{pull_number} not found.")
        return [
            ChangedFile(
                filename="jwt.py",
                status="modified",
                additions=15,
                deletions=4,
                changes=19,
                patch="@@ -1,4 +1,15 @@",
            )
        ]

    async def get_pr_comments(self, owner: str, repo: str, pull_number: int) -> list[PRComment]:
        if pull_number == 9999:
            raise GitHubNotFoundError(f"PR #{pull_number} not found.")
        return [
            PRComment(
                id=505,
                user="alice",
                body="Please check algorithm whitelist.",
                created_at="2026-10-08T08:15:00Z",
                html_url="https://github.com/owner/repo/pull/1#issuecomment-505",
            )
        ]

    async def read_repo_file(
        self, owner: str, repo: str, path: str, ref: str | None = None
    ) -> str:
        if path == "nonexistent.py":
            raise GitHubNotFoundError(f"File {path} not found.")
        return "ALLOWED_ALGORITHMS = ['RS256', 'ES256']"

    async def post_review_comment(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        body: str,
        commit_id: str | None = None,
        path: str | None = None,
        line: int | None = None,
    ) -> ReviewCommentResult:
        comment_record = {
            "owner": owner,
            "repo": repo,
            "pull_number": pull_number,
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
        }
        self.posted_comments.append(comment_record)
        return ReviewCommentResult(
            id=777,
            body=body,
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}#comment-777",
            created_at="2026-10-08T08:45:00Z",
            path=path,
            line=line,
        )


@pytest.fixture
def mock_client():
    return MockGitHubClient()


@pytest.fixture
def server(mock_client):
    return create_mcp_server(client=mock_client)


@pytest.mark.asyncio
async def test_mcp_tools_registration(server):
    tools = await server.list_tools()
    tool_names = {t.name for t in tools}

    expected_tools = {
        "get_pr",
        "get_pr_diff",
        "get_changed_files",
        "get_pr_comments",
        "get_repo_file",
        "post_review_comment",
    }
    assert tool_names == expected_tools

    # Explicitly ensure dangerous operations are not registered
    for dangerous in ["merge", "push", "write_file", "delete_file", "create_branch", "admin"]:
        assert dangerous not in tool_names


def extract_tool_result(result):
    """Helper to parse TextContent outputs from MCPServer."""
    assert not result.is_error
    if not result.content:
        return []
    items = []
    for c in result.content:
        try:
            items.append(json.loads(c.text))
        except (ValueError, json.JSONDecodeError):
            items.append(c.text)
    return items


@pytest.mark.asyncio
async def test_mcp_tool_get_pr(server):
    result = await server.call_tool(
        "get_pr",
        {"owner": "my-org", "repo": "my-repo", "pull_number": 12},
    )
    items = extract_tool_result(result)
    assert len(items) == 1
    data = items[0]
    assert data["number"] == 12
    assert data["author"] == "bob"
    assert data["title"] == "Refactor auth token parser"


@pytest.mark.asyncio
async def test_mcp_tool_get_pr_diff(server):
    result = await server.call_tool(
        "get_pr_diff",
        {"owner": "my-org", "repo": "my-repo", "pull_number": 12},
    )
    items = extract_tool_result(result)
    assert len(items) == 1
    diff = items[0]
    assert "diff --git a/jwt.py b/jwt.py" in diff


@pytest.mark.asyncio
async def test_mcp_tool_get_changed_files(server):
    result = await server.call_tool(
        "get_changed_files",
        {"owner": "my-org", "repo": "my-repo", "pull_number": 12},
    )
    files = extract_tool_result(result)
    assert len(files) == 1
    assert files[0]["filename"] == "jwt.py"


@pytest.mark.asyncio
async def test_mcp_tool_get_pr_comments(server):
    result = await server.call_tool(
        "get_pr_comments",
        {"owner": "my-org", "repo": "my-repo", "pull_number": 12},
    )
    comments = extract_tool_result(result)
    assert len(comments) == 1
    assert comments[0]["user"] == "alice"


@pytest.mark.asyncio
async def test_mcp_tool_get_repo_file(server):
    result = await server.call_tool(
        "get_repo_file",
        {"owner": "my-org", "repo": "my-repo", "path": "auth/config.py"},
    )
    items = extract_tool_result(result)
    assert len(items) == 1
    content = items[0]
    assert "ALLOWED_ALGORITHMS" in content


@pytest.mark.asyncio
async def test_mcp_tool_post_review_comment(server, mock_client):
    result = await server.call_tool(
        "post_review_comment",
        {
            "owner": "my-org",
            "repo": "my-repo",
            "pull_number": 12,
            "body": "PRism review: Ensure HS256 is explicitly forbidden.",
            "path": "jwt.py",
            "line": 10,
            "commit_id": "deadbeef12345678",
        },
    )
    items = extract_tool_result(result)
    assert len(items) == 1
    res_data = items[0]
    assert res_data["id"] == 777
    assert len(mock_client.posted_comments) == 1
    assert mock_client.posted_comments[0]["path"] == "jwt.py"


@pytest.mark.asyncio
async def test_mcp_nonexistent_pr_handling(server):
    with pytest.raises(UnexpectedToolError) as exc_info:
        await server.call_tool(
            "get_pr",
            {"owner": "my-org", "repo": "my-repo", "pull_number": 9999},
        )
    assert "Error executing tool get_pr" in str(exc_info.value)


@pytest.mark.asyncio
async def test_mcp_input_rejections(server):
    # Invalid pull number
    with pytest.raises(UnexpectedToolError):
        await server.call_tool(
            "get_pr",
            {"owner": "my-org", "repo": "my-repo", "pull_number": -5},
        )

    # Path traversal
    with pytest.raises(UnexpectedToolError):
        await server.call_tool(
            "get_repo_file",
            {"owner": "my-org", "repo": "my-repo", "path": "../../../etc/passwd"},
        )
