#!/usr/bin/env python3
"""Local smoke test script for PRism MCP Server and Permission Firewall."""

import asyncio
import sys
from pathlib import Path

# Ensure project root is in sys.path when invoked directly as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prism.github.client import GitHubClientProtocol
from prism.github.models import ChangedFile, PRComment, PRMetadata, ReviewCommentResult
from prism.mcp_server.security import (
    InputValidationError,
    PermissionDeniedError,
    PermissionFirewall,
)
from prism.mcp_server.server import create_mcp_server


class FakeGitHubClient(GitHubClientProtocol):
    """Fake GitHub client for deterministic local smoke testing."""

    async def get_pr_metadata(self, owner: str, repo: str, pull_number: int) -> PRMetadata:
        return PRMetadata(
            number=pull_number,
            title="feat: add safe authentication middleware",
            body="Implements OAuth2 PKCE auth flow without secrets.",
            state="open",
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}",
            head_sha="a1b2c3d4e5f67890",
            head_branch="feat/auth",
            base_branch="main",
            author="octocat",
            draft=False,
            created_at="2026-10-08T10:00:00Z",
            updated_at="2026-10-08T10:30:00Z",
            additions=45,
            deletions=12,
            changed_files_count=2,
        )

    async def get_pr_diff(self, owner: str, repo: str, pull_number: int) -> str:
        return (
            "diff --git a/auth.py b/auth.py\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -10,3 +10,6 @@\n"
            "+def authenticate():\n"
            "+    return True\n"
        )

    async def get_changed_files(self, owner: str, repo: str, pull_number: int) -> list[ChangedFile]:
        return [
            ChangedFile(
                filename="auth.py",
                status="modified",
                additions=6,
                deletions=0,
                changes=6,
                patch="@@ -10,3 +10,6 @@ +def authenticate(): + return True",
            ),
            ChangedFile(
                filename="tests/test_auth.py",
                status="added",
                additions=25,
                deletions=0,
                changes=25,
                patch="@@ -0,0 +1,25 @@",
            ),
        ]

    async def get_pr_comments(self, owner: str, repo: str, pull_number: int) -> list[PRComment]:
        return [
            PRComment(
                id=101,
                user="reviewer-bot",
                body="Automated CI check passed.",
                created_at="2026-10-08T10:05:00Z",
                html_url="https://github.com/owner/repo/pull/1#issuecomment-101",
            )
        ]

    async def read_repo_file(
        self, owner: str, repo: str, path: str, ref: str | None = None
    ) -> str:
        return "# PRism sample config\nDEBUG = False\n"

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
        return ReviewCommentResult(
            id=999,
            body=body,
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}#discussion_r999",
            created_at="2026-10-08T10:45:00Z",
            path=path,
            line=line,
        )


async def run_smoke_test() -> None:
    print("=" * 70)
    print("PRism MCP Server Smoke Test & Permission Firewall Verification")
    print("=" * 70)

    fake_client = FakeGitHubClient()
    server = create_mcp_server(client=fake_client)

    # 1. Verify Exposed Tools
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    print(f"\n[+] Registered MCP Tools ({len(tools)} total):")
    for name in tool_names:
        print(f"    - {name}")

    expected_tools = {
        "get_pr",
        "get_pr_diff",
        "get_changed_files",
        "get_pr_comments",
        "get_repo_file",
        "post_review_comment",
    }
    assert set(tool_names) == expected_tools, f"Tool mismatch! Found: {tool_names}"
    print("    -> OK: All 6 safe tools verified.")

    # 2. Verify Execution of Safe Read Tools
    print("\n[+] Testing Safe Tool Invocations:")
    pr_result = await server.call_tool(
        "get_pr", {"owner": "test-org", "repo": "test-repo", "pull_number": 1}
    )
    assert not pr_result.is_error
    print("    - get_pr() -> SUCCESS")

    diff_result = await server.call_tool(
        "get_pr_diff", {"owner": "test-org", "repo": "test-repo", "pull_number": 1}
    )
    assert not diff_result.is_error
    print("    - get_pr_diff() -> SUCCESS")

    files_result = await server.call_tool(
        "get_changed_files", {"owner": "test-org", "repo": "test-repo", "pull_number": 1}
    )
    assert not files_result.is_error
    print("    - get_changed_files() -> SUCCESS")

    comments_result = await server.call_tool(
        "get_pr_comments", {"owner": "test-org", "repo": "test-repo", "pull_number": 1}
    )
    assert not comments_result.is_error
    print("    - get_pr_comments() -> SUCCESS")

    file_result = await server.call_tool(
        "get_repo_file", {"owner": "test-org", "repo": "test-repo", "path": "config.py"}
    )
    assert not file_result.is_error
    print("    - get_repo_file() -> SUCCESS")

    comment_result = await server.call_tool(
        "post_review_comment",
        {
            "owner": "test-org",
            "repo": "test-repo",
            "pull_number": 1,
            "body": "PRism review: Looks clean and meets safety criteria.",
        },
    )
    assert not comment_result.is_error
    print("    - post_review_comment() -> SUCCESS")

    # 3. Verify Dangerous Operations are Absent from MCP Server
    print("\n[+] Verifying Dangerous Operations are Absent from MCP Server:")
    prohibited_ops = ["merge", "push", "write_file", "delete_file", "create_branch", "admin"]
    for op in prohibited_ops:
        assert op not in tool_names, f"Security hole: {op} is exposed in MCP tools!"
        print(f"    - '{op}' NOT exposed in MCP tools -> OK")

    # 4. Verify Permission Firewall Enforcement in Code
    print("\n[+] Verifying Code-Level Permission Firewall Rejections:")
    blocked_count = 0
    for op in [
        "merge_pr",
        "merge",
        "push_code",
        "push",
        "write_file",
        "modify_file",
        "delete_file",
        "create_branch",
        "change_settings",
        "admin",
        "delete_repo",
        "execute_command",
        "run_bash",
    ]:
        try:
            PermissionFirewall.validate_operation(op)
            raise AssertionError(f"Expected operation '{op}' to be blocked, but it passed!")
        except PermissionDeniedError as err:
            blocked_count += 1
            print(f"    - Blocked '{op}': {err.capability}")

    print(f"    -> OK: All {blocked_count} dangerous operations successfully blocked by firewall.")

    # 5. Verify Path Traversal and Input Validation Guardrails
    print("\n[+] Verifying Input Guardrails:")
    try:
        PermissionFirewall.validate_file_path("../../../etc/passwd")
        raise AssertionError("Path traversal should have been rejected!")
    except InputValidationError:
        print("    - Path traversal ('../../../etc/passwd') -> REJECTED (OK)")

    try:
        PermissionFirewall.validate_repo_identifier("bad;rm -rf", "repo")
        raise AssertionError("Shell injection in repo owner should have been rejected!")
    except InputValidationError:
        print("    - Shell injection in repo name -> REJECTED (OK)")

    try:
        PermissionFirewall.validate_pull_number(-5)
        raise AssertionError("Negative PR number should have been rejected!")
    except InputValidationError:
        print("    - Negative PR number -> REJECTED (OK)")

    print("\n" + "=" * 70)
    print("ALL LOCAL SMOKE TESTS PASSED CLEANLY (Zero external dependencies)")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_smoke_test())
