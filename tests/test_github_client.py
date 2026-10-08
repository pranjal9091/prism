"""Comprehensive tests for GitHubClient using httpx mock transports."""

import base64

import httpx
import pytest

from prism.github.client import GitHubClient
from prism.github.exceptions import (
    GitHubAuthError,
    GitHubNotFoundError,
    GitHubRateLimitError,
    GitHubTimeoutError,
    GitHubValidationError,
)


@pytest.mark.asyncio
async def test_get_pr_metadata_success():
    payload = {
        "number": 42,
        "title": "Add secure password hashing",
        "body": "Uses bcrypt instead of sha1.",
        "state": "open",
        "html_url": "https://github.com/org/repo/pull/42",
        "head": {"sha": "abc1234567890", "ref": "feat/bcrypt"},
        "base": {"ref": "main"},
        "user": {"login": "alice"},
        "draft": False,
        "created_at": "2026-10-08T09:00:00Z",
        "updated_at": "2026-10-08T09:30:00Z",
        "additions": 30,
        "deletions": 5,
        "changed_files": 2,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/org/repo/pulls/42"
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="ghp_test_token", http_client=client)

    pr = await gh.get_pr_metadata("org", "repo", 42)
    assert pr.number == 42
    assert pr.title == "Add secure password hashing"
    assert pr.head_sha == "abc1234567890"
    assert pr.author == "alice"
    assert pr.additions == 30


@pytest.mark.asyncio
async def test_get_pr_diff_success_and_safety_truncation():
    sample_diff = "diff --git a/file.py b/file.py\n+print('hello')"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=sample_diff)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="ghp_test_token", http_client=client)

    diff = await gh.get_pr_diff("org", "repo", 42)
    assert diff == sample_diff

    # Test diff size boundary truncation
    huge_diff = "A" * 1500
    gh_limited = GitHubClient(token="ghp_test_token", max_diff_chars=500, http_client=client)

    def huge_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=huge_diff)

    limited_client = httpx.AsyncClient(transport=httpx.MockTransport(huge_handler))
    gh_limited._custom_http_client = limited_client

    result = await gh_limited.get_pr_diff("org", "repo", 42)
    assert len(result) < 1000
    assert "TRUNCATED BY PRISM: Diff exceeded safety limit" in result


@pytest.mark.asyncio
async def test_get_changed_files():
    payload = [
        {
            "filename": "src/security.py",
            "status": "modified",
            "additions": 10,
            "deletions": 2,
            "changes": 12,
            "patch": "@@ -1,2 +1,10 @@",
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/org/repo/pulls/42/files"
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="ghp_test_token", http_client=client)

    files = await gh.get_changed_files("org", "repo", 42)
    assert len(files) == 1
    assert files[0].filename == "src/security.py"
    assert files[0].status == "modified"


@pytest.mark.asyncio
async def test_read_repo_file_base64_and_truncation():
    content_raw = "SECRET_CONFIG = False\nALLOW_OVERRIDE = False\n"
    encoded = base64.b64encode(content_raw.encode("utf-8")).decode("utf-8")
    payload = {
        "type": "file",
        "encoding": "base64",
        "size": len(content_raw),
        "content": encoded,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/org/repo/contents/settings.py"
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="ghp_test_token", http_client=client)

    text = await gh.read_repo_file("org", "repo", "settings.py")
    assert text == content_raw


@pytest.mark.asyncio
async def test_post_review_comment_top_level_and_inline():
    top_comment_payload = {
        "id": 1001,
        "body": "PRism review summary: Approved.",
        "html_url": "https://github.com/org/repo/issues/42#issuecomment-1001",
        "created_at": "2026-10-08T10:00:00Z",
    }
    inline_comment_payload = {
        "id": 2002,
        "body": "Inline note: Possible integer overflow on line 15.",
        "html_url": "https://github.com/org/repo/pull/42#discussion_r2002",
        "created_at": "2026-10-08T10:05:00Z",
        "path": "math.py",
        "line": 15,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/issues/42/comments"):
            return httpx.Response(201, json=top_comment_payload)
        elif request.url.path.endswith("/pulls/42/comments"):
            return httpx.Response(201, json=inline_comment_payload)
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="ghp_test_token", http_client=client)

    # 1. Post top-level comment
    top_res = await gh.post_review_comment("org", "repo", 42, "PRism review summary: Approved.")
    assert top_res.id == 1001
    assert top_res.body == "PRism review summary: Approved."

    # 2. Post inline review comment
    inline_res = await gh.post_review_comment(
        "org",
        "repo",
        42,
        "Inline note: Possible integer overflow on line 15.",
        commit_id="abc12345",
        path="math.py",
        line=15,
    )
    assert inline_res.id == 2002
    assert inline_res.path == "math.py"
    assert inline_res.line == 15


@pytest.mark.asyncio
async def test_error_handling_auth_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="invalid_token", http_client=client)

    with pytest.raises(GitHubAuthError, match="GitHub authentication failed"):
        await gh.get_pr_metadata("org", "repo", 42)


@pytest.mark.asyncio
async def test_error_handling_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="token", http_client=client)

    with pytest.raises(GitHubNotFoundError, match="GitHub resource not found"):
        await gh.get_pr_metadata("org", "repo", 9999)


@pytest.mark.asyncio
async def test_error_handling_rate_limit():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1760000000"},
            json={"message": "API rate limit exceeded for user."},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="token", http_client=client)

    with pytest.raises(GitHubRateLimitError, match="GitHub API rate limit exceeded"):
        await gh.get_pr_metadata("org", "repo", 42)


@pytest.mark.asyncio
async def test_error_handling_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Read timed out")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = GitHubClient(token="token", http_client=client)

    with pytest.raises(GitHubTimeoutError, match="timed out"):
        await gh.get_pr_metadata("org", "repo", 42)


@pytest.mark.asyncio
async def test_client_validation_rejections():
    gh = GitHubClient()
    with pytest.raises(GitHubValidationError, match="positive integer"):
        await gh.get_pr_metadata("org", "repo", -1)

    with pytest.raises(GitHubValidationError, match="File path cannot be empty"):
        await gh.read_repo_file("org", "repo", "")

    with pytest.raises(GitHubValidationError, match="Review comment body cannot be empty"):
        await gh.post_review_comment("org", "repo", 42, "   ")
