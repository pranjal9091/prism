"""Clean, least-privilege GitHub REST API client abstraction."""

import base64
import json
import logging
from typing import Protocol, runtime_checkable

import httpx

from prism.config import Settings, get_settings
from prism.github.exceptions import (
    GitHubAuthError,
    GitHubError,
    GitHubNotFoundError,
    GitHubRateLimitError,
    GitHubTimeoutError,
    GitHubValidationError,
)
from prism.github.models import ChangedFile, PRComment, PRMetadata, ReviewCommentResult

logger = logging.getLogger(__name__)


@runtime_checkable
class GitHubClientProtocol(Protocol):
    """Protocol defining strictly allowed GitHub operations for PRism."""

    async def get_pr_metadata(self, owner: str, repo: str, pull_number: int) -> PRMetadata: ...

    async def get_pr_diff(self, owner: str, repo: str, pull_number: int) -> str: ...

    async def get_changed_files(self, owner: str, repo: str, pull_number: int) -> list[ChangedFile]: ...

    async def get_pr_comments(self, owner: str, repo: str, pull_number: int) -> list[PRComment]: ...

    async def read_repo_file(
        self, owner: str, repo: str, path: str, ref: str | None = None
    ) -> str: ...

    async def post_review_comment(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        body: str,
        commit_id: str | None = None,
        path: str | None = None,
        line: int | None = None,
    ) -> ReviewCommentResult: ...


class GitHubClient:
    """Least-privilege GitHub REST client supporting read operations and comment-only posting.

    Strictly does NOT implement or expose any methods for:
    - merge
    - push
    - edit/delete files
    - branch management
    - repository admin/settings
    """

    def __init__(
        self,
        token: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        max_diff_chars: int | None = None,
        max_file_chars: int | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        settings: Settings = get_settings()
        self.token = token if token is not None else settings.github_token
        self.base_url = (base_url or settings.github_api_url).rstrip("/")
        self.timeout = timeout or settings.github_timeout_seconds
        self.max_diff_chars = max_diff_chars or settings.max_diff_characters
        self.max_file_chars = max_file_chars or settings.max_file_characters
        self._custom_http_client = http_client

    def _get_headers(self, custom_accept: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": custom_accept or "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PRism-Agentic-Reviewer/0.1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token.strip()}"
        return headers

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_data: dict | None = None,
        custom_accept: str | None = None,
    ) -> httpx.Response:
        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers(custom_accept)

        try:
            if self._custom_http_client:
                response = await self._custom_http_client.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    headers=headers,
                    timeout=self.timeout,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        json=json_data,
                        headers=headers,
                    )
        except httpx.TimeoutException as exc:
            raise GitHubTimeoutError(
                f"GitHub API request timed out after {self.timeout}s: {method} {endpoint}"
            ) from exc
        except httpx.RequestError as exc:
            raise GitHubError(f"Network error during GitHub API request: {exc}") from exc

        # Handle specific error status codes
        if response.is_error:
            self._handle_error_response(response, method, endpoint)

        return response

    def _handle_error_response(self, response: httpx.Response, method: str, endpoint: str) -> None:
        status = response.status_code
        try:
            payload = response.json()
            message = payload.get("message", response.text)
        except (ValueError, json.JSONDecodeError):
            payload = {}
            message = response.text or f"HTTP {status}"

        # 401 Unauthorized or 403 Bad Credentials
        if status == 401 or (status == 403 and "bad credentials" in message.lower()):
            raise GitHubAuthError(
                f"GitHub authentication failed ({status}): {message}. Please verify GITHUB_TOKEN.",
                status_code=status,
                details=payload,
            )

        # 403 Rate Limit or 429
        rate_limit_remaining = response.headers.get("x-ratelimit-remaining")
        if status == 429 or (
            status == 403
            and (
                "rate limit" in message.lower()
                or (rate_limit_remaining is not None and rate_limit_remaining == "0")
            )
        ):
            reset_time = response.headers.get("x-ratelimit-reset", "unknown")
            raise GitHubRateLimitError(
                f"GitHub API rate limit exceeded. Reset at {reset_time}.",
                status_code=status,
                details=payload,
            )

        # 404 Not Found
        if status == 404:
            raise GitHubNotFoundError(
                f"GitHub resource not found at {method} {endpoint}: {message}",
                status_code=status,
                details=payload,
            )

        # Generic error
        raise GitHubError(
            f"GitHub API error ({status}) at {method} {endpoint}: {message}",
            status_code=status,
            details=payload,
        )

    async def get_pr_metadata(self, owner: str, repo: str, pull_number: int) -> PRMetadata:
        """Fetch metadata for a pull request."""
        if pull_number <= 0:
            raise GitHubValidationError("pull_number must be a positive integer.")
        response = await self._request("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}")
        data = response.json()
        return PRMetadata(
            number=data["number"],
            title=data.get("title", ""),
            body=data.get("body") or "",
            state=data.get("state", "open"),
            html_url=data.get("html_url", ""),
            head_sha=data["head"]["sha"],
            head_branch=data["head"]["ref"],
            base_branch=data["base"]["ref"],
            author=data["user"]["login"] if data.get("user") else "unknown",
            draft=data.get("draft", False),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            additions=data.get("additions", 0),
            deletions=data.get("deletions", 0),
            changed_files_count=data.get("changed_files", 0),
        )

    async def get_pr_diff(self, owner: str, repo: str, pull_number: int) -> str:
        """Fetch unified git diff for a pull request with character-budget safety limits."""
        if pull_number <= 0:
            raise GitHubValidationError("pull_number must be a positive integer.")
        response = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pull_number}",
            custom_accept="application/vnd.github.v3.diff",
        )
        diff_text = response.text
        if len(diff_text) > self.max_diff_chars:
            logger.warning(
                "PR diff length %d exceeds safety limit %d; truncating.",
                len(diff_text),
                self.max_diff_chars,
            )
            truncated_diff = diff_text[: self.max_diff_chars]
            return (
                f"{truncated_diff}\n\n[TRUNCATED BY PRISM: Diff exceeded safety limit "
                f"of {self.max_diff_chars} characters]"
            )
        return diff_text

    async def get_changed_files(self, owner: str, repo: str, pull_number: int) -> list[ChangedFile]:
        """Fetch list of changed files with diff patches for a pull request."""
        if pull_number <= 0:
            raise GitHubValidationError("pull_number must be a positive integer.")
        response = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pull_number}/files",
            params={"per_page": 100},
        )
        data = response.json()
        files = []
        for item in data:
            files.append(
                ChangedFile(
                    filename=item["filename"],
                    status=item.get("status", "modified"),
                    additions=item.get("additions", 0),
                    deletions=item.get("deletions", 0),
                    changes=item.get("changes", 0),
                    patch=item.get("patch"),
                    previous_filename=item.get("previous_filename"),
                )
            )
        return files

    async def get_pr_comments(self, owner: str, repo: str, pull_number: int) -> list[PRComment]:
        """Fetch existing issue comments and review comments on a pull request."""
        if pull_number <= 0:
            raise GitHubValidationError("pull_number must be a positive integer.")
        comments: list[PRComment] = []

        # 1. PR review comments (inline comments on diff)
        review_resp = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pull_number}/comments",
            params={"per_page": 50},
        )
        for item in review_resp.json():
            comments.append(
                PRComment(
                    id=item["id"],
                    user=item["user"]["login"] if item.get("user") else "unknown",
                    body=item.get("body", ""),
                    created_at=item.get("created_at", ""),
                    html_url=item.get("html_url", ""),
                    path=item.get("path"),
                    line=item.get("line"),
                    commit_id=item.get("commit_id"),
                )
            )

        # 2. General issue comments on PR
        issue_resp = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/issues/{pull_number}/comments",
            params={"per_page": 50},
        )
        for item in issue_resp.json():
            comments.append(
                PRComment(
                    id=item["id"],
                    user=item["user"]["login"] if item.get("user") else "unknown",
                    body=item.get("body", ""),
                    created_at=item.get("created_at", ""),
                    html_url=item.get("html_url", ""),
                )
            )

        return comments

    async def read_repo_file(
        self, owner: str, repo: str, path: str, ref: str | None = None
    ) -> str:
        """Read content of a single repository file at a specified git ref."""
        clean_path = path.lstrip("/")
        if not clean_path:
            raise GitHubValidationError("File path cannot be empty.")

        params = {}
        if ref:
            params["ref"] = ref

        response = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/contents/{clean_path}",
            params=params,
        )
        data = response.json()

        if isinstance(data, list):
            raise GitHubValidationError(f"Path '{clean_path}' is a directory, not a file.")

        encoding = data.get("encoding")
        raw_content = data.get("content", "")

        if encoding == "base64" and raw_content:
            try:
                decoded_bytes = base64.b64decode(raw_content)
                text = decoded_bytes.decode("utf-8", errors="replace")
            except Exception as exc:
                raise GitHubError(f"Failed to decode base64 file content: {exc}") from exc
        else:
            text = raw_content

        if len(text) > self.max_file_chars:
            logger.warning(
                "File %s length %d exceeds safety limit %d; truncating.",
                clean_path,
                len(text),
                self.max_file_chars,
            )
            return (
                f"{text[:self.max_file_chars]}\n\n[TRUNCATED BY PRISM: File exceeded safety limit "
                f"of {self.max_file_chars} characters]"
            )

        return text

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
        """Post a review comment to GitHub.

        If path, line, and commit_id are provided, posts an inline review comment on the diff.
        Otherwise, posts a top-level review/issue comment on the pull request.
        """
        if pull_number <= 0:
            raise GitHubValidationError("pull_number must be a positive integer.")
        if not body or not body.strip():
            raise GitHubValidationError("Review comment body cannot be empty.")

        # Inline review comment
        if path and line is not None and commit_id:
            payload = {
                "body": body,
                "commit_id": commit_id,
                "path": path,
                "line": line,
            }
            response = await self._request(
                "POST",
                f"/repos/{owner}/{repo}/pulls/{pull_number}/comments",
                json_data=payload,
            )
        else:
            # Top-level comment on pull request
            payload = {"body": body}
            response = await self._request(
                "POST",
                f"/repos/{owner}/{repo}/issues/{pull_number}/comments",
                json_data=payload,
            )

        data = response.json()
        return ReviewCommentResult(
            id=data["id"],
            body=data["body"],
            html_url=data.get("html_url", ""),
            created_at=data.get("created_at", ""),
            path=data.get("path"),
            line=data.get("line"),
        )
