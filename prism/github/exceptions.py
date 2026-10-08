"""Domain-specific exceptions for GitHub API interactions."""


class GitHubError(Exception):
    """Base exception for all GitHub API interactions."""

    def __init__(self, message: str, status_code: int | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class GitHubAuthError(GitHubError):
    """Raised when GitHub credentials are missing, invalid, or expired (HTTP 401/403)."""


class GitHubNotFoundError(GitHubError):
    """Raised when a requested repository, PR, commit, or file is not found (HTTP 404)."""


class GitHubRateLimitError(GitHubError):
    """Raised when GitHub API rate limits have been exceeded (HTTP 403 rate-limit or 429)."""


class GitHubTimeoutError(GitHubError):
    """Raised when an API request to GitHub times out."""


class GitHubValidationError(GitHubError):
    """Raised when parameters or payload fail client-side validation."""
