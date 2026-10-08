"""GitHub API client module for PRism."""

from prism.github.client import GitHubClient, GitHubClientProtocol
from prism.github.exceptions import (
    GitHubAuthError,
    GitHubError,
    GitHubNotFoundError,
    GitHubRateLimitError,
    GitHubTimeoutError,
    GitHubValidationError,
)
from prism.github.models import ChangedFile, PRComment, PRMetadata, ReviewCommentResult

__all__ = [
    "ChangedFile",
    "GitHubAuthError",
    "GitHubClient",
    "GitHubClientProtocol",
    "GitHubError",
    "GitHubNotFoundError",
    "GitHubRateLimitError",
    "GitHubTimeoutError",
    "GitHubValidationError",
    "PRComment",
    "PRMetadata",
    "ReviewCommentResult",
]
