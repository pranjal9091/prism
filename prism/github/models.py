"""Pydantic schemas for GitHub API entities."""


from pydantic import BaseModel


class PRMetadata(BaseModel):
    """Normalized metadata for a GitHub Pull Request."""

    number: int
    title: str
    body: str | None = ""
    state: str
    html_url: str
    head_sha: str
    head_branch: str
    base_branch: str
    author: str
    draft: bool = False
    created_at: str
    updated_at: str
    additions: int = 0
    deletions: int = 0
    changed_files_count: int = 0


class ChangedFile(BaseModel):
    """Represents a file changed in a pull request."""

    filename: str
    status: str  # added, modified, removed, renamed
    additions: int = 0
    deletions: int = 0
    changes: int = 0
    patch: str | None = None
    previous_filename: str | None = None


class PRComment(BaseModel):
    """Represents an issue comment or review comment on a PR."""

    id: int
    user: str
    body: str
    created_at: str
    html_url: str
    path: str | None = None
    line: int | None = None
    commit_id: str | None = None


class ReviewCommentResult(BaseModel):
    """Result of successfully posting a review comment."""

    id: int
    body: str
    html_url: str
    created_at: str
    path: str | None = None
    line: int | None = None
