"""Configuration management for PRism using Pydantic Settings."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """PRism runtime settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # GitHub API Configuration
    github_token: str | None = Field(
        default=None,
        description="GitHub Personal Access Token or App Installation Token",
    )
    github_api_url: str = Field(
        default="https://api.github.com",
        description="Base URL for the GitHub REST API",
    )
    github_default_repo: str | None = Field(
        default=None,
        description="Default repository in 'owner/repo' format",
    )
    github_timeout_seconds: float = Field(
        default=15.0,
        ge=1.0,
        le=60.0,
        description="HTTP request timeout in seconds",
    )

    # Safety limits for diff and file sizes (memory boundary protection)
    max_diff_characters: int = Field(
        default=200_000,
        ge=1_000,
        description="Max diff characters allowed before truncation with warning",
    )
    max_file_characters: int = Field(
        default=100_000,
        ge=1_000,
        description="Max file content characters allowed before truncation",
    )

    # MCP Server Settings
    mcp_server_name: str = Field(
        default="prism-github-mcp",
        description="Identifier for the PRism MCP server",
    )
    mcp_server_version: str = Field(
        default="0.1.0",
        description="Version string for the PRism MCP server",
    )
    mcp_log_level: str = Field(
        default="INFO",
        description="Logging level for MCP server runtime",
    )

    # Checkpoint Persistence Settings
    checkpoint_db_path: str = Field(
        default="prism_checkpoints.db",
        description="Path to SQLite database file for LangGraph checkpoint persistence",
    )

    # M4 Application & Webhook Settings
    github_webhook_secret: str | None = Field(
        default=None,
        description="Secret used to verify GitHub webhook HMAC-SHA256 signatures",
    )
    prism_api_key: str | None = Field(
        default=None,
        description="Optional API key required for approval endpoints (X-PRISM-API-KEY). In local dev, None allows open access.",
    )
    review_db_path: str = Field(
        default="prism_reviews.db",
        description="Path to SQLite database for review records, webhook deliveries, and publications",
    )
    auto_publish_reviews: bool = Field(
        default=True,
        description="Whether to automatically publish reviews to GitHub upon approval or low risk",
    )
    publish_inline_comments: bool = Field(
        default=True,
        description="Whether to publish inline file/line comments in addition to summary comment",
    )

    # Milestone 6 Observability & Environment Settings
    langfuse_enabled: bool = Field(
        default=False,
        description="Whether Langfuse execution tracing is enabled",
    )
    langfuse_public_key: str | None = Field(
        default=None,
        description="Langfuse project public API key",
    )
    langfuse_secret_key: str | None = Field(
        default=None,
        description="Langfuse project secret API key",
    )
    langfuse_host: str = Field(
        default="https://cloud.langfuse.com",
        description="Langfuse API endpoint host URL",
    )
    log_level: str = Field(
        default="INFO",
        description="Application structured log level (DEBUG, INFO, WARNING, ERROR)",
    )
    environment: str = Field(
        default="development",
        description="Deployment environment ('development', 'staging', 'production')",
    )

    def validate_production_readiness(self) -> tuple[bool, list[str]]:
        """Validate whether current configuration satisfies production deployment requirements."""
        errors: list[str] = []
        is_prod = self.environment.strip().lower() == "production"

        if is_prod:
            if self.auto_publish_reviews and not self.github_token:
                errors.append(
                    "GITHUB_TOKEN is required in production when auto_publish_reviews is enabled."
                )
            if not self.github_webhook_secret:
                errors.append(
                    "GITHUB_WEBHOOK_SECRET is mandatory in production for HMAC signature verification."
                )
            if self.langfuse_enabled and (not self.langfuse_public_key or not self.langfuse_secret_key):
                errors.append(
                    "LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are required when LANGFUSE_ENABLED is true."
                )

        return len(errors) == 0, errors

    @field_validator("github_api_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @classmethod
    def parse_repo_slug(cls, repo_slug: str) -> tuple[str, str]:
        """Validate and split 'owner/repo' into (owner, repo)."""
        parts = repo_slug.strip().split("/")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(
                f"Invalid repository identifier '{repo_slug}'. Expected 'owner/repo' format."
            )
        return parts[0], parts[1]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached global settings instance."""
    return Settings()
