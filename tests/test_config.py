"""Tests for PRism configuration and environment loading."""

import pytest

from prism.config import Settings


def test_default_settings():
    settings = Settings()
    assert settings.github_api_url == "https://api.github.com"
    assert settings.github_timeout_seconds == 15.0
    assert settings.max_diff_characters == 200_000
    assert settings.max_file_characters == 100_000
    assert settings.mcp_server_name == "prism-github-mcp"


def test_trailing_slash_stripped():
    settings = Settings(github_api_url="https://github.enterprise.local/api/v3/")
    assert settings.github_api_url == "https://github.enterprise.local/api/v3"


def test_parse_repo_slug_valid():
    owner, repo = Settings.parse_repo_slug("octocat/Spoon-Knife")
    assert owner == "octocat"
    assert repo == "Spoon-Knife"


def test_parse_repo_slug_invalid():
    with pytest.raises(ValueError, match="Invalid repository identifier"):
        Settings.parse_repo_slug("invalid-slug-without-slash")

    with pytest.raises(ValueError, match="Invalid repository identifier"):
        Settings.parse_repo_slug("owner/repo/extra")
