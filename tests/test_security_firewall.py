"""Tests for PRism PermissionFirewall and input security boundaries."""

import pytest

from prism.mcp_server.security import (
    Capability,
    InputValidationError,
    PermissionDeniedError,
    PermissionFirewall,
)


def test_allowed_capabilities():
    # READ and COMMENT must be accepted without error
    PermissionFirewall.check_capability(Capability.READ, "test_read")
    PermissionFirewall.check_capability(Capability.COMMENT, "test_comment")


@pytest.mark.parametrize(
    "denied_cap",
    [
        Capability.MERGE,
        Capability.PUSH,
        Capability.WRITE_FILE,
        Capability.DELETE_FILE,
        Capability.CREATE_BRANCH,
        Capability.CHANGE_SETTINGS,
        Capability.ADMIN,
        Capability.EXECUTE,
    ],
)
def test_explicitly_denied_capabilities(denied_cap: Capability):
    with pytest.raises(PermissionDeniedError) as exc_info:
        PermissionFirewall.check_capability(denied_cap, f"op_{denied_cap.value}")
    assert denied_cap.value in str(exc_info.value)
    assert "strictly blocked" in str(exc_info.value)


@pytest.mark.parametrize(
    "safe_op,expected_cap",
    [
        ("get_pr", Capability.READ),
        ("get_pr_diff", Capability.READ),
        ("get_changed_files", Capability.READ),
        ("get_pr_comments", Capability.READ),
        ("get_repo_file", Capability.READ),
        ("post_review_comment", Capability.COMMENT),
    ],
)
def test_validate_allowed_operations(safe_op: str, expected_cap: Capability):
    cap = PermissionFirewall.validate_operation(safe_op)
    assert cap == expected_cap


@pytest.mark.parametrize(
    "dangerous_op,expected_denied_cap",
    [
        ("merge", Capability.MERGE),
        ("merge_pr", Capability.MERGE),
        ("push", Capability.PUSH),
        ("push_code", Capability.PUSH),
        ("write_file", Capability.WRITE_FILE),
        ("modify_file", Capability.WRITE_FILE),
        ("delete_file", Capability.DELETE_FILE),
        ("create_branch", Capability.CREATE_BRANCH),
        ("change_settings", Capability.CHANGE_SETTINGS),
        ("admin", Capability.ADMIN),
        ("delete_repo", Capability.ADMIN),
        ("execute_command", Capability.EXECUTE),
        ("run_bash", Capability.EXECUTE),
    ],
)
def test_dangerous_operations_are_blocked(dangerous_op: str, expected_denied_cap: Capability):
    with pytest.raises(PermissionDeniedError) as exc_info:
        PermissionFirewall.validate_operation(dangerous_op)
    assert exc_info.value.capability == expected_denied_cap


def test_default_deny_on_unknown_operations():
    with pytest.raises(PermissionDeniedError) as exc_info:
        PermissionFirewall.validate_operation("unregistered_arbitrary_function")
    assert "not recognized in the allowed PRism tool registry" in str(exc_info.value)


@pytest.mark.parametrize(
    "malicious_path",
    [
        "../secrets.env",
        "../../etc/passwd",
        "sub/../../root.txt",
        "/etc/shadow\0.txt",
    ],
)
def test_path_traversal_rejections(malicious_path: str):
    with pytest.raises(InputValidationError):
        PermissionFirewall.validate_file_path(malicious_path)


@pytest.mark.parametrize(
    "invalid_owner_or_repo",
    [
        ("owner;rm -rf", "repo"),
        ("owner$(whoami)", "repo"),
        ("owner", "repo`ls`"),
        ("owner", ""),
        ("", "repo"),
    ],
)
def test_repo_identifier_rejections(invalid_owner_or_repo: tuple[str, str]):
    owner, repo = invalid_owner_or_repo
    with pytest.raises(InputValidationError):
        PermissionFirewall.validate_repo_identifier(owner, repo)


def test_pull_number_validation():
    with pytest.raises(InputValidationError):
        PermissionFirewall.validate_pull_number(0)

    with pytest.raises(InputValidationError):
        PermissionFirewall.validate_pull_number(-10)

    # Valid pull numbers should pass
    PermissionFirewall.validate_pull_number(1)
    PermissionFirewall.validate_pull_number(12345)


def test_comment_body_validation():
    with pytest.raises(InputValidationError, match="cannot be empty"):
        PermissionFirewall.validate_comment_body("")

    with pytest.raises(InputValidationError, match="cannot be empty"):
        PermissionFirewall.validate_comment_body("    ")

    with pytest.raises(InputValidationError, match="exceeds maximum limit"):
        PermissionFirewall.validate_comment_body("X" * 100, max_chars=50)

    # Valid body passes
    PermissionFirewall.validate_comment_body("Valid comment text.")
