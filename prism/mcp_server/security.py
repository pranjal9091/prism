"""Centralized permission validator and security firewall for PRism MCP tools."""

import re
from enum import Enum
from typing import Final


class Capability(str, Enum):
    """System capabilities for GitHub operations."""

    # Explicitly Allowed Capabilities
    READ = "READ"
    COMMENT = "COMMENT"

    # Explicitly Denied Dangerous Capabilities
    MERGE = "MERGE"
    PUSH = "PUSH"
    WRITE_FILE = "WRITE_FILE"
    DELETE_FILE = "DELETE_FILE"
    CREATE_BRANCH = "CREATE_BRANCH"
    CHANGE_SETTINGS = "CHANGE_SETTINGS"
    ADMIN = "ADMIN"
    EXECUTE = "EXECUTE"


class PermissionDeniedError(Exception):
    """Raised when an operation violates PRism's least-privilege security policy."""

    def __init__(self, operation: str, capability: Capability | str, reason: str):
        self.operation = operation
        self.capability = capability
        self.reason = reason
        super().__init__(
            f"Security Violation: Operation '{operation}' requiring capability '{capability}' "
            f"is FORBIDDEN. Reason: {reason}"
        )


class InputValidationError(ValueError):
    """Raised when tool inputs fail security or schema validation."""


class PermissionFirewall:
    """Enforces strict read/comment-only boundary for all MCP operations.

    Ensures that any tool invocation or capability request mapping to
    prohibited operations (merge, push, file modification, admin) is
    unconditionally rejected before touching the network or system.
    """

    ALLOWED_CAPABILITIES: Final[set[Capability]] = {
        Capability.READ,
        Capability.COMMENT,
    }

    DENIED_CAPABILITIES: Final[set[Capability]] = {
        Capability.MERGE,
        Capability.PUSH,
        Capability.WRITE_FILE,
        Capability.DELETE_FILE,
        Capability.CREATE_BRANCH,
        Capability.CHANGE_SETTINGS,
        Capability.ADMIN,
        Capability.EXECUTE,
    }

    # Explicit registry mapping tool names/aliases to required capabilities
    OPERATION_CAPABILITY_MAP: Final[dict[str, Capability]] = {
        # Allowed Read Operations
        "get_pr": Capability.READ,
        "get_pr_diff": Capability.READ,
        "get_changed_files": Capability.READ,
        "get_pr_comments": Capability.READ,
        "get_repo_file": Capability.READ,
        # Allowed Comment Operations
        "post_review_comment": Capability.COMMENT,
        # Dangerous / Prohibited Operations (Explicitly registered for rejection verification)
        "merge_pr": Capability.MERGE,
        "merge": Capability.MERGE,
        "push_code": Capability.PUSH,
        "push": Capability.PUSH,
        "write_file": Capability.WRITE_FILE,
        "modify_file": Capability.WRITE_FILE,
        "delete_file": Capability.DELETE_FILE,
        "create_branch": Capability.CREATE_BRANCH,
        "change_settings": Capability.CHANGE_SETTINGS,
        "admin": Capability.ADMIN,
        "delete_repo": Capability.ADMIN,
        "execute_command": Capability.EXECUTE,
        "run_bash": Capability.EXECUTE,
    }

    @classmethod
    def check_capability(cls, capability: Capability, operation_name: str = "unknown") -> None:
        """Verify that the requested capability is allowed."""
        if capability in cls.DENIED_CAPABILITIES or capability not in cls.ALLOWED_CAPABILITIES:
            raise PermissionDeniedError(
                operation=operation_name,
                capability=capability,
                reason=(
                    f"Capability '{capability.value}' is strictly blocked. "
                    f"PRism enforces a read/comment-only security boundary."
                ),
            )

    @classmethod
    def validate_operation(cls, operation_name: str) -> Capability:
        """Validate an operation against the permission firewall.

        Returns the validated Capability if allowed, raises PermissionDeniedError otherwise.
        """
        normalized_op = operation_name.lower().strip()
        capability = cls.OPERATION_CAPABILITY_MAP.get(normalized_op)

        if capability is None:
            # Any unregistered operation is rejected by default (Default-Deny policy)
            raise PermissionDeniedError(
                operation=operation_name,
                capability="UNKNOWN",
                reason=f"Operation '{operation_name}' is not recognized in the allowed PRism tool registry.",
            )

        cls.check_capability(capability, operation_name=operation_name)
        return capability

    # Sanitization & Input Guardrails
    _REPO_NAME_REGEX: Final[re.Pattern] = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

    @classmethod
    def validate_repo_identifier(cls, owner: str, repo: str) -> None:
        """Validate owner and repo strings against directory traversal and shell characters."""
        if not owner or not repo:
            raise InputValidationError("Repository owner and name must not be empty.")
        if not cls._REPO_NAME_REGEX.match(owner):
            raise InputValidationError(
                f"Invalid owner format '{owner}'. Only alphanumeric, '.', '_', and '-' allowed."
            )
        if not cls._REPO_NAME_REGEX.match(repo):
            raise InputValidationError(
                f"Invalid repo format '{repo}'. Only alphanumeric, '.', '_', and '-' allowed."
            )

    @classmethod
    def validate_file_path(cls, path: str) -> None:
        """Prevent path traversal and null byte injections in file paths."""
        if not path or not path.strip():
            raise InputValidationError("File path cannot be empty.")
        if "\0" in path:
            raise InputValidationError("File path contains illegal null bytes.")
        normalized = path.replace("\\", "/").strip()
        parts = normalized.split("/")
        if ".." in parts:
            raise InputValidationError(
                f"Path traversal ('..') detected in path: '{path}'. Access denied."
            )

    @classmethod
    def validate_pull_number(cls, pull_number: int) -> None:
        """Ensure pull number is valid positive integer."""
        if not isinstance(pull_number, int) or pull_number <= 0:
            raise InputValidationError(
                f"Pull number must be a positive integer, got: {pull_number}"
            )

    @classmethod
    def validate_comment_body(cls, body: str, max_chars: int = 65_536) -> None:
        """Validate review comment body for non-emptiness and sensible payload length."""
        if not body or not body.strip():
            raise InputValidationError("Comment body cannot be empty.")
        if len(body) > max_chars:
            raise InputValidationError(
                f"Comment body length ({len(body)}) exceeds maximum limit of {max_chars} characters."
            )
