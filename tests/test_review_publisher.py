"""Unit tests for GitHub ReviewPublisher."""

import tempfile

import pytest

from prism.github.models import ChangedFile, PRComment, PRMetadata, ReviewCommentResult
from prism.services.models import ReviewRecord, ReviewStatus
from prism.services.review_publisher import (
    ReviewPublisher,
    format_inline_comment,
    format_summary_comment,
)
from prism.storage.review_store import ReviewStore


class MockGitHubPublisherClient:
    """Mock client tracking post_review_comment invocations and fulfilling GitHubClientProtocol."""

    def __init__(self):
        self.posted_comments = []
        self._next_id = 1000

    async def get_pr_metadata(self, owner: str, repo: str, pull_number: int) -> PRMetadata:
        return PRMetadata(
            number=pull_number,
            title="Sample PR",
            body="Sample PR description",
            state="open",
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}",
            head_sha="headsha123",
            head_branch="feature",
            base_branch="main",
            author="alice",
            created_at="2026-10-08T00:00:00Z",
            updated_at="2026-10-08T00:00:00Z",
        )

    async def get_pr_diff(self, owner: str, repo: str, pull_number: int) -> str:
        return "+ def sample():\n+     return True\n"

    async def get_changed_files(self, owner: str, repo: str, pull_number: int) -> list[ChangedFile]:
        return [
            ChangedFile(
                filename="src/main.py",
                status="modified",
                additions=2,
                deletions=0,
                changes=2,
                patch="+ def sample():\n+     return True\n",
            )
        ]

    async def get_pr_comments(self, owner: str, repo: str, pull_number: int) -> list[PRComment]:
        return []

    async def read_repo_file(
        self, owner: str, repo: str, path: str, ref: str | None = None
    ) -> str:
        return "# Sample file content"

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
        comment_id = self._next_id
        self._next_id += 1
        record = {
            "id": comment_id,
            "owner": owner,
            "repo": repo,
            "pull_number": pull_number,
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
        }
        self.posted_comments.append(record)
        return ReviewCommentResult(
            id=comment_id,
            body=body,
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}#comment-{comment_id}",
            created_at="2026-10-08T12:00:00Z",
            path=path,
            line=line,
        )


def test_format_summary_comment():
    review = ReviewRecord(
        review_id="rev-test-1",
        repository="octocat/Hello-World",
        pull_number=10,
        head_sha="abcdef123456",
        status=ReviewStatus.APPROVED,
        risk_level="high",
        summary="Automated review detected 1 high severity vulnerability.",
        findings_count=2,
        critical_count=0,
        high_count=1,
        medium_count=1,
        low_count=0,
        injection_detected=True,
        matched_rules=["RULE_AUTH_CODE"],
        policy_reasons=["Authentication module modified: auth/login.py"],
        approval_status="APPROVED",
        reviewer_notes="LGTM after review",
        thread_id="octocat/Hello-World#10",
        raw_findings=[
            {
                "severity": "high",
                "title": "Auth Token Leak",
                "file": "auth/login.py",
                "line": 42,
                "description": "Token exposed in logs",
                "recommendation": "Remove log statement",
            }
        ],
    )

    formatted = format_summary_comment(review)

    assert "## ⚠️ PRism Automated Review & Triage" in formatted
    assert "**Risk Level:** `HIGH`" in formatted
    assert "**Status:** `Approved`" in formatted
    assert "Prompt Injection Guardrail Triggered" in formatted
    assert "- **High:** 1" in formatted
    assert "Auth Token Leak (`auth/login.py:42`)" in formatted
    assert "Remove log statement" in formatted
    assert "Reviewer Note:* LGTM after review" in formatted


def test_format_inline_comment():
    finding = {
        "severity": "critical",
        "title": "SQL Injection",
        "description": "User input directly interpolated into SQL",
        "recommendation": "Use parameterized queries",
    }
    inline = format_inline_comment(finding)
    assert "**PRism [CRITICAL]**: **SQL Injection**" in inline
    assert "User input directly interpolated into SQL" in inline
    assert "**Recommendation:** Use parameterized queries" in inline


@pytest.mark.asyncio
async def test_publish_review_and_prevent_duplicates():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        store = ReviewStore(db_path=tmp.name)
        client = MockGitHubPublisherClient()
        publisher = ReviewPublisher(github_client=client, store=store)

        review = ReviewRecord(
            review_id="rev-pub-1",
            repository="octocat/Hello-World",
            pull_number=42,
            head_sha="commit_sha_123",
            status=ReviewStatus.APPROVED,
            risk_level="high",
            findings_count=1,
            critical_count=0,
            high_count=1,
            thread_id="octocat/Hello-World#42",
            raw_findings=[
                {
                    "severity": "high",
                    "title": "Insecure Deserialization",
                    "file": "utils/parser.py",
                    "line": 18,
                    "description": "pickle.loads used on external input",
                    "recommendation": "Use json.loads instead",
                }
            ],
        )

        # 1. First publication
        pub_record = await publisher.publish_review(review, publish_inline=True)
        assert pub_record is not None
        assert pub_record.summary_comment_id is not None
        assert pub_record.inline_comments_count == 1
        assert len(client.posted_comments) == 2  # 1 summary + 1 inline

        # 2. Second publication on same commit SHA must be prevented (idempotent)
        second_pub = await publisher.publish_review(review, publish_inline=True)
        assert second_pub.publication_id == pub_record.publication_id
        # Client comments count did NOT increase
        assert len(client.posted_comments) == 2
