"""PRism Milestone 4: Verification & Smoke Test Script.

Validates end-to-end M4 capabilities:
1. FastAPI app startup and GET /health
2. GitHub Webhook HMAC-SHA256 signature verification (valid, invalid, tampered, missing)
3. Webhook delivery idempotency via X-GitHub-Delivery
4. Review Execution Service with LangGraph SQLite persistence
5. Human-in-the-Loop approval API (resuming checkpoints, strict enum validation)
6. GitHub Review Publisher with summary/inline formatting and duplicate publication prevention
7. Optional API Key authorization boundary
"""

import asyncio
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from prism.api.app import create_app
from prism.api.dependencies import get_review_service, get_review_store
from prism.github.models import ChangedFile, PRMetadata, ReviewCommentResult
from prism.services.models import ReviewStatus
from prism.services.review_publisher import ReviewPublisher
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore


class MockGitHubClient:
    """Mock GitHub Client that implements GitHubClientProtocol."""

    def __init__(self) -> None:
        self.published_comments: list[dict] = []
        self.published_review_comments: list[dict] = []

    async def get_pr_metadata(self, owner: str, repo: str, pull_number: int) -> PRMetadata:
        return PRMetadata(
            number=pull_number,
            title="feat: update login handler with raw query",
            body="Replaces ORM query with f-string SQL query.",
            state="open",
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}",
            head_sha="sha-abc-101",
            head_branch="feat/login",
            base_branch="main",
            author="contributor",
            created_at="2026-03-30T10:00:00Z",
            updated_at="2026-03-30T10:05:00Z",
        )

    async def get_pr_diff(self, owner: str, repo: str, pull_number: int) -> str:
        return (
            "@@ -10,3 +10,4 @@\n"
            "+def authenticate(u, p):\n"
            "+    return db.execute(f'SELECT * FROM users WHERE u={u} AND p={p}')\n"
        )

    async def get_changed_files(self, owner: str, repo: str, pull_number: int) -> list[ChangedFile]:
        return [
            ChangedFile(
                filename="auth/login.py",
                status="modified",
                patch="+ def auth(): pass",
            )
        ]

    async def get_pr_comments(self, owner: str, repo: str, pull_number: int) -> list[Any]:
        return []

    async def read_repo_file(self, owner: str, repo: str, path: str, ref: str | None = None) -> str:
        return "# existing repo file"

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
        if path and line:
            record = {"owner": owner, "repo": repo, "pull_number": pull_number, "body": body, "path": path, "line": line}
            self.published_review_comments.append(record)
            comment_id = 8800 + len(self.published_review_comments)
        else:
            record = {"owner": owner, "repo": repo, "pull_number": pull_number, "body": body}
            self.published_comments.append(record)
            comment_id = 9900 + len(self.published_comments)

        return ReviewCommentResult(
            id=comment_id,
            body=body,
            html_url=f"https://github.com/{owner}/{repo}/pull/{pull_number}#comment-{comment_id}",
            created_at="2026-03-30T10:10:00Z",
            path=path,
            line=line,
        )


def compute_sig(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


async def run_m4_verification() -> None:
    print("=" * 80)
    print("PRism Milestone 4: End-to-End Verification & Smoke Test")
    print("FastAPI Webhook Receiver, Human Approval API, Publisher & Review Store")
    print("=" * 80)

    webhook_secret = "test-webhook-secret-999"
    api_key = "prism-dev-secret-key"

    with tempfile.TemporaryDirectory() as tmp_dir:
        review_db = str(Path(tmp_dir) / "reviews.db")
        checkpoint_db = str(Path(tmp_dir) / "checkpoints.db")

        import os

        from prism.config import get_settings

        os.environ["GITHUB_WEBHOOK_SECRET"] = webhook_secret
        os.environ["PRISM_API_KEY"] = api_key
        os.environ["REVIEW_DB_PATH"] = review_db
        os.environ["SQLITE_CHECKPOINT_PATH"] = checkpoint_db
        os.environ["AUTO_PUBLISH_REVIEWS"] = "true"
        os.environ["PUBLISH_INLINE_COMMENTS"] = "true"
        get_settings.cache_clear()

        app = create_app()
        mock_gh = MockGitHubClient()
        store = ReviewStore(db_path=review_db)
        await store.initialize()

        publisher = ReviewPublisher(github_client=mock_gh, store=store)
        service = ReviewService(
            store=store,
            publisher=publisher,
            github_client=mock_gh,
            checkpoint_db_path=checkpoint_db,
        )

        app.dependency_overrides[get_review_store] = lambda: store
        app.dependency_overrides[get_review_service] = lambda: service

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:

            # -------------------------------------------------------------
            # SCENARIO 1: Health Check Endpoint
            # -------------------------------------------------------------
            print("\n[1. HEALTH CHECK ENDPOINT]")
            resp = await client.get("/health")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
            data = resp.json()
            print(f"  Status: {data['status']}")
            print(f"  Service: {data['service']} v{data['version']}")
            print(f"  MCP Server: {data['mcp_server']}")
            print(f"  Checkpoint DB: {data['checkpoint_db']}")
            assert data["status"] == "healthy"
            print("  [PASS] Health check returns structured 200 OK.")

            # -------------------------------------------------------------
            # SCENARIO 2: Webhook HMAC Signature Verification
            # -------------------------------------------------------------
            print("\n[2. GITHUB WEBHOOK SIGNATURE VERIFICATION (HMAC-SHA256)]")
            raw_payload = json.dumps({
                "action": "opened",
                "repository": {"name": "auth-service", "full_name": "org/auth-service", "html_url": "https://github.com/org/auth-service"},
                "pull_request": {
                    "number": 101,
                    "title": "feat: unsafe auth handler",
                    "html_url": "https://github.com/org/auth-service/pull/101",
                    "state": "open",
                    "head": {"sha": "sha-abc-101", "ref": "feat/login"},
                    "body": "Updates login route.",
                },
            }).encode("utf-8")

            # 2a. Missing signature -> 401
            resp = await client.post(
                "/webhooks/github",
                content=raw_payload,
                headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "deliv-1"},
            )
            print(f"  Missing Signature: HTTP {resp.status_code} ({resp.json()['detail']})")
            assert resp.status_code == 401

            # 2b. Invalid signature -> 401
            resp = await client.post(
                "/webhooks/github",
                content=raw_payload,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "deliv-1",
                    "X-Hub-Signature-256": "sha256=invaliddeadbeef",
                },
            )
            print(f"  Invalid Signature: HTTP {resp.status_code} ({resp.json()['detail']})")
            assert resp.status_code == 401

            # 2c. Tampered payload -> 401
            valid_sig = compute_sig(webhook_secret, raw_payload)
            tampered_payload = raw_payload.replace(b"auth-service", b"tampered-service")
            resp = await client.post(
                "/webhooks/github",
                content=tampered_payload,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "deliv-1",
                    "X-Hub-Signature-256": valid_sig,
                },
            )
            print(f"  Tampered Payload: HTTP {resp.status_code}")
            assert resp.status_code == 401

            # 2d. Valid signature -> 200 OK
            resp = await client.post(
                "/webhooks/github",
                content=raw_payload,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "deliv-101",
                    "X-Hub-Signature-256": valid_sig,
                },
            )
            print(f"  Valid Signature: HTTP {resp.status_code} -> Status: {resp.json()['status']}")
            assert resp.status_code == 200
            review_id_1 = resp.json()["review_id"]
            print(f"  Review ID Created: {review_id_1}")
            print("  [PASS] HMAC-SHA256 signature verification enforced fail-closed.")

            # -------------------------------------------------------------
            # SCENARIO 3: Webhook Delivery Idempotency (X-GitHub-Delivery)
            # -------------------------------------------------------------
            print("\n[3. WEBHOOK DELIVERY IDEMPOTENCY (X-GitHub-Delivery)]")
            resp_dup = await client.post(
                "/webhooks/github",
                content=raw_payload,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "deliv-101",  # Same delivery ID
                    "X-Hub-Signature-256": valid_sig,
                },
            )
            print(f"  Duplicate Delivery Response: Status={resp_dup.json()['status']}")
            print(f"  Message: {resp_dup.json()['message']}")
            assert resp_dup.status_code == 200
            assert resp_dup.json()["status"] == "ignored"
            assert "Duplicate delivery identifier" in resp_dup.json()["message"]
            print("  [PASS] Duplicate delivery ID safely ignored without re-execution.")

            # -------------------------------------------------------------
            # SCENARIO 4: SQLite Review Store State & Human Gate Interruption
            # -------------------------------------------------------------
            print("\n[4. REVIEW EXECUTION & STATE IN REVIEW STORE]")
            rec = await store.get_review(review_id_1)
            assert rec is not None
            print(f"  Review ID: {rec.review_id}")
            print(f"  Repository: {rec.repository} #{rec.pull_number}")
            print(f"  Status: {rec.status.value}")
            print(f"  Risk Level: {rec.risk_level}")
            print(f"  Matched Policy Rules: {rec.matched_rules}")
            print(f"  Total Findings: {len(rec.raw_findings)}")
            assert rec.status == ReviewStatus.WAITING_FOR_APPROVAL
            assert rec.risk_level in ("high", "critical")
            print("  [PASS] High-risk PR paused at WAITING_FOR_APPROVAL in SQLite store.")

            # -------------------------------------------------------------
            # SCENARIO 5: Human Approval API & Resume Checkpoint
            # -------------------------------------------------------------
            print("\n[5. HUMAN APPROVAL API (/api/reviews/{id}/approve)]")
            # 5a. Verify API Key enforcement
            resp_no_key = await client.post(
                f"/api/reviews/{review_id_1}/approve",
                json={"decision": "approve", "notes": "Approved by secops"},
            )
            print(f"  Approval Missing API Key: HTTP {resp_no_key.status_code}")
            assert resp_no_key.status_code == 401

            # 5b. Valid approval with API Key -> resumes LangGraph checkpoint
            resp_appr = await client.post(
                f"/api/reviews/{review_id_1}/approve",
                json={"decision": "approve", "notes": "Approved by Lead SecOps Engineer"},
                headers={"X-PRISM-API-KEY": api_key},
            )
            print(f"  Approval Response: HTTP {resp_appr.status_code}")
            assert resp_appr.status_code == 200
            appr_data = resp_appr.json()
            print(f"  Resumed Status: {appr_data['status']}")
            print(f"  Published to GitHub: {appr_data['published']}")
            assert appr_data["status"] == ReviewStatus.PUBLISHED.value
            assert appr_data["published"] is True
            print("  [PASS] Interrupted LangGraph state resumed from SQLite and review published.")

            # -------------------------------------------------------------
            # SCENARIO 6: Duplicate Publication Prevention
            # -------------------------------------------------------------
            print("\n[6. DUPLICATE PUBLICATION PREVENTION]")
            rec_updated = await store.get_review(review_id_1)
            prior_comment_count = len(mock_gh.published_comments)
            pub_result = await publisher.publish_review(rec_updated)
            print(f"  Second publish call returned existing record: {pub_result.publication_id}")
            assert pub_result.publication_id == rec_updated.publication_id
            assert len(mock_gh.published_comments) == prior_comment_count
            print("  [PASS] Duplicate publication prevented by SQLite publication index.")

            # -------------------------------------------------------------
            # SCENARIO 7: Rejection Flow
            # -------------------------------------------------------------
            print("\n[7. HUMAN REJECTION FLOW (/api/reviews/{id}/reject)]")
            rej_review = await service.execute_fixture_review(
                repository="org/auth-service",
                pull_number=102,
                title="feat: another auth change",
                body="Testing rejection path",
                diff="@@ -1,2 +1,3 @@\n+ def unsafe(): pass\n",
                changed_files=[{"filename": "auth/tokens.py", "status": "modified"}],
            )
            print(f"  Created Review ID: {rej_review.review_id} (Status: {rej_review.status.value})")

            resp_rej = await client.post(
                f"/api/reviews/{rej_review.review_id}/reject",
                json={"decision": "reject", "notes": "Rejected: Insecure token handling."},
                headers={"X-PRISM-API-KEY": api_key},
            )
            print(f"  Rejection Response: HTTP {resp_rej.status_code}")
            assert resp_rej.status_code == 200
            rej_data = resp_rej.json()
            print(f"  Final Status: {rej_data['status']}")
            print(f"  Published: {rej_data['published']}")
            assert rej_data["status"] == ReviewStatus.REJECTED.value
            assert rej_data["published"] is False
            print("  [PASS] Review rejection cleanly recorded without publishing.")

            # -------------------------------------------------------------
            # SCENARIO 8: Dashboard Endpoints
            # -------------------------------------------------------------
            print("\n[8. LIGHTWEIGHT DASHBOARD ROUTES]")
            resp_dash = await client.get("/")
            assert resp_dash.status_code == 200
            assert "Pull Request Triage Dashboard" in resp_dash.text
            print(f"  Dashboard Index: HTTP {resp_dash.status_code} (HTML rendered with Jinja2)")

            resp_detail = await client.get(f"/reviews/{review_id_1}")
            assert resp_detail.status_code == 200
            assert "Review Detail" in resp_detail.text
            assert "org/auth-service" in resp_detail.text
            assert "#101" in resp_detail.text
            assert review_id_1 in resp_detail.text
            print(f"  Review Detail Page: HTTP {resp_detail.status_code} (Rendered findings & metadata)")
            print("  [PASS] Jinja2 triage dashboard and detail pages operational.")

    print("\n" + "=" * 80)
    print("ALL MILESTONE 4 VERIFICATION SCENARIOS PASSED CLEANLY!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_m4_verification())
