"""Review execution service: Orchestrates PR retrieval, LangGraph review, checkpoints, and publishing."""

import logging
import uuid
from typing import Any

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from prism.config import get_settings
from prism.github.client import GitHubClient, GitHubClientProtocol
from prism.graph.builder import build_review_graph, execute_pr_review, resume_pr_review
from prism.models.factory import get_llm
from prism.observability import get_observability_service, log_event
from prism.services.models import (
    ApprovalDecision,
    ReviewRecord,
    ReviewStatus,
)
from prism.services.review_publisher import ReviewPublisher
from prism.storage.review_store import ReviewStore

logger = logging.getLogger(__name__)


class ReviewService:
    """Core application service orchestrating Pull Request review execution and human approvals."""

    def __init__(
        self,
        github_client: GitHubClientProtocol | None = None,
        store: ReviewStore | None = None,
        publisher: ReviewPublisher | None = None,
        llm: Any | None = None,
        checkpoint_db_path: str | None = None,
    ):
        settings = get_settings()
        self.github_client = github_client or GitHubClient()
        self.store = store or ReviewStore()
        self.publisher = publisher or ReviewPublisher(github_client=self.github_client, store=self.store)
        self.llm = llm if llm is not None else get_llm()
        self.checkpoint_db_path = checkpoint_db_path or settings.checkpoint_db_path
        self.observability = get_observability_service()

    async def execute_review(
        self,
        repository: str,
        pull_number: int,
        auto_publish: bool | None = None,
    ) -> ReviewRecord:
        """Fetch PR content, execute multi-agent LangGraph workflow, and update review store."""
        settings = get_settings()
        owner, repo = settings.parse_repo_slug(repository)
        should_publish = auto_publish if auto_publish is not None else settings.auto_publish_reviews

        # 1. Fetch PR Context from GitHub
        logger.info("Fetching PR context for %s#%s", repository, pull_number)
        metadata = await self.github_client.get_pr_metadata(owner, repo, pull_number)
        diff = await self.github_client.get_pr_diff(owner, repo, pull_number)
        changed_files_raw = await self.github_client.get_changed_files(owner, repo, pull_number)
        changed_files = [f.model_dump() for f in changed_files_raw]

        head_sha = metadata.head_sha
        review_id = str(uuid.uuid4())
        thread_id = f"{repository}#{pull_number}"

        trace_ctx = self.observability.start_review_trace(
            review_id=review_id,
            repository=repository,
            pull_number=pull_number,
            head_sha=head_sha,
            thread_id=thread_id,
            author=getattr(metadata, "author", "unknown"),
        )
        log_event(
            "review_started",
            review_id=review_id,
            repository=repository,
            pull_request=pull_number,
            head_sha=head_sha,
        )

        # Initialize Review Record in store
        review_record = ReviewRecord(
            review_id=review_id,
            repository=repository,
            pull_number=pull_number,
            head_sha=head_sha,
            status=ReviewStatus.RUNNING,
            thread_id=thread_id,
        )
        await self.store.save_review(review_record)

        # 2. Run LangGraph Review Graph with Persistent SQLite Checkpointer
        try:
            async with AsyncSqliteSaver.from_conn_string(self.checkpoint_db_path) as checkpointer:
                result_state, _, _ = await execute_pr_review(
                    repository=repository,
                    pull_request_number=pull_number,
                    pr_metadata=metadata.model_dump(),
                    diff=diff,
                    changed_files=changed_files,
                    llm=self.llm,
                    checkpointer=checkpointer,
                    thread_id=thread_id,
                    return_control=True,
                )

            # 3. Process Execution State
            risk_decision = result_state.get("risk_decision", {})
            aggregated_findings = result_state.get("aggregated_findings", [])
            summary_info = result_state.get("review_summary", {})
            injection_info = result_state.get("injection_detection", {})
            interrupts = result_state.get("__interrupt__", [])

            # Compute severity counts
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in aggregated_findings:
                sev = f.get("severity", "low").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1

            review_record.risk_level = risk_decision.get("risk_level", "low")
            review_record.requires_human_approval = risk_decision.get("requires_human_approval", False)
            review_record.summary = summary_info.get("summary_text", "")
            review_record.findings_count = len(aggregated_findings)
            review_record.critical_count = sev_counts["critical"]
            review_record.high_count = sev_counts["high"]
            review_record.medium_count = sev_counts["medium"]
            review_record.low_count = sev_counts["low"]
            review_record.injection_detected = injection_info.get("detected", False)
            review_record.matched_rules = risk_decision.get("matched_rules", [])
            review_record.policy_reasons = risk_decision.get("reasons", [])
            review_record.raw_findings = aggregated_findings
            review_record.approval_status = result_state.get("human_approval_status")

            # 4. Handle Human Gate Pause vs Auto-Approval
            if interrupts or review_record.requires_human_approval:
                logger.info(
                    "Review for %s#%s paused at human gate. Awaiting decision.",
                    repository,
                    pull_number,
                )
                review_record.status = ReviewStatus.WAITING_FOR_APPROVAL
                log_event(
                    "review_interrupted_human_gate",
                    review_id=review_id,
                    repository=repository,
                    pull_request=pull_number,
                    risk_level=review_record.risk_level,
                    matched_rules=review_record.matched_rules,
                )
            else:
                review_record.status = ReviewStatus.APPROVED
                if should_publish:
                    try:
                        await self.publisher.publish_review(review_record)
                        review_record.status = ReviewStatus.PUBLISHED
                    except Exception as pub_exc:  # noqa: BLE001
                        logger.error("Failed to publish auto-approved review: %s", pub_exc)
                        review_record.error_message = f"Auto-publish failed: {pub_exc}"

                log_event(
                    "review_completed",
                    review_id=review_id,
                    repository=repository,
                    pull_request=pull_number,
                    status=review_record.status.value,
                    risk_level=review_record.risk_level,
                    findings_count=review_record.findings_count,
                )

            self.observability.end_review_trace(
                trace_ctx,
                status=review_record.status.value,
                risk_level=review_record.risk_level,
                requires_human_approval=review_record.requires_human_approval,
                injection_detected=review_record.injection_detected,
                finding_count=review_record.findings_count,
            )

            await self.store.save_review(review_record)
            return review_record

        except Exception as exc:
            logger.exception("Review execution failed for %s#%s", repository, pull_number)
            review_record.status = ReviewStatus.FAILED
            review_record.error_message = str(exc)
            await self.store.save_review(review_record)
            self.observability.end_review_trace(trace_ctx, status="FAILED", error=str(exc))
            log_event(
                "review_failed",
                level="ERROR",
                review_id=review_id,
                repository=repository,
                pull_request=pull_number,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            raise

    async def execute_fixture_review(
        self,
        repository: str,
        pull_number: int,
        title: str,
        body: str,
        diff: str,
        changed_files: list[dict[str, Any]],
        head_sha: str = "0000000000000000000000000000000000000001",
        auto_publish: bool = False,
    ) -> ReviewRecord:
        """Execute review against supplied in-memory PR data (useful for testing and demo)."""
        review_id = str(uuid.uuid4())
        thread_id = f"{repository}#{pull_number}"

        trace_ctx = self.observability.start_review_trace(
            review_id=review_id,
            repository=repository,
            pull_number=pull_number,
            head_sha=head_sha,
            thread_id=thread_id,
            author="demo-author",
        )
        log_event(
            "fixture_review_started",
            review_id=review_id,
            repository=repository,
            pull_request=pull_number,
            head_sha=head_sha,
        )

        review_record = ReviewRecord(
            review_id=review_id,
            repository=repository,
            pull_number=pull_number,
            head_sha=head_sha,
            status=ReviewStatus.RUNNING,
            thread_id=thread_id,
        )
        await self.store.save_review(review_record)

        metadata = {
            "title": title,
            "body": body,
            "author": "demo-author",
            "number": pull_number,
            "head_sha": head_sha,
        }

        try:
            async with AsyncSqliteSaver.from_conn_string(self.checkpoint_db_path) as checkpointer:
                result_state, _, _ = await execute_pr_review(
                    repository=repository,
                    pull_request_number=pull_number,
                    pr_metadata=metadata,
                    diff=diff,
                    changed_files=changed_files,
                    llm=self.llm,
                    checkpointer=checkpointer,
                    thread_id=thread_id,
                    return_control=True,
                )

            risk_decision = result_state.get("risk_decision", {})
            aggregated_findings = result_state.get("aggregated_findings", [])
            summary_info = result_state.get("review_summary", {})
            injection_info = result_state.get("injection_detection", {})
            interrupts = result_state.get("__interrupt__", [])

            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in aggregated_findings:
                sev = f.get("severity", "low").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1

            review_record.risk_level = risk_decision.get("risk_level", "low")
            review_record.requires_human_approval = risk_decision.get("requires_human_approval", False)
            review_record.summary = summary_info.get("summary_text", "")
            review_record.findings_count = len(aggregated_findings)
            review_record.critical_count = sev_counts["critical"]
            review_record.high_count = sev_counts["high"]
            review_record.medium_count = sev_counts["medium"]
            review_record.low_count = sev_counts["low"]
            review_record.injection_detected = injection_info.get("detected", False)
            review_record.matched_rules = risk_decision.get("matched_rules", [])
            review_record.policy_reasons = risk_decision.get("reasons", [])
            review_record.raw_findings = aggregated_findings
            review_record.approval_status = result_state.get("human_approval_status")

            if interrupts or review_record.requires_human_approval:
                review_record.status = ReviewStatus.WAITING_FOR_APPROVAL
                log_event(
                    "review_interrupted_human_gate",
                    review_id=review_id,
                    repository=repository,
                    pull_request=pull_number,
                    risk_level=review_record.risk_level,
                    matched_rules=review_record.matched_rules,
                )
            else:
                review_record.status = ReviewStatus.APPROVED
                if auto_publish:
                    await self.publisher.publish_review(review_record)
                    review_record.status = ReviewStatus.PUBLISHED

                log_event(
                    "review_completed",
                    review_id=review_id,
                    repository=repository,
                    pull_request=pull_number,
                    status=review_record.status.value,
                    risk_level=review_record.risk_level,
                    findings_count=review_record.findings_count,
                )

            self.observability.end_review_trace(
                trace_ctx,
                status=review_record.status.value,
                risk_level=review_record.risk_level,
                requires_human_approval=review_record.requires_human_approval,
                injection_detected=review_record.injection_detected,
                finding_count=review_record.findings_count,
            )

            await self.store.save_review(review_record)
            return review_record

        except Exception as exc:
            logger.exception("Fixture review execution failed")
            review_record.status = ReviewStatus.FAILED
            review_record.error_message = str(exc)
            await self.store.save_review(review_record)
            self.observability.end_review_trace(trace_ctx, status="FAILED", error=str(exc))
            log_event(
                "fixture_review_failed",
                level="ERROR",
                review_id=review_id,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            raise

    async def process_approval(
        self,
        review_id: str,
        decision: ApprovalDecision,
        notes: str = "",
        auto_publish: bool | None = None,
    ) -> ReviewRecord:
        """Resume an interrupted review from SQLite checkpoint and apply human decision."""
        review = await self.store.get_review(review_id)
        if not review:
            raise ValueError(f"Review '{review_id}' not found.")

        if review.status != ReviewStatus.WAITING_FOR_APPROVAL:
            raise ValueError(
                f"Review '{review_id}' is in status '{review.status.value}', not WAITING_FOR_APPROVAL."
            )

        settings = get_settings()
        should_publish = auto_publish if auto_publish is not None else settings.auto_publish_reviews
        thread_id = review.thread_id

        logger.info(
            "Resuming review %s (thread: %s) with decision: %s",
            review_id,
            thread_id,
            decision.value,
        )

        async with AsyncSqliteSaver.from_conn_string(self.checkpoint_db_path) as checkpointer:
            graph = build_review_graph(llm=self.llm, checkpointer=checkpointer)
            resumed_state = await resume_pr_review(
                graph=graph,
                thread_id=thread_id,
                decision=decision.value,
                notes=notes,
            )

        approval_status = resumed_state.get("human_approval_status")
        review.approval_status = approval_status
        review.reviewer_notes = notes

        if decision == ApprovalDecision.APPROVE and approval_status == "APPROVED":
            review.status = ReviewStatus.APPROVED
            if should_publish:
                try:
                    await self.publisher.publish_review(review)
                    review.status = ReviewStatus.PUBLISHED
                except Exception as pub_exc:  # noqa: BLE001
                    logger.error("Failed to publish approved review %s: %s", review_id, pub_exc)
                    review.error_message = f"Publish failed: {pub_exc}"
        else:
            review.status = ReviewStatus.REJECTED

        log_event(
            "review_approval_processed",
            review_id=review_id,
            decision=decision.value,
            final_status=review.status.value,
        )

        await self.store.save_review(review)
        return review
