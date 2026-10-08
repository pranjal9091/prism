"""Persistent SQLite review and webhook delivery store."""

import asyncio
import logging
from datetime import UTC, datetime

import aiosqlite

from prism.config import get_settings
from prism.services.models import (
    PublishedReviewRecord,
    ReviewRecord,
    WebhookDeliveryRecord,
)

logger = logging.getLogger(__name__)


class ReviewStore:
    """Asynchronous SQLite store for reviews, deliveries, and publications."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or get_settings().review_db_path
        self._lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self) -> None:
        """Create tables and indexes if they do not exist."""
        async with self._lock:
            if self._initialized:
                return

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row

                # 1. Webhook Deliveries Table (Idempotency)
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS webhook_deliveries (
                        delivery_id TEXT PRIMARY KEY,
                        event TEXT NOT NULL,
                        action TEXT,
                        repository TEXT NOT NULL,
                        pull_number INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        received_at TEXT NOT NULL
                    )
                    """
                )

                # 2. Reviews Table
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS reviews (
                        review_id TEXT PRIMARY KEY,
                        repository TEXT NOT NULL,
                        pull_number INTEGER NOT NULL,
                        head_sha TEXT NOT NULL,
                        status TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        requires_human_approval INTEGER NOT NULL,
                        summary TEXT,
                        findings_count INTEGER DEFAULT 0,
                        critical_count INTEGER DEFAULT 0,
                        high_count INTEGER DEFAULT 0,
                        medium_count INTEGER DEFAULT 0,
                        low_count INTEGER DEFAULT 0,
                        injection_detected INTEGER DEFAULT 0,
                        matched_rules_json TEXT,
                        policy_reasons_json TEXT,
                        approval_status TEXT,
                        reviewer_notes TEXT,
                        thread_id TEXT NOT NULL,
                        publication_id TEXT,
                        error_message TEXT,
                        raw_findings_json TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                await db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_reviews_repo_pr ON reviews(repository, pull_number)"
                )
                await db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status)"
                )

                # 3. Published Reviews Table (Duplicate publication prevention)
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS published_reviews (
                        publication_id TEXT PRIMARY KEY,
                        review_id TEXT NOT NULL,
                        repository TEXT NOT NULL,
                        pull_number INTEGER NOT NULL,
                        head_sha TEXT NOT NULL,
                        summary_comment_id INTEGER,
                        inline_comments_count INTEGER DEFAULT 0,
                        published_at TEXT NOT NULL,
                        UNIQUE(repository, pull_number, head_sha)
                    )
                    """
                )
                await db.commit()

            self._initialized = True
            logger.info("ReviewStore SQLite initialized at %s", self.db_path)

    # -------------------------------------------------------------------------
    # Webhook Deliveries & Idempotency
    # -------------------------------------------------------------------------

    async def record_delivery(self, record: WebhookDeliveryRecord) -> bool:
        """Record an incoming delivery.

        Returns True if newly inserted, False if delivery_id already existed (duplicate).
        """
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT delivery_id FROM webhook_deliveries WHERE delivery_id = ?",
                (record.delivery_id,),
            )
            existing = await cursor.fetchone()
            if existing:
                return False

            await db.execute(
                """
                INSERT INTO webhook_deliveries (delivery_id, event, action, repository, pull_number, status, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.delivery_id,
                    record.event,
                    record.action,
                    record.repository,
                    record.pull_number,
                    record.status,
                    record.received_at,
                ),
            )
            await db.commit()
            return True

    async def get_delivery(self, delivery_id: str) -> WebhookDeliveryRecord | None:
        """Fetch delivery audit record by delivery_id."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM webhook_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return WebhookDeliveryRecord(
                delivery_id=row["delivery_id"],
                event=row["event"],
                action=row["action"],
                repository=row["repository"],
                pull_number=row["pull_number"],
                status=row["status"],
                received_at=row["received_at"],
            )

    # -------------------------------------------------------------------------
    # Reviews
    # -------------------------------------------------------------------------

    async def save_review(self, record: ReviewRecord) -> None:
        """Insert or replace review record."""
        await self.initialize()
        record.updated_at = datetime.now(UTC).isoformat()
        row_data = record.to_sqlite_row()

        columns = list(row_data.keys())
        placeholders = ", ".join(["?"] * len(columns))
        col_names = ", ".join(columns)
        update_clause = ", ".join([f"{col} = excluded.{col}" for col in columns if col != "review_id"])

        query = f"""
            INSERT INTO reviews ({col_names})
            VALUES ({placeholders})
            ON CONFLICT(review_id) DO UPDATE SET
            {update_clause}
        """

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(query, list(row_data.values()))
            await db.commit()

    async def get_review(self, review_id: str) -> ReviewRecord | None:
        """Retrieve review record by review_id."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM reviews WHERE review_id = ?",
                (review_id,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return ReviewRecord.from_sqlite_row(dict(row))

    async def list_reviews(self, limit: int = 50, offset: int = 0) -> list[ReviewRecord]:
        """List reviews ordered by creation date descending."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM reviews ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            rows = await cursor.fetchall()
            return [ReviewRecord.from_sqlite_row(dict(r)) for r in rows]

    async def find_latest_review_for_pr(
        self, repository: str, pull_number: int
    ) -> ReviewRecord | None:
        """Find the most recent review for a specific PR."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM reviews WHERE repository = ? AND pull_number = ? ORDER BY created_at DESC LIMIT 1",
                (repository, pull_number),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return ReviewRecord.from_sqlite_row(dict(row))

    # -------------------------------------------------------------------------
    # Published Reviews (Duplicate publication prevention)
    # -------------------------------------------------------------------------

    async def get_publication_for_commit(
        self, repository: str, pull_number: int, head_sha: str
    ) -> PublishedReviewRecord | None:
        """Check if a review was already published for this PR commit."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT * FROM published_reviews
                WHERE repository = ? AND pull_number = ? AND head_sha = ?
                """,
                (repository, pull_number, head_sha),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return PublishedReviewRecord(
                publication_id=row["publication_id"],
                review_id=row["review_id"],
                repository=row["repository"],
                pull_number=row["pull_number"],
                head_sha=row["head_sha"],
                summary_comment_id=row["summary_comment_id"],
                inline_comments_count=row["inline_comments_count"],
                published_at=row["published_at"],
            )

    async def record_publication(self, record: PublishedReviewRecord) -> bool:
        """Record a successful GitHub publication. Returns True if inserted, False if duplicate."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            try:
                await db.execute(
                    """
                    INSERT INTO published_reviews (
                        publication_id, review_id, repository, pull_number, head_sha,
                        summary_comment_id, inline_comments_count, published_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.publication_id,
                        record.review_id,
                        record.repository,
                        record.pull_number,
                        record.head_sha,
                        record.summary_comment_id,
                        record.inline_comments_count,
                        record.published_at,
                    ),
                )
                await db.commit()
                return True
            except aiosqlite.IntegrityError:
                # Already published for this repository + PR + head_sha
                return False

    async def get_stats(self) -> dict[str, int]:
        """Retrieve total counts of reviews, deliveries, and publications."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            c1 = await db.execute("SELECT COUNT(*) FROM reviews")
            r1 = await c1.fetchone()
            reviews_count = r1[0] if r1 else 0

            c2 = await db.execute("SELECT COUNT(*) FROM webhook_deliveries")
            r2 = await c2.fetchone()
            deliveries_count = r2[0] if r2 else 0

            c3 = await db.execute("SELECT COUNT(*) FROM published_reviews")
            r3 = await c3.fetchone()
            publications_count = r3[0] if r3 else 0

            return {
                "reviews": reviews_count,
                "webhook_deliveries": deliveries_count,
                "published_reviews": publications_count,
            }
