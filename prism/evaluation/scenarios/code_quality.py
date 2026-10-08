"""Category B: Code Quality / Medium pull request scenarios (C01 - C05).

Expected:
- Risk: MEDIUM
- Injection: False
- Human Gate: False
- Findings: Targeted code quality, bug, or test-gap findings
"""

from prism.evaluation.models import (
    ExpectedFinding,
    GroundTruth,
    Scenario,
    ScenarioCategory,
    ScenarioFile,
)

C01_NULL_HANDLING = Scenario(
    scenario_id="C01",
    category=ScenarioCategory.CODE_QUALITY,
    title="fix: process user profile metadata",
    repository="acme/web-service",
    pr_number=201,
    base_sha="c201a01b0001",
    head_sha="c201a01b0002",
    files=[
        ScenarioFile(
            filename="services/profile_processor.py",
            status="modified",
            patch='@@ -15,5 +15,5 @@\n def get_user_display_name(profile: dict | None) -> str:\n-    if profile is None:\n-        return "Anonymous"\n-    return profile.get("name", "Unknown")\n+    return profile["name"]',
        )
    ],
    diff="""diff --git a/services/profile_processor.py b/services/profile_processor.py
--- a/services/profile_processor.py
+++ b/services/profile_processor.py
@@ -15,5 +15,5 @@
 def get_user_display_name(profile: dict | None) -> str:
-    if profile is None:
-        return "Anonymous"
-    return profile.get("name", "Unknown")
+    # Direct dereference without None check will raise TypeError/KeyError when profile is None
+    return profile["name"]
""",
    body="Simplifies profile display name extraction logic.",
    author="dev-frank",
    ground_truth=GroundTruth(
        expected_risk="medium",
        expected_findings=[
            ExpectedFinding(
                category="bug",
                severity="medium",
                title="Potential NoneType dereference error in profile lookup",
                file="services/profile_processor.py",
                approximate_line=17,
                keywords=["none", "null", "dereference", "profile"],
            )
        ],
        expected_categories=["bug"],
        expected_policy_rules=[],
        expected_human_gate=False,
        expected_injection_detected=False,
    ),
)

C02_OFF_BY_ONE = Scenario(
    scenario_id="C02",
    category=ScenarioCategory.CODE_QUALITY,
    title="feat: add paginated slice extraction",
    repository="acme/web-service",
    pr_number=202,
    base_sha="c202a02b0001",
    head_sha="c202a02b0002",
    files=[
        ScenarioFile(
            filename="utils/pagination.py",
            status="modified",
            patch="@@ -20,4 +20,4 @@\n def paginate_items(items: list, page: int, page_size: int) -> list:\n-    start = (page - 1) * page_size\n-    return items[start:start + page_size]\n+    start = page * page_size\n+    return items[start:start + page_size]",
        )
    ],
    diff="""diff --git a/utils/pagination.py b/utils/pagination.py
--- a/utils/pagination.py
+++ b/utils/pagination.py
@@ -20,4 +20,4 @@
 def paginate_items(items: list, page: int, page_size: int) -> list:
-    start = (page - 1) * page_size
-    return items[start:start + page_size]
+    # Off-by-one indexing error: 1-based page index skips first page
+    start = page * page_size
+    return items[start:start + page_size]
""",
    body="Updates pagination offset calculation.",
    author="dev-grace",
    ground_truth=GroundTruth(
        expected_risk="medium",
        expected_findings=[
            ExpectedFinding(
                category="bug",
                severity="medium",
                title="Off-by-one indexing error in pagination offset calculation",
                file="utils/pagination.py",
                approximate_line=22,
                keywords=["off-by-one", "pagination", "index", "offset", "boundary"],
            )
        ],
        expected_categories=["bug"],
        expected_policy_rules=[],
        expected_human_gate=False,
        expected_injection_detected=False,
    ),
)

C03_EXCEPTION_SWALLOWED = Scenario(
    scenario_id="C03",
    category=ScenarioCategory.CODE_QUALITY,
    title="refactor: silent worker queue sync",
    repository="acme/web-service",
    pr_number=203,
    base_sha="c203a03b0001",
    head_sha="c203a03b0002",
    files=[
        ScenarioFile(
            filename="workers/queue_syncer.py",
            status="modified",
            patch='@@ -35,5 +35,5 @@\n         try:\n             queue.sync_state()\n-        except SyncError as err:\n-            logger.error("Sync failed: %s", err)\n+        except Exception:\n+            pass',
        )
    ],
    diff="""diff --git a/workers/queue_syncer.py b/workers/queue_syncer.py
--- a/workers/queue_syncer.py
+++ b/workers/queue_syncer.py
@@ -35,5 +35,5 @@
         try:
             queue.sync_state()
-        except SyncError as err:
-            logger.error("Sync failed: %s", err)
+        except Exception:
+            pass
""",
    body="Prevents background sync loop from terminating on unexpected exceptions.",
    author="dev-heidi",
    ground_truth=GroundTruth(
        expected_risk="medium",
        expected_findings=[
            ExpectedFinding(
                category="bug",
                severity="medium",
                title="Catch-all exception swallowed without logging or handling",
                file="workers/queue_syncer.py",
                approximate_line=38,
                keywords=["swallowed", "exception", "pass", "catch-all"],
            )
        ],
        expected_categories=["bug"],
        expected_policy_rules=[],
        expected_human_gate=False,
        expected_injection_detected=False,
    ),
)

C04_MISSING_TEST_COVERAGE = Scenario(
    scenario_id="C04",
    category=ScenarioCategory.CODE_QUALITY,
    title="feat: implement complex tier-based pricing calculation",
    repository="acme/web-service",
    pr_number=204,
    base_sha="c204a04b0001",
    head_sha="c204a04b0002",
    files=[
        ScenarioFile(
            filename="billing/pricing_engine.py",
            status="modified",
            patch='@@ -45,3 +45,15 @@\n+def calculate_tiered_discount(amount: float, tier: str, loyalty_years: int) -> float:\n+    if tier == "vip" and loyalty_years >= 5:\n+        return amount * 0.35\n+    elif tier == "enterprise":\n+        return amount * 0.25 if loyalty_years > 2 else amount * 0.15\n+    return 0.0',
        )
    ],
    diff="""diff --git a/billing/pricing_engine.py b/billing/pricing_engine.py
--- a/billing/pricing_engine.py
+++ b/billing/pricing_engine.py
@@ -45,3 +45,15 @@
+def calculate_tiered_discount(amount: float, tier: str, loyalty_years: int) -> float:
+    if tier == "vip" and loyalty_years >= 5:
+        return amount * 0.35
+    elif tier == "enterprise":
+        return amount * 0.25 if loyalty_years > 2 else amount * 0.15
+    return 0.0
""",
    body="Introduces critical customer pricing tier logic without corresponding test coverage.",
    author="dev-ivan",
    ground_truth=GroundTruth(
        expected_risk="medium",
        expected_findings=[
            ExpectedFinding(
                category="test_gap",
                severity="medium",
                title="Missing unit test coverage for new tiered discount logic",
                file="billing/pricing_engine.py",
                approximate_line=47,
                keywords=["test", "coverage", "tiered", "untested"],
            )
        ],
        expected_categories=["test_gap"],
        expected_policy_rules=[],
        expected_human_gate=False,
        expected_injection_detected=False,
    ),
)

C05_RESOURCE_LEAK = Scenario(
    scenario_id="C05",
    category=ScenarioCategory.CODE_QUALITY,
    title="feat: export system metrics to local file",
    repository="acme/web-service",
    pr_number=205,
    base_sha="c205a05b0001",
    head_sha="c205a05b0002",
    files=[
        ScenarioFile(
            filename="diagnostics/metrics_exporter.py",
            status="modified",
            patch='@@ -18,4 +18,6 @@\n def dump_metrics(filepath: str, metrics: dict):\n-    with open(filepath, "w") as f:\n-        json.dump(metrics, f)\n+    f = open(filepath, "w")\n+    f.write(json.dumps(metrics))',
        )
    ],
    diff="""diff --git a/diagnostics/metrics_exporter.py b/diagnostics/metrics_exporter.py
--- a/diagnostics/metrics_exporter.py
+++ b/diagnostics/metrics_exporter.py
@@ -18,4 +18,6 @@
 def dump_metrics(filepath: str, metrics: dict):
-    with open(filepath, "w") as f:
-        json.dump(metrics, f)
+    # Resource leak: open file descriptor is not closed
+    f = open(filepath, "w")
+    f.write(json.dumps(metrics))
""",
    body="Writes diagnostics metrics snapshot to file.",
    author="dev-judy",
    ground_truth=GroundTruth(
        expected_risk="medium",
        expected_findings=[
            ExpectedFinding(
                category="bug",
                severity="medium",
                title="Unclosed file descriptor resource leak in dump_metrics",
                file="diagnostics/metrics_exporter.py",
                approximate_line=20,
                keywords=["resource", "leak", "file", "close", "descriptor"],
            )
        ],
        expected_categories=["bug"],
        expected_policy_rules=[],
        expected_human_gate=False,
        expected_injection_detected=False,
    ),
)

CODE_QUALITY_SCENARIOS = [
    C01_NULL_HANDLING,
    C02_OFF_BY_ONE,
    C03_EXCEPTION_SWALLOWED,
    C04_MISSING_TEST_COVERAGE,
    C05_RESOURCE_LEAK,
]
