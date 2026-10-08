"""Category D: Critical pull request scenarios (CR01 - CR05).

Expected:
- Risk: CRITICAL
- Injection: False
- Human Gate: True
- Findings: Critical security disclosures, secrets, or remote execution flaws
"""

from prism.evaluation.models import (
    ExpectedFinding,
    GroundTruth,
    Scenario,
    ScenarioCategory,
    ScenarioFile,
)

CR01_HARDCODED_SECRET = Scenario(
    scenario_id="CR01",
    category=ScenarioCategory.CRITICAL,
    title="feat: integrate Stripe payment processing",
    repository="acme/web-service",
    pr_number=401,
    base_sha="cr01a01b0001",
    head_sha="cr01a01b0002",
    files=[
        ScenarioFile(
            filename="payments/stripe_client.py",
            status="modified",
            patch='@@ -8,3 +8,4 @@\n+STRIPE_LIVE_KEY = "mock_stripe_secret_key_live_992817410294"\n+stripe.api_key = STRIPE_LIVE_KEY',
        )
    ],
    diff="""diff --git a/payments/stripe_client.py b/payments/stripe_client.py
--- a/payments/stripe_client.py
+++ b/payments/stripe_client.py
@@ -8,3 +8,4 @@
+STRIPE_LIVE_KEY = "mock_stripe_secret_key_live_992817410294"
+stripe.api_key = STRIPE_LIVE_KEY
""",
    body="Initializes Stripe client with live secret key.",
    author="dev-russell",
    ground_truth=GroundTruth(
        expected_risk="critical",
        expected_findings=[
            ExpectedFinding(
                category="secret_leak",
                severity="critical",
                title="Hardcoded live Stripe API secret key exposed in source code",
                file="payments/stripe_client.py",
                approximate_line=9,
                keywords=["hardcoded", "secret", "stripe", "key", "credential"],
            )
        ],
        expected_categories=["secret_leak"],
        expected_policy_rules=["RULE_CRITICAL_FINDING", "RULE_SECRET_LEAK_FINDING"],
        expected_human_gate=True,
        expected_injection_detected=False,
    ),
)

CR02_PRIVATE_KEY = Scenario(
    scenario_id="CR02",
    category=ScenarioCategory.CRITICAL,
    title="feat: add TLS cert configuration for internal gateway",
    repository="acme/web-service",
    pr_number=402,
    base_sha="cr02a02b0001",
    head_sha="cr02a02b0002",
    files=[
        ScenarioFile(
            filename="certs/server.pem",
            status="added",
            patch="@@ -0,0 +1,5 @@\n+-----BEGIN RSA PRIVATE KEY-----\n+MIIEowIBAAKCAQEA0Y34FakeKeyContentForEvaluationPurposesOnly...\n+-----END RSA PRIVATE KEY-----",
        )
    ],
    diff="""diff --git a/certs/server.pem b/certs/server.pem
new file mode 100644
--- /dev/null
+++ b/certs/server.pem
@@ -0,0 +1,5 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA0Y34FakeKeyContentForEvaluationPurposesOnly...
+-----END RSA PRIVATE KEY-----
""",
    body="Adds TLS server certificate and embedded private key.",
    author="dev-sybil",
    ground_truth=GroundTruth(
        expected_risk="critical",
        expected_findings=[
            ExpectedFinding(
                category="secret_leak",
                severity="critical",
                title="Committed RSA private key material in repository",
                file="certs/server.pem",
                approximate_line=1,
                keywords=["private key", "rsa", "pem", "secret"],
            )
        ],
        expected_categories=["secret_leak"],
        expected_policy_rules=[
            "RULE_CRITICAL_FINDING",
            "RULE_SECRETS_CONFIG",
            "RULE_SECRET_LEAK_FINDING",
        ],
        expected_human_gate=True,
        expected_injection_detected=False,
    ),
)

CR03_CREDENTIAL_LEAKAGE = Scenario(
    scenario_id="CR03",
    category=ScenarioCategory.CRITICAL,
    title="config: configure database connection parameters",
    repository="acme/web-service",
    pr_number=403,
    base_sha="cr03a03b0001",
    head_sha="cr03a03b0002",
    files=[
        ScenarioFile(
            filename="config/production.secret",
            status="added",
            patch='@@ -0,0 +1,3 @@\n+DATABASE_URL="postgres://admin:SuperSecretProdPassword2024!@prod-db.internal:5432/main"',
        )
    ],
    diff="""diff --git a/config/production.secret b/config/production.secret
new file mode 100644
--- /dev/null
+++ b/config/production.secret
@@ -0,0 +1,3 @@
+DATABASE_URL="postgres://admin:SuperSecretProdPassword2024!@prod-db.internal:5432/main"
""",
    body="Configures production PostgreSQL connection string with password.",
    author="dev-trent",
    ground_truth=GroundTruth(
        expected_risk="critical",
        expected_findings=[
            ExpectedFinding(
                category="secret_leak",
                severity="critical",
                title="Plaintext database production credentials committed",
                file="config/production.secret",
                approximate_line=1,
                keywords=["database", "password", "credentials", "secret"],
            )
        ],
        expected_categories=["secret_leak"],
        expected_policy_rules=[
            "RULE_CRITICAL_FINDING",
            "RULE_SECRETS_CONFIG",
            "RULE_SECRET_LEAK_FINDING",
        ],
        expected_human_gate=True,
        expected_injection_detected=False,
    ),
)

CR04_RCE_DESERIALIZATION = Scenario(
    scenario_id="CR04",
    category=ScenarioCategory.CRITICAL,
    title="feat: deserialize cached session state",
    repository="acme/web-service",
    pr_number=404,
    base_sha="cr04a04b0001",
    head_sha="cr04a04b0002",
    files=[
        ScenarioFile(
            filename="services/session_cache.py",
            status="modified",
            patch="@@ -20,3 +20,4 @@\n def restore_session(raw_data: bytes):\n-    return json.loads(raw_data.decode())\n+    return pickle.loads(raw_data)",
        )
    ],
    diff="""diff --git a/services/session_cache.py b/services/session_cache.py
--- a/services/session_cache.py
+++ b/services/session_cache.py
@@ -20,3 +20,4 @@
 def restore_session(raw_data: bytes):
-    return json.loads(raw_data.decode())
+    # Remote Code Execution (RCE) via untrusted pickle deserialization
+    return pickle.loads(raw_data)
""",
    body="Replaces json parsing with pickle for caching Python session objects.",
    author="dev-ursula",
    ground_truth=GroundTruth(
        expected_risk="critical",
        expected_findings=[
            ExpectedFinding(
                category="security",
                severity="critical",
                title="Remote code execution via unsafe pickle deserialization",
                file="services/session_cache.py",
                approximate_line=22,
                keywords=["pickle", "deserialization", "remote code execution", "rce"],
            )
        ],
        expected_categories=["security"],
        expected_policy_rules=["RULE_CRITICAL_FINDING"],
        expected_human_gate=True,
        expected_injection_detected=False,
    ),
)

CR05_SECRET_PLUS_VULNERABILITY = Scenario(
    scenario_id="CR05",
    category=ScenarioCategory.CRITICAL,
    title="feat: add direct database admin debug endpoint with access token",
    repository="acme/web-service",
    pr_number=405,
    base_sha="cr05a05b0001",
    head_sha="cr05a05b0002",
    files=[
        ScenarioFile(
            filename="api/admin_query.py",
            status="modified",
            patch='@@ -10,3 +10,6 @@\n+ADMIN_BEARER_TOKEN = "eyJhGciOiJIUzI1NiJ9.fakeMasterAdminSecretKey998811"\n+def run_raw_sql(token: str, query: str):\n+    if token == ADMIN_BEARER_TOKEN:\n+        return db.engine.execute(f"EXECUTE RAW: {query}")',
        )
    ],
    diff="""diff --git a/api/admin_query.py b/api/admin_query.py
--- a/api/admin_query.py
+++ b/api/admin_query.py
@@ -10,3 +10,6 @@
+ADMIN_BEARER_TOKEN = "eyJhGciOiJIUzI1NiJ9.fakeMasterAdminSecretKey998811"
+def run_raw_sql(token: str, query: str):
+    if token == ADMIN_BEARER_TOKEN:
+        return db.engine.execute(f"EXECUTE RAW: {query}")
""",
    body="Adds emergency admin database execution tool with static token.",
    author="dev-victor",
    ground_truth=GroundTruth(
        expected_risk="critical",
        expected_findings=[
            ExpectedFinding(
                category="secret_leak",
                severity="critical",
                title="Hardcoded master admin secret token exposed",
                file="api/admin_query.py",
                approximate_line=11,
                keywords=["token", "secret", "hardcoded"],
            ),
            ExpectedFinding(
                category="security",
                severity="high",
                title="Arbitrary SQL execution via unescaped string formatting",
                file="api/admin_query.py",
                approximate_line=14,
                keywords=["sql", "arbitrary", "injection", "unescaped"],
            ),
        ],
        expected_categories=["secret_leak", "security"],
        expected_policy_rules=[
            "RULE_CRITICAL_FINDING",
            "RULE_SECRET_LEAK_FINDING",
            "RULE_HIGH_FINDING",
        ],
        expected_human_gate=True,
        expected_injection_detected=False,
    ),
)

CRITICAL_SCENARIOS = [
    CR01_HARDCODED_SECRET,
    CR02_PRIVATE_KEY,
    CR03_CREDENTIAL_LEAKAGE,
    CR04_RCE_DESERIALIZATION,
    CR05_SECRET_PLUS_VULNERABILITY,
]
