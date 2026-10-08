"""Unit tests for PRism Observability, Langfuse tracing, and secret redaction."""

from unittest.mock import MagicMock

from prism.config import Settings
from prism.observability.config import ObservabilityConfig
from prism.observability.logging import log_event, redact_secrets, redact_string
from prism.observability.tracing import ObservabilityService, ReviewTraceContext


def test_observability_disabled_mode_is_noop():
    config = ObservabilityConfig(enabled=False)
    service = ObservabilityService(config=config)

    assert service.is_enabled is False

    ctx = service.start_review_trace(
        review_id="rev-123",
        repository="org/repo",
        pull_number=42,
        head_sha="abcdef123456",
    )

    assert isinstance(ctx, ReviewTraceContext)
    assert ctx.review_id == "rev-123"

    # Stage recording should execute safely without crashing
    service.record_stage(
        trace_context=ctx,
        stage="planner",
        duration_ms=45.2,
        input_data={"plan": "check"},
        output_data={"status": "done"},
    )
    assert "planner" in ctx.stages
    assert ctx.stages["planner"]["duration_ms"] == 45.2

    # Ending review trace should execute safely
    service.end_review_trace(
        trace_context=ctx,
        status="COMPLETED",
        risk_level="low",
        requires_human_approval=False,
    )
    assert ctx.metadata["status"] == "COMPLETED"


def test_observability_missing_credentials_gracefully_disables():
    settings = Settings(
        langfuse_enabled=True,
        langfuse_public_key="",
        langfuse_secret_key=None,
    )
    config = ObservabilityConfig.from_settings(settings)
    assert config.enabled is False


def test_observability_enabled_configuration_recognized():
    config = ObservabilityConfig(
        enabled=True,
        public_key="pk-lf-test",
        secret_key="sk-lf-test",
        host="https://cloud.langfuse.com",
        environment="staging",
    )
    assert config.enabled is True
    assert config.public_key == "pk-lf-test"
    assert config.secret_key == "sk-lf-test"
    assert config.environment == "staging"


def test_telemetry_failure_does_not_break_review():
    config = ObservabilityConfig(
        enabled=True,
        public_key="pk-mock",
        secret_key="sk-mock",
    )
    service = ObservabilityService(config=config)

    # Attach a mock Langfuse client whose operations raise exceptions
    faulty_client = MagicMock()
    faulty_client.trace.side_effect = RuntimeError("Langfuse server connection timed out")
    faulty_client.flush.side_effect = RuntimeError("Network partition")
    service.langfuse_client = faulty_client

    # Verify start_review_trace survives exception gracefully
    ctx = service.start_review_trace(
        review_id="rev-fault-1",
        repository="org/repo",
        pull_number=99,
        head_sha="11223344",
    )
    assert ctx.review_id == "rev-fault-1"

    # Verify record_stage survives exception gracefully
    service.record_stage(
        trace_context=ctx,
        stage="security_reviewer",
        duration_ms=120.0,
    )

    # Verify end_review_trace survives exception gracefully
    service.end_review_trace(
        trace_context=ctx,
        status="COMPLETED",
        risk_level="high",
    )
    assert ctx.metadata["status"] == "COMPLETED"


def test_secret_redaction_github_tokens_and_api_keys():
    raw_str = (
        "Found token ghp_1234567890abcdef1234567890 and "
        "OpenAI key sk-proj-1234567890abcdef1234567890 in config"
    )
    cleaned = redact_string(raw_str)
    assert "ghp_1234567890abcdef1234567890" not in cleaned
    assert "[REDACTED_GITHUB_TOKEN]" in cleaned
    assert "sk-proj-1234567890abcdef1234567890" not in cleaned
    assert "[REDACTED_API_KEY]" in cleaned


def test_secret_redaction_private_key_blocks():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y34FakeKeyContentForEvaluationPurposesOnly\n"
        "-----END RSA PRIVATE KEY-----"
    )
    cleaned = redact_string(pem)
    assert "FakeKeyContentForEvaluationPurposesOnly" not in cleaned
    assert "[REDACTED_PRIVATE_KEY]" in cleaned


def test_secret_redaction_dictionary_structures():
    payload = {
        "repository": "acme/service",
        "github_token": "ghp_secrettokenvalue123456789",
        "nested": {
            "password": "SuperSecretPassword123!",
            "database_url": "postgres://user:superpass123@db.prod.internal:5432/main",
            "safe_param": "visible_text",
        },
    }

    cleaned = redact_secrets(payload)
    assert cleaned["github_token"] == "[REDACTED]"
    assert cleaned["nested"]["password"] == "[REDACTED]"
    assert "superpass123" not in cleaned["nested"]["database_url"]
    assert "[REDACTED_PASSWORD]" in cleaned["nested"]["database_url"]
    assert cleaned["nested"]["safe_param"] == "visible_text"


def test_structured_log_event_redaction():
    entry = log_event(
        "test_event",
        level="INFO",
        review_id="rev-redact-1",
        api_key="sk-test-secret-value-123456",
        safe_meta="hello",
    )
    assert entry["event"] == "test_event"
    assert entry["api_key"] == "[REDACTED]"
    assert entry["safe_meta"] == "hello"
