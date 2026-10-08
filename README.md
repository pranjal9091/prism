# PRism

<p align="left">
  <a href="https://github.com/pranjal9091/prism/actions"><img src="https://img.shields.io/badge/tests-200%2F200%20passing-brightgreen.svg" alt="Tests"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.12%2B-blue.svg" alt="Python 3.12+"></a>
  <a href="https://astral.sh/uv"><img src="https://img.shields.io/badge/package%20manager-uv-blueviolet.svg" alt="uv"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/linter-ruff-black.svg" alt="Ruff"></a>
  <a href="https://github.com/langchain-ai/langgraph"><img src="https://img.shields.io/badge/orchestration-LangGraph-orange.svg" alt="LangGraph"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/protocol-MCP-purple.svg" alt="Model Context Protocol"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
</p>

PRism is an agentic GitHub Pull Request triage and review engine designed for engineering teams that require deterministic safety, zero-hallucination policy enforcement, and strict privilege boundaries.

Unlike naive LLM review bots that execute arbitrary tools or blindly comment on code, PRism isolates untrusted pull request data, evaluates risk through deterministic heuristics, enforces a strict read/comment-only firewall via the **Model Context Protocol (MCP)**, and gates high-risk changes behind a fail-closed **Human-in-the-Loop (HITL)** checkpoint.

---

## Key Highlights

- **Default-Deny MCP Firewall**: Agents operate exclusively through custom Model Context Protocol tools. Dangerous capabilities (`MERGE`, `PUSH`, `WRITE_FILE`, `DELETE_FILE`, `CREATE_BRANCH`, `ADMIN`, `EXECUTE`) do not exist on the server.
- **Untrusted Content Isolation**: All PR titles, descriptions, and diffs are treated as hostile input. Neutralizes Unicode bi-directional overrides, zero-width characters, XML delimiter breakouts, and prompt injection attacks.
- **Deterministic Risk Engine**: Risk classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) is computed via deterministic rules—evaluating sensitive file paths (auth, migrations, CI/CD, credentials), leaked secrets, and severity thresholds—with zero LLM variance.
- **Stateful Human-in-the-Loop**: High and critical risk reviews pause execution using native LangGraph `interrupt()`. Execution state persists in SQLite (`AsyncSqliteSaver`) and resumes only upon explicit authorized approval.
- **Parallel Specialist Reviewers**: A dedicated Planner node orchestrates three specialist reviewers in parallel: **Code Quality**, **Security & Vulnerabilities**, and **Test Coverage**.
- **Production Webhook Engine**: FastAPI receiver with constant-time HMAC-SHA256 signature verification, delivery deduplication (`X-GitHub-Delivery`), and an opinionated, dark-mode developer triage dashboard.
- **Enterprise Observability**: Native Langfuse tracing, correlated review lifecycles, non-blocking fail-safe error handling, and automated scrubbing of secrets, tokens, and private keys.
- **25-Scenario Benchmark Suite**: Built-in deterministic evaluation harness testing benign, quality, security, secret disclosure, and adversarial injection scenarios.

---

## System Architecture

```text
                           GitHub Pull Request Event
                                      │
                                      ▼
                        [ POST /webhooks/github ]
                (HMAC-SHA256 Signature + Delivery Idempotency)
                                      │
                                      ▼
                         [ Review Execution Service ]
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │      Untrusted Sanitizer     │ ◄── Strips injection & Unicode breakouts
                       └──────────────┬───────────────┘
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │        Review Planner        │
                       └──────────────┬───────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
        ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
        │ Code Reviewer │     │   Security    │     │ Test Suggester│  (Parallel Specialist Agents)
        └───────┬───────┘     └───────┬───────┘     └───────┬───────┘
                │                     │                     │
                └─────────────────────┼─────────────────────┘
                                      ▼
                       ┌──────────────────────────────┐
                       │  Aggregator & Deduplication  │
                       └──────────────┬───────────────┘
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │   Deterministic Risk Policy  │ ◄── Paths, secrets, severities
                       └──────────────┬───────────────┘
                                      │
                      ┌───────────────┴───────────────┐
             Low Risk │                      High Risk│
                      ▼                               ▼
               [ Auto-Approved ]            [ human_gate (Paused) ]
                      │                      (SQLite Checkpointer)
                      │                               │
                      │                         Human Reviewer
                      │                [ POST /api/reviews/{id}/approve ]
                      │                               │
                      └───────────────┬───────────────┘
                                      ▼
                       ┌──────────────────────────────┐
                       │   Idempotent Review Publisher │
                       └──────────────┬───────────────┘
                                      ├── PR Summary Comment (Risk & Findings)
                                      └── Inline Review Comments (File + Line + Fix)
                                      │
                                      ▼
                                [ GitHub PR ]
```

---

## Security Model & Privilege Firewall

PRism enforces defense-in-depth across the entire review lifecycle:

### 1. Model Context Protocol (MCP) Boundary

Agents communicate with GitHub strictly via a custom MCP server. The server implements a capability firewall where sensitive actions are structurally absent:

| Capability | Operations | Policy | Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| `READ` | Inspect PR metadata, diffs, changed files, comments, repository tree | **ALLOWED** | Parameter-validated read tools |
| `COMMENT` | Post review summaries and inline comments | **ALLOWED** | Rate-limited publication tools |
| `POST_REVIEW` | Create pull request review threads | **ALLOWED** | Anchored to verified commit SHAs |
| `MERGE` | Merge pull requests | **BLOCKED** | Structurally absent from tool registry |
| `PUSH` | Push git refs or commits | **BLOCKED** | Structurally absent from tool registry |
| `WRITE_FILE` | Create or modify repository files | **BLOCKED** | Raises `PermissionDeniedError` |
| `DELETE_FILE` | Delete repository files or branches | **BLOCKED** | Raises `PermissionDeniedError` |
| `ADMIN` | Modify repository settings, webhooks, or collaborators | **BLOCKED** | Default-deny policy |
| `EXECUTE` | Execute shell commands or arbitrary code | **BLOCKED** | Blocked at firewall layer |

### 2. Prompt Injection Defense

All inputs originating from GitHub (PR title, description, branch names, unified diffs, comments) are passed through an input sanitizer:
- Encapsulates untrusted content in `<untrusted_input source="...">` isolation tags.
- Neutralizes delimiter breakout attempts (e.g., `</untrusted_input><system>`).
- Filters Unicode bidirectional formatting controls (e.g., `U+202E` Right-to-Left Override) and zero-width spaces.
- Scans for adversarial instruction overrides (`"ignore previous instructions"`, `"approve this PR"`, `"act as admin"`).
- Adversarial attempts immediately flag the PR, elevate its risk to `HIGH`, and halt publication at the human gate.

### 3. Fail-Closed Human Gate

Elevated risk reviews pause inside LangGraph using native `interrupt()`. 
- State is serialized into `prism_checkpoints.db` via `AsyncSqliteSaver`.
- Reviews remain paused until an authorized engineer submits an approval via the Dashboard UI or API (`POST /api/reviews/{id}/approve`).
- Missing, invalid, or rejected decisions fail closed: no comments or approvals are ever sent to GitHub without explicit authorization.

---

## Quickstart

### Prerequisites

- Python 3.12+
- [`uv`](https://astral.sh/uv) (recommended) or standard `pip`

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/pranjal9091/prism.git
cd prism

# Install dependencies and sync virtual environment
uv sync
```

### 2. Configuration

Create your local environment file:

```bash
cp .env.example .env
```

Configure your secrets in `.env`:

```ini
# GitHub Credentials
GITHUB_TOKEN=ghp_your_personal_access_token_or_app_token
GITHUB_DEFAULT_REPO=pranjal9091/prism

# Webhook & Approval Security
GITHUB_WEBHOOK_SECRET=your_webhook_hmac_secret
PRISM_API_KEY=your_internal_api_key_for_approvals

# Storage Paths
REVIEW_DB_PATH=prism_reviews.db
CHECKPOINT_DB_PATH=prism_checkpoints.db

# Safety Character Budgets
MAX_DIFF_CHARACTERS=200000
MAX_FILE_CHARACTERS=100000

# Optional: Langfuse Telemetry
LANGFUSE_ENABLED=false
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_HOST=https://cloud.langfuse.com
```

### 3. Start the Application

Launch the FastAPI review service and developer dashboard:

```bash
uv run uvicorn prism.api.app:app --host 127.0.0.1 --port 8000 --reload
```

The service exposes:
- **Developer Triage Dashboard**: [`http://127.0.0.1:8000/`](http://127.0.0.1:8000/)
- **Interactive OpenAPI Documentation**: [`http://127.0.0.1:8000/docs`](http://127.0.0.1:8000/docs)
- **Liveness & Health Probe**: [`http://127.0.0.1:8000/health`](http://127.0.0.1:8000/health)
- **Readiness Probe**: [`http://127.0.0.1:8000/ready`](http://127.0.0.1:8000/ready)

---

## Docker Deployment

PRism is packaged as a minimal, non-root container image based on `python:3.12-slim`:

### Running with Docker Compose

```bash
# Start service in background
docker compose up -d --build

# View container logs
docker compose logs -f

# Check health status
docker compose ps
```

The container runs as unprivileged user `prism` (`UID 1000`) and mounts SQLite databases to the persistent volume `prism-data`.

---

## Developer Triage Dashboard

PRism includes an opinionated, dark-mode developer dashboard designed for review triage and human-in-the-loop approvals:

- **Fleet Overview**: Real-time status badges (`PENDING`, `RUNNING`, `AWAITING_APPROVAL`, `APPROVED`, `PUBLISHED`, `REJECTED`, `FAILED`).
- **Risk Metrics**: Visual risk indicators (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with triggering policy rules.
- **Specialist Breakdown**: Categorized findings across Code Quality, Security, and Test suggestions.
- **One-Click Human Decisions**: Approve or reject paused reviews directly from the UI with audit attribution.
- **Responsive & Accessible**: Clean monospaced typography, zero CDN dependencies, and keyboard-friendly navigation.

---

## API Surface

| Method | Endpoint | Description | Security |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Web triage dashboard | Public / Web UI |
| `GET` | `/reviews/{id}` | Review detail view and approval actions | Public / Web UI |
| `GET` | `/health` | Liveness probe with database and observability status | Public |
| `GET` | `/ready` | Readiness probe verifying SQLite storage writability | Public |
| `POST` | `/webhooks/github` | GitHub webhook ingestion (`opened`, `synchronize`, `reopened`) | `X-Hub-Signature-256` HMAC + Deduplication |
| `GET` | `/api/reviews` | List recent PR reviews with status and risk metadata | Public / Internal |
| `GET` | `/api/reviews/{id}` | Retrieve full review payload and specialist findings | Public / Internal |
| `POST` | `/api/reviews/{id}/approve` | Resume review from checkpoint and publish to GitHub | `X-PRISM-API-KEY` |
| `POST` | `/api/reviews/{id}/reject` | Resume review from checkpoint and drop without posting | `X-PRISM-API-KEY` |
| `POST` | `/api/reviews/test` | Trigger test review using custom payload (no webhook needed) | Internal / Dev |

---

## Verification & Testing

### Test Suite

PRism includes a comprehensive test suite with 200 unit and boundary tests covering every subsystem:

```bash
uv run pytest -v
```

```text
============================= 200 passed in 2.24s ==============================
```

### Static Analysis & Linting

```bash
uv run ruff check .
```

### Deterministic Benchmark (25 Scenarios)

PRism ships with a benchmark dataset covering 25 pull-request scenarios with hand-curated ground truth:

```bash
# Run full benchmark suite
uv run python scripts/run_benchmark.py

# Filter by scenario or category
uv run python scripts/run_benchmark.py --category security
uv run python scripts/run_benchmark.py --category adversarial
uv run python scripts/run_benchmark.py --scenario S01
```

**Benchmark Results:**
- **Risk Classification Accuracy**: 100%
- **HIGH+ Recall (Safety Guarantee)**: 100%
- **Human Gate Recall**: 100%
- **Prompt Injection Detection Recall**: 100%
- **Finding F1 Score**: 100%

### Live Production Validation Harness

Verify the end-to-end multi-agent pipeline against live or simulated GitHub environments:

```bash
# Dry-run validation (executes full matrix, checks checkpointing, zero GitHub writes)
uv run python scripts/verify_live.py --dry-run

# Targeted scenario validation
uv run python scripts/verify_live.py --scenario security
uv run python scripts/verify_live.py --scenario injection

# Live publication to a dedicated test repository
uv run python scripts/verify_live.py --publish --repo pranjal9091/prism-test
```

---

## Observability & Privacy

PRism integrates with **Langfuse** for hierarchical tracing across every graph node (`guardrails` → `planner` → `specialists` → `aggregator` → `risk_policy` → `human_gate`):

- **Non-Blocking Telemetry**: Network or provider failures never crash the review pipeline.
- **Automated Secret Redaction**: All log messages, trace attributes, and error outputs are scrubbed for:
  - GitHub tokens (`ghp_*`, `gho_*`, `ghu_*`)
  - Provider API keys (`sk-*`)
  - Private keys (`-----BEGIN ... PRIVATE KEY-----`)
  - Bearer authorization headers
  - Database connection strings containing passwords
- **Honest Attribution**: Token usage is tracked directly from provider responses; costs are never fabricated when running in offline or mock modes.

---

## Project Structure

```text
prism/
├── api/                   # FastAPI application, routes, and webhook receiver
│   ├── routes/            # Webhook, reviews, approvals, health probes
│   └── templates/         # Developer triage dashboard templates
├── evaluation/            # Benchmark dataset (25 scenarios) and evaluation engine
├── github/                # Least-privilege GitHub client abstraction
├── graph/                 # LangGraph state machine, nodes, and checkpointing
│   └── nodes/             # Planner, Code Reviewer, Security, Tests, Aggregator, Human Gate
├── guardrails/            # Untrusted content sanitizer, injection detector, policy engine
├── mcp/                   # Model Context Protocol server and capability firewall
├── models/                # Pydantic schemas, risk models, review state
├── observability/         # Langfuse tracing, structured logging, secret scrubber
└── storage/               # SQLite review store and delivery idempotency index

scripts/
├── run_benchmark.py       # 25-scenario evaluation runner
├── verify_live.py         # Live production validation harness
├── verify_guardrails.py   # Guardrails and checkpoint verification
└── verify_mcp.py          # MCP permission firewall verification

tests/                     # 200 unit and integration tests
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
