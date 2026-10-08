"""LangGraph review workflow builder and runner with M3 guardrails, policy, and human gate."""

from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from prism.graph.nodes.code_reviewer import create_code_reviewer_node
from prism.graph.nodes.guardrails import create_guardrails_node
from prism.graph.nodes.human_gate import create_human_gate_node
from prism.graph.nodes.planner import create_planner_node
from prism.graph.nodes.risk_aggregator import create_aggregator_node
from prism.graph.nodes.risk_policy import create_risk_policy_node
from prism.graph.nodes.security_reviewer import create_security_reviewer_node
from prism.graph.nodes.test_suggester import create_test_suggester_node
from prism.graph.state import PRState


def build_review_graph(
    llm: Any | None = None,
    checkpointer: Any | None = None,
) -> CompiledStateGraph:
    """Build and compile the PRism multi-agent review graph.

    Graph Architecture:
                    START
                      │
                      ▼
                  guardrails
                      │
                      ▼
                   planner
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
    code_reviewer security_reviewer test_suggester
        │             │             │
        └─────────────┼─────────────┘
                      │
                      ▼
                  aggregator
                      │
                      ▼
                 risk_policy
                      │
                      ▼
                  human_gate
                      │
                      ▼
                     END
    """
    if llm is not None:
        model = llm
    else:
        from prism.models.factory import get_llm

        model = get_llm()

    builder = StateGraph(PRState)

    # 1. Register Nodes
    builder.add_node("guardrails", create_guardrails_node())
    builder.add_node("planner", create_planner_node(model))
    builder.add_node("code_reviewer", create_code_reviewer_node(model))
    builder.add_node("security_reviewer", create_security_reviewer_node(model))
    builder.add_node("test_suggester", create_test_suggester_node(model))
    builder.add_node("aggregator", create_aggregator_node())
    builder.add_node("risk_policy", create_risk_policy_node())
    builder.add_node("human_gate", create_human_gate_node())

    # 2. Directed Edges
    builder.add_edge(START, "guardrails")
    builder.add_edge("guardrails", "planner")

    # Fan-out to 3 parallel specialist branches
    builder.add_edge("planner", "code_reviewer")
    builder.add_edge("planner", "security_reviewer")
    builder.add_edge("planner", "test_suggester")

    # Fan-in barrier: Aggregator waits for all 3 specialists to complete
    builder.add_edge("code_reviewer", "aggregator")
    builder.add_edge("security_reviewer", "aggregator")
    builder.add_edge("test_suggester", "aggregator")

    # Policy evaluation and Human-in-the-Loop approval gate
    builder.add_edge("aggregator", "risk_policy")
    builder.add_edge("risk_policy", "human_gate")
    builder.add_edge("human_gate", END)

    return builder.compile(checkpointer=checkpointer)


async def execute_pr_review(
    repository: str,
    pull_request_number: int,
    pr_metadata: dict[str, Any],
    diff: str,
    changed_files: list[dict[str, Any]],
    llm: Any | None = None,
    checkpointer: Any | None = None,
    thread_id: str | None = None,
    relevant_context: dict[str, Any] | None = None,
    return_control: bool = False,
) -> PRState | tuple[PRState, CompiledStateGraph, dict[str, Any]]:
    """Initialize state and execute review graph until completion or human approval interrupt.

    If `return_control` is True, returns `(result_state, compiled_graph, config)`.
    Otherwise, returns `result_state` directly for clean backward compatibility.
    """
    active_checkpointer = checkpointer if checkpointer is not None else MemorySaver()
    graph = build_review_graph(llm=llm, checkpointer=active_checkpointer)
    t_id = thread_id or f"{repository}#{pull_request_number}"
    config = {"configurable": {"thread_id": t_id}}

    initial_state: PRState = {
        "repository": repository,
        "pull_request_number": pull_request_number,
        "pr_metadata": pr_metadata,
        "diff": diff,
        "changed_files": changed_files,
        "relevant_context": relevant_context or {},
        "code_findings": [],
        "security_findings": [],
        "test_findings": [],
        "aggregated_findings": [],
        "guardrail_errors": [],
        "errors": [],
        "status": "INITIALIZED",
    }

    result_state = await graph.ainvoke(initial_state, config=config)

    if return_control:
        return result_state, graph, config
    return result_state


async def resume_pr_review(
    graph: CompiledStateGraph,
    thread_id: str,
    decision: str,
    notes: str = "",
) -> PRState:
    """Resume an interrupted review graph with an explicit human decision ('approve' or 'reject')."""
    config = {"configurable": {"thread_id": thread_id}}
    resume_payload = {
        "decision": decision,
        "notes": notes,
    }
    result_state = await graph.ainvoke(Command(resume=resume_payload), config=config)
    return result_state
