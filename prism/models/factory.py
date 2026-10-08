"""Model factory and deterministic mock LLM abstractions."""

import os
from typing import Any, TypeVar

from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel

from prism.graph.state import (
    CodeReviewOutput,
    ReviewPlan,
    SecurityReviewOutput,
    TestSuggestionOutput,
)

T = TypeVar("T", bound=BaseModel)


class MockReviewLLM:
    """Deterministic mock LLM for unit tests and offline evaluation.

    Provides `.with_structured_output(schema)` without calling external APIs.
    """

    def __init__(
        self,
        plan: ReviewPlan | None = None,
        code_output: CodeReviewOutput | None = None,
        security_output: SecurityReviewOutput | None = None,
        test_output: TestSuggestionOutput | None = None,
        error_on_schema: type | None = None,
    ):
        self.plan = plan
        self.code_output = code_output
        self.security_output = security_output
        self.test_output = test_output
        self.error_on_schema = error_on_schema

    def with_structured_output(self, schema: type[T]) -> Runnable[Any, T]:
        """Return a runnable returning deterministic structured data for the schema."""
        if self.error_on_schema is not None and issubclass(self.error_on_schema, schema):
            def raise_error(_: Any) -> T:
                raise RuntimeError(f"Simulated LLM failure for schema {schema.__name__}")

            return RunnableLambda(raise_error)

        if issubclass(schema, ReviewPlan):
            response = self.plan or ReviewPlan(
                summary="Default mock plan: inspect code changes.",
                key_changes=["Mock functional change"],
                affected_components=["core"],
                security_critical=False,
                testing_concerns=["unit test coverage"],
                specialist_guidance={},
            )
        elif issubclass(schema, CodeReviewOutput):
            response = self.code_output or CodeReviewOutput(findings=[])
        elif issubclass(schema, SecurityReviewOutput):
            response = self.security_output or SecurityReviewOutput(findings=[])
        elif issubclass(schema, TestSuggestionOutput):
            response = self.test_output or TestSuggestionOutput(findings=[])
        else:
            response = schema()

        return RunnableLambda(lambda _: response)


def get_llm(
    model_name: str | None = None,
    temperature: float = 0.0,
    mock_llm: Any | None = None,
) -> Any:
    """Retrieve an LLM instance.

    If `mock_llm` is provided, returns the mock instance.
    If `OPENAI_API_KEY` is present in the environment, returns `ChatOpenAI`.
    Otherwise, returns a fallback MockReviewLLM to permit zero-config testing.
    """
    if mock_llm is not None:
        return mock_llm

    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and api_key.strip():
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_name or "gpt-4o-mini",
            temperature=temperature,
            api_key=api_key.strip(),
        )

    # Default fallback when no API key is available
    return MockReviewLLM()
