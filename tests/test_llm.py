import json
import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analysis.evaluation import load_project_data
from orchestration.llm_interpreter import (
    build_llm_input,
    check_grounding,
    deterministic_interpretation,
    generate_llm_structured_report,
    validate_output,
)
from orchestration.orchestrator import infrastructure_orchestrator

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="module")
def summary():
    data, config = load_project_data(ROOT)
    return infrastructure_orchestrator(data, config)


def test_deterministic_output_respects_schema_and_is_grounded(summary):
    out = deterministic_interpretation(build_llm_input(summary))
    assert validate_output(out) == []
    assert check_grounding(out, build_llm_input(summary)) == []


def test_validate_output_detects_missing_keys():
    assert validate_output({"situation_summary": "x"})
    assert validate_output("pas un dict")


def test_grounding_rejects_invented_metrics(summary):
    llm_input = build_llm_input(summary)
    good = deterministic_interpretation(llm_input)
    bad = dict(good, explanation="Le CPU a atteint 99.9 % sur web-server-77 depuis 8.8.8.8")
    problems = check_grounding(bad, llm_input)
    assert any("99.9" in p for p in problems)
    assert any("web-server-77" in p for p in problems)
    assert any("8.8.8.8" in p for p in problems)


def test_valid_llm_answer_is_accepted(summary):
    good = deterministic_interpretation(build_llm_input(summary))
    out = generate_llm_structured_report(summary, llm_client=lambda s, u: "```json\n" + json.dumps(good) + "\n```")
    assert out["generation_mode"] == "llm" and "fallback_reason" not in out


def test_hallucinating_llm_is_rejected_and_falls_back(summary):
    good = deterministic_interpretation(build_llm_input(summary))
    bad = dict(good, explanation="Ajouter 2 vCPU car la charge atteint 94.12 %")
    out = generate_llm_structured_report(summary, llm_client=lambda s, u: json.dumps(bad))
    assert out["generation_mode"] == "deterministic"
    assert "rejetée" in out["fallback_reason"]


def test_broken_llm_falls_back(summary):
    out = generate_llm_structured_report(summary, llm_client=lambda s, u: "pas du json")
    assert out["generation_mode"] == "deterministic"
    assert validate_output(out) == []
