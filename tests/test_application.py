import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.application_agent import application_agent


def _log(minute, level, msg, hour=10):
    return f"2026-11-01 {hour:02d}:{minute:02d}:00 {level} {msg}"


def test_levels_and_grouping_of_similar_errors():
    logs = [_log(0, "INFO", "ok"), _log(1, "WARNING", "slow"),
            _log(2, "ERROR", "HTTP 500 Internal Server Error"),
            _log(3, "ERROR", "HTTP 503 Internal Server Error")]
    res = application_agent(logs)
    assert len(res["errors"]) == 2 and len(res["warnings"]) == 1
    assert res["error_frequency"] == {"HTTP N Internal Server Error": 2}


def test_error_burst_vs_isolated_error():
    burst = [_log(m, "ERROR", "Request timeout") for m in (0, 5, 10, 15)]
    lone = [_log(0, "ERROR", "Database connection failed", hour=15)]
    res = application_agent(burst + lone)
    assert len(res["error_bursts"]) == 1
    assert res["error_bursts"][0]["errors_count"] == 4
    assert res["error_bursts"][0]["start"] == "2026-11-01 10:00:00"
    assert len(res["isolated_errors"]) == 1


def test_no_errors_returns_empty_structure():
    res = application_agent([_log(0, "INFO", "ok")])
    assert res["errors"] == [] and res["error_bursts"] == []
