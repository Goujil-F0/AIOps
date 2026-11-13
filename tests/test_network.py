import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.network_agent import network_agent
import pandas as pd
import pytest


def test_network_agent_nominal():
    """Test le calcul de la latence moyenne et du taux d'échec nominal."""
    sample_data = pd.DataFrame(
        {
            "timestamp": ["2026-11-01 10:00:00", "2026-11-01 10:01:00"],
            "port": [80, 443],
            "status": ["OK", "OK"],
            "latency_ms": [50.0, 70.0],
        }
    )
    config = {
        "thresholds": {"latency_ms": 100.0, "failure_rate_pct": 5.0},
        "services": [{"port": 80, "name": "HTTP"}],
    }

    res = network_agent(sample_data, config)
    assert res["mean_latency_ms"] == 60.0
    assert res["failure_rate_pct"] == 0.0
    assert len(res["alerts"]) == 0


def test_network_agent_failure_and_latency_spike():
    """Test la détection d'un pic critique de latence et d'un taux d'échec élevé."""
    sample_data = pd.DataFrame(
        {
            "timestamp": ["2026-11-01 10:00:00", "2026-11-01 10:01:00"],
            "port": [5432, 5432],
            "status": ["FAILED", "FAILED"],
            "latency_ms": [800.0, 1100.0],
        }
    )
    config = {
        "thresholds": {"latency_ms": 150.0, "failure_rate_pct": 5.0},
        "services": [{"port": 5432, "name": "DATABASE"}],
    }

    res = network_agent(sample_data, config)
    assert res["mean_latency_ms"] == 950.0
    assert res["failure_rate_pct"] == 100.0
    assert len(res["problematic_services"]) == 1
    assert res["problematic_services"][0]["port"] == 5432
    assert any(a["type"] == "LATENCY_SPIKE_DETECTED" for a in res["alerts"])