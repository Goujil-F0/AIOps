import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.application_agent import application_agent
from agents.system_agent import system_agent
from orchestration.orchestrator import infrastructure_orchestrator
import pandas as pd
import pytest


def test_system_threshold_breach():
    """Test la détection de dépassements de seuils CPU et Disque."""
    sample_sys = pd.DataFrame(
        {
            "timestamp": ["2026-11-01 10:00:00"],
            "hostname": ["srv-test-01"],
            "cpu_usage": [95.5],
            "memory_usage": [60.0],
            "disk_usage": [92.0],
            "process_count": [120],
        }
    )
    config = {"thresholds": {"cpu": 80.0, "memory": 85.0, "disk": 90.0}}

    alerts = system_agent(sample_sys, config)
    assert len(alerts) == 2  # 1 CPU + 1 Disk
    metrics = [a["metric"] for a in alerts]
    assert "CPU" in metrics
    assert "DISK" in metrics


def test_application_agent_parsing():
    """Test l'extraction et le regroupement des erreurs applicatives."""
    raw_logs = [
        "2026-11-01 10:00:00 [INFO] Starting engine",
        "2026-11-01 10:01:00 [ERROR] Database connection failed to host 10.0.0.1",
        "2026-11-01 10:02:00 [ERROR] Database connection failed to host 10.0.0.2",
    ]
    res = application_agent(raw_logs)
    assert len(res["errors"]) == 2
    assert len(res["recommendations"]) >= 1


def test_orchestrator_consolidation():
    """Test de consolidation globale par l'orchestrateur."""
    data = {
        "network": pd.DataFrame(
            {
                "timestamp": ["2026-11-01 10:00:00"],
                "port": [80],
                "status": ["OK"],
                "latency_ms": [20.0],
            }
        ),
        "security": pd.DataFrame(
            {
                "timestamp": ["2026-11-01 10:00:00"],
                "username": ["user1"],
                "source_ip": ["10.0.0.1"],
                "status": ["SUCCESS"],
                "severity": ["LOW"],
                "event_type": ["AUTH"],
            }
        ),
        "system": pd.DataFrame(
            {
                "timestamp": ["2026-11-01 10:00:00"],
                "hostname": ["node1"],
                "cpu_usage": [30.0],
                "memory_usage": [40.0],
                "disk_usage": [50.0],
                "process_count": [100],
            }
        ),
        "application": ["2026-11-01 10:00:00 [INFO] All services healthy"],
    }
    config = {"thresholds": {"cpu": 80, "memory": 85, "disk": 90, "latency_ms": 150}}

    summary = infrastructure_orchestrator(data, config)
    assert summary["global_status"] == "HEALTHY"
    assert summary["total_alerts_count"] == 0