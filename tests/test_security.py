import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.security_agent import security_agent
import pandas as pd
import pytest


def test_security_brute_force_detection():
    """Test la détection de répétitions d'échecs dépassant le seuil configuré."""
    sample_sec = pd.DataFrame(
        {
            "timestamp": ["2026-11-01 12:00:00"] * 4,
            "username": ["admin", "admin", "admin", "admin"],
            "source_ip": ["198.51.100.22"] * 4,
            "status": ["FAILED", "FAILED", "FAILED", "FAILED"],
            "severity": ["MEDIUM", "MEDIUM", "MEDIUM", "MEDIUM"],
            "event_type": ["LOGIN"] * 4,
        }
    )
    config = {"security_rules": {"max_failed_attempts": 3}}

    alerts = security_agent(sample_sec, config)
    bf_alerts = [a for a in alerts if a["type"] == "BRUTE_FORCE_SUSPECTED"]

    assert len(bf_alerts) == 1
    assert bf_alerts[0]["source_ip"] == "198.51.100.22"
    assert bf_alerts[0]["failed_attempts"] == 4
    assert bf_alerts[0]["severity"] == "CRITICAL"  # car compte admin ciblé