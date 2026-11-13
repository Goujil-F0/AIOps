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

def _failures(times, ip="198.51.100.9"):
    return pd.DataFrame(
        {
            "timestamp": times,
            "username": ["admin"] * len(times),
            "source_ip": [ip] * len(times),
            "status": ["FAILED"] * len(times),
            "severity": ["LOW"] * len(times),
            "event_type": ["LOGIN"] * len(times),
        }
    )


def test_spread_failures_are_not_bruteforce():
    """Des échecs espacés de plusieurs heures (erreurs de saisie) ne sont pas une attaque."""
    df = _failures([f"2026-11-0{d} 10:00:00" for d in (1, 2, 3)] + ["2026-11-01 15:00:00", "2026-11-02 15:00:00"])
    alerts = security_agent(df, {"security_rules": {"failed_login_alert_threshold": 5}})
    assert [a for a in alerts if a["type"] == "BRUTE_FORCE_SUSPECTED"] == []


def test_threshold_read_from_real_config_key():
    """Le seuil vient de `failed_login_alert_threshold` (clé du fichier de configuration)."""
    cfg = {"security_rules": {"failed_login_alert_threshold": 5}}
    four = _failures([f"2026-11-01 10:0{m}:00" for m in range(4)])
    five = _failures([f"2026-11-01 10:0{m}:00" for m in range(5)])
    assert security_agent(four, cfg) == []
    alerts = security_agent(five, cfg)
    assert len(alerts) == 1 and alerts[0]["failed_attempts"] == 5
    assert alerts[0]["window"]["start"] == "2026-11-01 10:00:00"
