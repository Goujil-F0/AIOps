import json
import os
import sys

import pandas as pd
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analysis.evaluation import load_project_data
from orchestration.orchestrator import (
    cluster_events,
    extract_events,
    infrastructure_orchestrator,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HAS_DATA = os.path.exists(os.path.join(ROOT, "datasets", "network_logs.csv"))


def _ev(start, end, domain="system"):
    return {"start": pd.Timestamp(start), "end": pd.Timestamp(end), "domain": domain}


def test_clustering_merges_overlapping_and_separates_distant_events():
    a = _ev("2026-11-01 10:00", "2026-11-01 11:00")
    b = _ev("2026-11-01 10:50", "2026-11-01 12:00", "network")   # chevauche a
    c = _ev("2026-11-01 12:20", "2026-11-01 12:40", "security")  # 20 min après b : proche
    d = _ev("2026-11-01 18:00", "2026-11-01 18:10")              # loin
    clusters = cluster_events([d, c, b, a], tolerance_min=30)
    assert [len(x) for x in clusters] == [3, 1]


def _minimal_data(app_lines):
    return {
        "network": pd.DataFrame({"timestamp": ["2026-11-01 10:00:00"], "port": [80],
                                 "status": ["OK"], "latency_ms": [20.0]}),
        "security": pd.DataFrame({"timestamp": ["2026-11-01 10:00:00"], "username": ["u"],
                                  "source_ip": ["10.0.0.1"], "status": ["SUCCESS"],
                                  "severity": ["INFO"], "event_type": ["LOGIN"]}),
        "system": pd.DataFrame({"timestamp": ["2026-11-01 10:00:00"], "hostname": ["n1"],
                                "cpu_usage": [30.0], "memory_usage": [40.0],
                                "disk_usage": [50.0], "process_count": [100]}),
        "application": app_lines,
    }


def test_application_alerts_are_consolidated_in_global_status():
    lines = [f"2026-11-01 10:{m:02d}:00 ERROR Request timeout" for m in range(0, 12, 2)]
    out = infrastructure_orchestrator(_minimal_data(lines), {"thresholds": {"cpu": 80, "memory": 85, "disk": 90}})
    assert out["total_alerts_count"] == 1
    assert out["global_status"] == "DEGRADED"
    assert out["cross_incident_analysis"][0]["confidence"] == "ISOLATED"


@pytest.mark.skipif(not HAS_DATA, reason="datasets absents")
def test_real_data_incidents_and_causality_wording():
    data, config = load_project_data(ROOT)
    out = infrastructure_orchestrator(data, config)
    assert out["global_status"] == "CRITICAL"
    incs = out["cross_incident_analysis"]
    assert len(incs) == 6
    # Aucun incident ne revendique une causalité démontrée
    assert all("non démontrée" in i["causality_status"] or "Aucune corrélation" in i["causality_status"] for i in incs)
    assert not any("confirmée" in json.dumps(i, ensure_ascii=False) for i in incs)
    # La saturation CPU (05:40) suit le début des tentatives (05:00) : même incident, ordre respecté
    inc3 = next(i for i in incs if "203.0.113.77" in i["affected_components"])
    assert "web-server-01" in inc3["affected_components"]
    assert inc3["chronology"].index("203.0.113.77") < inc3["chronology"].index("web-server-01")
    # Le port 5432 n'est PAS rattaché à la saturation CPU (3 h d'écart)
    inc4 = next(i for i in incs if "DATABASE:5432" in i["affected_components"])
    assert "web-server-01" not in inc4["affected_components"]
