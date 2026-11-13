import os
import sys

import pandas as pd
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analysis.anomaly_detection import detect_anomalies_ml
from analysis.evaluation import load_project_data, match_events, naive_security_events, row_metrics, run_evaluation

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_match_events_counts_tp_fp_fn():
    gt = [{"id": "A", "domain": "system", "component": "h1", "start": "2026-11-01 10:00:00", "end": "2026-11-01 11:00:00"},
          {"id": "B", "domain": "system", "component": "h2", "start": "2026-11-01 15:00:00", "end": "2026-11-01 16:00:00"}]
    ts = pd.Timestamp
    det = [{"domain": "system", "component": "h1", "start": ts("2026-11-01 10:10"), "end": ts("2026-11-01 10:30")},
           {"domain": "system", "component": "h1", "start": ts("2026-11-01 10:40"), "end": ts("2026-11-01 10:50")},  # doublon
           {"domain": "system", "component": "h3", "start": ts("2026-11-01 10:10"), "end": ts("2026-11-01 10:30")}]  # mauvais serveur
    m = match_events(det, gt, 30)
    assert (m["true_positives"], m["false_positives"], m["false_negatives"]) == (1, 1, 1)
    assert m["detection_rate"] == 0.5 and m["missed"] == ["B"]


def test_row_metrics():
    m = row_metrics([1, 1, 0, 0, 0], [1, 0, 1, 0, 0])
    assert (m["tp"], m["fp"], m["fn"]) == (1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["f1"] == 0.5


def test_isolation_forest_adds_binary_anomaly_column():
    df = pd.DataFrame({"hostname": ["h"] * 100, "cpu_usage": [40.0 + i % 5 for i in range(100)],
                       "memory_usage": [50.0] * 100, "disk_usage": [60.0] * 100, "process_count": [140] * 100})
    df.loc[10, "cpu_usage"] = 99.0
    out = detect_anomalies_ml(df, contamination=0.02)
    assert set(out["anomaly"].unique()) <= {0, 1}
    assert out.loc[10, "anomaly"] == 1


@pytest.mark.skipif(not os.path.exists(os.path.join(ROOT, "datasets", "network_logs.csv")), reason="datasets absents")
def test_full_evaluation_on_dataset():
    data, config = load_project_data(ROOT)
    r = run_evaluation(data, config)
    assert r["total"]["false_negatives"] == 0 and r["total"]["false_positives"] == 0
    assert r["incident_grouping"]["exactly_correct"] == r["incident_grouping"]["expected_incidents"]
    # La règle v1 de comptage total produisait 4 faux positifs en sécurité
    assert len(naive_security_events(data["security"], 3)) == 5
    ab = list(r["security_ablation"].values())
    assert ab[0]["false_positives"] == 4 and ab[-1]["false_positives"] == 0
