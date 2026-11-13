"""Évaluation des agents et des détecteurs d'anomalies (point 21 du TP).

Indicateurs : anomalies détectées, taux de détection, faux positifs, faux négatifs,
nombre d'alertes, temps d'exécution. Référence : analysis/ground_truth.json
(anomalies injectées, reconstituées à partir des données — voir la note du fichier).
"""
import json
import os
import statistics
import sys
import time

import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.application_agent import application_agent
from agents.network_agent import network_agent
from agents.security_agent import security_agent
from agents.system_agent import system_agent
from analysis.anomaly_detection import detect_anomalies_ml
from orchestration.orchestrator import extract_events, infrastructure_orchestrator

GT_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")


# ------------------------------------------------------------ appariement d'événements
def load_ground_truth(path: str = GT_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _matches(ev: dict, gt: dict, tol: pd.Timedelta) -> bool:
    if ev["domain"] != gt["domain"]:
        return False
    if gt.get("component") and gt["component"] not in str(ev["component"]):
        return False
    return ev["start"] <= pd.Timestamp(gt["end"]) + tol and pd.Timestamp(gt["start"]) <= ev["end"] + tol


def match_events(detected: list, gt_events: list, tolerance_min: int = 30) -> dict:
    """Appariement domaine + composant + chevauchement temporel (tolérance en minutes).
    Plusieurs détections du même épisode ne comptent pas comme faux positifs."""
    tol = pd.Timedelta(minutes=tolerance_min)
    tp_det = [e for e in detected if any(_matches(e, g, tol) for g in gt_events)]
    found = [g for g in gt_events if any(_matches(e, g, tol) for e in detected)]
    n_gt, n_det = len(gt_events), len(detected)
    return {
        "detected": n_det,
        "ground_truth": n_gt,
        "true_positives": len(found),
        "false_positives": n_det - len(tp_det),
        "false_negatives": n_gt - len(found),
        "detection_rate": round(len(found) / n_gt, 3) if n_gt else None,
        "precision": round(len(tp_det) / n_det, 3) if n_det else None,
        "missed": [g["id"] for g in gt_events if g not in found],
    }


def row_metrics(y_true, y_pred) -> dict:
    yt, yp = pd.Series(y_true).astype(bool), pd.Series(y_pred).astype(bool)
    tp, fp = int((yt & yp).sum()), int((~yt & yp).sum())
    fn, tn = int((yt & ~yp).sum()), int((~yt & ~yp).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"flagged": tp + fp, "tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0}


# ------------------------------------------------------------ baselines
def naive_security_events(sec_df: pd.DataFrame, threshold: int) -> list:
    """Ancienne règle (v1) : nombre TOTAL d'échecs par IP sur toute la période."""
    f = sec_df[sec_df["status"].str.upper() == "FAILED"].copy()
    f["timestamp"] = pd.to_datetime(f["timestamp"])
    out = []
    for ip, g in f.groupby("source_ip"):
        if len(g) >= threshold:
            out.append({"domain": "security", "component": ip,
                        "start": g["timestamp"].min(), "end": g["timestamp"].max()})
    return out


def label_system_rows(sys_df: pd.DataFrame, gt_events: list) -> pd.Series:
    ts = pd.to_datetime(sys_df["timestamp"])
    y = pd.Series(False, index=sys_df.index)
    for g in gt_events:
        if g["domain"] == "system":
            y |= (sys_df["hostname"] == g["component"]) & (ts >= pd.Timestamp(g["start"])) & (ts <= pd.Timestamp(g["end"]))
    return y


def evaluate_system_detectors(sys_df: pd.DataFrame, config: dict, gt_events: list) -> dict:
    th = config["thresholds"]
    y = label_system_rows(sys_df, gt_events)
    rules = (sys_df["cpu_usage"] > th["cpu"]) | (sys_df["memory_usage"] > th["memory"]) | (sys_df["disk_usage"] > th["disk"])
    results = {"Règles (seuils du fichier de config)": row_metrics(y, rules)}
    ml = {}
    for name, kw in {
        "IF brut 5 % (exemple du sujet)": dict(contamination=0.05, scale=False),
        "IF standardisé 2 %": dict(contamination=0.02),
        "IF standardisé 5 %": dict(contamination=0.05),
        "IF standardisé 10 %": dict(contamination=0.10),
        "IF standardisé par serveur 5 %": dict(contamination=0.05, per_host=True),
    }.items():
        pred = detect_anomalies_ml(sys_df, **kw)["anomaly"].reindex(sys_df.index).fillna(0).astype(bool)
        ml[name] = pred
        results[name] = row_metrics(y, pred)
    results["Règles ∪ IF standardisé 5 %"] = row_metrics(y, rules | ml["IF standardisé 5 %"])
    best = max(results, key=lambda k: (results[k]["f1"], results[k]["precision"]))
    return {"n_rows": int(len(sys_df)), "n_anomalous_rows": int(y.sum()),
            "detectors": results, "best_by_f1": best}


# ------------------------------------------------------------ chronométrage
def _time(fn, reps: int = 5) -> float:
    runs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        runs.append(time.perf_counter() - t0)
    return round(statistics.median(runs) * 1000, 2)  # ms


# ------------------------------------------------------------ évaluation complète
def run_evaluation(data: dict, config: dict, gt_path: str = GT_PATH) -> dict:
    gt = load_ground_truth(gt_path)
    tol, gts = gt["tolerance_minutes"], gt["events"]

    net, sec = network_agent(data["network"], config), security_agent(data["security"], config)
    sy, app = system_agent(data["system"], config), application_agent(data["application"])
    events = extract_events(net, sec, sy, app)

    agents = {}
    spec = {
        "network": (lambda: network_agent(data["network"], config), len(net["alerts"])),
        "security": (lambda: security_agent(data["security"], config), len(sec)),
        "system": (lambda: system_agent(data["system"], config), len(sy)),
        "application": (lambda: application_agent(data["application"]), len(app["error_bursts"])),
    }
    for dom, (fn, n_alerts) in spec.items():
        m = match_events([e for e in events if e["domain"] == dom],
                         [g for g in gts if g["domain"] == dom], tol)
        m["alerts"], m["runtime_ms"] = n_alerts, _time(fn)
        agents[dom] = m
    total = match_events(events, gts, tol)
    total["alerts"] = sum(a["alerts"] for a in agents.values())
    total["runtime_ms"] = _time(lambda: infrastructure_orchestrator(data, config), reps=3)

    # Ablation : règle de sécurité v1 (comptage total) vs règle actuelle (fenêtre glissante)
    gs = [g for g in gts if g["domain"] == "security"]
    thr = config["security_rules"]["failed_login_alert_threshold"]
    ablation = {
        "v1 : total d'échecs par IP ≥ 3 (seuil codé en dur)": match_events(naive_security_events(data["security"], 3), gs, tol),
        f"v1 : total d'échecs par IP ≥ {thr} (seuil de la config)": match_events(naive_security_events(data["security"], thr), gs, tol),
        f"v2 : ≥ {thr} échecs en fenêtre glissante (version livrée)": agents["security"],
    }

    # Regroupement en incidents
    summary = infrastructure_orchestrator(data, config)
    by_id = {e["id"]: e for e in events}
    groups = {}
    for g in gts:
        groups.setdefault(g["group"], set()).add(g["id"])
    tolp = pd.Timedelta(minutes=tol)
    correct = 0
    for inc in summary["cross_incident_analysis"]:
        ids = {g["id"] for e in inc["events"] for g in gts if _matches(by_id[e], g, tolp)}
        if ids in groups.values():
            correct += 1

    return {
        "ground_truth_events": len(gts),
        "agents": agents, "total": total, "security_ablation": ablation,
        "system_detectors": evaluate_system_detectors(data["system"], config, gts),
        "incident_grouping": {"detected_incidents": len(summary["cross_incident_analysis"]),
                              "expected_incidents": len(groups), "exactly_correct": correct},
    }


# ------------------------------------------------------------ rapport markdown
def render_markdown(r: dict) -> str:
    L = ["# Évaluation des agents et des détecteurs (point 21)", "",
         "**Référence** : `analysis/ground_truth.json` — 8 épisodes injectés, reconstitués par inspection des données "
         "(aucune étiquette fournie). **Appariement** : même domaine, même composant (IP / serveur) et chevauchement "
         "temporel à ± 30 min. Plusieurs détections du même épisode ne comptent pas comme faux positifs.", "",
         "> **Limite à garder en tête** : les épisodes injectés dépassent les seuils de configuration, donc les règles "
         "sont avantagées par construction. Ce banc d'essai mesure la cohérence et la robustesse, pas la performance en production.", "",
         "## 1. Agents", "",
         "| Agent | Détections | Épisodes connus | Détectés (TP) | Faux positifs | Faux négatifs | Taux de détection | Alertes | Temps (ms) |",
         "|---|---|---|---|---|---|---|---|---|"]
    for k, a in {**r["agents"], "**Total**": r["total"]}.items():
        L.append(f"| {k} | {a['detected']} | {a['ground_truth']} | {a['true_positives']} | {a['false_positives']} | "
                 f"{a['false_negatives']} | {a['detection_rate']:.0%} | {a['alerts']} | {a['runtime_ms']} |")
    L += ["", "Le temps du total correspond à l'orchestrateur complet (4 agents, corrélation, Isolation Forest).", "",
          "## 2. Agent sécurité : comptage total (v1) contre fenêtre glissante (v2)", "",
          "| Règle | Détections | Faux positifs | Faux négatifs | Précision |", "|---|---|---|---|---|"]
    for k, a in r["security_ablation"].items():
        L.append(f"| {k} | {a['detected']} | {a['false_positives']} | {a['false_negatives']} | {a['precision']:.0%} |")
    sd = r["system_detectors"]
    L += ["", "## 3. Détection d'anomalies sur `system_metrics.csv` (niveau observation)", "",
          f"{sd['n_anomalous_rows']} observations anormales sur {sd['n_rows']}.", "",
          "| Détecteur | Signalées | VP | FP | FN | Précision | Rappel | F1 | Taux de FP |", "|---|---|---|---|---|---|---|---|---|"]
    for k, m in sd["detectors"].items():
        L.append(f"| {k} | {m['flagged']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['false_positive_rate']} |")
    ig = r["incident_grouping"]
    L += ["", f"**Meilleur détecteur selon le F1 : {sd['best_by_f1']}.**", "",
          "## 4. Regroupement en incidents (orchestrateur)", "",
          f"{ig['detected_incidents']} incidents détectés pour {ig['expected_incidents']} attendus ; "
          f"{ig['exactly_correct']} regroupés exactement comme dans la référence.", ""]
    return "\n".join(L)


def load_project_data(base: str = "."):
    data = {"network": pd.read_csv(f"{base}/datasets/network_logs.csv"),
            "security": pd.read_csv(f"{base}/datasets/security_logs.csv"),
            "system": pd.read_csv(f"{base}/datasets/system_metrics.csv")}
    with open(f"{base}/datasets/application_logs.txt", encoding="utf-8") as f:
        data["application"] = f.readlines()
    with open(f"{base}/datasets/infrastructure_config.json", encoding="utf-8") as f:
        config = json.load(f)
    return data, config


def main(base: str = "."):
    data, config = load_project_data(base)
    res = run_evaluation(data, config)
    with open(f"{base}/analysis/evaluation_results.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    with open(f"{base}/analysis/evaluation_report.md", "w", encoding="utf-8") as f:
        f.write(render_markdown(res))
    return res


if __name__ == "__main__":
    main()
