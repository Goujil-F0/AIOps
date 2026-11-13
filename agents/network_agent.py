import pandas as pd

try:
    from agents.common import fmt_ts, split_bursts
except ImportError:  # exécution directe du fichier
    from common import fmt_ts, split_bursts


def _degradation_windows(df: pd.DataFrame, gap_minutes: int = 60) -> list:
    """Fenêtres temporelles des communications dégradées (SLOW) ou en échec."""
    if "status" not in df.columns or "timestamp" not in df.columns:
        return []
    d = df.copy()
    d["timestamp"] = pd.to_datetime(d["timestamp"])
    d["_st"] = d["status"].astype(str).str.upper()
    windows = []
    for status in ["FAILED", "TIMEOUT", "ERROR", "SLOW"]:
        rows = d[d["_st"] == status]
        for start, end, n in split_bursts(rows["timestamp"], gap_minutes):
            part = rows[(rows["timestamp"] >= start) & (rows["timestamp"] <= end)]
            windows.append(
                {
                    "status": status,
                    "ports": sorted(int(p) for p in part["port"].unique()),
                    "start": fmt_ts(start),
                    "end": fmt_ts(end),
                    "count": int(n),
                    "max_latency_ms": round(float(part["latency_ms"].max()), 2),
                }
            )
    return windows


def network_agent(network_data: pd.DataFrame, config: dict) -> dict:
    """Agent responsable de la supervision des communications réseau."""
    results = {
        "incident_windows": [],
        "mean_latency_ms": 0.0,
        "failure_rate_pct": 0.0,
        "total_communications": len(network_data),
        "problematic_services": [],
        "alerts": [],
    }

    if network_data.empty:
        return results

    # 1. Extraction des seuils depuis la configuration
    thresholds = config.get("thresholds", {})
    max_latency_thresh = thresholds.get("latency_ms", 150.0)
    max_failure_rate_thresh = thresholds.get("failure_rate_pct", 5.0)

    # Dictionnaire des services connus pour contextualiser les ports
    services_map = {
        s.get("port"): s.get("name") for s in config.get("services", [])
    }

    # 2. Calcul de la latence moyenne
    mean_latency = float(network_data["latency_ms"].mean())
    results["mean_latency_ms"] = round(mean_latency, 2)

    # 3. Calcul du taux d'échec
    failed_df = network_data[
        network_data["status"].str.upper().isin(["FAILED", "TIMEOUT", "ERROR"])
    ]
    failure_rate = (len(failed_df) / len(network_data)) * 100.0
    results["failure_rate_pct"] = round(failure_rate, 2)

    # 4. Identification des services / ports problématiques
    if not failed_df.empty:
        port_failures = failed_df.groupby("port").size()
        for port, fail_count in port_failures.items():
            service_name = services_map.get(port, f"Service_Port_{port}")
            results["problematic_services"].append(
                {
                    "port": int(port),
                    "service": service_name,
                    "failed_requests": int(fail_count),
                    "issue": "availability",
                }
            )

    # 5. Comparaison aux seuils et Génération des alertes
    if mean_latency > max_latency_thresh:
        results["alerts"].append(
            {
                "type": "LATENCY_THRESHOLD_EXCEEDED",
                "severity": "WARNING",
                "message": f"Latence moyenne ({mean_latency:.2f} ms) supérieure au seuil ({max_latency_thresh} ms)",
            }
        )

    # Alerte sur les pics extrêmes individuels
    peak_latency = network_data["latency_ms"].max()
    if peak_latency > 500:
        results["alerts"].append(
            {
                "type": "LATENCY_SPIKE_DETECTED",
                "severity": "HIGH",
                "message": f"Pic critique de latence détecté : {peak_latency:.2f} ms",
            }
        )

    if failure_rate > max_failure_rate_thresh:
        results["alerts"].append(
            {
                "type": "HIGH_FAILURE_RATE",
                "severity": "CRITICAL",
                "message": f"Taux d'échec ({failure_rate:.2f}%) supérieur au seuil ({max_failure_rate_thresh}%)",
            }
        )

    if len(failed_df) > 0:
        results["alerts"].append(
            {
                "type": "NETWORK_FAILURES_DETECTED",
                "severity": "HIGH",
                "message": f"{len(failed_df)} requêtes réseau ont échoué",
            }
        )

    # 6. Fenêtres de dégradation (SLOW / FAILED) et services lents
    results["incident_windows"] = _degradation_windows(network_data)
    for w in results["incident_windows"]:
        if w["status"] != "SLOW":
            continue
        for port in w["ports"]:
            results["problematic_services"].append(
                {
                    "port": port,
                    "service": services_map.get(port, f"Service_Port_{port}"),
                    "failed_requests": 0,
                    "slow_requests": w["count"],
                    "issue": "performance",
                }
            )
        results["alerts"].append(
            {
                "type": "SLOW_COMMUNICATIONS",
                "severity": "WARNING",
                "message": (
                    f"{w['count']} communications lentes sur les ports "
                    f"{', '.join(map(str, w['ports']))} entre {w['start']} et {w['end']}"
                ),
            }
        )

    return results


# Bloc de test autonome de l'agent
if __name__ == "__main__":
    import json

    net_df = pd.read_csv("datasets/network_logs.csv")
    with open("datasets/infrastructure_config.json") as f:
        cfg = json.load(f)

    res = network_agent(net_df, cfg)
    print("=== Résultat Network Agent ===")
    print(json.dumps(res, indent=2))