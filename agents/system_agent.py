import json
import pandas as pd

try:
    from agents.common import fmt_ts
except ImportError:
    from common import fmt_ts


def _attach_windows(alerts: list, df: pd.DataFrame, limits: dict) -> None:
    """Ajoute à chaque alerte la fenêtre [premier, dernier] dépassement du seuil."""
    cols = {"CPU": "cpu_usage", "MEMORY": "memory_usage", "DISK": "disk_usage",
            "PROCESS_COUNT": "process_count"}
    if "timestamp" not in df.columns:
        return
    for a in alerts:
        col, th = cols.get(a["metric"]), limits.get(a["metric"])
        if col is None or th is None:
            continue
        rows = df[(df["hostname"] == a["hostname"]) & (df[col] > th)]
        if rows.empty:
            continue
        ts = pd.to_datetime(rows["timestamp"])
        a["window"] = {"start": fmt_ts(ts.min()), "end": fmt_ts(ts.max())}
        a["breach_samples_count"] = int(len(rows))


def system_agent(system_data: pd.DataFrame, config: dict) -> list:
    """Agent responsable de la supervision des ressources système (CPU, RAM, Disque, Processus)."""
    alerts = []

    if system_data.empty:
        return alerts

    # 1. Extraction des seuils configurés
    thresholds = config.get("thresholds", {})
    th_cpu = thresholds.get("cpu", 80.0)
    th_mem = thresholds.get("memory", 85.0)
    th_disk = thresholds.get("disk", 90.0)

    # 2. Analyse par serveur
    for host in system_data["hostname"].unique():
        host_df = system_data[system_data["hostname"] == host]

        max_cpu = float(host_df["cpu_usage"].max())
        max_mem = float(host_df["memory_usage"].max())
        max_disk = float(host_df["disk_usage"].max())
        max_proc = (
            int(host_df["process_count"].max())
            if "process_count" in host_df.columns
            else 0
        )

        # --- A. Analyse CPU ---
        if max_cpu > th_cpu:
            # Dépassements consécutifs / nombre d'échantillons en alerte
            breaches = len(host_df[host_df["cpu_usage"] > th_cpu])
            severity = "CRITICAL" if max_cpu >= 90.0 else "WARNING"

            alerts.append(
                {
                    "agent": "SystemAgent",
                    "hostname": host,
                    "metric": "CPU",
                    "severity": severity,
                    "max_value": round(max_cpu, 2),
                    "threshold": th_cpu,
                    "breach_samples_count": breaches,
                    "message": f"Surcharge CPU sur {host} : pic à {max_cpu:.2f}% (Seuil: {th_cpu}%, {breaches} mesures au-dessus du seuil)",
                    "recommendation": f"Vérifier les processus gourmands sur {host} via 'top/htop', optimiser les threads applicatifs ou allouer des vCPU supplémentaires.",
                }
            )

        # --- B. Analyse Mémoire ---
        if max_mem > th_mem:
            severity = "CRITICAL" if max_mem >= 92.0 else "WARNING"
            alerts.append(
                {
                    "agent": "SystemAgent",
                    "hostname": host,
                    "metric": "MEMORY",
                    "severity": severity,
                    "max_value": round(max_mem, 2),
                    "threshold": th_mem,
                    "message": f"Consommation mémoire critique sur {host} : {max_mem:.2f}% (Seuil: {th_mem}%)",
                    "recommendation": f"Risque imminent d'activation du kernel OOM-Killer sur {host}. Identifier d'éventuelles fuites mémoire et redémarrer les services concernés.",
                }
            )

        # --- C. Analyse Disque ---
        if max_disk > th_disk:
            severity = "CRITICAL" if max_disk >= 95.0 else "HIGH"
            alerts.append(
                {
                    "agent": "SystemAgent",
                    "hostname": host,
                    "metric": "DISK",
                    "severity": severity,
                    "max_value": round(max_disk, 2),
                    "threshold": th_disk,
                    "message": f"Espace disque saturé sur {host} : occupation à {max_disk:.2f}% (Seuil: {th_disk}%)",
                    "recommendation": f"Purger immédiatement les fichiers journaux obsolètes dans /var/log sur {host}, vider les caches temporaires et prévoir l'extension du volume de stockage.",
                }
            )

        # --- D. Analyse Process Count (Détection de fork bomb ou zombie processes) ---
        if max_proc > 300:
            alerts.append(
                {
                    "agent": "SystemAgent",
                    "hostname": host,
                    "metric": "PROCESS_COUNT",
                    "severity": "WARNING",
                    "max_value": max_proc,
                    "message": f"Nombre anormalement élevé de processus sur {host} ({max_proc} processus)",
                    "recommendation": f"Inspecter l'arbre des processus sur {host} pour éliminer d'éventuels processus zombies ou boucles infinies de subprocess.",
                }
            )

    _attach_windows(
        alerts, system_data,
        {"CPU": th_cpu, "MEMORY": th_mem, "DISK": th_disk, "PROCESS_COUNT": 300},
    )
    return alerts


# Bloc de test autonome
if __name__ == "__main__":
    sys_df = pd.read_csv("datasets/system_metrics.csv")
    with open("datasets/infrastructure_config.json") as f:
        cfg = json.load(f)

    alerts = system_agent(sys_df, cfg)
    print(f"=== Résultat System Agent : {len(alerts)} alerte(s) ===")
    print(json.dumps(alerts, indent=2))