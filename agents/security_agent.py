import json

import pandas as pd

try:
    from agents.common import fmt_ts, split_bursts
except ImportError:
    from common import fmt_ts, split_bursts


def _densest_window(times: pd.Series, window_minutes: int):
    """Plus forte concentration d'événements dans une fenêtre glissante.
    Retourne (nombre, début, fin)."""
    t = list(pd.to_datetime(times).sort_values())
    best, best_i, best_j, i = 0, 0, 0, 0
    delta = pd.Timedelta(minutes=window_minutes)
    for j in range(len(t)):
        while t[j] - t[i] > delta:
            i += 1
        if j - i + 1 > best:
            best, best_i, best_j = j - i + 1, i, j
    return best, t[best_i], t[best_j]


def security_agent(security_data: pd.DataFrame, config: dict) -> list:
    """Agent de détection d'intrusions.

    Règle principale : au moins `failed_login_alert_threshold` échecs
    d'authentification depuis une même IP dans une fenêtre glissante de
    `failed_login_window_minutes` (30 min par défaut). Compter les échecs sur
    toute la période (ancienne version) produisait des faux positifs : un
    utilisateur légitime se trompe de temps en temps.
    """
    alerts = []
    if security_data.empty:
        return alerts

    # 1. Règles de sécurité (clé réelle du fichier de configuration en priorité)
    sec_rules = config.get("security_rules", {})
    threshold = sec_rules.get(
        "failed_login_alert_threshold",
        sec_rules.get("max_failed_attempts", sec_rules.get("max_failed_logins", 3)),
    )
    window_min = sec_rules.get("failed_login_window_minutes", 30)

    # 2. Échecs d'authentification
    failed_df = security_data[security_data["status"].str.upper() == "FAILED"].copy()
    failed_df["timestamp"] = pd.to_datetime(failed_df["timestamp"])

    covered_users = set()
    if not failed_df.empty:
        # 3. Regroupement par IP + règle de détection par fenêtre glissante
        for ip, grp in failed_df.groupby("source_ip"):
            count, start, end = _densest_window(grp["timestamp"], window_min)
            if count < threshold:
                continue
            # Étendre à toute la rafale contiguë (écart entre échecs <= fenêtre)
            for b_start, b_end, b_n in split_bursts(grp["timestamp"], window_min):
                if b_start <= start and end <= b_end:
                    start, end, count = b_start, b_end, b_n
                    break
            burst = grp[(grp["timestamp"] >= start) & (grp["timestamp"] <= end)]
            users = sorted(burst["username"].unique())
            covered_users.update(users)
            # 4. Classification
            severity = "CRITICAL" if count >= 10 or "admin" in users else "HIGH"
            alerts.append(
                {
                    "agent": "SecurityAgent",
                    "type": "BRUTE_FORCE_SUSPECTED",
                    "severity": severity,
                    "source_ip": ip,
                    "failed_attempts": int(count),
                    "total_failed_attempts": int(len(grp)),
                    "targeted_users": users,
                    "window": {"start": fmt_ts(start), "end": fmt_ts(end)},
                    "message": (
                        f"Suspicion de brute-force depuis {ip} : {count} échecs "
                        f"en {window_min} min maximum (seuil {threshold})"
                    ),
                    "recommendation": (
                        f"Proposer le blocage de {ip} au pare-feu (validation humaine "
                        f"requise) et vérifier les comptes ciblés : {', '.join(users)}."
                    ),
                }
            )

        # Comptes privilégiés visés, non déjà couverts par une alerte brute-force
        for user, grp in failed_df.groupby("username"):
            if user in ("admin", "root", "administrator") and len(grp) >= 5:
                if user in covered_users:
                    continue
                alerts.append(
                    {
                        "agent": "SecurityAgent",
                        "type": "PRIVILEGED_ACCOUNT_TARGETED",
                        "severity": "HIGH",
                        "user": user,
                        "failed_attempts": int(len(grp)),
                        "window": {
                            "start": fmt_ts(grp["timestamp"].min()),
                            "end": fmt_ts(grp["timestamp"].max()),
                        },
                        "message": f"Le compte privilégié '{user}' cumule {len(grp)} échecs d'authentification",
                        "recommendation": f"Imposer le MFA pour '{user}' et vérifier l'absence de session compromise.",
                    }
                )

    # 5. Événements à forte criticité non déjà couverts par une alerte brute-force
    sev = security_data["severity"].str.upper().isin(["HIGH", "CRITICAL"])
    high = security_data[sev].copy()
    high["timestamp"] = pd.to_datetime(high["timestamp"])
    done_ips = {a.get("source_ip") for a in alerts}
    for (ip, ev), grp in high.groupby(["source_ip", "event_type"]):
        if ip in done_ips:
            continue
        alerts.append(
            {
                "agent": "SecurityAgent",
                "type": "CRITICAL_SECURITY_EVENT",
                "severity": grp["severity"].iloc[0].upper(),
                "source_ip": ip,
                "event_type": ev,
                "window": {
                    "start": fmt_ts(grp["timestamp"].min()),
                    "end": fmt_ts(grp["timestamp"].max()),
                },
                "message": f"Événement de sévérité {grp['severity'].iloc[0]} : {ev} depuis {ip} ({len(grp)} occurrence(s))",
                "recommendation": "Analyser les journaux d'audit de la source ; isolement uniquement après validation humaine.",
            }
        )
    return alerts


if __name__ == "__main__":
    sec_df = pd.read_csv("datasets/security_logs.csv")
    with open("datasets/infrastructure_config.json") as f:
        cfg = json.load(f)
    res = security_agent(sec_df, cfg)
    print(f"=== Security Agent : {len(res)} alerte(s) ===")
    print(json.dumps(res, indent=2, ensure_ascii=False))
