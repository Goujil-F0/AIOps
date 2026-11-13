import json
import pandas as pd


def security_agent(security_data: pd.DataFrame, config: dict) -> list:
    """Agent responsable de la détection d'intrusions et de l'analyse des logs de sécurité."""
    alerts = []

    if security_data.empty:
        return alerts

    # 1. Extraction des règles de sécurité depuis la configuration
    sec_rules = config.get("security_rules", {})
    max_failed_auth = sec_rules.get(
        "max_failed_attempts",
        sec_rules.get("max_failed_logins", 3),
    )

    # 2. Identifier les échecs d'authentification
    failed_df = security_data[security_data["status"].str.upper() == "FAILED"]

    # 3. Regrouper les échecs par IP source et par utilisateur
    if not failed_df.empty:
        # A. Détection des répétitions d'échecs par IP (suspicion Brute-Force / Scanning)
        failed_by_ip = failed_df.groupby("source_ip").size()

        for ip, count in failed_by_ip.items():
            if count >= max_failed_auth:
                targeted_users = list(
                    failed_df[failed_df["source_ip"] == ip]["username"].unique()
                )

                # Classifier l'alerte
                severity = (
                    "CRITICAL"
                    if count >= 10 or "admin" in targeted_users
                    else "HIGH"
                )

                alerts.append(
                    {
                        "agent": "SecurityAgent",
                        "type": "BRUTE_FORCE_SUSPECTED",
                        "severity": severity,
                        "source_ip": ip,
                        "failed_attempts": int(count),
                        "targeted_users": targeted_users,
                        "message": f"Suspicion d'attaque par brute-force depuis l'IP {ip} ({count} échecs consécutifs)",
                        "recommendation": f"Bloquer l'adresse IP {ip} au niveau du pare-feu et vérifier l'intégrité des comptes ciblés: {', '.join(targeted_users)}.",
                    }
                )

        # B. Détection de comptes sensibles ciblés de manière répétée
        failed_by_user = failed_df.groupby("username").size()
        for user, count in failed_by_user.items():
            if user in ["admin", "root", "administrator"] and count >= 5:
                alerts.append(
                    {
                        "agent": "SecurityAgent",
                        "type": "PRIVILEGED_ACCOUNT_TARGETED",
                        "severity": "HIGH",
                        "user": user,
                        "failed_attempts": int(count),
                        "message": f"Le compte à privilèges '{user}' subit de multiples échecs d'authentification ({count} tentatives)",
                        "recommendation": f"Activer/imposer l'authentification multifacteur (MFA) pour '{user}' et vérifier l'absence de session compromise.",
                    }
                )

    # 4. Identification des événements à criticité native élevée (HIGH ou CRITICAL)
    high_sev_events = security_data[
        security_data["severity"].str.upper().isin(["HIGH", "CRITICAL"])
    ]

    # Déduplication par type d'événement et IP source pour éviter d'inonder la liste
    unique_threats = high_sev_events.drop_duplicates(
        subset=["event_type", "source_ip"]
    )
    for _, row in unique_threats.iterrows():
        # Éviter de dupliquer si déjà capturé par la détection brute-force
        if not any(
            a.get("source_ip") == row["source_ip"]
            and a.get("type") == "BRUTE_FORCE_SUSPECTED"
            for a in alerts
        ):
            alerts.append(
                {
                    "agent": "SecurityAgent",
                    "type": "CRITICAL_SECURITY_EVENT",
                    "severity": row["severity"].upper(),
                    "source_ip": row["source_ip"],
                    "event_type": row["event_type"],
                    "message": f"Événement de sévérité {row['severity']} détecté : {row['event_type']} depuis {row['source_ip']}",
                    "recommendation": "Isoler la machine source du réseau interne et analyser les journaux d'audit.",
                }
            )

    return alerts


# Bloc de test autonome
if __name__ == "__main__":
    sec_df = pd.read_csv("datasets/security_logs.csv")
    with open("datasets/infrastructure_config.json") as f:
        cfg = json.load(f)

    alerts = security_agent(sec_df, cfg)
    print(f"=== Résultat Security Agent : {len(alerts)} alerte(s) ===")
    print(json.dumps(alerts, indent=2))