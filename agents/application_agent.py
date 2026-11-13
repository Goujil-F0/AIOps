from collections import Counter
import json
import re
import pandas as pd


def application_agent(application_logs: list) -> dict:
    """Agent responsable de l'analyse des journaux applicatifs, de la catégorisation des erreurs

    et de l'identification des périodes de dégradation logicielle.
    """
    results = {
        "errors": [],
        "warnings": [],
        "error_frequency": {},
        "peak_error_period": None,
        "recommendations": [],
    }

    if not application_logs:
        return results

    # 1. Regex de détection du niveau et extraction structurée
    level_pattern = re.compile(r"\b(INFO|WARNING|WARN|ERROR|CRITICAL)\b")
    parsed_events = []

    for line in application_logs:
        line_clean = line.strip()
        if not line_clean:
            continue

        match = level_pattern.search(line_clean)
        if match:
            lvl = match.group(1).upper()
            if lvl == "WARN":
                lvl = "WARNING"
            start_idx = match.start()
            end_idx = match.end()

            ts_str = line_clean[:start_idx].strip(" []-:,")
            msg_str = line_clean[end_idx:].strip(" []-:,")

            event_dict = {"timestamp": ts_str, "level": lvl, "message": msg_str}
            parsed_events.append(event_dict)

            if lvl == "ERROR":
                results["errors"].append(event_dict)
            elif lvl == "WARNING":
                results["warnings"].append(event_dict)

    if not results["errors"]:
        return results

    # 2. Regroupement des erreurs similaires (Normalisation des IDs et valeurs numériques)
    normalized_errors = []
    for err in results["errors"]:
        msg = err["message"]
        norm = re.sub(r"\b\d+\b", "N", msg)
        norm = re.sub(r"0x[0-9a-fA-F]+", "HEX", norm)
        normalized_errors.append(norm.strip())

    error_counts = dict(Counter(normalized_errors))
    results["error_frequency"] = error_counts

    # 3. Identification des périodes présentant une concentration d'erreurs (fenêtrage temporel)
    try:
        err_df = pd.DataFrame(results["errors"])
        err_df["timestamp"] = pd.to_datetime(err_df["timestamp"])
        # Regroupement par tranche de 1 heure
        hourly_counts = (
            err_df.set_index("timestamp")
            .resample("1h")
            .size()
            .sort_values(ascending=False)
        )
        if not hourly_counts.empty and hourly_counts.iloc[0] > 0:
            peak_hour = hourly_counts.index[0]
            peak_val = int(hourly_counts.iloc[0])
            results["peak_error_period"] = {
                "period": str(peak_hour),
                "errors_count": peak_val,
            }
    except Exception:
        results["peak_error_period"] = "Non déterminé"

    # 4. Pistes de diagnostic & Recommandations ciblées
    for signature, count in error_counts.items():
        sig_lower = signature.lower()
        if "database" in sig_lower or "connection" in sig_lower:
            results["recommendations"].append(
                f"[BDD / Persistance] {count} erreurs liées à la base de données ('{signature}'). "
                f"Piste de diagnostic : Vérifier la disponibilité de l'hôte BDD, la saturation du pool de connexions (connection pool exhaustion) et les requêtes lentes bloquantes."
            )
        elif "timeout" in sig_lower or "timed out" in sig_lower:
            results["recommendations"].append(
                f"[Réseau / Latence] {count} erreurs de type Timeout détectées. "
                f"Piste de diagnostic : Examiner la latence réseau inter-services ou un engorgement CPU/I-O sur le service cible."
            )
        elif "nullpointer" in sig_lower or "500" in sig_lower or "internal" in sig_lower:
            results["recommendations"].append(
                f"[Bug Applicatif] {count} exceptions internes détectées. "
                f"Piste de diagnostic : Analyser la stack trace du code source et tester la gestion des exceptions sur les données en entrée."
            )
        else:
            results["recommendations"].append(
                f"[Application] {count} occurrences de : '{signature}'. Piste : Contrôler les logs d'erreurs détaillés du service concerné."
            )

    return results


# Bloc de test autonome
if __name__ == "__main__":
    with open("datasets/application_logs.txt", "r", encoding="utf-8") as f:
        raw_logs = f.readlines()

    res = application_agent(raw_logs)
    print(f"=== Résultat Application Agent ===")
    print(f"Total erreurs : {len(res['errors'])}")
    print(f"Total avertissements : {len(res['warnings'])}")
    print(f"Période de pic : {res['peak_error_period']}")
    print(f"Distribution des erreurs : {json.dumps(res['error_frequency'], indent=2)}")
    print(f"\nRecommandations techniques :")
    for r in res["recommendations"]:
        print(f"- {r}")