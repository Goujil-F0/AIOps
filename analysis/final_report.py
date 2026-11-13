"""Génère le rapport final « incidents détectés et recommandations » (livrable 24)."""
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestration.llm_interpreter import generate_llm_structured_report


def render_final_report(summary: dict, interpretation: dict, evaluation: dict = None) -> str:
    b, a = summary["alerts_breakdown"], summary["agents_results"]
    net, app = a["network"], a["application"]
    L = ["# Rapport final — Incidents détectés et recommandations", "",
         "**Plateforme AIOps DemoTech** — période analysée : 1er au 3 novembre 2026 (données synthétiques).", "",
         "## 1. Synthèse", "",
         f"- **État global : {summary['global_status']}**",
         f"- {summary['total_alerts_count']} alertes consolidées (CRITICAL : {b['CRITICAL']}, HIGH : {b['HIGH']}, WARNING : {b['WARNING']}).",
         f"- {len(summary['cross_incident_analysis'])} incidents après regroupement temporel (tolérance de 30 min).",
         f"- Réseau : latence moyenne {net['mean_latency_ms']} ms, taux d'échec {net['failure_rate_pct']} %.",
         f"- Application : {app['errors_count']} erreurs, {app['warnings_count']} avertissements.",
         f"- Texte d'interprétation produit par : **{interpretation['generation_mode']}**"
         + (f" ({interpretation['fallback_reason']})" if interpretation.get("fallback_reason") else "") + ".", "",
         "## 2. Incidents", ""]
    for i in summary["cross_incident_analysis"]:
        L += [f"### {i['incident_id']} — {i['incident_name']}", "",
              f"- **Sévérité** : {i['severity']} · **Catégorie** : {i['category']} · **Corrélation** : {i['confidence']}",
              f"- **Période** : {i['start']} → {i['end']}",
              f"- **Composants** : {', '.join(i['affected_components'])}",
              f"- **{i['chronology']}**",
              f"- **Hypothèse** : {i['hypothesis']}",
              f"- **Causalité** : {i['causality_status']}",
              "- **Recommandations** :"] + [f"  - {r}" for r in i["recommendations"]]
        L += ["- **À vérifier par un humain** :"] + [f"  - {v}" for v in i["verification_needed"]] + [""]
    ml = summary.get("ml_anomaly_summary", {})
    if ml.get("enabled"):
        L += ["## 3. Détection par Machine Learning", "",
              f"Isolation Forest (contamination {ml['contamination']}) : {ml['n_anomalies']} observations atypiques "
              f"sur {ml['n_samples']} ({ml['by_host']}). {ml['not_covered_by_rules']} observation(s) se situent hors des "
              "fenêtres déjà signalées par les règles : à examiner, sans présumer d'un incident.", ""]
    L += ["## 4. Recommandations consolidées", ""] + [f"1. {r}" for r in interpretation["actionable_recommendations"]]
    L += ["", "## 5. Décisions nécessitant une validation humaine", ""]
    L += [f"- {c}" for c in interpretation["human_validation_checkpoints"]]
    L += ["", "Aucune action n'est exécutée automatiquement par la plateforme : elle observe, analyse et recommande.", ""]
    if evaluation:
        t = evaluation["total"]
        L += ["## 6. Évaluation", "",
              f"Taux de détection {t['detection_rate']:.0%}, {t['false_positives']} faux positif(s), {t['false_negatives']} faux négatif(s) "
              f"sur {t['ground_truth']} épisodes connus (voir `analysis/evaluation_report.md` et ses limites).", ""]
    L += ["## 7. Corrections apportées à la version précédente", "",
          "- **Agent sécurité** : l'ancienne version comptait tous les échecs d'une IP sur trois jours et lisait un seuil de 3 au lieu de "
          "`failed_login_alert_threshold` (5) du fichier de configuration. Elle signalait 5 IP comme brute-force ; seule 203.0.113.77 "
          "(13 échecs sur `admin` en 84 minutes) en est une. Les 4 autres sont des erreurs sporadiques réparties sur 2 à 3 jours.",
          "- **Corrélation** : l'ancienne analyse concluait à une cascade « CPU de web-server-01 → erreurs → échecs de la base » avec "
          "une « causalité confirmée ». Les données la contredisent : les erreurs applicatives du 02/11 démarrent à 04:00, avant la saturation CPU (05:40), "
          "et les échecs sur le port 5432 surviennent à 11:30, plus de 3 h après la fin de la saturation (08:10). La nouvelle analyse ne retient que des corrélations temporelles.",
          "- **Mémoire de db-server-01** (97,3 %) : incident ignoré par l'ancienne synthèse LLM, désormais traité (INC-5).",
          "- **Module LLM** : l'ancienne version renvoyait un texte écrit en dur (chiffres non issus des données). Le texte est maintenant construit "
          "à partir des résultats, ou produit par un LLM puis rejeté s'il contient une valeur absente de l'entrée.", ""]
    return "\n".join(L)


def main(base: str = "."):
    from analysis.evaluation import load_project_data
    from orchestration.orchestrator import infrastructure_orchestrator

    data, config = load_project_data(base)
    summary = infrastructure_orchestrator(data, config)
    interp = generate_llm_structured_report(summary)
    ev_path = f"{base}/analysis/evaluation_results.json"
    ev = json.load(open(ev_path, encoding="utf-8")) if os.path.exists(ev_path) else None
    with open(f"{base}/analysis/rapport_final.md", "w", encoding="utf-8") as f:
        f.write(render_final_report(summary, interp, ev))
    with open(f"{base}/analysis/llm_interpretation.json", "w", encoding="utf-8") as f:
        json.dump(interp, f, indent=2, ensure_ascii=False)
    return summary, interp


if __name__ == "__main__":
    main()
