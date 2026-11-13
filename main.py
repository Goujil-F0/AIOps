import json
from analysis.anomaly_detection import run_isolation_forest_detection
from orchestration.orchestrator import (
    generate_llm_structured_report,
    infrastructure_orchestrator,
)
import pandas as pd


def main():
    print("=" * 70)
    print("🚀 LANCEMENT DE LA PLATEFORME AIOPS DEMOTECH (MULTI-AGENTS)")
    print("=" * 70)

    # 1. Chargement des données
    data = {
        "network": pd.read_csv("datasets/network_logs.csv"),
        "security": pd.read_csv("datasets/security_logs.csv"),
        "system": pd.read_csv("datasets/system_metrics.csv"),
    }
    with open("datasets/application_logs.txt", "r", encoding="utf-8") as f:
        data["application"] = f.readlines()
    with open(
        "datasets/infrastructure_config.json", "r", encoding="utf-8"
    ) as f:
        config = json.load(f)

    # 2. Exécution de l'orchestration multi-agents
    summary = infrastructure_orchestrator(data, config)

    print(f"\n📊 État global de l'infrastructure : [{summary['global_status']}]")
    print(f"🔔 Nombre total d'alertes actives   : {summary['total_alerts_count']}")
    print(f"Détail par sévérité               : {summary['alerts_breakdown']}")

    print("\n🔍 Incidents transversaux corrélés :")
    for inc in summary["cross_incident_analysis"]:
        print(f"   - [{inc['confidence']}] {inc['incident_name']}")
        print(f"     Composants : {', '.join(inc['affected_components'])}")

    # 3. Interprétation LLM
    print("\n🤖 Recommandations IA (Module LLM) :")
    llm_res = generate_llm_structured_report(summary)
    print(f"   Root Cause : {llm_res['root_cause_explanation']}")
    for act in llm_res["actionable_recommendations"]:
        print(f"   - {act}")

    print("\n" + "=" * 70)
    print("Pour démarrer l'interface web : streamlit run dashboard/app.py")
    print("Pour exécuter les tests Pytest : pytest tests/")
    print("=" * 70)


if __name__ == "__main__":
    main()