"""Point d'entrée : exécute la plateforme AIOps de bout en bout."""
import json
import os

from analysis import evaluation, final_report
from analysis.anomaly_detection import run_isolation_forest_detection
from analysis.report_generator import generate_livrable_1_report
from orchestration.orchestrator import infrastructure_orchestrator
from orchestration.llm_interpreter import generate_llm_structured_report


def main():
    print("=" * 70)
    print("PLATEFORME AIOPS DEMOTECH (MULTI-AGENTS)")
    print("=" * 70)
    data, config = evaluation.load_project_data(".")

    # Étape 1 : rapport statistiques (Livrable 1)
    generate_livrable_1_report()

    # Étapes 2 et 4 : agents + orchestrateur
    summary = infrastructure_orchestrator(data, config)
    print("\n" + summary["synthetic_report"])

    # Étape 3 : Isolation Forest (Livrable 3)
    run_isolation_forest_detection()

    # Interprétation LLM (réelle si ANTHROPIC_API_KEY est définie, sinon déterministe)
    interp = generate_llm_structured_report(summary)
    print(f"\nInterprétation ({interp['generation_mode']}) :")
    print(interp["situation_summary"])

    # Étape 6 : évaluation + rapport final
    res = evaluation.main(".")
    t = res["total"]
    print(f"\nÉvaluation : détection {t['detection_rate']:.0%}, FP={t['false_positives']}, FN={t['false_negatives']}")
    final_report.main(".")
    print("\nRapports : analysis/rapport_final.md, analysis/evaluation_report.md")
    print("Interface : streamlit run dashboard/app.py   |   Tests : pytest tests/")


if __name__ == "__main__":
    main()
