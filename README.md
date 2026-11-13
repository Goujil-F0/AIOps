# AIOps DemoTech — supervision multi-agents (TP 5)

Plateforme Python qui analyse des journaux synthétiques (réseau, sécurité, système, applications), détecte des anomalies, regroupe les alertes en incidents, propose des recommandations et présente le tout dans une interface Streamlit.

## Lancer

```bash
pip install -r requirements.txt
python main.py                    # génère rapports + évaluation
streamlit run dashboard/app.py    # interface
pytest tests/                     # 24 tests
```

Variables facultatives pour utiliser un vrai LLM : `ANTHROPIC_API_KEY` (et `AIOPS_LLM_MODEL`). Sans clé, un interprète déterministe produit le même format JSON ; le champ `generation_mode` dit toujours lequel a servi.

## Architecture

```
datasets/ ──► agents/                       orchestration/                    sorties
              network_agent.py   ─┐
              security_agent.py  ─┤  alertes + fenêtres temporelles
              system_agent.py    ─┼──► orchestrator.py ──► incidents (chronologie, hypothèses)
              application_agent.py┘      │  état global, ML (analysis/anomaly_detection.py)
                                         ▼
                              llm_interpreter.py ──► JSON validé + contrôle des faits
                                         │
        dashboard/app.py ◄───────────────┴──► analysis/final_report.py, evaluation.py
```

| Dossier | Contenu |
|---|---|
| `agents/` | 4 agents indépendants ; chacun renvoie un résultat structuré avec les fenêtres temporelles de ses alertes |
| `orchestration/orchestrator.py` | exécution des agents, consolidation, état global, regroupement en incidents, résumé ML |
| `orchestration/llm_interpreter.py` | entrée structurée, schéma JSON, contrôle anti-invention, repli déterministe |
| `analysis/anomaly_detection.py` | Isolation Forest (fonction pure + version avec graphique) |
| `analysis/evaluation.py`, `ground_truth.json` | évaluation (détection, FP, FN, alertes, temps) |
| `analysis/report_generator.py`, `final_report.py` | Livrable 1, rapport final |
| `dashboard/app.py` | interface Streamlit |
| `docs/` | réponses aux questions, Livrable 3 |

## Choix techniques

- **Fenêtre glissante pour la sécurité** : compter les échecs d'une IP sur trois jours signalait 5 IP, dont 4 inoffensives. Une rafale de ≥ 5 échecs en 30 min (seuil lu dans `failed_login_alert_threshold`) n'en retient qu'une.
- **Regroupement temporel des incidents** : les événements dont les fenêtres se chevauchent ou sont à moins de 30 min sont regroupés ; les corrélations sont étiquetées HIGH (chevauchement ou erreur concomitante), MEDIUM (proximité) ou ISOLATED. L'orchestrateur n'affirme jamais une causalité.
- **LLM sous contrôle** : il ne reçoit que les résultats des agents ; sa sortie est rejetée si le schéma est faux ou si elle contient un nombre, une IP ou un serveur absent de l'entrée.
- **Agents en lecture seule** : aucune action n'est exécutée ; les actions sensibles sont listées pour validation humaine.
- **Isolation Forest standardisé** : sans mise à l'échelle, `process_count` dominerait.

## Limites connues

- La vérité terrain de l'évaluation est reconstituée à partir des données (aucune étiquette fournie) et les épisodes franchissent les seuils : les règles y sont avantagées. Les 100 % de détection mesurent la cohérence, pas la performance réelle.
- Le chemin « vrai LLM » n'a pas pu être exécuté dans l'environnement de développement (pas d'accès réseau/clé) : il est couvert par des tests avec un faux client, pas par un appel réel.
- Les seuils de corrélation (30 min) et de rafale (30 min, 3 erreurs) sont des choix de paramétrage.
- Travail supplémentaire (PDF, FastAPI, SQLite, Docker, CI/CD) non réalisé.
