# Évaluation des agents et des détecteurs (point 21)

**Référence** : `analysis/ground_truth.json` — 8 épisodes injectés, reconstitués par inspection des données (aucune étiquette fournie). **Appariement** : même domaine, même composant (IP / serveur) et chevauchement temporel à ± 30 min. Plusieurs détections du même épisode ne comptent pas comme faux positifs.

> **Limite à garder en tête** : les épisodes injectés dépassent les seuils de configuration, donc les règles sont avantagées par construction. Ce banc d'essai mesure la cohérence et la robustesse, pas la performance en production.

## 1. Agents

| Agent | Détections | Épisodes connus | Détectés (TP) | Faux positifs | Faux négatifs | Taux de détection | Alertes | Temps (ms) |
|---|---|---|---|---|---|---|---|---|
| network | 2 | 2 | 2 | 0 | 0 | 100% | 3 | 8.17 |
| security | 1 | 1 | 1 | 0 | 0 | 100% | 1 | 10.38 |
| system | 3 | 3 | 3 | 0 | 0 | 100% | 3 | 4.49 |
| application | 2 | 2 | 2 | 0 | 0 | 100% | 2 | 17.24 |
| **Total** | 8 | 8 | 8 | 0 | 0 | 100% | 9 | 297.6 |

Le temps du total correspond à l'orchestrateur complet (4 agents, corrélation, Isolation Forest).

## 2. Agent sécurité : comptage total (v1) contre fenêtre glissante (v2)

| Règle | Détections | Faux positifs | Faux négatifs | Précision |
|---|---|---|---|---|
| v1 : total d'échecs par IP ≥ 3 (seuil codé en dur) | 5 | 4 | 0 | 20% |
| v1 : total d'échecs par IP ≥ 5 (seuil de la config) | 4 | 3 | 0 | 25% |
| v2 : ≥ 5 échecs en fenêtre glissante (version livrée) | 1 | 0 | 0 | 100% |

## 3. Détection d'anomalies sur `system_metrics.csv` (niveau observation)

62 observations anormales sur 1080.

| Détecteur | Signalées | VP | FP | FN | Précision | Rappel | F1 | Taux de FP |
|---|---|---|---|---|---|---|---|---|
| Règles (seuils du fichier de config) | 62 | 62 | 0 | 0 | 1.0 | 1.0 | 1.0 | 0.0 |
| IF brut 5 % (exemple du sujet) | 54 | 53 | 1 | 9 | 0.981 | 0.855 | 0.914 | 0.001 |
| IF standardisé 2 % | 22 | 22 | 0 | 40 | 1.0 | 0.355 | 0.524 | 0.0 |
| IF standardisé 5 % | 54 | 53 | 1 | 9 | 0.981 | 0.855 | 0.914 | 0.001 |
| IF standardisé 10 % | 108 | 62 | 46 | 0 | 0.574 | 1.0 | 0.729 | 0.0452 |
| IF standardisé par serveur 5 % | 54 | 37 | 17 | 25 | 0.685 | 0.597 | 0.638 | 0.0167 |
| Règles ∪ IF standardisé 5 % | 63 | 62 | 1 | 0 | 0.984 | 1.0 | 0.992 | 0.001 |

**Meilleur détecteur selon le F1 : Règles (seuils du fichier de config).**

## 4. Regroupement en incidents (orchestrateur)

6 incidents détectés pour 6 attendus ; 6 regroupés exactement comme dans la référence.
