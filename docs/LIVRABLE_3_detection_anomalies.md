# Livrable 3 — Détection d'anomalies : comparaison et choix du modèle

Données : `system_metrics.csv` (1 080 observations, 3 serveurs). Référence : 62 observations appartenant aux 3 épisodes injectés (CPU `web-server-01`, mémoire `db-server-01`, disque `app-server-01`). Résultats complets : `analysis/evaluation_report.md`. Figure : `analysis/figures/isolation_forest_anomalies.png`.

## Résultats mesurés

| Détecteur | Signalées | VP | FP | FN | Précision | Rappel | F1 |
|---|---|---|---|---|---|---|---|
| Règles (seuils de la config) | 62 | 62 | 0 | 0 | 1,00 | 1,00 | 1,00 |
| Isolation Forest brut, 5 % (exemple du sujet) | 54 | 53 | 1 | 9 | 0,98 | 0,86 | 0,91 |
| Isolation Forest standardisé, 2 % | 22 | 22 | 0 | 40 | 1,00 | 0,36 | 0,52 |
| Isolation Forest standardisé, 5 % | 54 | 53 | 1 | 9 | 0,98 | 0,86 | 0,91 |
| Isolation Forest standardisé, 10 % | 108 | 62 | 46 | 0 | 0,57 | 1,00 | 0,73 |
| Isolation Forest par serveur, 5 % | 54 | 37 | 17 | 25 | 0,69 | 0,60 | 0,64 |
| **Règles ∪ Isolation Forest 5 %** | 63 | 62 | 1 | 0 | 0,98 | 1,00 | 0,99 |

**Attention à la lecture.** Les épisodes injectés dépassent les seuils de configuration : les règles obtiennent donc 100 % par construction. Ce tableau ne prouve pas que les règles sont supérieures en général ; il montre surtout comment Isolation Forest réagit à ses paramètres.

Ce que les chiffres enseignent :
- La standardisation n'a rien changé ici (même résultat que l'exemple du sujet), car les épisodes sont assez marqués pour sortir en tête dans les deux cas. Elle reste préférable en principe : sans elle, `process_count` (~150) pèse davantage que les pourcentages.
- La contamination est le réglage décisif : à 2 %, 64 % des anomalies sont manquées ; à 10 %, 46 observations normales sont signalées. Le bon réglage (5 %) coïncide ici avec la proportion réelle d'anomalies (5,7 %), ce qu'on ne sait pas en production.
- Un modèle par serveur est moins bon : chaque serveur n'a que 360 points et un épisode anormal y pèse lourd dans la définition du « normal ».
- Isolation Forest signale 1 observation que les règles ignorent (`app-server-01`, 03/11 09:00, mémoire 32,7 %). Sans vérité terrain, impossible de dire si c'est un faux positif ou un vrai signal faible : à faire examiner.

## Comparaison des trois approches (point 13)

| | Règles déterministes | Isolation Forest | Interprétation par LLM |
|---|---|---|---|
| **Avantages** | Précises, explicables, reproductibles, nulle donnée d'apprentissage, très rapides (≈ 4 ms) | Détecte des combinaisons inhabituelles sans seuil fixé ; s'adapte aux données | Explique en langage naturel, relie des signaux de sources différentes, rédige les recommandations |
| **Limites** | Ne voient que ce qui est prévu ; seuils à régler et à maintenir ; pas de notion de « inhabituel pour ce serveur » | Réglage de `contamination` ; score peu explicable ; signale toujours ~x % des points, même si tout va bien ; sensible à l'échelle des variables | Peut inventer ; non déterministe ; coût et latence ; ne remplace pas une détection (il interprète) |
| **Mesuré ici** | F1 = 1,00 (biais de construction) | F1 = 0,91 (5 %) | Non évalué quantitativement : aucun LLM accessible dans l'environnement de développement. Le module est prêt (`ANTHROPIC_API_KEY`) et ses garde-fous sont testés. |

## Meilleur modèle (point 14)

**Retenu : combinaison Règles ∪ Isolation Forest standardisé (contamination 5 %).**
- Rappel 100 %, précision 98 %, F1 = 0,99 sur la référence.
- Les règles garantissent la détection des dépassements de seuil connus et leur explication ; Isolation Forest ajoute un filet pour les anomalies sans seuil (ici, 1 observation à examiner).
- Réserve : si la mesure ne portait que sur la référence, les règles seules seraient imbattables. Le choix de la combinaison repose sur le raisonnement opérationnel (couvrir aussi l'inconnu) plus que sur ces chiffres.
- Isolation Forest seul n'est pas recommandé : il manque 9 observations anormales sur 62 et sa qualité dépend d'un paramètre qu'on ne peut pas connaître à l'avance.
