# Réponses aux questions du TP 5

Les chiffres proviennent des exécutions du projet (`python main.py`).

## Étape 1 — questions à compléter

**Quelles informations indiquent un problème de disponibilité ou de performance d'un service réseau ?**
Disponibilité : communications `FAILED` et taux d'échec par port (9 échecs, tous sur le port 5432, soit 1,5 % du trafic). Performance : statut `SLOW`, latence au-dessus du seuil de 150 ms, pics (1 018,5 ms) et durée de la dégradation. Le regroupement par port et par fenêtre de temps distingue un service défaillant d'une gêne diffuse.

**Pourquoi une succession d'échecs d'authentification justifie-t-elle une investigation ?**
Un échec isolé est banal. Une rafale depuis une même source, en peu de temps, est la signature d'une attaque par force brute ou par bourrage d'identifiants ; si un succès suit, le compte peut être compromis. Le contexte pèse : compte privilégié, IP externe, criticité, heure. Dans les données, `203.0.113.77` fait 13 échecs sur `admin` en 84 minutes, alors que les quatre autres IP font des erreurs sporadiques sur 2 à 3 jours.

## Étape 3 — questions sur Isolation Forest

**a) Détection par seuil ou par Isolation Forest ?**
Un seuil juge chaque variable séparément avec une limite fixée par un humain (CPU > 80 %). Isolation Forest apprend la forme des données : il isole les points qu'il suffit de peu de coupes aléatoires pour séparer du reste, sans seuil explicite et en tenant compte de plusieurs variables à la fois. Le seuil est explicable mais rigide ; la forêt est souple mais moins lisible.

**b) Pourquoi choisir soigneusement `contamination` ?**
Ce paramètre fixe la part de points déclarés anormaux, quelle que soit la réalité. Mesuré ici : à 2 % la forêt manque 40 des 62 observations anormales (rappel 36 %) ; à 5 % elle en manque 9 pour 1 fausse alerte ; à 10 % elle déclare 46 observations normales anormales (précision 57 %). Une valeur trop haute noie les administrateurs, trop basse masque les incidents.

**c) Anomalie détectée = incident ?**
Non. Une anomalie est un écart statistique ; un incident est un impact sur le service. Une charge légitime (sauvegarde, pic de trafic) peut être atypique sans être un problème. Dans nos données, Isolation Forest signale une observation hors de tout épisode connu (`app-server-01`, 03/11 09:00) : à examiner, pas à classer incident d'office.

**d) Évaluer sans vérité terrain complète ?**
Plusieurs approches : construire une référence partielle à partir d'anomalies injectées ou déjà connues (comme ici) ; revue manuelle d'un échantillon des alertes pour estimer la précision ; comparer avec des règles ou un autre modèle (accord entre méthodes) ; tester la stabilité (autres graines, autres périodes) ; suivre le retour des opérateurs (alertes jugées utiles ou non). Aucune ne remplace un étiquetage fiable ; on indique donc toujours les limites de la référence.

## Point 13-14 — comparaison et choix du modèle
Voir `docs/LIVRABLE_3_detection_anomalies.md`.

## Étape 4 — corrélation et causalité (point 16)
La corrélation est un constat (deux signaux coïncident dans le temps) ; la causalité exige un mécanisme et des preuves (ordre des événements, traces, test contrôlé). Exemple de nos données : la saturation CPU de `web-server-01` (05:40–08:10) et les erreurs applicatives du matin (dès 04:00, donc **avant**) ne permettent pas de dire que le CPU a causé les erreurs. Les échecs du port 5432 (11:30) surviennent plus de 3 h après la fin de la saturation CPU. L'orchestrateur n'affirme donc que des chronologies et des hypothèses étiquetées « non démontrées ».

## Sécurité et autonomie des agents (point 21)

**a) Un agent peut-il modifier directement la configuration d'un serveur ?**
Non, pas dans ce contexte. Une erreur d'agent ou de LLM aurait un effet direct sur la production. Nos agents sont en lecture seule : ils observent, analysent et recommandent.

**b) Actions automatisables ?**
Celles qui sont sans effet de bord ou réversibles : lire et analyser des journaux, calculer des métriques, générer des rapports, créer une alerte ou un ticket, enrichir une alerte (géolocalisation d'IP, historique).

**c) Actions nécessitant une validation humaine ?**
Celles qui modifient le système ou peuvent bloquer des utilisateurs légitimes : blocage d'IP au pare-feu, purge de fichiers, redémarrage de services, changement de configuration, désactivation de compte, montée en charge coûteuse. Le module LLM les liste dans `human_validation_checkpoints`.

**d) Comment empêcher une action non autorisée ?**
Principe du moindre privilège (comptes de service en lecture seule) ; liste blanche d'actions ; séparation entre proposer et exécuter ; approbation explicite avec journalisation ; limites de débit et mode simulation (dry-run) ; revue régulière des droits.

**e) Pourquoi conserver un historique des décisions ?**
Pour auditer (qui a décidé quoi, sur quelle base), reproduire et corriger une erreur, mesurer la fiabilité de l'agent au fil du temps, répondre à des exigences de conformité et améliorer les règles. Il faut conserver l'entrée, la sortie, la version du modèle et l'humain ayant validé.

**f) Limiter erreurs et hallucinations d'un LLM ?**
Dans ce projet : le LLM ne voit que des résultats structurés ; sa sortie doit respecter un schéma JSON ; toute valeur numérique, IP ou serveur absent de l'entrée la fait rejeter (`check_grounding`) ; repli sur un interprète déterministe ; température 0 ; la sortie annonce son origine (`generation_mode`). Dans l'idée : validation humaine pour les actions, et citation des sources des faits.

## Questions de synthèse

**a) Programme de supervision classique ou agent IA ?**
Le programme classique applique des règles fixes et réagit à ce qui est prévu. Un agent IA perçoit, raisonne sur des données hétérogènes, s'adapte (apprentissage, interprétation) et peut proposer des actions. Il apporte de la souplesse mais aussi de l'incertitude, d'où la nécessité de garde-fous.

**b) Pourquoi séparer les responsabilités ?**
Chaque agent maîtrise un domaine (réseau, sécurité, système, application), se teste isolément, évolue sans toucher aux autres, et un échec reste local. C'est aussi plus lisible pour les équipes.

**c) Rôle de l'orchestrateur ?**
Lancer les agents, consolider leurs alertes, déterminer l'état global, rapprocher les événements dans le temps pour former des incidents, produire la synthèse et alimenter l'interface et le LLM.

**d) Règles ou Machine Learning ?**
Les règles encodent une connaissance explicite : précises et explicables, mais limitées à l'attendu. Le ML apprend de données : il détecte l'inattendu, mais dépend du réglage et des données, et explique mal ses décisions.

**e) Avantages et limites d'un LLM pour analyser des logs ?**
Avantages : résume de gros volumes, explique en langage clair, rapproche des signaux hétérogènes, rédige des recommandations. Limites : hallucinations, non-déterminisme, coût et latence, confidentialité des journaux, difficulté à compter ou à calculer de façon fiable, pas de vérité garantie. D'où son rôle d'interprète sous contrôle, non de détecteur.

**f) Collaboration pour un incident transversal ?**
Chaque agent publie des événements datés et localisés ; l'orchestrateur les regroupe par proximité temporelle et composant, établit la chronologie, formule des hypothèses et signale ce qui reste à vérifier. Exemple : l'incident INC-3 réunit l'agent sécurité (échecs sur `admin` dès 05:00) et l'agent système (CPU dès 05:40).

**g) Pourquoi limiter l'autonomie ?**
Un agent peut se tromper, être manipulé (injection de contenu dans les journaux) ou agir sur de fausses informations ; ses erreurs se propagent vite en production. Limiter l'autonomie réduit le rayon d'impact, garde la responsabilité chez un humain et permet de monter progressivement en confiance.

**h) Un système multi-agents est-il toujours plus performant qu'un système centralisé ?**
Non. Il est plus modulaire, testable et extensible, mais ajoute de la coordination, des échanges et des points de défaillance. Sur ce jeu de données de 600 à 1 080 lignes, un script unique serait aussi rapide et plus simple ; l'avantage apparaît avec la croissance (plus de sources, plus d'équipes, déploiement séparé). Le bon choix dépend du besoin.
