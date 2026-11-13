# Rapport final — Incidents détectés et recommandations

**Plateforme AIOps DemoTech** — période analysée : 1er au 3 novembre 2026 (données synthétiques).

## 1. Synthèse

- **État global : CRITICAL**
- 9 alertes consolidées (CRITICAL : 4, HIGH : 3, WARNING : 2).
- 6 incidents après regroupement temporel (tolérance de 30 min).
- Réseau : latence moyenne 62.03 ms, taux d'échec 1.5 %.
- Application : 40 erreurs, 0 avertissements.
- Texte d'interprétation produit par : **deterministic** (aucun LLM configuré).

## 2. Incidents

### INC-1 — Lenteur réseau (HTTP:80, HTTPS:443) + Rafale d'erreurs applicatives

- **Sévérité** : HIGH · **Catégorie** : application / performance · **Corrélation** : HIGH
- **Période** : 2026-11-01 18:05:00 → 2026-11-01 20:05:00
- **Composants** : HTTP:80, HTTPS:443, application
- **Chronologie : Lenteur réseau (HTTP:80, HTTPS:443) (01/11 18:05–01/11 20:05) → Rafale d'erreurs applicatives (01/11 18:40–01/11 19:52).**
- **Hypothèse** : Hypothèse non démontrée : dégradation de performance du service concerné (HTTP:80, HTTPS:443) avec répercussion sur l'application. Aucun seuil CPU, mémoire ou disque n'est franchi dans cette fenêtre : une cause applicative, base de données ou réseau est plus plausible qu'une saturation de ressources.
- **Causalité** : Corrélation temporelle observée ; causalité non démontrée (aucune trace n'établit un lien de cause à effet).
- **Recommandations** :
  - Vérifier la disponibilité et les journaux du service (HTTP:80, HTTPS:443).
  - Examiner les erreurs dominantes de la rafale : Database connection failed (6), HTTP N Internal Server Error (4), Request timeout (4).
- **À vérifier par un humain** :
  - Consulter les journaux du service et du client concernés pour établir l'ordre exact des défaillances.
  - Vérifier le pool de connexions et la disponibilité de la base de données.

### INC-2 — Rafale d'erreurs applicatives

- **Sévérité** : WARNING · **Catégorie** : application · **Corrélation** : ISOLATED
- **Période** : 2026-11-02 04:00:00 → 2026-11-02 04:28:00
- **Composants** : application
- **Chronologie : Rafale d'erreurs applicatives (02/11 04:00–02/11 04:28).**
- **Hypothèse** : Rafale d'erreurs sans signal réseau ou système concomitant. Hypothèse : régression applicative, dépendance externe ou configuration (voir les messages dominants).
- **Causalité** : Aucune corrélation inter-composants observée.
- **Recommandations** :
  - Examiner les erreurs dominantes de la rafale : Database connection failed (3), Invalid application configuration (3), HTTP N Internal Server Error (2).
- **À vérifier par un humain** :
  - Vérifier les déploiements ou changements de configuration autour de cette période.

### INC-3 — Échecs d'authentification répétés (203.0.113.77) + Saturation CPU web-server-01

- **Sévérité** : CRITICAL · **Catégorie** : capacité / ressources / cybersécurité · **Corrélation** : HIGH
- **Période** : 2026-11-02 05:00:00 → 2026-11-02 08:10:00
- **Composants** : 203.0.113.77, web-server-01
- **Chronologie : Échecs d'authentification répétés (203.0.113.77) (02/11 05:00–02/11 06:24) → Saturation CPU web-server-01 (02/11 05:40–02/11 08:10) ; 4 erreur(s) applicative(s) isolée(s) dans la fenêtre (HTTP N Internal Server Error, Invalid application configuration).**
- **Hypothèse** : Les tentatives d'authentification depuis 203.0.113.77 et la charge de web-server-01 se chevauchent. Hypothèse non démontrée : la charge pourrait être aggravée par le trafic d'attaque. La surcharge se prolonge jusqu'à 02/11 08:10, après la fin des tentatives (02/11 06:24) : la charge ne peut pas être attribuée seulement à l'attaque.
- **Causalité** : Corrélation temporelle observée ; causalité non démontrée (aucune trace n'établit un lien de cause à effet).
- **Recommandations** :
  - Proposer le blocage de 203.0.113.77 au pare-feu (validation humaine requise) et vérifier les comptes ciblés : admin.
  - Vérifier les processus gourmands sur web-server-01 via 'top/htop', optimiser les threads applicatifs ou allouer des vCPU supplémentaires.
- **À vérifier par un humain** :
  - Corréler avec les journaux d'accès du serveur concerné et les processus les plus consommateurs.
  - Valider avec l'équipe sécurité la légitimité de 203.0.113.77 avant tout blocage.

### INC-4 — Échecs réseau (DATABASE:5432)

- **Sévérité** : HIGH · **Catégorie** : disponibilité · **Corrélation** : HIGH
- **Période** : 2026-11-02 11:30:00 → 2026-11-02 12:40:00
- **Composants** : DATABASE:5432
- **Chronologie : Échecs réseau (DATABASE:5432) (02/11 11:30–02/11 12:40) ; 1 erreur(s) applicative(s) isolée(s) dans la fenêtre (Database connection failed).**
- **Hypothèse** : Hypothèse non démontrée : indisponibilité du service concerné (DATABASE:5432) avec répercussion sur l'application. Aucun seuil CPU, mémoire ou disque n'est franchi dans cette fenêtre : une cause applicative, base de données ou réseau est plus plausible qu'une saturation de ressources.
- **Causalité** : Corrélation temporelle observée ; causalité non démontrée (aucune trace n'établit un lien de cause à effet).
- **Recommandations** :
  - Vérifier la disponibilité et les journaux du service (DATABASE:5432).
- **À vérifier par un humain** :
  - Consulter les journaux du service et du client concernés pour établir l'ordre exact des défaillances.
  - Vérifier le pool de connexions et la disponibilité de la base de données.

### INC-5 — Mémoire élevée db-server-01

- **Sévérité** : CRITICAL · **Catégorie** : capacité / ressources · **Corrélation** : ISOLATED
- **Période** : 2026-11-02 22:20:00 → 2026-11-03 00:50:00
- **Composants** : db-server-01
- **Chronologie : Mémoire élevée db-server-01 (02/11 22:20–03/11 00:50).**
- **Hypothèse** : Événement isolé : aucun autre signal concomitant. Hypothèse : fuite mémoire ou charge inhabituelle sur db-server-01.
- **Causalité** : Aucune corrélation inter-composants observée.
- **Recommandations** :
  - Risque imminent d'activation du kernel OOM-Killer sur db-server-01. Identifier d'éventuelles fuites mémoire et redémarrer les services concernés.
- **À vérifier par un humain** :
  - Identifier les processus consommateurs sur db-server-01 avant tout redémarrage.

### INC-6 — Disque saturé app-server-01

- **Sévérité** : CRITICAL · **Catégorie** : capacité / ressources · **Corrélation** : ISOLATED
- **Période** : 2026-11-03 15:00:00 → 2026-11-03 19:50:00
- **Composants** : app-server-01
- **Chronologie : Disque saturé app-server-01 (03/11 15:00–03/11 19:50).**
- **Hypothèse** : Événement isolé : aucun autre signal concomitant. Hypothèse : accumulation de données ou de journaux sur app-server-01.
- **Causalité** : Aucune corrélation inter-composants observée.
- **Recommandations** :
  - Purger immédiatement les fichiers journaux obsolètes dans /var/log sur app-server-01, vider les caches temporaires et prévoir l'extension du volume de stockage.
- **À vérifier par un humain** :
  - Inspecter l'occupation par répertoire sur app-server-01 avant toute purge.

## 3. Détection par Machine Learning

Isolation Forest (contamination 0.05) : 54 observations atypiques sur 1080 ({'app-server-01': 31, 'web-server-01': 16, 'db-server-01': 7}). 1 observation(s) se situent hors des fenêtres déjà signalées par les règles : à examiner, sans présumer d'un incident.

## 4. Recommandations consolidées

1. Vérifier la disponibilité et les journaux du service (HTTP:80, HTTPS:443).
1. Examiner les erreurs dominantes de la rafale : Database connection failed (6), HTTP N Internal Server Error (4), Request timeout (4).
1. Examiner les erreurs dominantes de la rafale : Database connection failed (3), Invalid application configuration (3), HTTP N Internal Server Error (2).
1. Proposer le blocage de 203.0.113.77 au pare-feu (validation humaine requise) et vérifier les comptes ciblés : admin.
1. Vérifier les processus gourmands sur web-server-01 via 'top/htop', optimiser les threads applicatifs ou allouer des vCPU supplémentaires.
1. Vérifier la disponibilité et les journaux du service (DATABASE:5432).
1. Risque imminent d'activation du kernel OOM-Killer sur db-server-01. Identifier d'éventuelles fuites mémoire et redémarrer les services concernés.
1. Purger immédiatement les fichiers journaux obsolètes dans /var/log sur app-server-01, vider les caches temporaires et prévoir l'extension du volume de stockage.

## 5. Décisions nécessitant une validation humaine

- INC-1 : Consulter les journaux du service et du client concernés pour établir l'ordre exact des défaillances.
- INC-1 : Vérifier le pool de connexions et la disponibilité de la base de données.
- INC-2 : Vérifier les déploiements ou changements de configuration autour de cette période.
- INC-3 : Corréler avec les journaux d'accès du serveur concerné et les processus les plus consommateurs.
- INC-3 : Valider avec l'équipe sécurité la légitimité de 203.0.113.77 avant tout blocage.
- INC-4 : Consulter les journaux du service et du client concernés pour établir l'ordre exact des défaillances.
- INC-4 : Vérifier le pool de connexions et la disponibilité de la base de données.
- INC-5 : Identifier les processus consommateurs sur db-server-01 avant tout redémarrage.
- INC-6 : Inspecter l'occupation par répertoire sur app-server-01 avant toute purge.

Aucune action n'est exécutée automatiquement par la plateforme : elle observe, analyse et recommande.

## 6. Évaluation

Taux de détection 100%, 0 faux positif(s), 0 faux négatif(s) sur 8 épisodes connus (voir `analysis/evaluation_report.md` et ses limites).

## 7. Corrections apportées à la version précédente

- **Agent sécurité** : l'ancienne version comptait tous les échecs d'une IP sur trois jours et lisait un seuil de 3 au lieu de `failed_login_alert_threshold` (5) du fichier de configuration. Elle signalait 5 IP comme brute-force ; seule 203.0.113.77 (13 échecs sur `admin` en 84 minutes) en est une. Les 4 autres sont des erreurs sporadiques réparties sur 2 à 3 jours.
- **Corrélation** : l'ancienne analyse concluait à une cascade « CPU de web-server-01 → erreurs → échecs de la base » avec une « causalité confirmée ». Les données la contredisent : les erreurs applicatives du 02/11 démarrent à 04:00, avant la saturation CPU (05:40), et les échecs sur le port 5432 surviennent à 11:30, plus de 3 h après la fin de la saturation (08:10). La nouvelle analyse ne retient que des corrélations temporelles.
- **Mémoire de db-server-01** (97,3 %) : incident ignoré par l'ancienne synthèse LLM, désormais traité (INC-5).
- **Module LLM** : l'ancienne version renvoyait un texte écrit en dur (chiffres non issus des données). Le texte est maintenant construit à partir des résultats, ou produit par un LLM puis rejeté s'il contient une valeur absente de l'entrée.
