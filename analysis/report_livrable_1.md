# 📊 Livrable 1 : Rapport d'Analyse et de Supervision de l'Infrastructure DemoTech
**Module :** CI GI - Intelligence Artificielle Générative & Modèles de Langues  
**Enseignant :** Pr. C. AZROUMAHLI  
**Contexte :** Plateforme AIOps - Étape 1 : Préparation & Analyse Exploratoire  

---

## 1. Synthèse Globale des Données Analysées

| Source de données | Volume | Doublons | Valeurs manquantes | État |
| :--- | :--- | :--- | :--- | :--- |
| `network_logs.csv` | 600 lignes | 0 | 0 | Conforme |
| `security_logs.csv` | 420 lignes | 0 | 0 | Conforme |
| `system_metrics.csv` | 1080 lignes | 0 | 0 | Conforme |
| `application_logs.txt` | 500 lignes | 0 | 0 | Conforme |
| `infrastructure_config.json` | 7 sections | - | - | Conforme |

---

## 2. Analyse des Données Réseau (`network_logs.csv`)

### Statistiques principales :
- **Total des communications :** 600
- **Répartition des protocoles :** TCP : 454 (75.67%) | UDP : 146 (24.33%)
- **Latence moyenne :** 62.03 ms (Pic maximal : 1018.50 ms)
- **Taux d'échec global :** 1.50% (9 requêtes en échec)
- **Ports les plus sollicités :**
  - Port 443 : 156 requêtes
  - Port 5432 : 156 requêtes
  - Port 53 : 146 requêtes
  - Port 80 : 142 requêtes

### Visualisation de la latence réseau :
![Évolution de la latence réseau](figures/network_latency.png)

### Anomalies réseau observées :
1. **Pic critique de latence (> 1000 ms)** le **02 novembre vers 12h00**, coïncidant avec l'intégralité des 9 échecs réseau (`FAILED`).
2. Dégradations de performance temporaires (`SLOW`, latence ~300 ms) constatées le **01 novembre entre 18h et 20h**.

---

## 3. Analyse des Événements de Sécurité (`security_logs.csv`)

### Statistiques principales :
- **Authentifications réussies :** 371
- **Authentifications échouées :** 49
- **Répartition par criticité :**
  - INFO : 371 (88.3%)
  - LOW : 33 (7.9%)
  - HIGH : 13 (3.1%)
  - MEDIUM : 3 (0.7%)

### Anomalies de sécurité détectées :
- **Suspicion d'attaque par Brute-Force :** Multiples tentatives infructueuses issues d'adresses IP récurrentes :
  - IP `192.168.1.51` : 14 échecs
  - IP `203.0.113.77` : 13 échecs
  - IP `10.0.0.40` : 9 échecs
  - IP `172.16.0.12` : 9 échecs
  - IP `192.168.1.50` : 4 échecs
- **Comptes privilégiés ciblés :** `admin` (14 échecs), `app_user` (13 échecs).

---

## 4. Analyse des Ressources Système (`system_metrics.csv`)

### Métriques moyennes par serveur :
- **CPU moyen :**
  - `app-server-01` : 41.41%
  - `db-server-01` : 42.15%
  - `web-server-01` : 43.66%
- **Mémoire moyenne :**
  - `app-server-01` : 58.58%
  - `db-server-01` : 59.94%
  - `web-server-01` : 57.25%

### Visualisation de l'utilisation CPU :
![Évolution CPU par serveur](figures/system_cpu.png)

### Dépassements de seuils critiques :
1. **Saturation CPU (> 80%) :** Observée sur `web-server-01` entre **2026-11-02 05:40:00** et **2026-11-02 08:10:00**, avec des pointes à 94.6%.
2. **Saturation Disque critique :** Le serveur `app-server-01` a atteint un taux d'occupation de **97.20%** le 2026-11-03 17:30:00.

---

## 5. Analyse des Journaux Applicatifs (`application_logs.txt`)

### Répartition des niveaux :
- **INFO** : 460 logs (92.0%)
- **ERROR** : 40 logs (8.0%)

### Visualisation des erreurs applicatives récurrentes :
![Fréquence des erreurs applicatives](figures/app_errors.png)

---

## 6. Synthèse et Détection d'Incidents Transversaux

L'analyse croisée des quatre sources de données démontre des interconnexions évidentes :
1. **Incident du 02 Novembre (Matinée) :** La surcharge prolongée du CPU sur `web-server-01` génère des erreurs applicatives en cascade qui débouchent vers midi sur des dépassements de délais (timeouts) et des échecs de connexions réseau.
2. **Incident Disque du 03 Novembre :** Saturation critique du disque à 97.2% sur `app-server-01` nécessitant une purge d'urgence.
3. **Activité Malveillante :** Tentatives d'authentifications répétées sur le compte `admin`, appelant à un durcissement des règles de filtrage pare-feu.
