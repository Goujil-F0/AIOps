"""Orchestrateur multi-agents de la plateforme AIOps DemoTech.

Étapes : exécution des 4 agents -> consolidation des alertes -> état global ->
extraction d'événements datés -> regroupement en incidents par proximité temporelle
(analyse croisée) -> détection ML complémentaire -> rapport synthétique.

Règle d'honnêteté : l'orchestrateur ne conclut JAMAIS à une causalité. Il établit
une chronologie, signale les chevauchements de fenêtres et formule des hypothèses
explicitement non démontrées.
"""
import json
import os
import sys

import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.application_agent import application_agent
from agents.network_agent import network_agent
from agents.security_agent import security_agent
from agents.system_agent import system_agent
from orchestration.llm_interpreter import generate_llm_structured_report  # noqa: F401 (ré-export)

SEV_ORDER = {"INFO": 0, "WARNING": 1, "HIGH": 2, "CRITICAL": 3}


# ------------------------------------------------------------------ événements
def extract_events(net_res: dict, sec_res: list, sys_res: list, app_res: dict) -> list:
    """Transforme les résultats des agents en événements datés homogènes."""
    events = []

    def add(domain, component, kind, label, severity, start, end, message, reco=None):
        events.append(
            {
                "domain": domain, "component": component, "kind": kind, "label": label,
                "severity": severity, "start": pd.Timestamp(start), "end": pd.Timestamp(end),
                "message": message, "recommendation": reco,
            }
        )

    names = {s["port"]: s["service"] for s in net_res.get("problematic_services", [])}
    for w in net_res.get("incident_windows", []):
        comp = ", ".join(f"{names.get(p, 'port')}:{p}" for p in w["ports"])
        failed = w["status"] != "SLOW"
        add(
            "network", comp, "FAILED" if failed else "SLOW",
            f"{'Échecs' if failed else 'Lenteur'} réseau ({comp})",
            "HIGH" if failed else "WARNING", w["start"], w["end"],
            f"{w['count']} communications {w['status']} sur {comp}",
            f"Vérifier la disponibilité et les journaux du service ({comp}).",
        )
    for a in sec_res:
        if "window" in a:
            comp = a.get("source_ip") or a.get("user")
            add("security", comp, a["type"], f"Échecs d'authentification répétés ({comp})",
                a["severity"], a["window"]["start"], a["window"]["end"], a["message"],
                a.get("recommendation"))
    labels = {"CPU": "Saturation CPU", "MEMORY": "Mémoire élevée", "DISK": "Disque saturé",
              "PROCESS_COUNT": "Processus en excès"}
    for a in sys_res:
        if "window" in a:
            add("system", a["hostname"], a["metric"],
                f"{labels.get(a['metric'], a['metric'])} {a['hostname']}", a["severity"],
                a["window"]["start"], a["window"]["end"], a["message"], a.get("recommendation"))
    for b in app_res.get("error_bursts", []):
        top = ", ".join(f"{m} ({n})" for m, n in b["top_messages"].items())
        add("application", "application", "ERROR_BURST", "Rafale d'erreurs applicatives",
            "HIGH" if b["errors_count"] >= 10 else "WARNING", b["start"], b["end"],
            f"{b['errors_count']} erreurs applicatives entre {b['start']} et {b['end']} : {top}",
            f"Examiner les erreurs dominantes de la rafale : {top}.")
    for i, e in enumerate(sorted(events, key=lambda x: x["start"]), 1):
        e["id"] = f"E{i}"
    return sorted(events, key=lambda x: x["start"])


def cluster_events(events: list, tolerance_min: int = 30) -> list:
    """Regroupe les événements dont les fenêtres se chevauchent ou sont séparées
    de moins de `tolerance_min` minutes."""
    tol = pd.Timedelta(minutes=tolerance_min)
    clusters = []
    for ev in sorted(events, key=lambda e: e["start"]):
        if clusters and ev["start"] <= clusters[-1]["end"] + tol:
            clusters[-1]["events"].append(ev)
            clusters[-1]["end"] = max(clusters[-1]["end"], ev["end"])
        else:
            clusters.append({"events": [ev], "end": ev["end"]})
    return [c["events"] for c in clusters]


def _overlap(a, b) -> bool:
    return a["start"] <= b["end"] and b["start"] <= a["end"]


def _hm(ts) -> str:
    return ts.strftime("%d/%m %H:%M")


CATEGORY = {"security": "cybersécurité", "system": "capacité / ressources",
            "application": "application"}


def _hypothesis(evs: list, support: list):
    """(hypothèse, éléments à vérifier) à partir des seuls faits observés."""
    dom = {e["domain"] for e in evs} | ({"application"} if support else set())
    kinds = {e["kind"] for e in evs}
    sysev = [e for e in evs if e["domain"] == "system"]
    secev = [e for e in evs if e["domain"] == "security"]
    net = [e for e in evs if e["domain"] == "network"]
    app = [e for e in evs if e["domain"] == "application"]
    if secev and sysev:
        s, y = secev[0], sysev[0]
        after = (f"La surcharge se prolonge jusqu'à {_hm(y['end'])}, après la fin des tentatives "
                 f"({_hm(s['end'])}) : la charge ne peut pas être attribuée seulement à l'attaque."
                 if y["end"] > s["end"] else "La surcharge se termine avec les tentatives.")
        return (f"Les tentatives d'authentification depuis {s['component']} et la charge de "
                f"{y['component']} se chevauchent. Hypothèse non démontrée : la charge pourrait "
                f"être aggravée par le trafic d'attaque. {after}",
                ["Corréler avec les journaux d'accès du serveur concerné et les processus les plus consommateurs.",
                 f"Valider avec l'équipe sécurité la légitimité de {s['component']} avant tout blocage."])
    if net and (app or support) and not sysev:
        failed = any(e["kind"] == "FAILED" for e in net)
        return (("Hypothèse non démontrée : indisponibilité du service concerné "
                 if failed else "Hypothèse non démontrée : dégradation de performance du service concerné ")
                + f"({net[0]['component']}) avec répercussion sur l'application. Aucun seuil CPU, "
                  "mémoire ou disque n'est franchi dans cette fenêtre : une cause applicative, base de "
                  "données ou réseau est plus plausible qu'une saturation de ressources.",
                ["Consulter les journaux du service et du client concernés pour établir l'ordre exact des défaillances.",
                 "Vérifier le pool de connexions et la disponibilité de la base de données."])
    if len(dom) >= 2:
        first = evs[0]
        return (f"Plusieurs signaux coïncident ; le premier observé est « {first['label']} » "
                f"({_hm(first['start'])}). L'ordre chronologique est un indice, pas une preuve de causalité.",
                ["Reconstituer la séquence à partir des journaux détaillés."])
    e = evs[0]
    if e["kind"] == "DISK":
        return ("Événement isolé : aucun autre signal concomitant. Hypothèse : accumulation de données ou de journaux "
                f"sur {e['component']}.", [f"Inspecter l'occupation par répertoire sur {e['component']} avant toute purge."])
    if e["kind"] == "MEMORY":
        return ("Événement isolé : aucun autre signal concomitant. Hypothèse : fuite mémoire ou charge inhabituelle "
                f"sur {e['component']}.", [f"Identifier les processus consommateurs sur {e['component']} avant tout redémarrage."])
    if e["kind"] == "CPU":
        return ("Événement isolé : aucun autre signal concomitant. Hypothèse : charge applicative ou processus emballé "
                f"sur {e['component']}.", [f"Identifier les processus consommateurs sur {e['component']}."])
    if e["domain"] == "application":
        return ("Rafale d'erreurs sans signal réseau ou système concomitant. Hypothèse : régression applicative, "
                "dépendance externe ou configuration (voir les messages dominants).",
                ["Vérifier les déploiements ou changements de configuration autour de cette période."])
    if e["domain"] == "security":
        return ("Tentatives répétées isolées. Hypothèse : attaque par force brute ou compte compromis.",
                ["Valider la légitimité de la source avec l'équipe sécurité."])
    return ("Événement isolé : aucune corrélation inter-composants observée.", ["Surveiller l'évolution."])


def build_incidents(events, app_res: dict, tolerance_min: int = 30) -> list:
    tol = pd.Timedelta(minutes=tolerance_min)
    isolated = [
        {"ts": pd.Timestamp(e["timestamp"]), "message": e["message"]}
        for e in app_res.get("isolated_errors", [])
    ]
    incidents = []
    for n, evs in enumerate(cluster_events(events, tolerance_min), 1):
        start, end = min(e["start"] for e in evs), max(e["end"] for e in evs)
        support = [e for e in isolated if start - tol <= e["ts"] <= end + tol] \
            if not any(e["domain"] == "application" for e in evs) else []
        domains = sorted({e["domain"] for e in evs} | ({"application"} if support else set()))
        overlapping = any(_overlap(a, b) for i, a in enumerate(evs) for b in evs[i + 1:])
        multi = len(domains) >= 2
        confidence = "ISOLATED" if not multi else ("HIGH" if overlapping or support else "MEDIUM")
        severity = max((e["severity"] for e in evs), key=lambda s: SEV_ORDER.get(s, 0))
        hypothesis, verif = _hypothesis(evs, support)
        chrono = "Chronologie : " + " → ".join(f"{e['label']} ({_hm(e['start'])}–{_hm(e['end'])})" for e in evs)
        if support:
            chrono += f" ; {len(support)} erreur(s) applicative(s) isolée(s) dans la fenêtre ({', '.join(sorted({s['message'] for s in support}))})"
        chrono += "."
        causal = ("Corrélation temporelle observée ; causalité non démontrée (aucune trace n'établit un lien de cause à effet)."
                  if multi else "Aucune corrélation inter-composants observée.")
        cats = {CATEGORY.get(e["domain"]) or ("disponibilité" if e["kind"] == "FAILED" else "performance") for e in evs}
        recos = []
        for e in evs:
            if e.get("recommendation") and e["recommendation"] not in recos:
                recos.append(e["recommendation"])
        incidents.append(
            {
                "incident_id": f"INC-{n}", "incident_name": " + ".join(e["label"] for e in evs),
                "severity": severity, "category": " / ".join(sorted(cats)),
                "start": start.strftime("%Y-%m-%d %H:%M:%S"), "end": end.strftime("%Y-%m-%d %H:%M:%S"),
                "domains": domains, "affected_components": sorted({e["component"] for e in evs}),
                "events": [e["id"] for e in evs], "windows_overlap": overlapping,
                "confidence": confidence, "chronology": chrono, "hypothesis": hypothesis,
                "explanation": chrono + " " + hypothesis, "causality_status": causal,
                "distinction_causalite": causal, "recommendations": recos,
                "verification_needed": verif,
            }
        )
    return incidents


# ------------------------------------------------------------------ ML
def ml_anomaly_summary(system_df: pd.DataFrame, sys_res: list, contamination: float = 0.05):
    from analysis.anomaly_detection import FEATURE_COLS, detect_anomalies_ml

    if len(system_df) < 50 or not set(FEATURE_COLS) <= set(system_df.columns):
        return {"enabled": False, "reason": "données insuffisantes pour l'apprentissage"}
    res = detect_anomalies_ml(system_df, contamination)
    an = res[res["anomaly"] == 1]
    uncovered = 0
    for r in an.itertuples():
        ts = pd.Timestamp(r.timestamp)
        covered = any(
            a.get("hostname") == r.hostname and "window" in a
            and pd.Timestamp(a["window"]["start"]) <= ts <= pd.Timestamp(a["window"]["end"])
            for a in sys_res
        )
        uncovered += 0 if covered else 1
    return {
        "enabled": True, "contamination": contamination, "n_samples": int(len(res)),
        "n_anomalies": int(len(an)),
        "by_host": {k: int(v) for k, v in an["hostname"].value_counts().items()},
        "not_covered_by_rules": int(uncovered),
    }


# ------------------------------------------------------------------ orchestrateur
def infrastructure_orchestrator(data: dict, config: dict) -> dict:
    # 1. Appel des agents spécialisés
    net_res = network_agent(data["network"], config)
    sec_res = security_agent(data["security"], config)
    sys_res = system_agent(data["system"], config)
    app_res = application_agent(data["application"])

    # 2. Consolidation des alertes
    alerts = []
    for a in net_res.get("alerts", []):
        alerts.append({"source": "NetworkAgent", "severity": a.get("severity", "INFO"),
                       "message": a.get("message"), "recommendation": None})
    for src, lst in (("SecurityAgent", sec_res), ("SystemAgent", sys_res)):
        for a in lst:
            alerts.append({"source": src, "severity": a.get("severity", "INFO"),
                           "message": a.get("message"), "recommendation": a.get("recommendation"),
                           "window": a.get("window")})
    for b in app_res.get("error_bursts", []):
        top = ", ".join(f"{m} ({n})" for m, n in b["top_messages"].items())
        alerts.append({"source": "ApplicationAgent",
                       "severity": "HIGH" if b["errors_count"] >= 10 else "WARNING",
                       "message": f"Rafale de {b['errors_count']} erreurs entre {b['start']} et {b['end']} : {top}",
                       "recommendation": None, "window": {"start": b["start"], "end": b["end"]}})

    # 3. État global
    sevs = {a["severity"] for a in alerts}
    status = "CRITICAL" if "CRITICAL" in sevs else ("DEGRADED" if sevs & {"HIGH", "WARNING"} else "HEALTHY")

    # 4. Analyse croisée
    tol = config.get("correlation", {}).get("window_minutes", 30)
    incidents = build_incidents(extract_events(net_res, sec_res, sys_res, app_res), app_res, tol)

    summary = {
        "global_status": status,
        "total_alerts_count": len(alerts),
        "alerts_breakdown": {s: sum(1 for a in alerts if a["severity"] == s)
                             for s in ("CRITICAL", "HIGH", "WARNING")},
        "consolidated_alerts": alerts,
        "agents_results": {
            "network": net_res, "security": sec_res, "system": sys_res,
            "application": {
                "errors_count": len(app_res.get("errors", [])),
                "warnings_count": len(app_res.get("warnings", [])),
                "peak_period": app_res.get("peak_error_period"),
                "error_frequency": app_res.get("error_frequency", {}),
                "error_bursts": app_res.get("error_bursts", []),
                "recommendations": app_res.get("recommendations", []),
            },
        },
        "cross_incident_analysis": incidents,
        "ml_anomaly_summary": ml_anomaly_summary(data["system"], sys_res),
    }
    # 5. Recommandations consolidées + rapport synthétique
    recos = []
    for i in incidents:
        for r in i["recommendations"]:
            if r not in recos:
                recos.append(r)
    summary["recommendations"] = recos
    summary["synthetic_report"] = render_synthetic_report(summary)
    return summary


def render_synthetic_report(s: dict) -> str:
    b = s["alerts_breakdown"]
    lines = [f"ÉTAT GLOBAL : {s['global_status']} — {s['total_alerts_count']} alertes "
             f"(CRITICAL {b['CRITICAL']}, HIGH {b['HIGH']}, WARNING {b['WARNING']}) — "
             f"{len(s['cross_incident_analysis'])} incident(s)"]
    for i in s["cross_incident_analysis"]:
        lines.append(f"- {i['incident_id']} [{i['severity']}] {i['incident_name']} "
                     f"({i['start']} → {i['end']}) | corrélation : {i['confidence']}")
    ml = s.get("ml_anomaly_summary", {})
    if ml.get("enabled"):
        lines.append(f"ML : {ml['n_anomalies']} observations atypiques sur {ml['n_samples']} "
                     f"({ml['not_covered_by_rules']} hors des fenêtres déjà alertées par les règles).")
    return "\n".join(lines)


if __name__ == "__main__":
    data = {
        "network": pd.read_csv("datasets/network_logs.csv"),
        "security": pd.read_csv("datasets/security_logs.csv"),
        "system": pd.read_csv("datasets/system_metrics.csv"),
    }
    with open("datasets/application_logs.txt", encoding="utf-8") as f:
        data["application"] = f.readlines()
    with open("datasets/infrastructure_config.json", encoding="utf-8") as f:
        config = json.load(f)
    rep = infrastructure_orchestrator(data, config)
    print(rep["synthetic_report"])
    print(json.dumps(generate_llm_structured_report(rep), indent=2, ensure_ascii=False))
