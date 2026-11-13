"""Interprétation des résultats structurés par un LLM (avec garde-fous).

Principes (consigne 17) :
  * le LLM ne reçoit QUE les résultats structurés des agents (`build_llm_input`) ;
  * la sortie doit respecter un schéma JSON fixé à l'avance (`validate_output`) ;
  * toute valeur numérique, IP ou nom de serveur absent de l'entrée est rejeté
    (`check_grounding`) : pas d'invention de métriques ni d'événements ;
  * si aucun LLM n'est disponible (pas de clé API, erreur réseau) ou si la sortie
    est rejetée, un interprète déterministe, lui aussi limité aux faits transmis,
    produit le même schéma. Le champ `generation_mode` indique toujours l'origine
    réelle ("llm" ou "deterministic").
"""
import json
import os
import re

OUTPUT_SCHEMA = {
    "generation_mode": str,
    "situation_summary": str,
    "incident_classification": list,
    "explanation": str,
    "root_cause_explanation": str,
    "actionable_recommendations": list,
    "requires_human_validation": bool,
    "human_validation_checkpoints": list,
}

SYSTEM_PROMPT = (
    "Tu es un analyste AIOps. Tu reçois UNIQUEMENT des résultats structurés d'agents de "
    "supervision au format JSON. Réponds par un unique objet JSON (sans texte autour) avec "
    "les clés : situation_summary (str), incident_classification (liste d'objets "
    "{incident_id, title, severity, category}), explanation (str), root_cause_explanation "
    "(str, formulée comme HYPOTHÈSE), actionable_recommendations (liste de str), "
    "requires_human_validation (bool), human_validation_checkpoints (liste de str). "
    "RÈGLES : n'invente aucune métrique, valeur, date, adresse IP ou serveur absent de "
    "l'entrée ; ne présente jamais une corrélation comme une causalité démontrée ; toute "
    "action à effet de bord (blocage IP, purge, redémarrage) doit apparaître dans "
    "human_validation_checkpoints."
)


# ----------------------------------------------------------------- entrée
def build_llm_input(summary: dict) -> dict:
    """Vue compacte et strictement factuelle du résumé de l'orchestrateur."""
    agents = summary.get("agents_results", {})
    net = agents.get("network", {})
    return {
        "global_status": summary.get("global_status"),
        "total_alerts_count": summary.get("total_alerts_count"),
        "alerts_breakdown": summary.get("alerts_breakdown"),
        "incidents_count": len(summary.get("cross_incident_analysis", [])),
        "network": {
            "mean_latency_ms": net.get("mean_latency_ms"),
            "failure_rate_pct": net.get("failure_rate_pct"),
            "problematic_services": net.get("problematic_services", []),
        },
        "alerts": [
            {k: a.get(k) for k in ("source", "severity", "message")}
            for a in summary.get("consolidated_alerts", [])
        ],
        "incidents": [
            {
                "incident_id": i["incident_id"],
                "title": i["incident_name"],
                "severity": i["severity"],
                "category": i["category"],
                "start": i["start"],
                "end": i["end"],
                "components": i["affected_components"],
                "chronology": i["chronology"],
                "hypothesis": i["hypothesis"],
                "causality_status": i["causality_status"],
                "recommendations": i["recommendations"],
                "verification_needed": i["verification_needed"],
            }
            for i in summary.get("cross_incident_analysis", [])
        ],
        "ml_anomaly_summary": summary.get("ml_anomaly_summary"),
    }


# ----------------------------------------------------------------- garde-fous
def validate_output(out) -> list:
    """Retourne la liste des violations de schéma (vide si conforme)."""
    if not isinstance(out, dict):
        return ["la sortie n'est pas un objet JSON"]
    errs = []
    for key, typ in OUTPUT_SCHEMA.items():
        if key not in out:
            errs.append(f"clé manquante : {key}")
        elif not isinstance(out[key], typ):
            errs.append(f"type invalide pour {key} (attendu {typ.__name__})")
    for item in out.get("incident_classification", []) if isinstance(
        out.get("incident_classification"), list
    ) else []:
        if not isinstance(item, dict) or not {"incident_id", "title", "severity", "category"} <= set(item):
            errs.append("incident_classification : objet incomplet")
            break
    return errs


_NUM = re.compile(r"\d+(?:[.,]\d+)?")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOST = re.compile(r"\b[a-z]+-[a-z]+-\d+\b|\b[a-z]+-server-\d+\b")


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k != "generation_mode":
                yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


def check_grounding(output: dict, llm_input: dict) -> list:
    """Liste les nombres / IP / serveurs de la sortie absents de l'entrée."""
    source = json.dumps(llm_input, ensure_ascii=False)
    src_nums = set(_NUM.findall(source)) | {n.replace(",", ".") for n in _NUM.findall(source)}
    src_ips = set(_IP.findall(source))
    src_hosts = set(_HOST.findall(source))
    bad = []
    for text in _strings(output):
        for ip in _IP.findall(text):
            if ip not in src_ips:
                bad.append(f"IP inventée : {ip}")
        for h in _HOST.findall(text):
            if h not in src_hosts:
                bad.append(f"serveur inventé : {h}")
        for n in _NUM.findall(_IP.sub(" ", text)):
            if n not in src_nums and n.replace(",", ".") not in src_nums:
                bad.append(f"valeur numérique absente de l'entrée : {n}")
    return sorted(set(bad))


# ----------------------------------------------------------------- interprète déterministe
def deterministic_interpretation(llm_input: dict) -> dict:
    incidents = llm_input["incidents"]
    status = llm_input["global_status"]
    br = llm_input["alerts_breakdown"] or {}
    summary = (
        f"État global : {status}. {llm_input['total_alerts_count']} alertes consolidées "
        f"({br.get('CRITICAL', 0)} CRITICAL, {br.get('HIGH', 0)} HIGH, {br.get('WARNING', 0)} WARNING) "
        f"regroupées en {llm_input['incidents_count']} incident(s) par proximité temporelle."
    )
    classification = [
        {
            "incident_id": i["incident_id"],
            "title": i["title"],
            "severity": i["severity"],
            "category": i["category"],
        }
        for i in incidents
    ]
    explanation = " ".join(
        f"{i['incident_id']} ({i['start']} → {i['end']}) : {i['chronology']} {i['causality_status']}"
        for i in incidents
    ) or "Aucun incident détecté."
    hypotheses = " ".join(f"{i['incident_id']} — {i['hypothesis']}" for i in incidents)
    recos, seen = [], set()
    for i in incidents:
        for r in i["recommendations"]:
            if r not in seen:
                seen.add(r)
                recos.append(r)
    checkpoints = []
    for i in incidents:
        for v in i["verification_needed"]:
            checkpoints.append(f"{i['incident_id']} : {v}")
    return {
        "generation_mode": "deterministic",
        "situation_summary": summary,
        "incident_classification": classification,
        "explanation": explanation,
        "root_cause_explanation": "Hypothèses (non démontrées) : " + hypotheses if hypotheses else "Aucune hypothèse nécessaire.",
        "actionable_recommendations": recos,
        "requires_human_validation": bool(incidents),
        "human_validation_checkpoints": checkpoints,
    }


# ----------------------------------------------------------------- client LLM
def default_llm_client():
    """Client Anthropic via HTTP si ANTHROPIC_API_KEY est définie, sinon None."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None

    def client(system: str, user: str) -> str:
        import requests

        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": os.environ.get("AIOPS_LLM_MODEL", "claude-sonnet-5-5"),
                "max_tokens": 2000,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            timeout=60,
        )
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json()["content"])

    return client


def _parse_json(raw: str):
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.M).strip()
    return json.loads(raw)


def generate_llm_structured_report(summary: dict, llm_client="auto") -> dict:
    """Produit l'interprétation JSON des résultats de l'orchestrateur.

    llm_client : callable(system, user) -> str, None (désactive le LLM) ou "auto"
    (client Anthropic si une clé est configurée)."""
    llm_input = build_llm_input(summary)
    client = default_llm_client() if llm_client == "auto" else llm_client
    reason = "aucun LLM configuré"
    if client is not None:
        try:
            out = _parse_json(client(SYSTEM_PROMPT, json.dumps(llm_input, ensure_ascii=False)))
            out["generation_mode"] = "llm"
            errors = validate_output(out) + check_grounding(out, llm_input)
            if not errors:
                return out
            reason = "sortie LLM rejetée : " + "; ".join(errors[:5])
        except Exception as exc:  # réseau, JSON invalide, quota...
            reason = f"échec de l'appel LLM : {exc}"
    out = deterministic_interpretation(llm_input)
    out["fallback_reason"] = reason
    return out
