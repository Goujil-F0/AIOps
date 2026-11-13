import json
import os
import sys

# Permettre l'accès aux modules parents (orchestration, agents, analysis)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analysis.anomaly_detection import run_isolation_forest_detection
from orchestration.orchestrator import (
    generate_llm_structured_report,
    infrastructure_orchestrator,
)
import pandas as pd
import plotly.express as px
import streamlit as st

# Configuration de la page
st.set_page_config(
    page_title="DemoTech - Plateforme AIOps",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Chargement et mise en cache des données
@st.cache_data
def load_all_data():
    net_df = pd.read_csv("datasets/network_logs.csv")
    sec_df = pd.read_csv("datasets/security_logs.csv")
    sys_df = pd.read_csv("datasets/system_metrics.csv")

    net_df["timestamp"] = pd.to_datetime(net_df["timestamp"])
    sec_df["timestamp"] = pd.to_datetime(sec_df["timestamp"])
    sys_df["timestamp"] = pd.to_datetime(sys_df["timestamp"])

    with open("datasets/application_logs.txt", "r", encoding="utf-8") as f:
        app_raw = f.readlines()

    with open("datasets/infrastructure_config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    data_bundle = {
        "network": net_df,
        "security": sec_df,
        "system": sys_df,
        "application": app_raw,
    }
    return data_bundle, config


data_bundle, config = load_all_data()

# Exécution de l'orchestrateur multi-agents
report = infrastructure_orchestrator(data_bundle, config)
llm_insights = generate_llm_structured_report(report)

# ==========================================
# 1. HEADER & ÉTAT GLOBAL DE L'INFRASTRUCTURE
# ==========================================
st.title("🛡️ AIOps - Infrastructure Monitoring Platform")
st.caption(
    "Supervision intelligente, administration des systèmes et cybersécurité multi-agents"
)

st.header("Infrastructure Status")

# Définition de la couleur du badge selon l'état global
status = report["global_status"]
if status == "CRITICAL":
    status_color = "red"
elif status == "DEGRADED":
    status_color = "orange"
else:
    status_color = "green"

col1, col2, col3, col4 = st.columns(4)
col1.metric("État Global", f":{status_color}[{status}]")
col2.metric("Total Alertes Détectées", report["total_alerts_count"])
col3.metric("Alertes Critiques", report["alerts_breakdown"]["CRITICAL"])
col4.metric(
    "Incidents Transversaux", len(report["cross_incident_analysis"])
)

st.divider()

# ==========================================
# 2. VUES PAR DOMAINE (TABS INTERACTIFS)
# ==========================================
tab_net, tab_sec, tab_sys, tab_app, tab_ai = st.tabs(
    [
        "🌐 Network Monitoring",
        "🔒 Security Monitoring",
        "🖥️ System Monitoring",
        "📦 Application Monitoring",
        "🧠 AI & LLM Recommendations",
    ]
)

# -----------------
# TAB 1 : RÉSEAU
# -----------------
with tab_net:
    st.subheader("Supervision des Communications Réseau")
    net_res = report["agents_results"]["network"]

    m1, m2, m3 = st.columns(3)
    m1.metric("Latence Moyenne", f"{net_res['mean_latency_ms']} ms")
    m2.metric("Taux d'échec", f"{net_res['failure_rate_pct']} %")
    m3.metric(
        "Services Dégradés", len(net_res.get("problematic_services", []))
    )

    # Graphique interactif de la latence avec Plotly
    fig_lat = px.line(
        data_bundle["network"],
        x="timestamp",
        y="latency_ms",
        color="status",
        title="Évolution de la latence réseau (ms) par statut",
        labels={"latency_ms": "Latence (ms)", "timestamp": "Horodatage"},
        color_discrete_map={
            "OK": "#2ecc71",
            "SLOW": "#f39c12",
            "FAILED": "#e74c3c",
        },
    )
    st.plotly_chart(fig_lat, use_container_width=True)

    if net_res["alerts"]:
        st.write("##### Alertes Réseau Actives :")
        for a in net_res["alerts"]:
            st.warning(f"**[{a['severity']}]** {a['message']}")

# -----------------
# TAB 2 : SÉCURITÉ
# -----------------
with tab_sec:
    st.subheader("Événements de Cybersécurité")
    sec_alerts = report["agents_results"]["security"]

    st.write("##### Tableau des Menaces et Alertes de Sécurité :")
    if sec_alerts:
        sec_df_display = pd.DataFrame(sec_alerts)
        st.dataframe(
            sec_df_display[
                [
                    c
                    for c in [
                        "type",
                        "severity",
                        "source_ip",
                        "targeted_users",
                        "message",
                        "recommendation",
                    ]
                    if c in sec_df_display.columns
                ]
            ],
            use_container_width=True,
        )
    else:
        st.success("Aucune menace de sécurité détectée.")

# -----------------
# TAB 3 : SYSTÈME & ML
# -----------------
with tab_sys:
    st.subheader("Métriques Système & Détection ML (Isolation Forest)")
    sys_df = data_bundle["system"]

    col_s1, col_s2 = st.columns(2)
    # Graphique CPU
    with col_s1:
        fig_cpu = px.line(
            sys_df,
            x="timestamp",
            y="cpu_usage",
            color="hostname",
            title="Utilisation CPU par serveur (%)",
        )
        fig_cpu.add_hline(
            y=config.get("thresholds", {}).get("cpu", 80),
            line_dash="dash",
            line_color="red",
            annotation_text="Seuil 80%",
        )
        st.plotly_chart(fig_cpu, use_container_width=True)

    # Graphique RAM
    with col_s2:
        fig_mem = px.line(
            sys_df,
            x="timestamp",
            y="memory_usage",
            color="hostname",
            title="Utilisation Mémoire par serveur (%)",
        )
        st.plotly_chart(fig_mem, use_container_width=True)

    st.write("##### Alertes Système Déterministes :")
    for a in report["agents_results"]["system"]:
        st.error(
            f"**[{a['severity']}] {a['hostname']}** - {a['message']} | *Recommandation :* {a.get('recommendation')}"
        )

# -----------------
# TAB 4 : APPLICATIF
# -----------------
with tab_app:
    st.subheader("Supervision des Journaux Applicatifs")
    app_res = report["agents_results"]["application"]

    st.write(
        f"**Nombre d'erreurs applicatives :** {app_res['errors_count']} | **Période de pic :** {app_res.get('peak_period')}"
    )

    # Extraction des erreurs pour le tableau
    app_agent_full = report["agents_results"]["application"]
    st.write("##### Tableau des Recommandations Applicatives :")
    for r in app_res.get("recommendations", []):
        st.info(r)

# -----------------
# TAB 5 : RECOMMANDATIONS IA & LLM
# -----------------
with tab_ai:
    st.subheader("Synthèse de l'Orchestrateur & Recommandations IA (LLM)")

    st.markdown("#### 1. Incidents Transversaux Détectés (Corrélation Multi-Agents)")
    for corr in report["cross_incident_analysis"]:
        with st.expander(
            f"🚨 {corr['incident_id']} [{corr['severity']}] {corr['incident_name']} - Corrélation : {corr['confidence']}",
            expanded=False,
        ):
            st.write(f"**Période :** {corr['start']} → {corr['end']}")
            st.write(f"**Composants impactés :** {', '.join(corr['affected_components'])}")
            st.write(corr["chronology"])
            st.write(f"**Hypothèse :** {corr['hypothesis']}")
            st.caption(f"**Causalité :** {corr['causality_status']}")

    st.markdown("#### 2. Rapport Décisionnel Généré par le Module LLM")
    st.caption(
        f"Mode de génération : **{llm_insights['generation_mode']}**"
        + (f" ({llm_insights['fallback_reason']})" if llm_insights.get("fallback_reason") else "")
    )
    st.info(f"**Résumé de situation :** {llm_insights['situation_summary']}")
    st.write(
        f"**Hypothèse de cause racine (Root Cause) :** {llm_insights['root_cause_explanation']}"
    )

    st.write("##### Actions recommandées :")
    for act in llm_insights["actionable_recommendations"]:
        st.markdown(f"- 🔧 {act}")

    if llm_insights["requires_human_validation"]:
        st.warning("⚠️ **Validation humaine requise pour les actions suivantes :**")
        for cp in llm_insights["human_validation_checkpoints"]:
            st.markdown(f"- 👤 {cp}")