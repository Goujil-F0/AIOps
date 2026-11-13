import os
import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def run_isolation_forest_detection(
    data_path="datasets/system_metrics.csv",
    contamination=0.05,
    output_fig="analysis/figures/isolation_forest_anomalies.png",
):
    print("=" * 60)
    print("Étape 3 : DÉTECTION D'ANOMALIES MACHINE LEARNING (LIVRABLE 3)")
    print("=" * 60)

    # 1. Chargement et sélection des features
    df = pd.read_csv(data_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    feature_cols = [
        "cpu_usage",
        "memory_usage",
        "disk_usage",
        "process_count",
    ]
    clean_df = df.dropna(subset=feature_cols).copy()
    X = clean_df[feature_cols]

    # 2. Entraînement de l'algorithme Isolation Forest
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=150,
    )
    raw_preds = model.fit_predict(X)

    # 3. Ajout de la colonne 'anomaly' demandée par le sujet (1 = anomalie, 0 = normal)
    clean_df["anomaly"] = [1 if p == -1 else 0 for p in raw_preds]
    anomalies_df = clean_df[clean_df["anomaly"] == 1]

    print(f"Total d'échantillons analysés : {len(clean_df)}")
    print(
        f"Observations détectées comme anormales : {len(anomalies_df)} ({contamination*100}%)"
    )

    # 4. Génération de l'image du graphique
    os.makedirs(os.path.dirname(output_fig), exist_ok=True)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))

    # Graphe 1 : Espace CPU vs RAM
    normal_pts = clean_df[clean_df["anomaly"] == 0]
    ax1.scatter(
        normal_pts["cpu_usage"],
        normal_pts["memory_usage"],
        c="#3498db",
        alpha=0.35,
        s=25,
        label="Normal",
    )
    ax1.scatter(
        anomalies_df["cpu_usage"],
        anomalies_df["memory_usage"],
        c="#e74c3c",
        marker="x",
        s=55,
        linewidths=1.5,
        label="Anomalies ML",
    )
    ax1.set_xlabel("CPU Usage (%)")
    ax1.set_ylabel("Memory Usage (%)")
    ax1.set_title("Espace CPU vs RAM")
    ax1.legend()
    ax1.grid(True, linestyle="--", alpha=0.5)

    # Graphe 2 : Évolution temporelle avec dates propres
    ax2.plot(
        clean_df["timestamp"],
        clean_df["cpu_usage"],
        color="#7f8c8d",
        alpha=0.5,
        label="CPU Usage",
    )
    ax2.scatter(
        anomalies_df["timestamp"],
        anomalies_df["cpu_usage"],
        color="#e74c3c",
        s=35,
        label="Points anormaux",
    )
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %H:%M"))
    ax2.xaxis.set_major_locator(mdates.HourLocator(interval=12))
    fig.autofmt_xdate(rotation=35, ha="right")

    ax2.set_xlabel("Horodatage")
    ax2.set_ylabel("CPU (%)")
    ax2.set_title("Anomalies ML au cours du temps")
    ax2.legend()
    ax2.grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(output_fig, dpi=200)
    plt.close()

    print(f"✅ Graphique sauvegardé avec succès dans : {output_fig}")
    return clean_df, anomalies_df, model


if __name__ == "__main__":
    df_result, anomalies, model = run_isolation_forest_detection()