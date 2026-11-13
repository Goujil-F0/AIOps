"""Utilitaires partagés par les agents (fenêtres temporelles)."""
import pandas as pd

TS_FMT = "%Y-%m-%d %H:%M:%S"


def fmt_ts(ts) -> str:
    return pd.Timestamp(ts).strftime(TS_FMT)


def split_bursts(timestamps, gap_minutes: float = 60):
    """Découpe une série d'horodatages en rafales : une nouvelle rafale démarre
    quand l'écart avec l'événement précédent dépasse `gap_minutes`.
    Retourne une liste de tuples (début, fin, nombre_d_evenements)."""
    ts = pd.Series(pd.to_datetime(list(timestamps))).sort_values()
    groups, cur = [], []
    for t in ts:
        if cur and (t - cur[-1]) > pd.Timedelta(minutes=gap_minutes):
            groups.append(cur)
            cur = []
        cur.append(t)
    if cur:
        groups.append(cur)
    return [(g[0], g[-1], len(g)) for g in groups]
