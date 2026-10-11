from __future__ import annotations

import math
import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "msg_rate", "interarrival_mean", "interarrival_std", "interarrival_min",
    "unique_id_count", "can_id_entropy", "dominant_id_ratio", "dominant_id_int",
    "id_switch_rate", "dlc_mean", "dlc_std", "payload_mean", "payload_std",
    "payload_zero_ratio", "payload_entropy", "payload_change_mean", "zero_id_ratio",
]


def _entropy(values) -> float:
    arr = pd.Series(values).dropna()
    if arr.empty:
        return 0.0
    p = arr.value_counts(normalize=True).to_numpy()
    return float(-(p * np.log2(p + 1e-12)).sum())


def window_features(window: pd.DataFrame) -> dict:
    ts = window["timestamp"].to_numpy(float)
    dt = np.diff(ts)
    dt_pos = dt[dt > 0]
    duration = max(float(ts[-1] - ts[0]), 1e-6) if len(ts) > 1 else 1e-6

    ids = window["can_id_int"].to_numpy(int)
    id_series = pd.Series(ids)
    dominant_id = int(id_series.mode().iloc[0]) if len(id_series) else 0
    dominant_ratio = float((ids == dominant_id).mean()) if len(ids) else 0.0

    payload_cols = [f"d{i}_int" for i in range(8)]
    payload = window[payload_cols].to_numpy(float)
    if len(payload) > 1:
        payload_change = np.abs(np.diff(payload, axis=0)).mean()
    else:
        payload_change = 0.0

    feats = {
        "msg_rate": len(window) / duration,
        "interarrival_mean": float(dt_pos.mean()) if len(dt_pos) else 0.0,
        "interarrival_std": float(dt_pos.std()) if len(dt_pos) else 0.0,
        "interarrival_min": float(dt_pos.min()) if len(dt_pos) else 0.0,
        "unique_id_count": int(id_series.nunique()),
        "can_id_entropy": _entropy(ids),
        "dominant_id_ratio": dominant_ratio,
        "dominant_id_int": dominant_id,
        "id_switch_rate": float((ids[1:] != ids[:-1]).mean()) if len(ids) > 1 else 0.0,
        "dlc_mean": float(window["dlc"].mean()),
        "dlc_std": float(window["dlc"].std(ddof=0)),
        "payload_mean": float(payload.mean()),
        "payload_std": float(payload.std()),
        "payload_zero_ratio": float((payload == 0).mean()),
        "payload_entropy": _entropy(payload.reshape(-1)),
        "payload_change_mean": float(payload_change),
        "zero_id_ratio": float((ids == 0).mean()),
    }
    return feats


def make_windows(df: pd.DataFrame, window_size=200, stride=200, source_attack_type: str | None = None,
                 min_attack_ratio=0.01) -> pd.DataFrame:
    rows = []
    if len(df) < window_size:
        return pd.DataFrame(columns=FEATURE_COLUMNS + ["label", "attack_ratio", "start_time", "end_time"])

    for start in range(0, len(df) - window_size + 1, stride):
        w = df.iloc[start:start + window_size]
        feats = window_features(w)
        attack_ratio = float((w["flag"] == "T").mean())
        if source_attack_type and source_attack_type != "normal" and attack_ratio >= min_attack_ratio:
            label = source_attack_type
        else:
            label = "normal"
        feats.update({
            "label": label,
            "attack_ratio": attack_ratio,
            "start_time": float(w["timestamp"].iloc[0]),
            "end_time": float(w["timestamp"].iloc[-1]),
        })
        rows.append(feats)
    return pd.DataFrame(rows)
