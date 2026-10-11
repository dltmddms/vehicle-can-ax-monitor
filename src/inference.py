from __future__ import annotations

import numpy as np
import pandas as pd
from .data_loader import hex_to_numeric
from .features import make_windows


def analyze_frames(df: pd.DataFrame, bundle: dict, window_size=200, stride=200):
    numeric = hex_to_numeric(df)
    windows = make_windows(numeric, window_size=window_size, stride=stride, source_attack_type=None)
    if windows.empty:
        raise ValueError(f"메시지가 너무 적습니다. 최소 {window_size}개 이상 필요합니다.")
    X = windows[bundle["feature_columns"]]
    model = bundle["model"]
    windows["prediction"] = model.predict(X)
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)
        windows["confidence"] = probs.max(axis=1)
    else:
        windows["confidence"] = 1.0
    windows["is_abnormal"] = windows["prediction"] != "normal"
    return windows


def incident_summary(raw_df: pd.DataFrame, windows: pd.DataFrame):
    abnormal = windows[windows["is_abnormal"]]
    if abnormal.empty:
        return {
            "status": "NORMAL", "predicted_attack": "normal", "confidence": 0.0,
            "abnormal_windows": 0, "total_windows": len(windows), "suspicious_ids": [],
            "start_time": None, "end_time": None,
        }

    attack = abnormal["prediction"].value_counts().idxmax()
    conf = float(abnormal.loc[abnormal["prediction"] == attack, "confidence"].mean())
    t0, t1 = float(abnormal["start_time"].min()), float(abnormal["end_time"].max())
    slice_df = raw_df[(raw_df["timestamp"] >= t0) & (raw_df["timestamp"] <= t1)]
    ids = slice_df["can_id"].value_counts().head(5)
    suspicious = [{"can_id": str(i), "count": int(c)} for i, c in ids.items()]
    return {
        "status": "ABNORMAL",
        "predicted_attack": str(attack),
        "confidence": conf,
        "abnormal_windows": int(len(abnormal)),
        "total_windows": int(len(windows)),
        "suspicious_ids": suspicious,
        "start_time": t0,
        "end_time": t1,
    }
