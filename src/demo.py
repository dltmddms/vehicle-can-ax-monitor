from __future__ import annotations

import numpy as np
import pandas as pd

from .features import FEATURE_COLUMNS


DEMO_SAMPLES = {
    "Normal example": "normal",
    "DoS-like example": "dos",
    "Fuzzy-like example": "fuzzy",
}


class DemoRuleModel:
    """Deterministic rule-based detector used only for the synthetic demo.

    It intentionally does not load or imitate the trained HCRL model.
    The purpose is to let visitors exercise the UI and analysis flow.
    """

    def predict(self, X: pd.DataFrame):
        dominant = X["dominant_id_ratio"].to_numpy(float)
        unique_ids = X["unique_id_count"].to_numpy(float)
        entropy = X["can_id_entropy"].to_numpy(float)

        predictions = np.full(len(X), "normal", dtype=object)
        predictions[(unique_ids >= 40) & (entropy >= 4.5)] = "fuzzy"
        predictions[dominant >= 0.75] = "dos"
        return predictions

    def predict_proba(self, X: pd.DataFrame):
        predictions = self.predict(X)
        rows = []
        for prediction in predictions:
            if prediction == "dos":
                rows.append([0.03, 0.95, 0.02])
            elif prediction == "fuzzy":
                rows.append([0.03, 0.02, 0.95])
            else:
                rows.append([0.96, 0.02, 0.02])
        return np.asarray(rows, dtype=float)


def demo_bundle() -> dict:
    return {
        "model": DemoRuleModel(),
        "feature_columns": FEATURE_COLUMNS,
        "dataset_mode": "synthetic_demo",
    }


def make_demo_log(sample: str, window_size: int = 200, total_windows: int = 6) -> pd.DataFrame:
    """Build a deterministic HCRL-shaped synthetic CAN log for UI demonstration."""
    if sample not in {"normal", "dos", "fuzzy"}:
        raise ValueError(f"지원하지 않는 demo sample: {sample}")
    if window_size < 1 or total_windows < 1:
        raise ValueError("window_size와 total_windows는 1 이상이어야 합니다.")

    total = window_size * total_windows
    attack_windows = {2, 3} if total_windows >= 4 else {total_windows - 1}
    base_ids = [0x100 + i for i in range(16)]

    rows = []
    for i in range(total):
        window_no = i // window_size
        pos = i % window_size
        abnormal = sample != "normal" and window_no in attack_windows

        if sample == "dos" and abnormal:
            can_id_int = 0x0000 if pos < int(window_size * 0.90) else base_ids[pos % len(base_ids)]
            payload_seed = 0
        elif sample == "fuzzy" and abnormal:
            can_id_int = 0x300 + ((pos * 37 + window_no * 17) % max(64, min(window_size, 180)))
            payload_seed = (pos * 53 + window_no * 29) % 256
        else:
            can_id_int = base_ids[(pos + window_no) % len(base_ids)]
            payload_seed = (pos + window_no * 7) % 256

        payload = [
            (payload_seed + 13 * j + (pos % 5) * j) % 256
            for j in range(8)
        ]

        rows.append(
            {
                "timestamp": i * 0.002,
                "can_id": f"{can_id_int:04x}",
                "dlc": 8,
                **{f"d{j}": f"{payload[j]:02x}" for j in range(8)},
                "flag": "T" if abnormal else "R",
            }
        )

    return pd.DataFrame(rows)
