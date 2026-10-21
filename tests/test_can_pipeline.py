from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.data_loader import hex_to_numeric
from src.features import FEATURE_COLUMNS, make_windows, window_features
from src.inference import analyze_frames, incident_summary
from src.report import template_report


def synthetic_log(can_ids: list[str], flags: list[str] | None = None) -> pd.DataFrame:
    """Create a small HCRL-like CAN log without external data files."""
    n = len(can_ids)
    if flags is None:
        flags = ["R"] * n

    rows = []
    for i, (can_id, flag) in enumerate(zip(can_ids, flags)):
        rows.append(
            {
                "timestamp": i * 0.01,
                "can_id": can_id,
                "dlc": 8,
                "d0": f"{i % 256:02x}",
                "d1": f"{(i + 1) % 256:02x}",
                "d2": "10",
                "d3": "20",
                "d4": "30",
                "d5": "40",
                "d6": "50",
                "d7": "60",
                "flag": flag,
            }
        )
    return pd.DataFrame(rows)


class RepeatingIdMockModel:
    """Tiny deterministic stand-in for the trained HCRL model.

    A window is treated as DoS-like when one CAN ID dominates at least 75%
    of the messages. This is only for pipeline tests, not model evaluation.
    """

    def predict(self, X):
        return np.where(X["dominant_id_ratio"].to_numpy() >= 0.75, "dos", "normal")

    def predict_proba(self, X):
        is_dos = X["dominant_id_ratio"].to_numpy() >= 0.75
        return np.column_stack(
            [
                np.where(is_dos, 0.05, 0.95),
                np.where(is_dos, 0.95, 0.05),
            ]
        )


class FeatureTests(unittest.TestCase):
    def test_window_features_for_non_repeating_ids(self):
        raw = synthetic_log(["0100", "0101", "0102", "0103"])
        numeric = hex_to_numeric(raw)

        features = window_features(numeric)

        self.assertEqual(features["unique_id_count"], 4)
        self.assertAlmostEqual(features["dominant_id_ratio"], 0.25)
        self.assertAlmostEqual(features["id_switch_rate"], 1.0)
        self.assertAlmostEqual(features["zero_id_ratio"], 0.0)
        self.assertEqual(set(features), set(FEATURE_COLUMNS))

    def test_window_features_for_repeating_zero_id(self):
        raw = synthetic_log(["0000", "0000", "0000", "0001"])
        numeric = hex_to_numeric(raw)

        features = window_features(numeric)

        self.assertEqual(features["unique_id_count"], 2)
        self.assertEqual(features["dominant_id_int"], 0)
        self.assertAlmostEqual(features["dominant_id_ratio"], 0.75)
        self.assertAlmostEqual(features["zero_id_ratio"], 0.75)


class WindowingTests(unittest.TestCase):
    def test_exact_window_size_creates_one_window(self):
        raw = synthetic_log(["0100", "0101", "0102", "0103"])
        numeric = hex_to_numeric(raw)

        windows = make_windows(numeric, window_size=4, stride=4)

        self.assertEqual(len(windows), 1)
        self.assertAlmostEqual(windows.iloc[0]["start_time"], 0.00)
        self.assertAlmostEqual(windows.iloc[0]["end_time"], 0.03)

    def test_trailing_partial_window_is_ignored(self):
        raw = synthetic_log(
            ["0100", "0101", "0102", "0103", "0200", "0201", "0202", "0203", "0300"]
        )
        numeric = hex_to_numeric(raw)

        windows = make_windows(numeric, window_size=4, stride=4)

        self.assertEqual(len(windows), 2)
        self.assertAlmostEqual(windows.iloc[1]["start_time"], 0.04)
        self.assertAlmostEqual(windows.iloc[1]["end_time"], 0.07)

    def test_too_few_messages_returns_empty_feature_frame(self):
        raw = synthetic_log(["0100", "0101", "0102"])
        numeric = hex_to_numeric(raw)

        windows = make_windows(numeric, window_size=4, stride=4)

        self.assertTrue(windows.empty)
        self.assertEqual(
            list(windows.columns),
            FEATURE_COLUMNS + ["label", "attack_ratio", "start_time", "end_time"],
        )


class InferenceAndSummaryTests(unittest.TestCase):
    def setUp(self):
        self.bundle = {
            "model": RepeatingIdMockModel(),
            "feature_columns": FEATURE_COLUMNS,
        }

    def test_analyze_frames_rejects_too_short_log(self):
        raw = synthetic_log(["0100", "0101", "0102"])

        with self.assertRaisesRegex(ValueError, "최소 4개 이상"):
            analyze_frames(raw, self.bundle, window_size=4, stride=4)

    def test_dos_like_window_is_detected_and_summarized(self):
        raw = synthetic_log(
            ["0100", "0101", "0102", "0103", "0000", "0000", "0000", "0000"]
        )

        windows = analyze_frames(raw, self.bundle, window_size=4, stride=4)
        summary = incident_summary(raw, windows)

        self.assertEqual(windows["prediction"].tolist(), ["normal", "dos"])
        self.assertEqual(windows["is_abnormal"].tolist(), [False, True])
        self.assertAlmostEqual(float(windows.iloc[1]["confidence"]), 0.95)

        self.assertEqual(summary["status"], "ABNORMAL")
        self.assertEqual(summary["predicted_attack"], "dos")
        self.assertEqual(summary["abnormal_windows"], 1)
        self.assertEqual(summary["total_windows"], 2)
        self.assertEqual(summary["suspicious_ids"][0], {"can_id": "0000", "count": 4})
        self.assertAlmostEqual(summary["start_time"], 0.04)
        self.assertAlmostEqual(summary["end_time"], 0.07)

    def test_normal_log_produces_normal_summary(self):
        raw = synthetic_log(
            ["0100", "0101", "0102", "0103", "0200", "0201", "0202", "0203"]
        )

        windows = analyze_frames(raw, self.bundle, window_size=4, stride=4)
        summary = incident_summary(raw, windows)

        self.assertTrue((windows["prediction"] == "normal").all())
        self.assertEqual(summary["status"], "NORMAL")
        self.assertEqual(summary["predicted_attack"], "normal")
        self.assertEqual(summary["abnormal_windows"], 0)
        self.assertEqual(summary["suspicious_ids"], [])
        self.assertIsNone(summary["start_time"])
        self.assertIsNone(summary["end_time"])


class ReportTests(unittest.TestCase):
    def test_normal_report_has_no_recommended_checks(self):
        summary = {
            "status": "NORMAL",
            "predicted_attack": "normal",
            "confidence": 0.0,
            "abnormal_windows": 0,
            "total_windows": 2,
            "suspicious_ids": [],
            "start_time": None,
            "end_time": None,
        }

        report = template_report(summary, model_mode="test")

        self.assertIn("Status | **NORMAL**", report)
        self.assertIn("Detected pattern | **NORMAL**", report)
        self.assertNotIn("### Recommended checks", report)

    def test_dos_report_contains_follow_up_checks(self):
        summary = {
            "status": "ABNORMAL",
            "predicted_attack": "dos",
            "confidence": 0.95,
            "abnormal_windows": 1,
            "total_windows": 2,
            "suspicious_ids": [{"can_id": "0000", "count": 4}],
            "start_time": 0.04,
            "end_time": 0.07,
        }

        report = template_report(summary, model_mode="test")

        self.assertIn("Detected pattern | **DOS**", report)
        self.assertIn("0x0000 (4)", report)
        self.assertIn("### Recommended checks", report)
        self.assertIn("메시지 발생 주기와 전송률", report)


if __name__ == "__main__":
    unittest.main()
