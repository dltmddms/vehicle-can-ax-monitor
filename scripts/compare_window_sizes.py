from pathlib import Path
import sys
import pandas as pd
from sklearn.metrics import f1_score, recall_score, balanced_accuracy_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.data_loader import read_hcrl_csv
from src.modeling import load_bundle
from src.inference import analyze_frames

MODEL = ROOT / "models" / "can_ax_model.joblib"
SAMPLES = ROOT / "data" / "test_samples"
OUT = ROOT / "experiments" / "window_size_results.csv"

SAMPLE_INFO = {
    "normal": ("normal_real_sample.csv", "normal"),
    "dos": ("dos_real_sample.csv", "dos"),
    "fuzzy": ("fuzzy_real_sample.csv", "fuzzy"),
    "gear": ("gear_real_sample.csv", "gear"),
    "rpm": ("rpm_real_sample.csv", "rpm"),
}

WINDOW_SIZES = [100, 200, 500]
MIN_ATTACK_RATIO = 0.01


def truth_for_windows(raw, attack_type, window_size):
    labels = []
    for start in range(0, len(raw) - window_size + 1, window_size):
        w = raw.iloc[start:start + window_size]
        ratio = float((w["flag"] == "T").mean())
        if attack_type != "normal" and ratio >= MIN_ATTACK_RATIO:
            labels.append(attack_type)
        else:
            labels.append("normal")
    return labels


def main():
    if not MODEL.exists():
        raise FileNotFoundError("models/can_ax_model.joblib not found")
    bundle = load_bundle(MODEL)
    rows = []

    for ws in WINDOW_SIZES:
        y_true_all, y_pred_all = [], []
        sample_correct = 0
        sample_total = 0

        for sample_name, (filename, attack_type) in SAMPLE_INFO.items():
            path = SAMPLES / filename
            if not path.exists():
                print(f"[SKIP] {path} not found")
                continue

            raw = read_hcrl_csv(path)
            pred_df = analyze_frames(raw, bundle, window_size=ws, stride=ws)
            y_true = truth_for_windows(raw, attack_type, ws)
            y_pred = pred_df["prediction"].tolist()

            n = min(len(y_true), len(y_pred))
            y_true = y_true[:n]
            y_pred = y_pred[:n]

            y_true_all.extend(y_true)
            y_pred_all.extend(y_pred)

            if attack_type == "normal":
                predicted_sample = "normal" if all(p == "normal" for p in y_pred) else "abnormal"
                expected_sample = "normal"
            else:
                abnormal_preds = [p for p in y_pred if p != "normal"]
                predicted_sample = (
                    pd.Series(abnormal_preds).value_counts().idxmax()
                    if abnormal_preds else "normal"
                )
                expected_sample = attack_type

            sample_correct += int(predicted_sample == expected_sample)
            sample_total += 1

        if not y_true_all:
            continue

        binary_true = [0 if x == "normal" else 1 for x in y_true_all]
        binary_pred = [0 if x == "normal" else 1 for x in y_pred_all]

        rows.append({
            "window_size": ws,
            "windows_evaluated": len(y_true_all),
            "macro_f1": f1_score(y_true_all, y_pred_all, average="macro", zero_division=0),
            "attack_recall": recall_score(binary_true, binary_pred, zero_division=0),
            "balanced_accuracy": balanced_accuracy_score(binary_true, binary_pred),
            "sample_type_accuracy": sample_correct / sample_total if sample_total else 0.0,
        })

    result = pd.DataFrame(rows)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUT, index=False, encoding="utf-8-sig")

    print("\n=== Window-size experiment ===")
    print(result.to_string(index=False))
    print(f"\nSaved: {OUT}")


if __name__ == "__main__":
    main()
