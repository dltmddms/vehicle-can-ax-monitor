from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score, balanced_accuracy_score,
    precision_recall_fscore_support, recall_score, precision_score, accuracy_score
)

from .features import FEATURE_COLUMNS


def temporal_split_per_class(df: pd.DataFrame, test_ratio=0.25):
    train_parts, test_parts = [], []
    for label, part in df.groupby("label", sort=False):
        part = part.sort_values("start_time").reset_index(drop=True)
        cut = max(1, int(len(part) * (1 - test_ratio)))
        if cut >= len(part):
            cut = len(part) - 1
        train_parts.append(part.iloc[:cut])
        test_parts.append(part.iloc[cut:])
    train = pd.concat(train_parts, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    test = pd.concat(test_parts, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    return train, test


def _metrics(y_true, y_pred):
    labels = sorted(pd.Series(y_true).unique().tolist())
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    binary_true = np.array([0 if y == "normal" else 1 for y in y_true])
    binary_pred = np.array([0 if y == "normal" else 1 for y in y_pred])
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro")),
        "attack_precision": float(precision_score(binary_true, binary_pred, zero_division=0)),
        "attack_recall": float(recall_score(binary_true, binary_pred, zero_division=0)),
        "attack_f1": float(f1_score(binary_true, binary_pred, zero_division=0)),
        "classification_report": report,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "labels": labels,
    }


def train_compare(window_df: pd.DataFrame, out_dir: str | Path, dataset_mode="demo"):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_df, test_df = temporal_split_per_class(window_df)
    X_train, y_train = train_df[FEATURE_COLUMNS], train_df["label"]
    X_test, y_test = test_df[FEATURE_COLUMNS], test_df["label"]

    baseline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)),
    ])
    baseline.fit(X_train, y_train)
    base_pred = baseline.predict(X_test)
    base_metrics = _metrics(y_test, base_pred)

    rf = RandomForestClassifier(
        n_estimators=240,
        max_depth=14,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    pred = rf.predict(X_test)
    rf_metrics = _metrics(y_test, pred)

    importances = sorted(
        zip(FEATURE_COLUMNS, rf.feature_importances_), key=lambda x: x[1], reverse=True
    )
    bundle = {
        "model": rf,
        "feature_columns": FEATURE_COLUMNS,
        "dataset_mode": dataset_mode,
        "classes": list(rf.classes_),
        "feature_importance": importances,
    }
    joblib.dump(bundle, out_dir / "can_ax_model.joblib")
    joblib.dump(baseline, out_dir / "baseline_logreg.joblib")

    metrics = {
        "dataset_mode": dataset_mode,
        "random_forest": rf_metrics,
        "logistic_regression": base_metrics,
        "train_windows": len(train_df),
        "test_windows": len(test_df),
        "feature_importance": [{"feature": k, "importance": float(v)} for k, v in importances],
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    test_out = test_df[["start_time", "end_time", "label"]].copy()
    test_out["prediction"] = pred
    test_out.to_csv(out_dir / "test_predictions.csv", index=False)
    return metrics


def load_bundle(model_path: str | Path):
    return joblib.load(model_path)
