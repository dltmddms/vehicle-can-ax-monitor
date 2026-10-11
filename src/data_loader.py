from __future__ import annotations

import io
import re
from pathlib import Path
import pandas as pd
import numpy as np

CAN_COLUMNS = ["timestamp", "can_id", "dlc", *[f"d{i}" for i in range(8)], "flag"]


def _clean_hex(x, width=2):
    if pd.isna(x):
        return "00"
    s = str(x).strip().lower().replace("0x", "")
    s = re.sub(r"[^0-9a-f]", "", s)
    if not s:
        return "00"
    return s[-width:].zfill(width)


def _standardize(df: pd.DataFrame, default_flag: str = "R") -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]

    aliases = {
        "timestamp": ["timestamp", "time"],
        "can_id": ["can_id", "id", "arbitration_id", "canid"],
        "dlc": ["dlc", "data_length_code"],
        "flag": ["flag", "class", "label"],
    }
    rename = {}
    for target, names in aliases.items():
        for n in names:
            if n in df.columns:
                rename[n] = target
                break
    df = df.rename(columns=rename)

    for i in range(8):
        candidates = [f"data[{i}]", f"data_{i}", f"data{i}", f"d{i}"]
        for c in candidates:
            if c in df.columns:
                df = df.rename(columns={c: f"d{i}"})
                break

    missing_core = [c for c in ["timestamp", "can_id", "dlc"] if c not in df.columns]
    if missing_core:
        raise ValueError(f"필수 CAN 컬럼이 없습니다: {missing_core}. 현재 컬럼={list(df.columns)}")

    if "flag" not in df.columns:
        df["flag"] = default_flag
    for i in range(8):
        if f"d{i}" not in df.columns:
            df[f"d{i}"] = "00"

    df = df[["timestamp", "can_id", "dlc", *[f"d{i}" for i in range(8)], "flag"]]
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df["dlc"] = pd.to_numeric(df["dlc"], errors="coerce").fillna(0).clip(0, 8).astype(int)
    df["can_id"] = df["can_id"].map(lambda x: _clean_hex(x, 4))
    for i in range(8):
        df[f"d{i}"] = df[f"d{i}"].map(_clean_hex)

    def norm_flag(x):
        s = str(x).strip().upper()
        if s in {"T", "1", "ATTACK", "ABNORMAL", "TRUE"}:
            return "T"
        return "R"

    df["flag"] = df["flag"].map(norm_flag)
    df = df.dropna(subset=["timestamp"]).reset_index(drop=True)
    return df


def read_hcrl_csv(path_or_file, nrows: int | None = None, default_flag="R") -> pd.DataFrame:
    """Read HCRL-like CSV with or without a header."""
    if hasattr(path_or_file, "read"):
        raw = path_or_file.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="ignore")
        source = io.StringIO(raw)
        peek = raw.splitlines()[0] if raw.splitlines() else ""
    else:
        path = Path(path_or_file)
        peek = path.open("r", encoding="utf-8", errors="ignore").readline()
        source = path

    has_header = any(k in peek.lower() for k in ["timestamp", "can", "dlc", "flag"])
    if has_header:
        df = pd.read_csv(source, nrows=nrows, skipinitialspace=True)
    else:
        # Attack CSVs: usually 12 columns. Normal converted CSV: 11 columns.
        test = pd.read_csv(source, header=None, nrows=5, skipinitialspace=True)
        cols = test.shape[1]
        if hasattr(path_or_file, "read"):
            raw2 = raw
            source = io.StringIO(raw2)
        else:
            source = Path(path_or_file)
        names = CAN_COLUMNS if cols >= 12 else CAN_COLUMNS[:-1]
        df = pd.read_csv(source, header=None, names=names, usecols=range(len(names)), nrows=nrows, skipinitialspace=True)
    return _standardize(df, default_flag=default_flag)


def read_normal_txt(path: str | Path, nrows: int | None = None) -> pd.DataFrame:
    rows = []
    pattern = re.compile(r"Timestamp:\s*([0-9.]+)\s+ID:\s*([0-9A-Fa-f]+)(?:\s+000)?\s+DLC:\s*(\d+)\s+(.*)")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f):
            if nrows is not None and idx >= nrows:
                break
            m = pattern.search(line.strip())
            if not m:
                continue
            payload = m.group(4).split()[:8]
            payload += ["00"] * (8 - len(payload))
            rows.append([m.group(1), m.group(2), m.group(3), *payload, "R"])
    return _standardize(pd.DataFrame(rows, columns=CAN_COLUMNS), default_flag="R")


def hex_to_numeric(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["can_id_int"] = out["can_id"].map(lambda x: int(str(x), 16))
    for i in range(8):
        out[f"d{i}_int"] = out[f"d{i}"].map(lambda x: int(str(x), 16))
    return out
