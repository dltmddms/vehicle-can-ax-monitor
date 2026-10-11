import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
from src.data_loader import read_hcrl_csv, read_normal_txt

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "test_samples"
OUT.mkdir(parents=True, exist_ok=True)

ATTACK_FILES = {
    "dos": "DoS_dataset.csv",
    "fuzzy": "Fuzzy_dataset.csv",
    "gear": "gear_dataset.csv",
    "rpm": "RPM_dataset.csv",
}

# 실제 HCRL 파일의 앞부분을 읽어 첫 injected(T) message 주변의 연속 구간을 저장한다.
# 연속 구간을 쓰는 이유: CAN 이상 탐지에서 메시지 순서/간격 자체가 feature이기 때문.
READ_ROWS = 500_000
BEFORE_ATTACK = 5_000
AFTER_ATTACK = 25_000

def save_attack_sample(kind, filename):
    path = RAW / filename
    if not path.exists():
        print(f"[SKIP] {path} not found")
        return

    print(f"Reading {filename}...")
    df = read_hcrl_csv(path, nrows=READ_ROWS)
    attack_idx = df.index[df["flag"] == "T"]

    if len(attack_idx) == 0:
        print(f"[WARN] No T flag found in first {READ_ROWS:,} rows of {filename}")
        sample = df.iloc[:30_000].copy()
    else:
        first = int(attack_idx[0])
        start = max(0, first - BEFORE_ATTACK)
        end = min(len(df), first + AFTER_ATTACK)
        sample = df.iloc[start:end].copy()

    out = OUT / f"{kind}_real_sample.csv"
    sample.to_csv(out, index=False)
    print(
        f"  -> {out.name}: {len(sample):,} messages, "
        f"T={int((sample['flag']=='T').sum()):,}, "
        f"R={int((sample['flag']=='R').sum()):,}"
    )

def save_normal_sample():
    txt = RAW / "normal_run_data.txt"
    csv = RAW / "normal_run_data.csv"
    if txt.exists():
        print("Reading normal_run_data.txt...")
        df = read_normal_txt(txt, nrows=30_000)
    elif csv.exists():
        print("Reading normal_run_data.csv...")
        df = read_hcrl_csv(csv, nrows=30_000, default_flag="R")
    else:
        print("[SKIP] dedicated normal_run_data.txt/csv not found")
        return

    out = OUT / "normal_real_sample.csv"
    df.to_csv(out, index=False)
    print(f"  -> {out.name}: {len(df):,} messages")

if __name__ == "__main__":
    for kind, fn in ATTACK_FILES.items():
        save_attack_sample(kind, fn)
    save_normal_sample()
    print("\nDone. Real HCRL test samples are in data/test_samples/")
