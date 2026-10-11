import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pathlib import Path
import argparse
import pandas as pd

from src.data_loader import read_hcrl_csv, read_normal_txt, hex_to_numeric
from src.features import make_windows
from src.modeling import train_compare

FILES = {
    "dos": "DoS_dataset.csv",
    "fuzzy": "Fuzzy_dataset.csv",
    "gear": "gear_dataset.csv",
    "rpm": "RPM_dataset.csv",
}


def load_one(path: Path, kind: str, nrows: int):
    print(f"Loading {path.name} ({kind})...")
    df=read_hcrl_csv(path, nrows=nrows, default_flag="R")
    return hex_to_numeric(df)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/raw")
    ap.add_argument("--nrows", type=int, default=400000, help="Max rows per file for quick laptop training")
    ap.add_argument("--window", type=int, default=200)
    args=ap.parse_args()
    base=Path(args.data_dir)
    pieces=[]

    for kind, filename in FILES.items():
        path=base/filename
        if not path.exists():
            raise FileNotFoundError(f"Missing: {path}")
        num=load_one(path,kind,args.nrows)
        pieces.append(make_windows(num,args.window,args.window,source_attack_type=kind,min_attack_ratio=0.01))

    normal_txt=base/"normal_run_data.txt"
    normal_csv=base/"normal_run_data.csv"
    if normal_txt.exists():
        normal=hex_to_numeric(read_normal_txt(normal_txt,nrows=args.nrows))
    elif normal_csv.exists():
        normal=hex_to_numeric(read_hcrl_csv(normal_csv,nrows=args.nrows,default_flag="R"))
    else:
        # attack files already contain R windows, but a dedicated normal file is preferable.
        print("WARNING: normal_run_data.txt/csv not found; using only normal windows inside attack files.")
        normal=None
    if normal is not None:
        pieces.append(make_windows(normal,args.window,args.window,source_attack_type="normal"))

    windows=pd.concat(pieces,ignore_index=True)
    # Cap very large normal class to keep training quick, without synthesizing data.
    sampled=[]
    max_per_class=min(2500, max(400, windows["label"].value_counts().min()*2))
    for label, part in windows.groupby("label"):
        sampled.append(part.sample(n=min(len(part),max_per_class),random_state=42).sort_values("start_time"))
    windows=pd.concat(sampled,ignore_index=True)
    print("Windows per class:\n",windows["label"].value_counts())
    metrics=train_compare(windows,"models",dataset_mode="real_hcrl")
    print("Saved real-HCRL model to models/can_ax_model.joblib")
    print("RF macro F1:",round(metrics["random_forest"]["macro_f1"],4))
    print("Attack recall:",round(metrics["random_forest"]["attack_recall"],4))

if __name__ == "__main__":
    main()
