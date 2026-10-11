import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pathlib import Path
import pandas as pd
from src.data_loader import read_hcrl_csv, hex_to_numeric
from src.features import make_windows
from src.modeling import train_compare


def main():
    path=Path("data/demo/demo_can_labeled.csv")
    raw=pd.read_csv(path)
    pieces=[]
    # Use the provided synthetic source attack_type only to make training labels.
    # Consecutive same-type segments are grouped by changes.
    grp=(raw["attack_type"] != raw["attack_type"].shift()).cumsum()
    for _, part in raw.groupby(grp):
        kind=str(part["attack_type"].iloc[0])
        core=part.drop(columns=["attack_type"])
        from src.data_loader import _standardize
        core=_standardize(core)
        num=hex_to_numeric(core)
        w=make_windows(num, window_size=200, stride=200, source_attack_type=kind, min_attack_ratio=0.02)
        pieces.append(w)
    windows=pd.concat(pieces,ignore_index=True)
    print(windows["label"].value_counts())
    metrics=train_compare(windows, "models", dataset_mode="demo")
    print("RF macro F1:", round(metrics["random_forest"]["macro_f1"],4))
    print("Attack recall:", round(metrics["random_forest"]["attack_recall"],4))

if __name__ == "__main__":
    main()
