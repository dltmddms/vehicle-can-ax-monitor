from __future__ import annotations

import random
from pathlib import Path
import numpy as np
import pandas as pd

random.seed(42)
rng = np.random.default_rng(42)
NORMAL_IDS = [0x140,0x18F,0x260,0x2A0,0x316,0x329,0x43F,0x545,0x608]


def payload_for(can_id, t):
    base = (can_id + int(t*10)) % 256
    arr = [(base + i*7 + int(10*np.sin(t+i))) % 256 for i in range(8)]
    if can_id in [0x316, 0x43F]:
        arr[0] = int((100 + 60*np.sin(t*2)) % 256)
    return arr


def normal_message(t):
    cid = random.choice(NORMAL_IDS)
    return cid, payload_for(cid, t), "R"


def build_segment(kind, n=12000, start_t=0.0):
    rows=[]; t=start_t
    for i in range(n):
        if kind == "normal":
            dt = max(0.0004, rng.normal(0.0032, 0.0010)); cid,payload,flag=normal_message(t)
        else:
            injected = rng.random() < 0.18
            if kind == "dos" and injected:
                dt=max(0.0001,rng.normal(0.00032,0.00005)); cid=0x0000; payload=[0]*8; flag="T"
            elif kind == "fuzzy" and injected:
                dt=max(0.0001,rng.normal(0.0005,0.00008)); cid=int(rng.integers(0,0x7FF)); payload=rng.integers(0,256,8).tolist(); flag="T"
            elif kind == "gear" and injected:
                dt=max(0.00015,rng.normal(0.0010,0.0001)); cid=0x043F; payload=payload_for(cid,t); payload[2]=int(rng.choice([1,2,3,4,5,6])); flag="T"
            elif kind == "rpm" and injected:
                dt=max(0.00015,rng.normal(0.0010,0.0001)); cid=0x0316; payload=payload_for(cid,t); payload[0]=int(rng.integers(180,255)); payload[1]=int(rng.integers(0,255)); flag="T"
            else:
                dt=max(0.0004,rng.normal(0.0032,0.0010)); cid,payload,flag=normal_message(t)
        t += dt
        rows.append([t,f"{cid:04x}",8,*[f"{x:02x}" for x in payload],flag,kind])
    cols=["Timestamp","CAN ID","DLC",*[f"DATA[{i}]" for i in range(8)],"Flag","attack_type"]
    return pd.DataFrame(rows,columns=cols), t


def main():
    out=Path("data/demo"); out.mkdir(parents=True, exist_ok=True)
    t=0.0; all_parts=[]
    for kind in ["normal","dos","normal","fuzzy","normal","gear","normal","rpm"]:
        part,t=build_segment(kind, n=10000, start_t=t+0.3)
        all_parts.append(part)
    df=pd.concat(all_parts,ignore_index=True)
    df.to_csv(out/"demo_can_labeled.csv",index=False)
    # incident upload: mixed normal + DoS + normal, labels retained for learning but app ignores ground truth.
    incident=pd.concat([all_parts[0].tail(5000), all_parts[1].iloc[2000:9000], all_parts[2].head(5000)], ignore_index=True)
    incident.to_csv(out/"demo_incident.csv",index=False)
    print(f"generated {len(df):,} rows")

if __name__ == "__main__":
    main()
