# HCRL 실제 데이터 적용

공식 Car-Hacking Dataset 페이지:
https://ocslab.hksecurity.net/Datasets/car-hacking-dataset

이 프로젝트는 원 데이터셋을 재배포하지 않습니다. 직접 다운로드해 `data/raw/`에 넣으세요.

필요 파일:
```
data/raw/
├─ DoS_dataset.csv
├─ Fuzzy_dataset.csv
├─ gear_dataset.csv
├─ RPM_dataset.csv
└─ normal_run_data.txt   # 권장
```

공식 페이지에 따르면 공격 CSV는 Timestamp, CAN ID, DLC, DATA[0]~DATA[7], Flag 구조이며 Flag의 T는 injected message, R은 normal message입니다.

빠른 학습:
```bat
python scripts\train_real_hcrl.py --nrows 400000
```

좀 더 많은 데이터:
```bat
python scripts\train_real_hcrl.py --nrows 1000000
```

주의: 결과는 train/test 방법, sampling, window size에 따라 달라집니다. 실제 측정값만 이력서에 기재하세요.
