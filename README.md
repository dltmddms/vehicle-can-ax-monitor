# Vehicle CAN Log Analysis & Incident Report Automation

> **Automotive CAN × Machine Learning × AX Workflow**  
> 실제 차량 CAN 로그의 이상 구간과 공격 패턴을 분석하고, 엔지니어 검토용 Incident Report까지 자동 생성하는 소프트웨어 기반 AX 프로젝트입니다.

![CAN AX Monitor](docs/assets/can_monitor_dos.png)

## Project Summary

차량 CAN 로그는 대량의 메시지가 연속적으로 발생하기 때문에 사람이 직접 이상 구간을 선별하고 초기 분석 보고서를 작성하기 어렵습니다.

이 프로젝트는 **HCRL Car-Hacking Dataset의 실제 차량 CAN 로그**를 사용하여 다음 Workflow를 구현했습니다.

```text
Raw CAN Log
    ↓
Window Feature Extraction
    ↓
Random Forest Attack Classification
    ↓
Abnormal Interval / CAN ID Analysis
    ↓
Incident Report Generation
    ↓
Human Review
```

### 핵심 포인트

- Normal / DoS / Fuzzy / Gear spoofing / RPM spoofing 분류
- CAN 메시지를 Window로 묶어 17개 통계 feature 추출
- Random Forest + Logistic Regression baseline 비교
- 이상 Window timeline과 고빈도 CAN ID 시각화
- deterministic Incident Report 생성
- 선택적으로 로컬 Ollama 기반 자연어 리포트 생성
- 실제 조치 전 **Human-in-the-loop**를 전제로 설계

---

## Real-data Validation

실제 HCRL 원본 데이터에서 연속 샘플을 추출해 앱 동작을 직접 검증했습니다.

| Sample | CAN Messages | Windows | Abnormal Windows | Injected T | Prediction |
|---|---:|---:|---:|---:|---|
| Normal | 30,000 | 150 | 0 | 0.00% | NORMAL |
| DoS | 26,476 | 132 | 70 | 27.21% | DOS |
| Fuzzy | 26,567 | 132 | 42 | 11.65% | FUZZY |
| Gear spoofing | 27,140 | 135 | 71 | 16.38% | GEAR |
| RPM spoofing | 26,708 | 133 | 75 | 17.52% | RPM |

실제 데이터 재학습 시 내부 hold-out 평가에서:

- **Random Forest Macro F1: 0.9965**
- **Attack Recall: 0.995**

> 이 수치는 동일 HCRL 데이터셋 내부 평가입니다. 새로운 차량·ECU·공격 유형에 동일하게 일반화된다고 주장하지 않습니다.

---

## Window-size Experiment

`100 / 200 / 500 messages`를 비교했습니다.

| Window | Windows evaluated | Macro F1 | Attack Recall | Balanced Accuracy | Sample-type Accuracy |
|---:|---:|---:|---:|---:|---:|
| 100 | 1,367 | 0.9809 | **0.9980** | 0.9915 | 80% |
| **200** | 682 | **0.9974** | 0.9961 | **0.9981** | **100%** |
| 500 | 272 | 1.0000 | 1.0000 | 1.0000 | 100% |

### Why 200?

500 messages는 이 샘플 평가에서 가장 높은 점수를 기록했지만, 한 Window가 커져 **이상 발생 위치를 세밀하게 확인하는 시간적 해상도**가 낮아집니다.  
100 messages는 더 촘촘하지만 sample-type accuracy가 80%로 떨어졌습니다.

따라서 높은 분류 성능을 유지하면서 500보다 세밀한 구간 분석이 가능한 **200 messages를 운영 기본값**으로 선택했습니다.

> 이 실험은 “200이 보편적으로 최적”이라는 증명이 아니라, 현재 MVP에서 기본값을 정하기 위한 비교 실험입니다.

---

## Incident Report

![Incident Report](docs/assets/incident_report.png)

수치적인 공격 판정은 ML 모델이 수행합니다.  
리포트 단계에서는 이미 계산된 결과를 정리하며, CAN ID의 실제 신호 의미를 임의로 추측하지 않습니다.

---

## Architecture

자세한 구조: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

```text
CAN Log
  → Windowing
  → 17 Statistical Features
  → Random Forest
  → Window-level Detection
  → Incident Summary
  → Report
  → Human Review
```

---

## Tech Stack

`Python` · `Pandas` · `NumPy` · `scikit-learn` · `Streamlit` · `joblib` · `Optional Ollama`

---

## Run Locally

### 1. Setup

```bat
RUN_FIRST.bat
```

`RUN_FIRST.bat`은 의존성 설치와 UI 확인용 demo model을 생성합니다.

### 2. Download HCRL data

공식 데이터:
https://ocslab.hksecurity.net/Datasets/car-hacking-dataset

`data/raw/`에 다음 파일을 넣습니다.

```text
DoS_dataset.csv
Fuzzy_dataset.csv
gear_dataset.csv
RPM_dataset.csv
normal_run_data.txt
```

### 3. Train on real data

```bat
TRAIN_REAL_DATA.bat
```

### 4. Create compact real samples

```bat
MAKE_REAL_TEST_FILES.bat
```

### 5. Run app

```bat
RUN_APP.bat
```

`http://localhost:8501`

### 6. Run parameter experiment

```bat
RUN_WINDOW_EXPERIMENT.bat
```

결과는 `experiments/window_size_results.csv`에 저장됩니다.

---

## Design Decisions

### Why Window-based analysis?
DoS와 spoofing은 CAN 메시지 한 줄의 값보다 일정 구간에서 나타나는 **전송 빈도, CAN ID 분포, 반복 패턴 변화**가 중요하기 때문입니다.

### Why Random Forest?
짧은 기간의 MVP에서 표 형태 통계 feature를 빠르게 학습할 수 있고, 비선형 패턴을 처리하며 feature importance를 확인할 수 있기 때문입니다.

### Why not use an LLM as the detector?
공격 판단은 평가 가능하고 재현 가능한 ML 모델이 담당합니다. 생성형 AI는 선택적으로 이미 계산된 결과를 자연어 보고서로 정리하는 역할만 담당합니다.

---

## Limitations

1. HCRL 한 데이터셋의 차량·공격 패턴에 의존합니다.
2. DBC/OEM 사양이 없어 CAN ID의 실제 물리 신호 의미를 확정하지 않습니다.
3. 실제 차량의 실시간 네트워크 배포 환경은 검증하지 않았습니다.
4. 높은 내부 평가 점수를 외부 차량에 대한 일반화 성능으로 해석하지 않습니다.
5. 새로운 IDS 알고리즘 연구보다 **자동차 로그 분석 업무의 AX Workflow 구현**에 초점을 맞춘 MVP입니다.

---

## Development Approach

생성형 AI를 개발 보조 도구로 활용했으며, 실제 데이터 적용·실행 검증·Window-size 비교 실험·결과 해석을 통해 시스템 동작과 설계 결정을 검증했습니다.

면접 준비: [`docs/INTERVIEW_NOTES.md`](docs/INTERVIEW_NOTES.md)
