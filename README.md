# Vehicle CAN AX Monitor

> **Vehicle CAN Log Analysis & Incident Report Automation**  
> 실제 차량 CAN 로그의 이상 구간과 공격 패턴을 분석하고, 엔지니어 검토용 Incident Report까지 자동 생성하는 소프트웨어 기반 AX 프로젝트다.

![CAN AX Monitor](docs/assets/can_monitor_dos.png)

## 1. Project Overview

차량 CAN 로그는 대량의 메시지가 연속적으로 발생하기 때문에 사람이 직접 이상 구간을 선별하고 초기 분석 보고서를 작성하는 데 시간이 많이 든다.

이 프로젝트는 **HCRL Car-Hacking Dataset의 실제 차량 CAN 로그**를 활용해 다음 흐름을 자동화했다.

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

### 핵심 기능

- Normal / DoS / Fuzzy / Gear spoofing / RPM spoofing 분류
- CAN 메시지를 Window 단위로 묶어 17개 통계 feature 추출
- Random Forest 기반 공격 유형 분류
- Logistic Regression baseline 비교
- 이상 Window timeline 및 고빈도 CAN ID 시각화
- Incident Report 자동 생성
- 선택적으로 로컬 Ollama 기반 자연어 리포트 생성
- 실제 조치 전 **Human-in-the-loop** 구조 적용

---

## 2. Why AX?

단순히 모델 정확도만 출력하는 ML 실습에서 끝내지 않고, 기존의 반복 업무를 다음과 같이 재구성했다.

```text
로그 확인
→ 이상 구간 선별
→ 공격 유형 판단
→ 초기 원인 정리
→ 보고서 작성
```

이를 다음 흐름으로 자동화했다.

```text
로그 입력
→ ML 자동 탐지
→ 이상 구간 구조화
→ Incident Report 생성
→ 엔지니어 검토 및 승인
```

### 역할 분리

- **ML**: 수치 기반 공격 패턴 판정을 담당한다.
- **Rule-based analysis**: 이상 Window와 CAN ID 통계를 구조화한다.
- **Optional GenAI**: 이미 계산된 결과를 엔지니어가 읽기 쉬운 자연어 보고서로 정리한다.
- **Human-in-the-loop**: 실제 ECU/Gateway 조치 전 담당자의 검토와 승인을 전제로 한다.

---

## 3. Dataset

**HCRL Car-Hacking Dataset**을 사용했다.

데이터에는 다음 공격 유형이 포함된다.

- DoS
- Fuzzy
- Gear spoofing
- RPM spoofing
- Normal traffic

공식 데이터는 아래에서 받을 수 있다.

https://ocslab.hksecurity.net/Datasets/car-hacking-dataset

원본 데이터는 파일 크기가 크기 때문에 GitHub 저장소에는 포함하지 않았다.

---

## 4. Detection Pipeline

### 4.1 Windowing

CAN 메시지를 한 줄씩 바로 분류하지 않고 일정 개수의 메시지를 하나의 Window로 묶었다.

기본 Window size는 **200 messages**다.

### 4.2 Statistical Features

각 Window에서 다음과 같은 통계 feature를 추출했다.

- message rate
- inter-arrival mean / std / min
- CAN ID diversity
- CAN ID entropy
- dominant ID ratio
- ID switch rate
- DLC statistics
- payload mean / std
- payload zero ratio
- payload entropy
- payload change
- zero CAN ID ratio

총 **17개 feature**를 사용했다.

### 4.3 Classification

Random Forest를 주 모델로 사용하고 Logistic Regression을 baseline으로 비교했다.

Random Forest를 선택한 이유는 다음과 같다.

- 표 형태의 통계 feature에 적용하기 쉽다.
- 비선형 패턴을 처리할 수 있다.
- 짧은 기간에도 빠르게 학습할 수 있다.
- feature importance를 확인할 수 있다.

---

## 5. Real-data Validation

실제 HCRL 원본 데이터에서 연속 구간을 추출해 앱 동작을 직접 검증했다.

| Sample | CAN Messages | Windows | Abnormal Windows | Injected T | Prediction |
|---|---:|---:|---:|---:|---|
| Normal | 30,000 | 150 | 0 | 0.00% | NORMAL |
| DoS | 26,476 | 132 | 70 | 27.21% | DOS |
| Fuzzy | 26,567 | 132 | 42 | 11.65% | FUZZY |
| Gear spoofing | 27,140 | 135 | 71 | 16.38% | GEAR |
| RPM spoofing | 26,708 | 133 | 75 | 17.52% | RPM |

실제 데이터 재학습 후 내부 hold-out 평가에서는 다음 결과를 확인했다.

- **Random Forest Macro F1: 0.9965**
- **Attack Recall: 0.995**

> 위 수치는 동일 HCRL 데이터셋 내부 평가 결과다. 새로운 차량, ECU, 공격 유형에 동일하게 일반화된다고 해석하지 않는다.

---

## 6. Window-size Experiment

Window size에 따른 영향을 확인하기 위해 `100 / 200 / 500 messages`를 비교했다.

| Window | Windows evaluated | Macro F1 | Attack Recall | Balanced Accuracy | Sample-type Accuracy |
|---:|---:|---:|---:|---:|---:|
| 100 | 1,367 | 0.9809 | **0.9980** | 0.9915 | 80% |
| **200** | 682 | **0.9974** | 0.9961 | **0.9981** | **100%** |
| 500 | 272 | 1.0000 | 1.0000 | 1.0000 | 100% |

### Why 200?

500 messages는 샘플 평가에서 가장 높은 성능을 기록했지만, 한 Window가 커져 이상 발생 위치를 세밀하게 확인하기 어렵다.

100 messages는 시간 해상도는 높지만 sample-type accuracy가 80%로 떨어졌다.

따라서 높은 분류 성능을 유지하면서 500보다 세밀한 구간 분석이 가능한 **200 messages를 운영 기본값으로 선택했다.**

> 이 실험은 200이 보편적으로 최적이라는 의미가 아니라, 현재 MVP에서 기본값을 결정하기 위한 비교 실험이다.

---

## 7. Incident Report Automation

![Incident Report](docs/assets/incident_report.png)

모델이 공격 유형을 판정한 뒤 다음 정보를 자동으로 정리한다.

- 상태
- 추정 공격 유형
- 이상 Window 수
- 고빈도 CAN ID
- 분석 구간
- 권장 점검 항목
- Human-in-the-loop 안내

생성형 AI는 공격 여부를 직접 판단하지 않는다.

수치적인 공격 판정은 ML 모델이 수행하고, 생성형 AI는 선택적으로 이미 계산된 결과를 자연어 보고서로 정리하는 역할만 담당한다.

---

## 8. Architecture

자세한 구조는 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)에서 확인할 수 있다.

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

## 9. Tech Stack

- Python
- Pandas
- NumPy
- scikit-learn
- Streamlit
- joblib
- Optional Ollama

---

## 10. Project Structure

```text
vehicle-can-ax-monitor/
├─ app.py
├─ requirements.txt
├─ RUN_APP.bat
├─ RUN_FIRST.bat
├─ TRAIN_REAL_DATA.bat
├─ MAKE_REAL_TEST_FILES.bat
├─ RUN_WINDOW_EXPERIMENT.bat
├─ src/
├─ scripts/
├─ docs/
├─ results/
├─ data/
└─ models/
```

---

## 11. Run Locally

### 1) Initial setup

```bat
RUN_FIRST.bat
```

### 2) Download HCRL data

`data/raw/`에 다음 파일을 넣는다.

```text
DoS_dataset.csv
Fuzzy_dataset.csv
gear_dataset.csv
RPM_dataset.csv
normal_run_data.txt
```

### 3) Train with real data

```bat
TRAIN_REAL_DATA.bat
```

### 4) Create compact real-data samples

```bat
MAKE_REAL_TEST_FILES.bat
```

### 5) Run the Streamlit app

```bat
RUN_APP.bat
```

브라우저에서 아래 주소를 연다.

```text
http://localhost:8501
```

### 6) Run Window-size experiment

```bat
RUN_WINDOW_EXPERIMENT.bat
```

결과는 아래 파일에 저장된다.

```text
experiments/window_size_results.csv
```

---

## 12. Limitations

이 프로젝트는 다음 한계를 가진다.

1. HCRL 한 데이터셋의 차량·공격 패턴에 의존한다.
2. DBC/OEM 사양이 없어 CAN ID의 실제 물리 신호 의미를 확정하지 않는다.
3. 실제 차량의 실시간 CAN 네트워크에 배포해 latency와 resource usage를 검증하지 않았다.
4. 높은 내부 평가 점수를 새로운 차량에 대한 일반화 성능으로 해석하지 않는다.
5. 새로운 IDS 알고리즘을 제안하는 연구보다 **차량 로그 분석 업무의 AX Workflow 구현**에 초점을 맞춘 MVP다.

---

## 13. Development Approach

생성형 AI를 개발 보조 도구로 활용했다.

코드 초안과 디버깅 과정에서 AI를 활용했으며, 이후 실제 HCRL 데이터 적용, 모델 재학습, Normal/DoS/Fuzzy/Gear/RPM 샘플 검증, Window-size 비교 실험, 결과 해석을 직접 수행해 시스템 동작과 설계 결정을 검증했다.

면접 대비 설명은 [`docs/INTERVIEW_NOTES.md`](docs/INTERVIEW_NOTES.md)에 정리했다.
