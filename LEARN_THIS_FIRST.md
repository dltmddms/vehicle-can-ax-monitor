# 먼저 이것만 이해하세요 — 30분 학습용

## CAN 메시지 1줄
- Timestamp: 메시지가 기록된 시각
- CAN ID: 어떤 종류의 메시지인지 구분하는 식별자. **ECU 주소라고 단정하면 안 됨**
- DLC: payload byte 수(클래식 CAN은 0~8)
- DATA[0]~DATA[7]: 실제 payload byte
- Flag: HCRL에서 R=정상, T=주입된 공격 메시지

## 공격
- DoS: 매우 짧은 간격으로 특정 ID(공식 데이터에서는 0000)를 반복 주입
- Fuzzy: 임의 CAN ID와 payload를 빠르게 주입
- Gear/RPM spoofing: 특정 신호와 관련된 ID에 조작 메시지 주입

## 우리 코드의 핵심
1. 200개 메시지를 하나의 window로 묶음
2. message rate, ID entropy, dominant ID ratio 같은 feature 계산
3. Random Forest가 window를 normal/dos/fuzzy/gear/rpm 중 하나로 분류
4. 이상 window의 시간범위를 찾아 가장 많이 등장한 CAN ID를 보여줌
5. 자동 Incident Report 생성

## 왜 Random Forest?
- 표 형태 feature에 빠르고 안정적인 baseline
- 비선형 관계 처리
- feature importance 확인 가능
- GPU 불필요
- 3일 MVP에서 설명하기 쉬움

## 왜 Logistic Regression도 같이 사용?
Random Forest 하나만 돌리고 '좋았다'고 하면 기준이 없습니다. 단순 baseline과 동일 test set에서 비교해 복잡한 모델을 쓴 이유를 설명하기 위함입니다.

## 꼭 말할 수 있어야 하는 한계
- HCRL 공격 패턴은 실험적으로 주입된 공격이므로 실제 모든 차량 공격을 대표하지 않음
- 차종/환경이 바뀌면 성능이 떨어질 수 있음
- CAN ID만으로 실제 물리 신호 의미를 함부로 확정할 수 없음
- random/temporal split 방식에 따라 성능이 달라질 수 있음
- 이 시스템은 엔지니어 의사결정을 보조하며 자동 제어를 수행하지 않음
