# Development Notes

이 프로젝트는 **AI-assisted development** 방식으로 빠르게 MVP를 구현했습니다.

생성형 AI는 코드 초안과 디버깅 보조에 활용했고, 포트폴리오 검증 과정에서는 다음을 직접 수행했습니다.

- 실제 HCRL 데이터 다운로드 및 로컬 학습
- Normal / DoS / Fuzzy / Gear / RPM 실데이터 샘플 실행 검증
- Incident Report 생성 및 다운로드 확인
- Window size 100 / 200 / 500 비교 실험
- 결과 해석 및 기본 Window size 200 선택
- 과도한 일반화를 피하기 위한 한계점 정리

면접에서는 코드 작성 방식보다 **왜 이 구조를 선택했고 무엇을 검증했는지** 설명하는 것을 목표로 합니다.
