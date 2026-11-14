<!-- translated from docs/README.md @ 9d41982 -->
# vmsctl 문서

[English](README.md)

## 사용하기

| | |
|---|---|
| [컨테이너 이미지 점검](images.ko.md) | `--image-tar`: 이미지 점검이 보는 것, 한계, 결과를 서버로 보내기 |
| [CI에서 vmsctl 쓰기](ci.ko.md) | 종료 코드, GitHub Action, GitLab CI, 그 밖의 CI |
| [vmsctl을 컨테이너로 실행하기](container.ko.md) | 릴리스 이미지, 점검할 수 있는 것, 이미지 검증 |
| [서버와 대시보드](fleet.ko.md) | 결과 보내기, 요청 시 스캔용 에이전트, 토큰, 서명된 결과, API, 서버 운영 |
| [설정](configuration.ko.md) | `vmsctl.yaml`: 매개변수, 예외, 증명 |
| [DISA STIG 프로파일](stig.ko.md) | `stig-ubuntu2204`: Ubuntu 22.04용 미국 기준, 어디까지 점검하고 무엇은 점검하지 않는지 |
| [정책 팩](packs.ko.md) | 직접 만드는 점검과 프로파일 |
| [hostlint에서 옮기기](migrating-from-hostlint.ko.md) | v0.27의 이름 변경 |
| [다른 도구와 비교](comparison.ko.md) | Lynis, OpenSCAP, Wazuh와 비교하고, 어떤 경우에 그쪽을 고를지 |

## 참고 자료

- [규칙과 프로파일](rules.ko.md): 모든 점검과 점검 항목이 무엇을 보고, 왜 중요하고, 어떻게 고치는지(영어판: [rules.md](rules.md))
- [사실(facts)](facts.md): 수집기가 읽는 것. 직접 점검을 만들 때 참고(영어)
- [결과 스키마](../schema/result-v1.schema.json): JSON 결과와 [올바른 예시](../schema/result-v1.example.json)

## 프로젝트에 대해

- [비전](VISION.md): vmsctl이 무엇을 위한 것이고 무엇을 하지 않는지(영어)
- [로드맵](ROADMAP.md)과 [릴리스 절차](RELEASING.md)(영어)
- [설계 결정](adr/README.md)(ADR, 영어)
- [기여하기](../CONTRIBUTING.md)와 [보안 정책](../SECURITY.md)(영어)
