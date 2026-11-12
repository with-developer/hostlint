<!-- translated from docs/comparison.md @ d520f74 -->
# 다른 도구와 비교

서버의 설정을 점검하는 도구는 vmsctl 말고도 여럿 있습니다. 이 문서는 vmsctl이 무엇이 다른지, 그리고 어떤 경우에는 다른 도구가 더
낫다는 점을 적었습니다. 다른 도구의 설명은 각 도구의 공식 문서를 바탕으로 했고(문서 끝에 링크), 도구는 계속 바뀌므로 고르기 전에
직접 확인하세요.

[English](comparison.md)

## vmsctl이 하는 일, 하지 않는 일

vmsctl은 호스트의 **설정**(계정, SSH, PAM, 파일 권한, 서비스, 커널 매개변수, 패키지)을 읽고, 점검 항목마다 결과와 그 근거를
보여 줍니다. 다음과 같은 도구는 아닙니다.

- **CVE 기준의 취약점 스캐너가 아닙니다.** Trivy나 Grype 같은 도구는 호스트나 이미지에 든 패키지의 알려진 취약점을 찾고, vmsctl은
  시스템이 어떻게 설정되어 있는지를 봅니다. 묻는 질문이 달라서 함께 쓰는 것이 맞습니다.
- **조치 도구가 아닙니다.** 호스트를 절대 바꾸지 않습니다. 실패한 점검은 고치는 방법을 알려 주고, 실제로 고치는 일은 사용자(또는
  설정 관리 도구)의 몫입니다.
- **CIS 벤치마크 스캐너가 아닙니다.** 기본 제공 프로파일은 KISA 기술적 취약점 분석·평가 가이드(Unix, 2026년판)와 짧고 중립적인
  `essentials` 기준이며, [정책 팩](packs.ko.md)으로 직접 만들 수도 있습니다. CIS 벤치마크의 문구는 CC BY-NC-SA 4.0이라 상업적 이용이 제한되므로
  가져다 쓰지 않았고, 점검 항목 번호로 연결하는 일은 [로드맵](ROADMAP.md)에 있습니다.

## 한눈에 비교

| | vmsctl | Lynis | OpenSCAP | Wazuh (SCA) |
|---|---|---|---|---|
| 형태 | Go 바이너리 하나(리눅스에서는 정적 빌드). 선택해서 쓰는 서버와 대시보드도 모두 Apache-2.0 | 유닉스 계열용 셸 스크립트 도구(GPL). 상용 Lynis Enterprise(SaaS 또는 자체 설치)가 중앙 관리, 대시보드, 보고서를 더함 | `oscap`과 SCAP Security Guide 콘텐츠. 결과는 XCCDF/ARF XML, 보고서는 HTML | Wazuh 에이전트의 모듈. 결과는 Wazuh 대시보드에서 |
| 점검을 정의하는 방식 | YAML 데이터와 CEL 표현식. 규칙은 명령을 실행할 수 없음 | 도구에 들어 있는 테스트와 사용자 정의 테스트(플러그인은 데이터 수집용) | SCAP 콘텐츠(XCCDF 프로파일, OVAL 점검) | 에이전트가 실행하는 YAML 정책. CIS 벤치마크 기반 정책 포함 |
| 결과 | PASS, FAIL, ERROR, MANUAL, WAIVED, N/A마다 값과 그 출처(있으면 파일과 줄 번호). 판단할 수 없는 점검은 ERROR나 MANUAL로 보고하고 PASS로 보고하지 않음 | 보안 강화 지수와 제안 | 프로파일 규칙별 결과(통과, 실패, 오류, 해당 없음 등) | 엔드포인트별 통과·실패·해당 없음 개수와 점수 |
| 조치 | "조치 방법" 문구만 보여 주고 아무것도 적용하지 않음 | 제안 | 조치를 적용(`--remediate`)하거나 스크립트를 생성할 수 있음 | 정책에 담긴 권고 |
| 컨테이너 이미지 | `docker save`나 OCI 아카이브에서 직접. 데몬도 없고 아무것도 실행하지 않음 | | | |
| 여러 호스트 | 호스트가 결과를 서버로 보내고, 서버가 이력, 서명된 결과, 추이, 매트릭스를 보관. 서버가 호스트에 접속하지 않음 | 유료 서비스에서 | `oscap-ssh`로 원격 점검. 여러 대 관리는 다른 도구의 몫 | Wazuh 매니저와 대시보드 |
| 직접 만드는 점검 | [정책 팩](packs.ko.md): YAML, 테스트 포함, 새로운 능력을 더하지 못함 | 사용자 정의 테스트 | SCAP 콘텐츠 작성 | YAML 사용자 정책 |

빈 칸은 위 공식 문서에 적혀 있지 않다는 뜻이고, 그 기능이 없다는 주장이 아닙니다.

## 다른 도구가 더 나은 경우

- 조치를 대신 적용해 주기를 원하거나, **CIS에 맞춘** 프로파일이 필요하거나, 감사인이 **SCAP** 결과를 요구한다면 OpenSCAP입니다.
- 이미 침입 탐지용으로 **Wazuh**를 쓰고 있고 같은 에이전트와 대시보드에서 설정 점검도 보고 싶다면 Wazuh의 SCA 모듈입니다.
- 리눅스 말고 다른 유닉스 계열까지 아우르는, 오래 쓰여 온 폭넓은 **시스템 감사**와 보안 강화 제안이 필요하다면 Lynis입니다.
- **CVE** 대조가 필요하다면 취약점 스캐너를 vmsctl 옆에 두세요.

vmsctl이 맞는 경우는 이렇습니다. 결과마다 근거가 붙고 판단할 수 없는 점검을 PASS로 보고하지 않는 것, KISA 가이드가 기본
프로파일로 들어 있다는 점, CI에서 점검하는 컨테이너 이미지, 호스트가 결과를 보내고 서버는 호스트에 접속하지 않는 서버 전체 현황(선택해서
쓰는 에이전트는 바깥으로만 연결하며 요청 시 스캔에만 씁니다)입니다.

## 출처

- Lynis: [cisofy.com/lynis](https://cisofy.com/lynis/), [github.com/CISOfy/lynis](https://github.com/CISOfy/lynis/), [문서](https://cisofy.com/documentation/lynis/)(사용자 정의 테스트, 플러그인), [보안 강화 지수](https://linux-audit.com/lynis-hardening-index/)
- OpenSCAP: [사용자 매뉴얼](https://static.open-scap.org/openscap-1.3/oscap_user_manual.html)(결과, 보고서, 조치), [Red Hat, 설정 준수 점검](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/security_hardening/scanning-the-system-for-configuration-compliance), [Red Hat, OpenSCAP으로 CIS 준수](https://www.redhat.com/en/blog/center-internet-security-cis-compliance-red-hat-enterprise-linux-using-openscap)
- Wazuh: [보안 설정 평가(SCA)](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html), [사용자 정책 만들기](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html), [점수가 나오는 사용 사례](https://documentation.wazuh.com/4.14/getting-started/use-cases/configuration-assessment.html)
