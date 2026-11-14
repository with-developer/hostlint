<!-- translated from docs/stig.md @ c6ff767 -->
# DISA STIG 프로파일 (Ubuntu 22.04)

`stig-ubuntu2204`는 미 국방부가 DISA를 통해 공개하는
[Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide](https://public.cyber.mil/stigs/)(STIG) V2R8의 점검 항목으로
호스트를 점검합니다. 미국 기준을 다루는 첫 프로파일이고, 다음은 RHEL 9용 프로파일입니다.

```sh
sudo vmsctl scan --profile stig-ubuntu2204
vmsctl explain UBTU-22-255040          # 점검 항목이 무엇을 보고, 왜 중요하고, 어떻게 고치는지
```

## 어디까지 점검하고, 무엇은 점검하지 않나

**STIG 전체를 평가하는 것이 아닙니다.** V2R8의 점검 항목 188개 중 vmsctl이 판정할 수 있는 27개만 담았고, 나머지 161개는
아무것도 말하지 않습니다. 감사 규칙, 시스템 명령과 라이브러리의 소유자·권한, 스마트 카드와 PKI, FIPS, 부트로더 비밀번호, 그래픽 세션,
`sudo` 정책의 세부 사항, 대부분의 PAM 설정은 아직 점검하지 않습니다. 이 프로파일을 통과했다는 것은 그 27개가 통과했다는
뜻이지, 호스트가 STIG를 충족한다는 뜻이 아닙니다. 평가에는 STIG의 SCAP 콘텐츠나 체크리스트를 쓰고, 이 프로파일은 점검하는 범위에
대해 항목마다 근거와 함께 결과를 보는 데 쓰세요.

| 영역 | 점검 항목 |
|---|---|
| 부팅과 커널 | `UBTU-22-211015`(Ctrl-Alt-Delete 마스크), `UBTU-22-213010`(커널 로그), `UBTU-22-213020`(ASLR), `UBTU-22-253010`(SYN 쿠키) |
| 패키지 | 설치되어 있어야 함: `215010`(libpam-pwquality), `215015`(chrony), `251010`(ufw), `255010`(openssh-server), `431010`(apparmor), `653010`(auditd). 설치되어 있지 않아야 함: `215020`(systemd-timesyncd), `215025`(ntp), `215030`(rsh-server), `215035`(telnetd), `215040`(nfs-kernel-server) |
| 방화벽 | `251015`(ufw가 켜져 있음), `251020`(ufw 서비스가 부팅할 때 시작) |
| SSH | `255015`(서비스가 부팅할 때 시작), `255025`(빈 비밀번호와 사용자 환경 변수 금지), `255040`(X11 전달 금지) |
| 계정과 비밀번호 | `411010`(root 잠금), `411015`(고유한 UID), `411025`(최소 사용 기간 1일), `411030`(최대 사용 기간 60일), `412030`(유휴 셸 15분), `611035`(15자), `611065`(빈 비밀번호 금지) |

(점검 항목 ID는 `UBTU-22-` 뒤에 번호가 붙은 것입니다.)

## 점검 항목을 어떻게 연결하나

점검은 STIG가 요구하는 것을 정확히 판정할 때만 점검 항목에 연결하고, STIG가 숫자를 정해 둔 곳(60일, 15자, 900초)에는 그 숫자를
매개변수로 넣습니다. 더 느슨한 점검을 연결하면 호스트가 실제로는 실패하는 항목을 통과할 수 있는데, vmsctl은 그렇게 하지 않습니다.
예를 들어 STIG는 `SHA512` 비밀번호 해시를 요구하는데 `accounts.password-hash-method`는 yescrypt도 받아들이므로, 그 STIG 점검 항목은
연결하지 않았습니다. 패키지, 유닛, 숫자가 필요한 항목에는 그 값을 매개변수로 받는 작은 범용 점검(`packages.installed`,
`packages.absent`, `services.unit-enabled`, `services.unit-masked`)을 쓰고, 어느 값인지는 프로파일이 정합니다.

점검 항목 ID와 중요도(CAT I은 `high`, CAT II는 `medium`, CAT III은 `low`)는 STIG의 것이며 STIG는 미국 정부 저작물입니다. 제목은
vmsctl이 직접 짧게 쓴 것입니다. 연결은 [ComplianceAsCode](https://github.com/ComplianceAsCode/content)가 이 STIG에 대해 공개한
점검 항목 목록을 기준으로, 항목마다 요구 사항과 대조해서 만들었습니다. 어떤 배포판의 호스트든 점검 결과는 나오지만, 이 프로파일이
대상으로 하는 것은 Ubuntu 22.04 호스트뿐입니다.

점검이 갖춰지는 대로 항목을 늘립니다(가장 큰 묶음은 감사 규칙입니다).
