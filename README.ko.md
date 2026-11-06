<!-- translated from README.md @ 4c1f575 -->
# hostlint

[![CI](https://github.com/with-developer/hostlint/actions/workflows/ci.yml/badge.svg)](https://github.com/with-developer/hostlint/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**리눅스 서버를 위한 eslint.** 정적 Go 바이너리 하나로 호스트의 보안 설정을 하드닝 기준과 비교하고,
컨트롤마다 결과와 그 근거를 함께 보여 줍니다.

[English](README.md)

![터미널 애니메이션: hostlint scan이 실패한 컨트롤과 그 근거를 보여 줍니다](docs/demo/scan.gif)

```text
$ sudo hostlint scan
hostlint v0.2.1 · kisa-2026 · web-01 (Debian GNU/Linux 12 (bookworm))

✗ FAIL   U-01   Restrict direct remote root login [high]
    ✗ ssh.permit-root-login — SSH does not allow direct root login
        "yes" (explicit); expected one of [no]  /etc/ssh/sshd_config:33
    ? services.review-remote-root-login — Review root login through telnet and other remote terminal services
        Check that root cannot log in through the service (pam_securetty in its auth stack and no pts/N line in /etc/securetty, where that module exists). Better, turn the service off.
        telnet (inetd) at /etc/inetd.conf:42
? MANUAL U-07   Remove unneeded accounts [low]
    ? accounts.review-login-accounts — Review accounts that can log in
        Confirm that every listed account is still needed, especially accounts of people who have left. Default accounts such as lp, uucp or games appear here only when they were given a login shell, which they should not have.
        root (uid 0, /bin/bash)
✗ FAIL   U-18   Ownership and permissions of /etc/shadow [high]
    ✗ files.shadow-perms — /etc/shadow is owned by root and readable by root only
        /etc/shadow: root:shadow 0640 — mode 0640 exceeds 0400
✗ FAIL   U-52   Telnet is off [medium]
    ✗ services.no-telnet — Telnet is not started
        telnet (inetd, /usr/sbin/telnetd) at /etc/inetd.conf:42
...

kisa-2026: 67 controls — 10 FAIL, 11 MANUAL, 29 PASS, 17 NOT_APPLICABLE
```

위 출력은 `PermitRootLogin yes`와 inetd telnet 서비스를 추가한 Debian 12 컨테이너의 결과를 줄인 것입니다
(호스트 이름은 줄였습니다).

> 🚧 **초기 릴리스입니다.** 흔치 않은 환경에서는 거친 부분이 있을 수 있으니 알려 주세요.
> [로드맵](docs/ROADMAP.md)과 [릴리스 이력](docs/RELEASING.md)을 참고하세요.

## 왜 hostlint인가

- **모든 판정에 근거가 붙습니다.** 값, 그 값이 나온 파일과 줄, 명시적으로 설정한 값인지 기본값인지를
  보여 줍니다. 이유를 모르는 "FAIL"은 없습니다.
- **잘못된 PASS를 내지 않습니다.** 판단할 수 없는 경우(읽을 수 없는 파일, 시간 초과로 끝나지 못한
  수집, 한도에 걸린 파일시스템 순회)에는 추측한 `PASS` 대신 `ERROR`나 `MANUAL`을 냅니다. 설정은 그
  프로그램이 읽는 방식대로 읽습니다. PAM 스택은 libpam처럼 평가하고, `login.defs`는 shadow-utils처럼,
  셸 시작 파일은 bash가 읽는 순서대로 읽습니다.
- **관찰만 합니다.** 점검은 호스트를 절대 바꾸지 않습니다. 규칙은 스크립트가 아니라 데이터라서 명령을
  실행할 수 없습니다. 비밀번호 해시, 키, 토큰은 결과에 나오지 않습니다.
- **기준은 덧씌우는 방식입니다.** 점검은 한 번 작성하고 컨트롤에 매핑합니다. 첫 프로파일은
  주요정보통신기반시설 기술적 취약점 분석·평가 가이드 2026년판(Unix U-01–U-67)입니다.
- **운영 중인 호스트와 이미지 모두.** 실행 중인 시스템을 점검하거나, 다른 곳에 마운트한 루트
  파일시스템(`--root`, 예: CI의 골든 이미지)을 점검합니다.
- **파이프라인에 맞춰 만들었습니다.** 터미널 표, JSON(스키마 포함), SARIF, JUnit을 지원하고, 종료
  코드는 지정한 심각도를 따릅니다.

## 빠른 시작

릴리스를 설치합니다(Linux, amd64 또는 arm64). `install.sh`는 아카이브의 SHA-256을 확인하고,
`cosign`이 있으면 체크섬의 Sigstore 서명도 확인합니다.

```sh
curl -fsSLO https://raw.githubusercontent.com/with-developer/hostlint/v0.9.0/install.sh
sudo sh install.sh -v v0.9.0     # 먼저 읽어 보세요. root 없이 설치하려면 -b DIR
sudo hostlint scan
```

[릴리스](https://github.com/with-developer/hostlint/releases)에는 `.deb`·`.rpm` 패키지, SBOM, 빌드
출처 증명도 있습니다(`gh attestation verify 파일 -R with-developer/hostlint`). 직접 빌드하려면
(Go 1.26 이상, 바이너리 자체는 의존성이 없습니다):

```sh
go install github.com/with-developer/hostlint/cmd/hostlint@v0.9.0
sudo "$(go env GOPATH)/bin/hostlint" scan
```

root가 아니면 보호된 파일(예: `/etc/shadow`)이 필요한 점검은 `ERROR`가 됩니다.

```sh
# 기계가 읽을 수 있는 결과
sudo hostlint scan --format json --output web-01.json

# 마운트한 루트 파일시스템(이미지, VM 디스크). 운영 중일 때만 알 수 있는 점검은 ERROR나 NOT_APPLICABLE
sudo hostlint scan --root /mnt/image

# CI: 심각도 high인 컨트롤이 실패할 때만 실패 처리
sudo hostlint scan --fail-on high --format junit --output hostlint.xml

# 여러 호스트를 HTML 보고서 하나로: 네트워크 요청을 하지 않는 파일 하나
hostlint report results/*.json --output report.html

# 지난 스캔 이후 무엇이 바뀌었나: 새로 실패한 것, 해결된 것, 그 원인이 된 점검
hostlint diff before.json after.json
hostlint diff baseline.json current.json --fail-on-regression   # 컨트롤이 나빠지면 종료 코드 1

# 여러 호스트의 결과를 모으는 플릿 서버 (초기 단계, docs/fleet.ko.md 참고)
hostlint server run --db server.db --listen :8443
sudo HOSTLINT_TOKEN=hlt_ing_... hostlint scan --push https://hostlint.example.org:8443

# 프로파일을 고르고, 기준을 더 엄격하게 하고, 안고 가기로 한 발견을 예외로 처리
sudo hostlint scan --config hostlint.yaml
```

각 결과를 정하는 점검은 출력에 나열됩니다. `--config`와 파일 형식은
[docs/configuration.ko.md](docs/configuration.ko.md)에 있습니다.

| 플래그 | 의미 |
|---|---|
| `-p, --profile` | 점검할 프로파일 (기본값 `kisa-2026`) |
| `-f, --format` | `table`, `json`, `sarif`, `junit` |
| `-o, --output` | 결과를 파일로 저장 |
| `--fail-on` | 이 심각도 이상의 컨트롤이 실패하거나 점검할 수 없으면(`ERROR`) 종료 코드 1: `low`(기본값), `medium`, `high`, `none` |
| `--root` | 이 디렉터리에 마운트된 파일시스템을 점검 (운영체제가 있어야 함) |
| `--config` | 설정 파일 (기본값: `./hostlint.yaml`, 없으면 `/etc/hostlint/hostlint.yaml`) |
| `--label key=value` | 결과의 호스트 정보에 라벨 추가 |
| `--color` | `auto`(기본값), `always`, `never` |
| `-v, --verbose` | 통과·해당 없음 컨트롤도 표에 표시 |

## 결과

| 상태 | 의미 |
|---|---|
| `PASS` | 컨트롤을 충족하며, 근거가 그 이유를 보여 줍니다 |
| `FAIL` | 컨트롤을 충족하지 않으며, 근거가 무엇이 문제인지 나열합니다 |
| `MANUAL` | 사람이 판단해야 하며, 검토할 사실을 보여 줍니다 |
| `NOT_APPLICABLE` | 컨트롤이 해당되지 않습니다 (예: 서비스가 설치되지 않음) |
| `ERROR` | 신뢰할 수 있게 판단할 수 없으며, 이유를 보여 줍니다 |
| `WAIVED` | 설정 파일의 예외가 `FAIL`이나 `MANUAL` 결과를 받아들였습니다. 원래 상태와 근거는 남습니다 ([docs/configuration.ko.md](docs/configuration.ko.md)) |

컨트롤의 상태는 점검 결과 중 가장 나쁜 것입니다: `FAIL` > `ERROR` > `MANUAL` > `WAIVED` >
`PASS` > `NOT_APPLICABLE`.

종료 코드: `--fail-on` 이상으로 실패한 것이 없으면 0, 있으면 1, 사용법 오류나 실행하지 못한 점검은 2,
중단되면 130입니다.

## 무엇을 점검하나

`kisa-2026` 프로파일은 KISA 가이드(2026년판) Unix 컨트롤 67개를 모두 매핑합니다. 컨트롤마다 점검,
매개변수, 조치 방법은 [규칙 참조](docs/rules.md)에 있습니다(점검 제목은 한국어 병기).

- **계정 관리 (U-01–U-13):** root 원격 접속, 비밀번호 길이·복잡도·사용 기간, 계정 잠금, 비밀번호
  파일 보호, UID 0, `su` 제한, 세션 타임아웃, 비밀번호 해시 알고리즘.
- **파일 및 디렉터리 관리 (U-14–U-33):** `PATH`, 시스템 파일의 소유자와 권한, 시작 스크립트,
  set-ID 프로그램, 모든 사용자가 쓸 수 있는 파일, `/dev`의 파일, `.rhosts`, `umask`, 홈 디렉터리.
  로컬 파일시스템을 한도 안에서 순회하는 점검을 포함합니다.
- **서비스·패치·로그 관리 (U-34–U-67):** finger, r 계열, telnet, tftp, NFS, NIS, SNMP 등 오래된
  서비스(활성화된 유닛, 실행 중인 유닛, init 스크립트, inetd·xinetd), SNMP community 문자열과 접근
  범위(`snmpd.conf`를 읽되 결과에는 담지 않음), Postfix 오픈 릴레이와 VRFY, BIND 존 전송·업데이트, NFS 공유, vsftpd 배너·TLS·root 로그인·익명 접근, Samba 게스트 공유, cron과 sudoers 권한, 시각 동기화.

사람의 판단이 필요한 컨트롤(남길 계정, 배너, 로그 정책, 패치 수준, 서비스 접근 범위)과 설정을 아직 읽지 않는
서버(Postfix 외의 메일 서버, BIND 외의 DNS 서버, vsftpd 외의 FTP 서버)의 설정은 `MANUAL`이고, 검토할 사실이
함께 나열됩니다. 해당 소프트웨어가 실행되지 않으면 `NOT_APPLICABLE`입니다. 지원 대상: Ubuntu 22.04/24.04/26.04,
Debian 12/13, RHEL 호환 9/10(Rocky Linux, AlmaLinux), Amazon Linux 2023, CentOS/RHEL 7(최선 노력). 다른 버전도 최선
노력으로 점검하고 결과에 그렇게 표시합니다.

제목과 설명은 hostlint가 직접 작성했고, 프로파일은 컨트롤 ID만 참조합니다.

## 플릿 대시보드 (초기)

호스트가 스스로 스캔하고 결과를 `hostlint server`로 보내면, 서버가 이력을 보관하고 웹 대시보드로 플릿을
보여 줍니다. 통과율, 가장 많이 실패하는 컨트롤, 직전 스캔 이후의 악화, 모든 호스트의 모든 컨트롤 매트릭스,
각 결과의 근거를 볼 수 있습니다. 서버는 호스트에 접속하지 않습니다. 호스트 없이 써 보려면
`hostlint server demo`가 가상의 플릿으로 서버를 띄웁니다. [docs/fleet.ko.md](docs/fleet.ko.md)를 참고하세요.

![대시보드 개요](docs/demo/dashboard-overview.png)

| 모든 호스트의 모든 컨트롤 매트릭스 | 호스트 하나: 컨트롤, 근거, 이력 |
|---|---|
| ![매트릭스](docs/demo/dashboard-matrix.png) | ![호스트](docs/demo/dashboard-host.png) |

## 원칙

hostlint는 양보하지 않는 몇 가지 원칙 위에 만들어졌습니다. [비전](docs/VISION.md)과
[아키텍처 결정 기록](docs/adr/)을 참고하세요.

1. 관찰만 합니다. 어떤 코드 경로도 점검 대상 호스트를 바꾸지 않습니다 ([ADR 0004](docs/adr/0004-observation-only.md)).
2. 비밀은 호스트를 떠나지 않습니다.
3. 잘못된 PASS를 내지 않습니다 ([ADR 0006](docs/adr/0006-rule-format-evaluation-results.md)).
4. 콘텐츠는 직접 작성합니다.
5. 설치와 실행이 지루할 만큼 단순해야 합니다.

## 상태

hostlint는 활발히 개발 중입니다. KISA 2026 프로파일(U-01–U-67), 수집기, 터미널·JSON·
SARIF·JUnit·여러 호스트 HTML 출력, 예외(waiver)를 담는 설정 파일, 릴리스 파이프라인(서명된 아카이브,
패키지, SBOM, `install.sh`), 지원하는 모든 배포판에 대한 컨테이너 테스트 매트릭스가 갖춰졌고, v0.9.0이
최신 릴리스입니다. 플릿 모드(에이전트와 웹 UI가 있는 서버)는 계획 중입니다. [로드맵](docs/ROADMAP.md)을
참고하세요.

## 라이선스

[Apache-2.0](LICENSE)
