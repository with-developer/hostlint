<!-- translated from docs/migrating-from-hostlint.md @ 2ca0d64 -->
# hostlint에서 vmsctl로 옮기기

hostlint는 v0.27.0에서 vmsctl로 이름을 바꿨습니다([ADR 0017](adr/0017-rename-to-vmsctl.md)). hostlint는 관계없는 호스팅 회사의
이름이기도 해서 프로젝트를 찾기 어려웠기 때문입니다. 무엇을 점검하는지, 점검 결과, 토큰, 서명, 서버 데이터베이스는 그대로입니다.
바뀌는 것은 명령에 쓰는 이름뿐입니다.

[English](migrating-from-hostlint.md)

## 바꿔야 하는 것

| 이전 (v0.26.0까지) | 지금 (v0.27.0부터) |
|---|---|
| `hostlint scan ...` | `vmsctl scan ...` |
| `/usr/local/bin/hostlint`, `/usr/bin/hostlint` | `vmsctl`. `.deb`·`.rpm` 패키지는 한동안 `hostlint` 링크를 함께 두고, `install.sh`는 예전 `hostlint`를 새 바이너리를 가리키는 링크로 바꿉니다. 둘 다 이름이 곧 없어진다는 안내를 출력합니다 |
| `ghcr.io/with-developer/hostlint:0.26.0` | `ghcr.io/with-developer/vmsctl:0.27.0` (예전 이미지는 남아 있고, 그 이름의 `:latest`는 0.26.0에서 멈춥니다) |
| `uses: with-developer/hostlint@v0.26.0` | `uses: with-developer/vmsctl@v0.27.0` |
| `go install github.com/with-developer/hostlint/cmd/hostlint@...` | `go install github.com/with-developer/vmsctl/cmd/vmsctl@v0.27.0` (예전 경로의 `@latest`는 v0.26.0에 머뭅니다) |
| `HOSTLINT_TOKEN`, `HOSTLINT_PACK`, `HOSTLINT_WEBHOOK_URL` | `VMSCTL_TOKEN`, `VMSCTL_PACK`, `VMSCTL_WEBHOOK_URL` |
| `hostlint.yaml`, `/etc/hostlint/hostlint.yaml` | `vmsctl.yaml`, `/etc/vmsctl/vmsctl.yaml` |
| `hostlint-server.db` (데이터베이스 기본 파일) | `vmsctl-server.db` |
| `pack.yaml`의 `requires_hostlint:` | `requires_vmsctl:` |
| `hostlint-scan.service`, `hostlint-agent.service`, `hostlint-server.service` (문서의 유닛 이름) | `vmsctl-scan.service` 등. 유닛 이름은 직접 정하면 됩니다 |

예전 환경 변수, 설정 파일 이름, 데이터베이스 파일 이름은 아직 동작합니다. 둘 다 있으면 새 이름이 우선합니다(`VMSCTL_PACK`은
`HOSTLINT_PACK`에 더해지지 않고 대신합니다). 한곳에 `vmsctl.yaml`과 `hostlint.yaml`이 함께 있으면 `vmsctl.yaml`을 쓰므로,
v0.26과 v0.27 호스트가 섞인 환경에서는 두 파일을 같이 두면 됩니다. 점검할 때 쓰지 않은 파일이 무엇인지 표준 오류로 알려
줍니다. 한 디렉터리에 데이터베이스 파일이 둘 다 있으면 오류이니 하나를 지우거나 이름을 바꾸거나 `--db`를 주세요.
`hostlint.yaml`만 있는 경우에도 표준 오류에 안내를 출력하고 계속 진행합니다.

## 그대로 두는 것

저장된 데이터에 기록되거나 버전이 다른 프로그램끼리 주고받는 것이라 이름을 바꾸지 않았습니다. 호스트 ID, 서명 키 형식과
서명 도메인, `X-Hostlint-*` HTTP 헤더(웹훅의 `X-Hostlint-Signature-256` 포함), 토큰 접두어(`hlt_ing_`, `hlt_api_`,
`hlt_opr_`), 세션 쿠키가 그렇습니다. v0.26 에이전트가 v0.27 서버로 결과를 보낼 수 있고 그 반대도 됩니다. 토큰과 서명된
결과도 그대로 이어집니다.

## 새 이름이 눈에 띄는 곳

- **결과와 SARIF.** `scan.tool.name`이 `vmsctl`입니다(스키마가 `hostlint`도 받으므로 예전 결과도 유효합니다). SARIF의 도구
  이름도 `vmsctl`이라서 코드 스캐닝은 새 도구로 취급합니다. 예전 hostlint 경고는 자동으로 닫히지 않고, 새 이름의 Action으로
  점검하면 경고가 새로 열립니다.
- **웹훅.** 메시지 문구가 `hostlint:` 대신 `vmsctl:`로 시작하고 user agent는 `vmsctl-server`입니다. 둘 중 하나로 거르던 수신 쪽은
  고쳐야 합니다. JSON 필드, 이벤트 `id`, 서명 헤더는 같습니다.
- **예전 릴리스를 고정한 경우.** `version: v0.26.0`인 Action과 `install.sh -v v0.26.0`은 예전 바이너리를 예전 이름으로 설치합니다
  (Action은 `vmsctl`이 그것을 가리키게 링크를 만듭니다). 이 바이너리는 `hostlint.yaml`과 `HOSTLINT_*` 변수만 읽습니다.
- **팩.** v0.26과 v0.27 바이너리에서 모두 돌아야 하는 팩은 `requires_hostlint:`를 그대로 두세요(v0.26은 새 키를 거부합니다).
  모든 호스트가 v0.27 이상이 되면 `requires_vmsctl:`을 쓰세요. `pack.yaml`을 고치면 팩의 다이제스트가 바뀝니다.
- **릴리스 검증.** v0.26.0까지는 저장소의 예전 이름으로 서명했습니다.
  `cosign verify-blob ... --certificate-identity https://github.com/with-developer/hostlint/.github/workflows/release.yml@refs/tags/vX.Y.Z`,
  `gh attestation verify 파일 -R with-developer/hostlint`로 검증하세요. v0.27.0부터는 `vmsctl`입니다. `install.sh`는 요청한 버전을 보고
  알아서 고릅니다.
- **설치 스크립트.** 문서처럼 태그에 고정해서 쓰세요(`.../vmsctl/v0.27.0/install.sh`). `main`의 `install.sh`는 최신 릴리스를 설치하고,
  더 오래된 버전은 예전 이름으로 설치합니다.
- **GitHub.** 저장소는 `with-developer/vmsctl`입니다. 예전 주소(clone, 릴리스, Action)는 GitHub가 새 주소로 넘겨 줍니다. 프로젝트
  페이지는 이제 `https://with-developer.github.io/vmsctl/`이고, 예전 주소는 넘겨 주지 않습니다.
