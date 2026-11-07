<!-- translated from docs/fleet.md @ 4839232 -->
# 플릿 서버 (초기)

> [ADR 0010](adr/0010-fleet-server-and-dashboard.md)의 1단계입니다. 서버는 결과를 받아 저장하고
> 조회 요청에 답합니다. 대시보드는 다음 단계입니다. 인터페이스는 아직 안정적이지 않습니다.

호스트가 스스로 스캔하고 결과를 서버로 **보냅니다(push)**. 서버는 호스트에 접속하지 않습니다.
호스트가 스캔하게 만들거나, 무언가를 실행하거나, 읽을 수 없습니다.

## 대시보드

대시보드가 포함되도록 빌드된 바이너리는 `hostlint server run`의 주소에서 웹 대시보드를 제공합니다.
릴리스 바이너리에는 포함되어 있고, 소스에서 빌드할 때는 `make build-web`(Node 22)을 씁니다.
`go install`로 설치한 바이너리에는 API만 있고 `/`에서 그렇게 안내합니다. 조회 토큰
(`hostlint server token create --scope api`)으로 로그인하면, 전체 현황(통과율, 실패한 컨트롤이 있는
호스트, 보고를 멈춘 호스트, 가장 많이 실패하는 컨트롤, 최근 악화), 호스트 목록(검색, 필터, 정렬, CSV
내보내기), 컨트롤 목록(컨트롤마다 무엇을 점검하는지, 왜 중요한지, 조치 방법, 실패한 호스트), 모든 호스트의 모든 컨트롤 매트릭스, 그리고 호스트별로 모든 점검의 근거가 있는 컨트롤, 이력, 직전 스캔과의 비교를 볼 수 있습니다.
영어와 한국어를 지원하고 시스템의 라이트/다크 테마를 따릅니다. 호스트가 보낸 내용은 모두 텍스트로만
표시합니다.

## 호스트 없이 써 보기

```sh
hostlint server demo
```

`127.0.0.1:8443`에서 가상의 플릿(호스트 12대, 2주치 스캔, 실제 컨트롤로 생성)으로 서버를 띄우고 로그인에 쓸
조회 토큰을 출력합니다. 데이터는 메모리에만 있고 명령이 끝나면 사라집니다. 대시보드가 포함된 바이너리(릴리스
바이너리 또는 `make build-web`)가 필요합니다.

## 빠른 시작

서버 머신에서:

```sh
# 호스트마다 토큰 하나. 한 번만 보여 주고 해시만 저장합니다.
hostlint server token create --db /var/lib/hostlint/server.db --name web-01 --host web-01

hostlint server run --db /var/lib/hostlint/server.db --listen :8443
# listening on https://[::]:8443
# certificate pin: sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

`--tls-cert`와 `--tls-key`가 없으면 서버가 데이터베이스 옆에 자체 서명 인증서를 만들고 공개 키의
핀을 출력합니다. 평문 HTTP는 루프백 주소에서만 허용되고, TLS 프록시가 앞에 있으면
`--plain-http --behind-proxy`로 쓸 수 있습니다.

각 호스트에서 스캔과 전송을 한 번에:

```sh
sudo HOSTLINT_TOKEN=hlt_ing_... hostlint scan \
  --push https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

스캔이 먼저 돌고 보고서는 평소처럼 출력된 뒤(`--format`, `--output`, `--fail-on`은 그대로 동작) 결과를 보냅니다.
보낼 수 없으면 오류(종료 코드 2)이고, 토큰이 없으면 스캔을 시작하기 전에 알려 줍니다. 앞서 저장한 결과를
보내려면:

```sh
HOSTLINT_TOKEN=hlt_ing_... hostlint push result.json \
  --server https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

토큰은 `HOSTLINT_TOKEN`이나 `--token-file`로 전달하며 명령줄에는 쓰지 않습니다. 공인 CA 인증서를
쓰면 `--pin`을 생략합니다. 두 단계를 cron이나 systemd 타이머로 돌리세요. 서버가 이미 가진 결과를 다시
보내는 것은 오류가 아닙니다.

## 예약 점검

서버는 점검을 시작하지 않습니다. 호스트가 일정에 따라 스스로 점검하고 결과를 보냅니다. systemd 타이머로 할 수 있습니다
(`/etc/systemd/system/hostlint-scan.service`와 `.timer`).

```ini
# hostlint-scan.service
[Unit]
Description=hostlint scan, sent to the fleet server
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hostlint scan --fail-on none --format json --output /dev/null \
  --push https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U= \
  --token-file /etc/hostlint/token --sign-key /etc/hostlint/signing-key
NoNewPrivileges=yes
PrivateTmp=yes
```

```ini
# hostlint-scan.timer
[Unit]
Description=Daily hostlint scan

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo install -m 600 /dev/null /etc/hostlint/token      # 그런 다음 토큰을 넣습니다
sudo hostlint key generate /etc/hostlint/signing-key   # 공개 키를 출력합니다: `server token create --key`로 토큰을 묶으세요
sudo systemctl enable --now hostlint-scan.timer
```

`RandomizedDelaySec`는 플릿을 두 시간에 걸쳐 분산하고(서버는 토큰 하나가 보내는 속도를 제한합니다), `Persistent`는 호스트가
꺼져 있어서 놓친 점검을 실행합니다. `--fail-on none`은 실패한 컨트롤 때문에 유닛이 실패로 표시되지 않게 합니다. 유닛이 실패했다는 것은
점검이나 전송이 동작하지 않았다는 뜻이며 알림을 보낼 만한 상태입니다. 출력은 `journalctl -u hostlint-scan`에 있습니다. cron으로는
`/etc/cron.d/hostlint`에 같은 명령(`17 3 * * * root ...`)을 쓰세요. 서버의 `--stale-after` 웹훅이 보고를 멈춘 호스트를 알려 줍니다.

## 요청 시 스캔: 에이전트

타이머는 일정에 따라 스캔합니다. 호스트를 대시보드에서 *지금* 스캔하려면 그 호스트에서 `hostlint agent`를 서비스로
실행하세요. 에이전트는 바깥으로만 연결합니다(서버는 여전히 호스트에 접속하지 않습니다). HTTPS 요청 하나(롱 폴링)를 열어
두고, 누군가 **지금 스캔**을 누르면 서버가 그 요청에 답합니다.

```sh
sudo hostlint server token create --name web-01 --host web-01 --key <공개키>   # --push와 같은, 호스트의 수집 토큰 (--key: `key generate`가 출력한 공개키)
sudo hostlint agent --server https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U= \
  --token-file /etc/hostlint/token --sign-key /etc/hostlint/signing-key --allow-profile kisa-2026
```

```ini
# /etc/systemd/system/hostlint-agent.service
[Unit]
Description=hostlint agent (scan when the fleet server asks)
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hostlint agent --server https://hostlint.example.org:8443 --pin sha256/... \
  --token-file /etc/hostlint/token --sign-key /etc/hostlint/signing-key --allow-profile kisa-2026
Restart=always
RestartSec=10
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

서버가 요청할 수 있는 것은 한 가지입니다. **이 호스트 자신의** `--allow-profile` 목록에 있는 프로파일(내장 프로파일 1~8개)로
스캔하는 것, 그것도 1분에 한 번까지입니다. 면제, 매개변수, 경로, 명령은 보낼 수 없습니다. `hostlint.yaml`은 호스트의
파일로 남고, 결과는 `hostlint scan --push`와 같은 방식(같은 토큰, 같은 `--pin`, 같은 서명)으로 돌아갑니다. 에이전트는 허용하지
않은 프로파일의 요청이나 마지막 스캔 1분 안의 요청도 거절하고, 이유를 서버에 알립니다. 서버가 침해되어도 호스트가 정해진
한도까지 더 자주 스캔하게 만들 수 있을 뿐 그 밖의 일은 할 수 없습니다. 에이전트는 `--pack`을 받지 않습니다. 정책 팩 결과는
서버가 아직 받지 않습니다.

호스트가 결과를 한 번은 보낸 적이 있어야 하고(`hostlint scan --push`), 토큰은 호스트에 묶여 있어야 합니다(`--host`). 에이전트는 새
종류의 신원이 아니라 호스트의 토큰입니다. 예약 점검은 에이전트와 함께 계속 동작합니다.

**누가 요청할 수 있나.** 버튼에는 **operator** 토큰(`hostlint server token create --scope operator --any-host --name ops`)이나 그
토큰으로 시작한 대시보드 세션이 필요합니다. operator는 `api` 토큰처럼 읽을 수 있고, 스캔도 요청할 수 있습니다. `api` 토큰으로 시작한
세션은 호스트의 에이전트를 볼 수는 있지만 버튼은 없습니다. 요청은 `{"profile": "kisa-2026"}`를 담은 JSON `POST
/api/v1/hosts/{id}/scan`입니다. 브라우저 세션에서는 서버 자신의 사이트인 `Origin`이 있을 때만 받아들이므로 다른 사이트의 페이지는
요청할 수 없습니다(세션 쿠키도 `SameSite=Strict`입니다). 응답은 작업과 함께 `202`, 최근 2분 안에 호스트의 에이전트가 폴링하지
않았거나 에이전트가 그 프로파일을 허용하지 않으면 `409`, 그 호스트의 스캔을 1분 안에 요청했거나 아직 처리 중이면 `429`입니다. 모든
요청은 감사 체인에 남습니다(`scan-requested`, 요청한 토큰과 주소 포함). 대시보드는 에이전트가 연결된 호스트에만 버튼을 보이고,
요청의 진행(대기, 스캔 중, 도착, 실패)을 따라갑니다. 아무도 답하지 않은 요청은 10분 뒤 만료됩니다. `GET /api/v1/hosts/{id}/agent`도
같은 상태를 줍니다.

## 회사의 계정으로 로그인시키기

대시보드는 읽기 토큰으로 사람을 로그인시킵니다. 회사에 이미 있는 로그인(Google, Entra ID, Okta, Keycloak: OIDC 또는 SAML)으로
사람들이 들어오게 하려면, 로그인을 처리하는 리버스 프록시를 서버 앞에 두고 프록시가 자신의 읽기 토큰으로 요청을 넘기게 하세요.
hostlint에는 이를 위한 로그인 코드가 일부러 없습니다. 로그인은 웹 애플리케이션에서 가장 많이 공격받는 부분이기 때문입니다
([ADR 0015](adr/0015-dashboard-sign-in.md)).

서버는 프록시 뒤의 루프백 주소에서 듣습니다.

```sh
hostlint server run --db /var/lib/hostlint/server.db --listen 127.0.0.1:8443 --plain-http --behind-proxy
hostlint server token create --db /var/lib/hostlint/server.db --scope api --name dashboard-proxy
```

nginx와 [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)의 개요입니다(`/etc/nginx/hostlint-token.conf`에는
`proxy_set_header Authorization "Bearer hlt_api_...";`가 들어 있고, root만 읽을 수 있으며 브라우저에는 보이지 않습니다).
설정은 위 영어 문서의 예시와 같습니다. 호스트는 자신의 수집 토큰으로 `/api/v1/results`에 보내므로 이 경로 하나만 로그인 없이
프록시를 통과시키고, 나머지는 `auth_request`로 로그인한 사람에게만 열어 서버로 넘깁니다.

시험한 것은 서버 쪽입니다. 모든 요청에 읽기 토큰이 있으면 대시보드의 로그인 폼 없이 동작하고, 수집 경로는 토큰으로 계속
보호됩니다. 프록시 설정은 프록시의 일반적인 설정을 개요로 적은 것이니 프록시의 문서와 대조해 확인하세요. 알아 둘 것:

- 서버 자신의 주소에 닿을 수 있는 사람(같은 머신의 다른 사용자)은 로그인을 우회합니다. 루프백 주소나 프록시만 닿을 수 있는
  호스트에 두고, 그 옆에서 다른 것이 듣지 않게 하세요.
- 서버의 감사 기록에는 사람이 아니라 프록시의 토큰이 남습니다. 사람은 프록시의 접근 로그에 있습니다.
- 프록시를 통과한 사람은 모두 모든 것을 읽을 수 있습니다. 누가 로그인할 수 있는지(그룹, 도메인)를 프록시에서 제한하세요.
- 프록시의 토큰도 다른 토큰처럼 교체하세요. `server token create`, 파일 변경, `server token revoke`.

## 결과 조회

호스트는 서로 다른 프로파일(`--profile`, `essentials`, 정책 팩)로 점검할 수 있으므로 대시보드의 모든 숫자는 **프로파일 하나**의
것입니다. 개요, 호스트 목록, 매트릭스, 컨트롤 목록은 `?profile=ID`를 받고, 없으면 가장 많은 호스트가 쓴 프로파일을 씁니다(**v0.19 전에는 `profile` 없이 이 호출을 읽던 스크립트는 이제 프로파일 하나를 읽습니다. 전처럼 모든 프로파일을 합산하려면 `?profile=all`을 주세요**). 최신
스캔에 그 프로파일의 컨트롤이 하나도 없는 호스트는 숫자에 집계하지 않으며(보고하지 않는 호스트는 어떤 프로파일로 스캔했든 오래 보고하지 않은 호스트로 셉니다), 대시보드가 그런 호스트의 수를 알려 주고 목록에 표시합니다.
대시보드에서는 프로파일이 둘 이상이면 사이드바의 선택기로 프로파일을 고르며(기억합니다).

조회 토큰(`--scope api`)으로 스크립트나 CI가 서버가 아는 것을 물어볼 수 있습니다.

```sh
hostlint server token create --db server.db --name ci --scope api
curl --cacert tls.crt -H "Authorization: Bearer hlt_api_..." https://hostlint.example.org:8443/api/v1/overview
```

| 요청 | 응답 |
|---|---|
| `GET /api/v1/profiles` | 최신 스캔의 프로파일과 호스트 수, 가장 많은 호스트가 쓰는 프로파일(`default`), 제목 |
| `GET /api/v1/overview` | 호스트 수, 실패 컨트롤이 있는 호스트, 오래 보고하지 않은 호스트, 상태별 개수, 가장 많은 호스트에서 실패하는 컨트롤, 최근 악화(`?staleDays=7`) |
| `GET /api/v1/hosts` | 호스트별 최신 스캔의 개수와 점수 (`?q=`, `?status=failing\|stale`, `?sort=name\|score\|last`, `?limit=`, `?offset=`, `?format=csv`) |
| `GET /api/v1/controls`, `GET /api/v1/controls/PROFILE/ID` | 최신 스캔 기준 컨트롤별 상태 개수, 컨트롤 하나의 호스트 목록과 점검 내용·조치 방법 |
| `GET /api/v1/matrix` | 모든 호스트의 모든 컨트롤의 최신 상태, 가장 많이 실패한 호스트가 먼저 |
| `GET /api/v1/hosts/ID` | 호스트 하나: 최신 컨트롤과 이력 |
| `GET /api/v1/scans/ID` | 받은 그대로의 저장된 결과 |
| `GET /api/v1/diff?old=ID&new=ID` | 두 스캔 사이의 변화(`hostlint diff`와 같음) |

### 대시보드 세션

대시보드는 조회 토큰을 세션으로 한 번 교환합니다. `POST /api/v1/login`에 `{"token": "hlt_api_..."}`를
(`application/json`으로) 보내면 `hl_session` 쿠키(`HttpOnly`, `SameSite=Strict`, TLS에서는 `Secure`)가
설정되고, `POST /api/v1/logout`이 끝내며, `GET /api/v1/session`이 아직 유효한지 알려 줍니다. 세션은 8시간
동안 쓰지 않거나 모두 합쳐 24시간이 지나면, 또는 토큰이 폐기·만료되면 끝나고, 토큰 하나는 세션을 최대
20개 가집니다. 쿠키는 `GET` 요청만 인증합니다. 로그인은 주소당 분당 10회로 제한됩니다. TLS 프록시 뒤
(`--plain-http --behind-proxy`)에서는 서버가 `Secure` 속성을 위해 `X-Forwarded-Proto`를, 클라이언트 주소로는
마지막 `X-Forwarded-For` 주소를 신뢰합니다. 실제로 프록시가 앞에 있을 때만 켜세요.

점수는 PASS ÷ (PASS + FAIL + ERROR + MANUAL)입니다. 판정되지 않은 결과는 점수에 불리하게 작용하고,
NOT_APPLICABLE과 WAIVED는 비율에서 빼고 옆에 따로 표시합니다. `staleDays` 동안 보고하지 않은 호스트는
오래된(stale) 호스트입니다.

## 운영하기

systemd 서비스(`/etc/systemd/system/hostlint-server.service`)는 상태 디렉터리를 임시 사용자가 소유하게
만듭니다.

```ini
[Unit]
Description=hostlint server
After=network-online.target

[Service]
DynamicUser=yes
StateDirectory=hostlint
ExecStart=/usr/local/bin/hostlint server run --db /var/lib/hostlint/server.db --listen :8443
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

토큰은 `sudo systemd-run --pipe --property=DynamicUser=yes --property=StateDirectory=hostlint
hostlint server token create --db /var/lib/hostlint/server.db ...`로 만들거나, root로 실행한 뒤
데이터베이스를 `chown`하세요. 서버는 다른 사용자가 읽을 수 있는 데이터베이스를 거부합니다.

컨테이너에서는(대시보드가 포함된 바이너리, 빈 `scratch` 이미지, uid 65532가 소유한 데이터 볼륨):

```dockerfile
FROM scratch
COPY hostlint /hostlint
VOLUME /data
EXPOSE 8443
USER 65532:65532
ENTRYPOINT ["/hostlint", "server", "run", "--db", "/data/hostlint.db", "--listen", ":8443"]
```

**백업과 보관.** `hostlint server backup FILE`은 서버가 도는 중에도 일관된 복사본을 만듭니다(파일이 이미 있으면
안 되고, 본인만 읽을 수 있습니다). 복원하려면 서버를 멈추고 복사본을 `--db` 위치에 두세요. 서버는
`--retention`(기본 400일, `0`은 모두 보관)보다 오래된 스캔을 하루에 한 번 지우되, 호스트마다 최신 스캔은 항상
남깁니다. `hostlint server prune --older-than 9600h`는 한 번 실행하고, `hostlint server stats`는 데이터베이스에
든 것을 보여 줍니다. 업그레이드는 바이너리를 바꾸는 것이며 서버가 시작될 때 스키마가 마이그레이션됩니다.

## 서버가 확인하는 것

- 유효한 토큰. 수집 토큰은 호스트 이름 하나(`--host`)에 묶이고, 첫 결과의 호스트 ID가 고정되어 이후
  다른 ID의 결과는 거부됩니다. `--any-host`는 모든 호스트를 대신할 수 있는 토큰으로, 명시적 선택입니다.
- 결과가 올바른 형식이고(`hostlint report`와 같은 검사), 2 MiB 이하(`--max-result-bytes`), 컨트롤
  500개·점검 5000개 이하이며, 식별자가 출력 가능한 문자이고, 시작 시각이 서버 시계와 가까울 것.
  스캔 ID는 호스트마다 한 번만 저장되고, 이미 알려진 호스트 이름에 두 번째 호스트 ID는 붙지 않습니다.
- 토큰 하나는 분당 60개의 결과를 보낼 수 있고(`--rate`), 잘못된 토큰의 요청은 주소별로 제한됩니다.
- 모든 것이 감사 테이블에 기록되며 각 행은 이전 행의 해시를 이어 받습니다. `hostlint server verify`가
  체인을 다시 계산해 마지막 해시를 출력하니, 다른 곳에 보관해 두면 이후의 변경을 알아챌 수 있습니다.

## 서명된 결과

호스트는 보내는 결과에 서명할 수 있습니다. 그러면 나중에 결과를 저장한 서버가 침해되더라도, 그 결과는 그
호스트의 키가 말한 내용의 증거가 됩니다.

```sh
sudo hostlint key generate /etc/hostlint/sign.key      # 호스트마다 한 번; 지문을 출력합니다
sudo HOSTLINT_TOKEN=hlt_ing_... hostlint scan --push https://hostlint.example.org:8443 \
  --sign-key /etc/hostlint/sign.key
```

서버는 호스트의 첫 서명된 결과에서 키를 등록합니다(처음 본 키를 신뢰). 훔친 토큰이 남의 키를 먼저 등록하는 일을
막으려면 토큰을 만들 때 호스트의 공개키에 묶으세요: `hostlint server token create --name web-01 --host web-01
--key <공개키>`. 그러면 그 키로 서명된 결과만 받습니다. 그 뒤로는 그 호스트의 서명 없는 결과와 다른 키로 서명된
결과를 거부하므로(토큰만 훔쳐서는 더 이상 충분하지 않습니다), 대시보드가 그 호스트를 키 지문과 함께
서명됨으로 표시합니다. `hostlint server verify`는 저장된 스캔을 모두, 받을 때 해시 체인 감사 기록에 남긴 값(문서의 다이제스트와
서명에 쓴 키) 및 서명과 대조하므로, 나중에 데이터베이스에서 바뀐 결과, 제거되거나 교체된 서명, 저장된 문서와 다르게
대시보드에 보이는 통제 항목, 다른 호스트로 옮겨진 스캔, 수신 기록이 없는 스캔을 찾아냅니다. 서명하는 호스트는 과거로
돌아가지 못합니다. 그 호스트의 마지막 스캔보다 늦게 시작하지 않은 서명된 결과는 거부하며(원본이 정리된 뒤 가로챈 결과를
재전송하는 공격 방지), 이미 저장된 스캔의 재시도에는 전처럼 응답합니다. 시계가 몇 분 앞서 간 호스트는 실제 시각이 따라잡을 때까지 기다려야 하고(서버는 5분 넘게 앞선 시작 시각을 받지 않습니다), 더 새로운 스캔 뒤로 밀린 스캔은 더 이상 받지 않습니다. 키를 일부러 바꾼 경우(다시 설치한 머신)에는
`hostlint server host reset-key ID --key <새 공개키>`가 등록된 키를 바로 바꿉니다(`--key` 없이 쓰면 키를 잊으며,
다음 서명된 결과가 키를 등록할 때까지는 서명 없는 결과도 받습니다). 이전 키에 묶인 토큰(`--key`)은 계속 그 키를 요구하므로 그 호스트용 토큰을 새로 발급하세요. 다른 사용자가 읽을 수 있는 키 파일은 거부됩니다.

## 보호하지 않는 것

서버는 저장소이지 권위가 아닙니다. 데이터베이스를 장악한 사람은 보이는 내용을 바꿀 수 있고, 저장된 결과와
그 서명·키를 함께 바꿀 수도 있습니다. 이를 알아채려면 키 지문(`hostlint server host list`)과 감사 해시
(`hostlint server verify`)의 사본을 다른 곳에 보관하세요. 훔친 토큰으로는, 그 호스트가 서명하지 않는 한 묶인
호스트의 결과를 보낼 수 있고, 키 자체를 도난당한 호스트는 무엇이든 서명할 수 있습니다.

## 알림

호스트가 나빠지거나 보고를 멈추면 서버가 웹훅으로 이벤트를 보낼 수 있습니다.

```sh
echo -n "긴 무작위 비밀값" > webhook.secret && chmod 600 webhook.secret
HOSTLINT_WEBHOOK_URL=https://hooks.example.com/services/XXX \
  hostlint server run --webhook-secret-file webhook.secret --stale-after 72h
```

- `regression`: 호스트의 이전 스캔에서는 아니었던 통제 항목이 FAIL 또는 ERROR가 된 결과. 통제 항목(프로파일, ID, 제목,
  심각도, 이전·현재 상태)을 최대 20개까지 담습니다.
- `stale`: `--stale-after`(기본 7일) 동안 보고하지 않은 호스트. 마지막 스캔마다 한 번만 보냅니다.

본문은 JSON이며, Slack·Mattermost·Discord의 Slack 호환 엔드포인트가 그대로 보여 주는 `text` 줄이 들어 있습니다.
통제 항목 ID와 상태만 담고 증거는 담지 않습니다. `--webhook-secret-file`을 주면 본문에 서명합니다:
`X-Hostlint-Signature-256: sha256=<본문의 HMAC-SHA256 16진수>`. URL은 https여야 하고(http는 루프백 주소만),
`--webhook-url` 또는 `HOSTLINT_WEBHOOK_URL`로 줍니다(웹훅 URL은 비밀이므로 환경 변수를 권장하며, 로그에는 남기지
않습니다). 리다이렉트는 따라가지 않습니다.

전달은 최소 한 번입니다. 웹훅이 2xx로 응답할 때까지 30초마다 다시 보내며, 웹훅을 켜기 전에 있었던 일(이미 조용한
호스트 포함)은 보내지 않습니다. 4xx 응답(408·429 제외)은 그 이벤트를 영구히 거부한다는 뜻이므로 로그에 남기고
버려서, 뒤의 이벤트를 막지 않습니다. 모든 이벤트에는 `id`가 있고 `X-Hostlint-Delivery`로도 보내며, 같은 이벤트는
몇 번을 보내도 같습니다. 반복을 걸러 내는 데 쓰세요. 호스트의 이전 스캔에 없던 통제 항목(새 규칙이나 프로파일)은
악화로 보고하지 않습니다.

## 호스트

```sh
hostlint server host list   --db server.db
hostlint server host delete --db server.db 4 --yes
```

이미 알려진 호스트 이름에는 두 번째 호스트 ID가 붙지 않습니다. 다시 설치한 머신(호스트 ID가 바뀜)은 거부되고
응답이 그렇게 알려 줍니다. 이전 호스트와 그 호스트에서 받은 모든 결과를 삭제하면(먼저 백업하세요) 같은
이름으로 다시 시작할 수 있습니다. 삭제는 감사 기록에 남습니다.

## 토큰

```sh
hostlint server token list   --db server.db
hostlint server token revoke --db server.db 3
hostlint server token create --db server.db --name ci --any-host --expires-in 2160h
hostlint server token create --db server.db --name ops --scope operator --any-host   # 읽기, 그리고 에이전트에 스캔 요청
```
