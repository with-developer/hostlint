<!-- translated from docs/fleet.md @ c70cc2b -->
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

## 결과 조회

조회 토큰(`--scope api`)으로 스크립트나 CI가 서버가 아는 것을 물어볼 수 있습니다.

```sh
hostlint server token create --db server.db --name ci --scope api
curl --cacert tls.crt -H "Authorization: Bearer hlt_api_..." https://hostlint.example.org:8443/api/v1/overview
```

| 요청 | 응답 |
|---|---|
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

## 보호하지 않는 것

서버는 저장소이지 권위가 아닙니다. 데이터베이스를 장악한 사람은 보이는 내용을 바꿀 수 있고, 훔친
토큰으로는 묶인 호스트의 결과를 보낼 수 있습니다. 서명된 결과를 계획하고 있습니다. 그 전까지 저장된
기록은 서버만큼만 신뢰할 수 있습니다.

## 토큰

```sh
hostlint server token list   --db server.db
hostlint server token revoke --db server.db 3
hostlint server token create --db server.db --name ci --any-host --expires-in 2160h
```
