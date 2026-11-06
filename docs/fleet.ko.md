<!-- translated from docs/fleet.md @ 15dc612 -->
# 플릿 서버 (초기)

> [ADR 0010](adr/0010-fleet-server-and-dashboard.md)의 1단계입니다. 서버는 결과를 받아 저장합니다.
> 대시보드와 조회 API는 다음 단계입니다. 인터페이스는 아직 안정적이지 않습니다.

호스트가 스스로 스캔하고 결과를 서버로 **보냅니다(push)**. 서버는 호스트에 접속하지 않습니다.
호스트가 스캔하게 만들거나, 무언가를 실행하거나, 읽을 수 없습니다.

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

각 호스트에서:

```sh
sudo hostlint scan --format json --output result.json
HOSTLINT_TOKEN=hlt_ing_... hostlint push result.json \
  --server https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

토큰은 `HOSTLINT_TOKEN`이나 `--token-file`로 전달하며 명령줄에는 쓰지 않습니다. 공인 CA 인증서를
쓰면 `--pin`을 생략합니다. 두 단계를 cron이나 systemd 타이머로 돌리세요. 서버가 이미 가진 결과를 다시
보내는 것은 오류가 아닙니다.

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
