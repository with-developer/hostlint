<!-- translated from docs/fleet.md @ 267c061 -->
# 서버로 모아 보기

> 설계는 [ADR 0010](adr/0010-fleet-server-and-dashboard.md)에 있습니다. 호스트가 결과를 보내고, 서버가 저장해 두었다가 조회
> 요청에 답하며 대시보드도 제공합니다. v1.0 전에는 API와 데이터베이스 스키마가 마이너 릴리스에서 바뀔 수 있고, 바뀌면
> 릴리스 노트에 적습니다.

호스트가 스스로 스캔하고 결과를 서버로 **보냅니다(push)**. 서버가 호스트에 접속하는 일은 없습니다. 서버는
호스트가 스캔하게 만들 수도, 호스트에서 무언가를 실행하거나 읽을 수도 없습니다.

## 대시보드

대시보드를 넣어 빌드한 바이너리라면 `vmsctl server run`이 듣는 주소에서 웹 대시보드가 열립니다. 릴리스
바이너리에는 대시보드가 들어 있고, 소스에서 빌드할 때는 `make build-web`(Node 22)을 씁니다. `go install`로
설치한 바이너리에는 API만 있고, `/`에 접속하면 그렇게 안내합니다. 조회 토큰(`vmsctl server token create
--scope api`)으로 로그인하면 다음을 볼 수 있습니다.

- **전체 현황**: 통과율, 7·30·90일간의 통과율 추이, 실패한 점검 항목이 있는 호스트, 보고를 멈춘 호스트, 가장 많이
  실패하는 점검 항목, 최근에 나빠진 항목
- **호스트 목록**: 검색, 필터, 정렬, CSV 내보내기. 호스트·점검 항목·이미지 목록은 필터가 주소에 들어가므로 걸러 놓은 목록을
  링크로 공유할 수 있고, 항목을 열었다가 브라우저의 뒤로 가기나 상세 페이지의 "← 호스트"·"← 점검 항목"·"← 이미지" 링크로 돌아가도
  같은 목록이 나옵니다. 호스트마다 운영체제, 레이블, 최근 스캔의 추이선, 에이전트
  연결 여부가 함께 나옵니다.
- **점검 항목 목록**: 점검 항목마다 무엇을 점검하는지, 왜 중요한지, 어떻게 고치는지, 실패한 호스트가 어디인지
- **매트릭스**: 모든 호스트의 모든 점검 항목을 한 표로
- **호스트 상세**: 점검 항목별 점검 근거, 스캔 이력, 어떤 스캔이든 직전 스캔과의 비교

한국어와 영어로 볼 수 있고 시스템의 라이트/다크 테마를 따릅니다. 호스트가 보낸 내용은 모두 텍스트로만
표시합니다.

## 호스트 없이 둘러보기

```sh
vmsctl server demo
```

이 명령은 `127.0.0.1:8443`에 가상의 서버 12대(2주치 스캔, 실제 점검 항목으로 만든 결과)를 담은 서버를 띄우고, 로그인에
쓸 조회 토큰을 출력합니다. 데이터는 메모리에만 있어서 명령을 끝내면 사라집니다. 대시보드가 들어 있는
바이너리(릴리스 바이너리 또는 `make build-web`)가 필요합니다.

## 빠른 시작

서버 머신에서:

```sh
# 호스트마다 토큰 하나. 한 번만 보여 주고 해시만 저장합니다.
vmsctl server token create --db /var/lib/vmsctl/server.db --name web-01 --host web-01

vmsctl server run --db /var/lib/vmsctl/server.db --listen :8443
# listening on https://[::]:8443
# certificate pin: sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

`--tls-cert`와 `--tls-key`를 주지 않으면 서버가 데이터베이스 옆에 자체 서명 인증서를 만들고 공개 키의 핀을
출력합니다. 평문 HTTP는 루프백 주소에서만 쓸 수 있습니다. 앞에 TLS 프록시가 있다면
`--plain-http --behind-proxy`로 쓸 수 있습니다.

각 호스트에서는 스캔과 전송을 한 번에 실행합니다.

```sh
sudo VMSCTL_TOKEN=hlt_ing_... vmsctl scan \
  --push https://vmsctl.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

스캔이 먼저 돌고 평소처럼 보고서가 출력되며(`--format`, `--output`, `--fail-on`도 그대로 동작합니다), 그다음에
결과를 보냅니다. 결과를 보내지 못하면 오류(종료 코드 2)입니다. 토큰이 없으면 스캔을 시작하기 전에 알려 줍니다.
앞서 저장해 둔 결과를 보내려면 이렇게 합니다.

```sh
VMSCTL_TOKEN=hlt_ing_... vmsctl push result.json \
  --server https://vmsctl.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

토큰은 `VMSCTL_TOKEN`이나 `--token-file`로 넘기고, 명령줄에는 쓰지 않습니다. 공인 CA가 발급한 인증서를 쓴다면
`--pin`은 생략합니다. 이 두 단계를 cron이나 systemd 타이머로 주기적으로 실행하세요. 서버가 이미 가지고 있는
결과를 다시 보내도 오류가 아닙니다.

## 예약 스캔

서버가 스캔을 시작하는 일은 없습니다. 호스트가 일정에 따라 스스로 스캔하고 결과를 보냅니다. systemd 타이머로
설정하려면 `/etc/systemd/system/vmsctl-scan.service`와 `.timer`를 만듭니다.

```ini
# vmsctl-scan.service
[Unit]
Description=vmsctl scan, sent to the fleet server
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vmsctl scan --fail-on none --format json --output /dev/null \
  --push https://vmsctl.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U= \
  --token-file /etc/vmsctl/token --sign-key /etc/vmsctl/signing-key
NoNewPrivileges=yes
PrivateTmp=yes
```

```ini
# vmsctl-scan.timer
[Unit]
Description=Daily vmsctl scan

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo install -m 600 /dev/null /etc/vmsctl/token      # 그런 다음 토큰을 넣습니다
sudo vmsctl key generate /etc/vmsctl/signing-key   # 공개 키를 출력합니다. `server token create --key`로 토큰에 묶으세요
sudo systemctl enable --now vmsctl-scan.timer
```

`RandomizedDelaySec`는 여러 호스트의 실행 시각을 두 시간 안에 흩어 놓습니다(서버는 토큰 하나가 결과를 보내는
속도를 제한합니다). `Persistent`는 호스트가 꺼져 있어서 놓친 스캔을 켜지는 대로 실행합니다. `--fail-on none`은
실패한 점검 항목 때문에 유닛이 실패 상태로 표시되지 않게 합니다. 유닛이 실패했다면 스캔이나 전송 자체가 동작하지
않았다는 뜻이므로 알림을 걸어 둘 만합니다. 출력은 `journalctl -u vmsctl-scan`에서 볼 수 있습니다. cron을
쓴다면 같은 명령을 `/etc/cron.d/vmsctl`에 적으세요(`17 3 * * * root ...`). 서버의 `--stale-after` 웹훅을 켜면
보고를 멈춘 호스트를 알려 줍니다.

## 대시보드에서 바로 스캔하기: 에이전트

타이머는 정해진 시각에 스캔합니다. 대시보드에서 호스트를 *지금* 스캔하고 싶다면 그 호스트에서 `vmsctl agent`를
서비스로 실행하세요. 에이전트는 바깥으로만 연결합니다(서버가 호스트에 접속하지는 않습니다). HTTPS 요청 하나를
열어 둔 채(롱 폴링) 기다리다가, 누군가 **지금 스캔**을 누르면 서버가 그 요청에 답을 보냅니다.

```sh
sudo vmsctl server token create --name web-01 --host web-01 --key <공개키>   # --push와 같은, 호스트의 수집 토큰 (--key: `key generate`가 출력한 공개키)
sudo vmsctl agent --server https://vmsctl.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U= \
  --token-file /etc/vmsctl/token --sign-key /etc/vmsctl/signing-key --allow-profile kisa-2026
```

```ini
# /etc/systemd/system/vmsctl-agent.service
[Unit]
Description=vmsctl agent (scan when the fleet server asks)
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/vmsctl agent --server https://vmsctl.example.org:8443 --pin sha256/... \
  --token-file /etc/vmsctl/token --sign-key /etc/vmsctl/signing-key --allow-profile kisa-2026
Restart=always
RestartSec=10
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

서버가 에이전트에게 시킬 수 있는 일은 하나뿐입니다. **그 호스트 자신의** `--allow-profile` 목록에 적힌
프로파일(내장 프로파일 1~8개)로 스캔하는 것이고, 그것도 1분에 한 번까지입니다. 예외 처리, 매개변수, 경로,
명령은 보낼 수 없습니다. `vmsctl.yaml`은 어디까지나 호스트에 있는 파일이고, 결과는 `vmsctl scan --push`와
같은 방식(같은 토큰, 같은 `--pin`, 같은 서명)으로 돌아갑니다. 에이전트는 허용하지 않은 프로파일의 요청이나
마지막 스캔 후 45초 안에 온 요청을 거절하고, 거절한 이유를 서버에 알립니다. 서버가 침해당하더라도 호스트가 위
한도 안에서 더 자주 스캔하게 만들 수 있을 뿐, 그 밖의 일은 할 수 없습니다. 에이전트는 `--pack`을 받지
않습니다. 정책 팩으로 만든 결과는 서버가 아직 받지 않기 때문입니다.

호스트가 결과를 한 번은 보낸 적이 있어야 하고(`vmsctl scan --push`), 토큰은 그 호스트에 묶여 있어야 합니다
(`--host`). 에이전트는 새로운 종류의 신원이 아니라 호스트의 토큰을 그대로 씁니다. 예약 스캔은 에이전트와 함께
계속 동작합니다.

**누가 요청할 수 있나요?** 버튼을 쓰려면 **operator** 토큰(`vmsctl server token create --scope operator
--any-host --name ops`)이나, 그 토큰으로 시작한 대시보드 세션이 필요합니다. operator는 `api` 토큰처럼 읽을 수
있고, 스캔도 요청할 수 있습니다. `api` 토큰으로 시작한 세션에서는 호스트의 에이전트가 연결됐는지는 보이지만
버튼은 나타나지 않습니다.

요청은 JSON `POST /api/v1/hosts/{id}/scan`이고 본문은 `{"profile": "kisa-2026"}`입니다. 브라우저 세션에서는
`Origin`이 서버 자신의 사이트일 때만 받아들이므로 다른 사이트의 페이지가 대신 요청할 수 없습니다(세션 쿠키도
`SameSite=Strict`입니다). 리버스 프록시 뒤에서는 `Host` 헤더를 바꾸지 말고 그대로 넘기세요. 응답은 다음과
같습니다.

- `202`: 작업을 만들었습니다.
- `409`: 최근 2분 안에 그 호스트의 에이전트가 폴링하지 않았거나, 에이전트가 그 프로파일을 허용하지 않습니다.
- `429`: 그 호스트의 스캔을 1분 안에 이미 요청했거나 아직 처리 중입니다.

모든 요청은 감사 기록에 남습니다(`scan-requested`, 요청한 토큰과 주소 포함). 대시보드는 에이전트가 연결된
호스트에만 버튼을 보여 주고, 요청이 대기 중인지, 스캔 중인지, 결과가 도착했는지, 실패했는지를 따라갑니다. 아무도
응답하지 않은 요청은 10분 뒤에 만료됩니다. `GET /api/v1/hosts/{id}/agent`로도 같은 상태를 볼 수 있습니다.

## 정책 팩의 결과

[정책 팩](packs.ko.md)으로 점검한 결과도 다른 결과와 똑같이 보냅니다(`vmsctl scan --pack DIR -p x-acme-baseline
--push ...`). 서버는 결과를 받은 그대로 보관합니다. 팩의 프로파일은 대시보드의 프로파일 선택기에 나타나고,
호스트 페이지에는 팩의 이름·버전·다이제스트가 표시됩니다. 서버는 팩 자체를 읽지 않으므로 팩에 들어 있는
점검 항목에는 "무엇을 점검하나" 설명이 나오지 않습니다.

결과 하나에 이름을 밝힐 수 있는 팩은 최대 8개이고, 각 팩에는 이름, 버전, sha256 다이제스트가 있어야 합니다.
팩의 프로파일(`x-`로 시작하는 ID)로 점검한 결과는 반드시 그 팩을 밝혀야 합니다. 호스트마다 팩의 개정이 달라도
페이지에서는 한 프로파일의 결과로 묶어서 셉니다. 스캔마다의 다이제스트는 저장된 문서에서만 구분되고 페이지에서는
구분되지 않습니다.

## 컨테이너 이미지

이미지 아카이브를 점검해서(`vmsctl scan --image-tar app.tar --push ...`, [docs/images.ko.md](images.ko.md))
보내면 호스트가 아니라 **이미지**로 저장됩니다. 이미지는 저장소 이름으로 구분하는 자산이고 호스트 ID가 없으며,
스캔마다 태그와 이미지 ID가 기록됩니다.

- 대시보드는 이미지를 호스트와 따로 보여 줍니다. 이미지가 하나라도 생기면 **이미지** 메뉴가 나타납니다.
- 개요, 추이, 매트릭스, 점검 항목, 오래 보고하지 않은 호스트, 보고 중단 알림 같은 전체 현황의 숫자는 호스트만
  셉니다.
- `GET /api/v1/hosts?kind=image`는 이미지를 나열합니다. 모든 호스트 항목에는 `kind`가 있고, 이미지의 스캔
  행에는 `imageRef`와 `imageDigest`가 있습니다.
- CI용 토큰은 접두어에 묶습니다(`server token create --host 'ghcr.io/acme/*'`). 접두어는 소유자 이름 뒤에
  `/*`로 끝나야 합니다. `ghcr.io/acme*`는 `ghcr.io/acme-evil`까지 받아들이게 되므로 거부합니다. 접두어 토큰은
  수집 토큰만 쓸 수 있고 이미지용입니다. 접두어 아래의 호스트 결과는 거부하며, 에이전트는 호스트 하나를
  대표합니다.
- 이미지는 최근에 스캔한 순서로 나열합니다(`?sort=recent`).
- 같은 이름이 호스트이면서 이미지일 수는 없습니다.

## 회사 계정으로 로그인시키기

대시보드는 조회 토큰으로 로그인합니다. 회사에서 이미 쓰는 로그인(Google, Entra ID, Okta, Keycloak 등 OIDC나
SAML)으로 사람들이 들어오게 하려면, 로그인을 처리하는 리버스 프록시를 서버 앞에 두고 프록시가 자신의 조회
토큰을 붙여 요청을 넘기게 하세요. vmsctl에는 이를 위한 로그인 코드를 일부러 넣지 않았습니다. 로그인은 웹
애플리케이션에서 가장 많이 공격받는 부분이기 때문입니다([ADR 0015](adr/0015-dashboard-sign-in.md)).

서버는 프록시 뒤의 루프백 주소에서 듣게 합니다.

```sh
vmsctl server run --db /var/lib/vmsctl/server.db --listen 127.0.0.1:8443 --plain-http --behind-proxy
vmsctl server token create --db /var/lib/vmsctl/server.db --scope api --name dashboard-proxy
```

nginx와 [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)를 쓰는 설정의 뼈대입니다.
`/etc/nginx/vmsctl-token.conf`에는 `proxy_set_header Authorization "Bearer hlt_api_...";`를 넣고, root만 읽을
수 있게 하세요. 이 값은 브라우저에 노출되지 않습니다.

```nginx
server {
    listen 443 ssl;
    server_name vmsctl.example.org;
    # ssl_certificate ...

    # 호스트는 자신의 수집 토큰으로 결과를 보내므로, 이 경로 하나만 로그인 없이 통과시킵니다.
    location = /api/v1/results {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:8443;
    }
    location /oauth2/ {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
    }
    location = /oauth2/auth {
        internal;
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Content-Length "";
        proxy_pass_request_body off;
    }
    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;
        include /etc/nginx/vmsctl-token.conf;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:8443;
    }
}
```

직접 시험해 본 것은 서버 쪽입니다. 모든 요청에 조회 토큰이 붙으면 대시보드의 로그인 폼 없이도 동작하고, 수집
경로는 여전히 토큰으로 보호됩니다. 프록시 설정은 일반적인 설정을 옮긴 뼈대일 뿐이니 쓰시는 프록시의 문서와
대조해 보세요. 알아 둘 점은 다음과 같습니다.

- 서버 주소에 직접 닿을 수 있는 사람(같은 머신의 다른 사용자 등)은 로그인을 건너뜁니다. 서버는 루프백 주소나
  프록시만 닿을 수 있는 호스트에 두고, 그 옆에서 다른 프로세스가 듣지 않게 하세요.
- 서버의 감사 기록에는 사람이 아니라 프록시의 토큰이 남습니다. 누가 접속했는지는 프록시의 접근 로그에 있습니다.
- 프록시를 통과한 사람은 모든 것을 읽을 수 있습니다. 로그인할 수 있는 사람은 프록시에서 제한하세요(그룹,
  도메인 등).
- 프록시의 토큰도 다른 토큰처럼 교체하세요. `server token create`로 새로 만들고, 파일을 바꾸고,
  `server token revoke`로 이전 것을 폐기합니다.

## 결과 읽기

호스트마다 스캔에 쓴 프로파일이 다를 수 있습니다(`--profile`, `essentials`, 정책 팩). 그래서 대시보드의 모든
숫자는 **프로파일 하나**를 기준으로 합니다. 개요, 호스트 목록, 매트릭스, 점검 항목 목록은 `?profile=ID`를 받고,
주지 않으면 가장 많은 호스트가 쓴 프로파일을 씁니다. **v0.19 이전에는 `profile` 없이 부르면 모든 프로파일을
합쳐서 답했습니다. 그렇게 읽던 스크립트는 이제 프로파일 하나의 값을 받으므로, 예전처럼 전체를 합치려면
`?profile=all`을 붙이세요.**

최신 스캔에 그 프로파일의 점검 항목이 하나도 없는 호스트는 숫자에 넣지 않습니다(보고를 멈춘 호스트는 어떤
프로파일로 스캔했든 오래된 호스트로 셉니다). 대시보드는 이런 호스트가 몇 대인지 알려 주고 목록에 표시합니다.
프로파일이 둘 이상이면 사이드바의 선택기로 프로파일을 고르고, 고른 값은 기억합니다.

조회 토큰(`--scope api`)이 있으면 스크립트나 CI에서도 서버가 아는 것을 물어볼 수 있습니다.

```sh
vmsctl server token create --db server.db --name ci --scope api
curl --cacert tls.crt -H "Authorization: Bearer hlt_api_..." https://vmsctl.example.org:8443/api/v1/overview
```

| 요청 | 응답 |
|---|---|
| `GET /api/v1/profiles` | 최신 스캔에 쓰인 프로파일과 프로파일별 호스트 수, 가장 많은 호스트가 쓰는 프로파일(`default`), 각 프로파일의 제목 |
| `GET /api/v1/trend` | 최근 며칠간의 전체 모습을 하루에 한 점씩, 오래된 날부터: 호스트 수, 실패한 점검 항목이 있는 호스트 수, 그날 기준의 상태별 개수와 통과율(`?days=30`, 1~90). 저장된 스캔으로 계산하므로 `server prune`을 하면 볼 수 있는 날짜가 달라지고, 같은 답을 30초 동안 재사용합니다 |
| `GET /api/v1/overview` | 호스트 수, 실패한 점검 항목이 있는 호스트 수, 오래 보고하지 않은 호스트 수, 상태별 개수, 가장 많은 호스트에서 실패하는 점검 항목, 최근 악화(`?staleDays=7`) |
| `GET /api/v1/hosts` | 호스트 목록과 각 호스트의 최신 스캔 개수·통과율(`?q=`, `?status=failing\|stale`, `?sort=name\|score\|last`, `?limit=`, `?offset=`, `?format=csv`, 이미지를 보려면 `?kind=image`, 레이블이 있는 호스트만 보려면 `?label=env%3Dprod`. 대시보드에서는 레이블을 눌러 거릅니다). 호스트마다 `os`, `labels`(최신 결과가 알려 준 값이고 개수에 상한이 있습니다), `agentOnline`, 최근 스캔의 통과율 `trend`도 들어 있습니다 |
| `GET /api/v1/controls`, `GET /api/v1/controls/PROFILE/ID` | 점검 항목 전체와 최신 스캔의 상태별 개수. 점검 항목 하나의 경우 해당 호스트, 무엇을 점검하는지, 어떻게 고치는지 |
| `GET /api/v1/matrix` | 모든 호스트의 모든 점검 항목의 최신 상태. 가장 많이 실패한 호스트가 먼저 나옵니다 |
| `GET /api/v1/hosts/ID` | 호스트 하나의 최신 점검 항목과 이력 |
| `GET /api/v1/scans/ID` | 저장된 결과를 받은 그대로. `?format=csv`를 붙이면 `vmsctl scan --format csv`와 같은 스프레드시트용 CSV 보고서(대시보드는 호스트의 이력에서 내려받게 해 줍니다) |
| `GET /api/v1/diff?old=ID&new=ID` | 두 스캔 사이에서 바뀐 것(`vmsctl diff`와 같습니다) |

### 대시보드 세션

대시보드는 조회 토큰을 세션으로 한 번 바꿔 씁니다. `{"token": "hlt_api_..."}`를 담아 `POST /api/v1/login`(콘텐츠
타입은 `application/json`)을 보내면 `hl_session` 쿠키가 설정됩니다(`HttpOnly`, `SameSite=Strict`, TLS에서는
`Secure`). `POST /api/v1/logout`으로 세션을 끝내고, `GET /api/v1/session`으로 세션이 아직 유효한지 확인합니다.
세션은 사용하지 않은 채 8시간이 지나거나 만든 지 24시간이 지나면, 또는 토큰이 폐기되거나 만료되면 끝납니다.
토큰 하나에 세션은 최대 20개까지 둡니다. 쿠키는 `GET` 요청의 인증에만 쓰입니다. 로그인은 주소당 분당 10번으로
제한합니다. TLS 프록시 뒤(`--plain-http --behind-proxy`)에서는 서버가 `Secure` 속성을 정할 때
`X-Forwarded-Proto`를 믿고, 클라이언트 주소는 마지막 `X-Forwarded-For`를 믿습니다. 프록시가 실제로 앞에 있을
때만 켜세요.

통과율은 PASS ÷ (PASS + FAIL + ERROR + MANUAL)입니다. 판정하지 못한 결과는 통과율에 불리하게 작용하고,
NOT_APPLICABLE과 WAIVED는 비율 계산에서 빼고 옆에 따로 표시합니다. 호스트가 `staleDays` 동안 보고하지 않으면
오래된 호스트입니다.

## 서버 운영하기

systemd 서비스로 실행하려면 `/etc/systemd/system/vmsctl-server.service`를 만듭니다. 상태 디렉터리는 임시
사용자가 만들고 소유합니다.

```ini
[Unit]
Description=vmsctl server
After=network-online.target

[Service]
DynamicUser=yes
StateDirectory=vmsctl
ExecStart=/usr/local/bin/vmsctl server run --db /var/lib/vmsctl/server.db --listen :8443
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

토큰은 `sudo systemd-run --pipe --property=DynamicUser=yes --property=StateDirectory=vmsctl vmsctl server
token create --db /var/lib/vmsctl/server.db ...`로 만들거나, 명령을 root로 실행한 뒤 데이터베이스를 `chown`하세요.
서버는 다른 사용자가 읽을 수 있는 데이터베이스를 거부합니다.

컨테이너로 실행하려면 대시보드가 들어 있는 바이너리, 빈 `scratch` 이미지, uid 65532가 소유한 데이터용 볼륨을
씁니다.

```dockerfile
FROM scratch
COPY vmsctl /vmsctl
VOLUME /data
EXPOSE 8443
USER 65532:65532
ENTRYPOINT ["/vmsctl", "server", "run", "--db", "/data/vmsctl.db", "--listen", ":8443"]
```

**백업과 보존 기간.** `vmsctl server backup FILE`은 서버가 실행 중이어도 일관된 사본을 만듭니다(파일이 이미
있으면 안 되고, 만든 사용자만 읽을 수 있습니다). 복원하려면 서버를 멈추고 사본을 `--db` 경로에 두세요. 서버는
`--retention`(기본 400일, `0`이면 모두 보관)보다 오래된 스캔을 하루에 한 번 지우되, 호스트마다 최신 스캔은 항상
남깁니다. `vmsctl server prune --older-than 9600h`는 같은 정리를 한 번 실행하고, `vmsctl server stats`는
데이터베이스에 든 내용을 보여 줍니다. 업그레이드는 바이너리를 바꾸는 것으로 끝납니다. 서버가 시작할 때 스키마를
자동으로 올립니다.

## 서버가 확인하는 것

- 유효한 토큰인지. 수집 토큰은 호스트 이름 하나(`--host`)에 묶이고, 첫 결과에 담긴 호스트 ID가 고정되어 이후에
  다른 ID로 오는 결과는 거부합니다. `--any-host`는 모든 호스트를 대표할 수 있는 토큰을 만드는 옵션이며, 명시적으로
  선택해야 합니다.
- 결과의 형식이 올바른지(`vmsctl report`의 검사와 같습니다). 크기는 최대 2 MiB(`--max-result-bytes`), 점검 항목은
  500개, 점검은 5000개까지이며, 식별자는 출력 가능한 문자여야 하고 시작 시각은 서버의 시계와 가까워야 합니다.
  스캔 ID는 호스트당 한 번만 저장하고, 이미 아는 호스트 이름에 두 번째 호스트 ID를 주지 않습니다.
- 토큰 하나는 분당 60개의 결과(`--rate`)까지 보낼 수 있고, 잘못된 토큰으로 오는 요청은 주소별로 속도를 제한합니다.
- 모든 일을 감사 테이블에 기록하며, 각 행은 앞 행의 해시를 이어받습니다. `vmsctl server verify`가 이 사슬을
  다시 계산해 마지막 해시를 출력합니다. 나중에 바뀐 것을 알아채도록 이 값을 다른 곳에 따로 적어 두세요.

## 서명된 결과

호스트가 보내는 결과에 서명하게 할 수 있습니다. 그러면 나중에 결과를 저장한 서버가 침해당하더라도, 그 호스트의
키가 무엇이라고 말했는지에 대한 증거로 쓸 수 있습니다.

```sh
sudo vmsctl key generate /etc/vmsctl/sign.key      # 호스트마다 한 번. 지문을 출력합니다
sudo VMSCTL_TOKEN=hlt_ing_... vmsctl scan --push https://vmsctl.example.org:8443 \
  --sign-key /etc/vmsctl/sign.key
```

서버는 호스트가 처음 보낸 서명된 결과에서 키를 등록합니다(처음 본 키를 믿는 방식). 훔친 토큰으로 남이 먼저 자기
키를 등록하는 일을 막으려면, 토큰을 만들 때 호스트의 공개 키에 묶으세요. `vmsctl server token create --name
web-01 --host web-01 --key <공개키>`로 만들면 그 키로 서명한 결과만 받습니다.

그 뒤로 서버는 그 호스트의 결과 중 서명이 없거나 다른 키로 서명된 것을 거부합니다(토큰만 훔쳐서는 더 이상
충분하지 않습니다). 대시보드에는 그 호스트가 서명하며 키의 지문이 무엇인지 표시됩니다.

`vmsctl server verify`는 저장된 모든 스캔을 두 가지와 대조합니다. 하나는 결과를 받을 때 해시로 이어진 감사
기록에 남긴 문서의 다이제스트와 서명에 쓴 키이고, 다른 하나는 서명 자체입니다. 그래서 다음과 같은 변조를 모두
찾아냅니다.

- 데이터베이스에서 나중에 바뀐 결과
- 제거되었거나 바꿔치기된 서명
- 저장된 문서와 다르게 대시보드에 보이는 점검 항목
- 다른 호스트로 옮겨진 스캔
- 수신 기록이 없는 스캔

서명하는 호스트는 과거로 돌아갈 수 없습니다. 호스트의 최신 스캔보다 늦게 시작하지 않은 서명된 결과는
거부합니다(원본이 정리된 뒤에 가로챈 결과를 재전송하는 일을 막습니다). 이미 저장된 스캔을 다시 보내는 재시도에는
전처럼 정상 응답을 줍니다. 시계가 몇 분 빠르게 간 호스트는 실제 시간이 따라올 때까지 기다려야 합니다(서버는 최대
5분 앞선 시작 시각까지 받습니다). 더 새로운 스캔 뒤로 밀린 스캔은 더 이상 받지 않습니다.

기계를 다시 설치하는 등 키를 일부러 바꿨다면 `vmsctl server host reset-key ID --key <새 공개키>`로 등록된 키를
즉시 바꿉니다. `--key` 없이 실행하면 등록된 키를 잊고, 다음 서명된 결과가 키를 등록할 때까지는 서명 없는 결과도
받습니다. 이전 키에 묶인 토큰(`--key`)은 계속 이전 키를 요구하므로 그 호스트의 토큰을 새로 발급하세요. 다른
사용자가 읽을 수 있는 키 파일은 거부합니다.

## 지켜 주지 못하는 것

서버는 저장소일 뿐 권위 있는 기관이 아닙니다. 데이터베이스를 장악한 사람은 보이는 내용을 바꿀 수 있고, 저장된
결과와 서명과 키를 한꺼번에 바꿔치기할 수도 있습니다. 이를 알아채려면 키 지문(`vmsctl server host list`)과
감사 해시(`vmsctl server verify`)의 사본을 다른 곳에 보관하세요. 토큰을 도난당하면 그 토큰이 묶인 호스트의
결과를 위조해 보낼 수 있습니다(그 호스트가 서명하지 않는 경우). 호스트 자신의 키를 도난당했다면 그 호스트의
이름으로 무엇이든 서명할 수 있습니다.

## 알림

호스트가 나빠졌거나 보고를 멈추면 서버가 웹훅으로 이벤트를 보내게 할 수 있습니다.

```sh
echo -n "a long random secret" > webhook.secret && chmod 600 webhook.secret
VMSCTL_WEBHOOK_URL=https://hooks.example.com/services/XXX \
  vmsctl server run --webhook-secret-file webhook.secret --stale-after 72h
```

- `regression`: 직전 스캔에는 없던 FAIL이나 ERROR 점검 항목이 생긴 결과입니다. 해당 점검 항목(프로파일, ID, 제목,
  심각도, 이전 상태와 새 상태)을 최대 20개까지 담습니다.
- `stale`: `--stale-after`(기본 7일) 동안 보고하지 않은 호스트입니다. 그 호스트의 최신 스캔마다 한 번씩
  보냅니다.

본문은 JSON이고 `text` 줄이 들어 있어서 Slack, Mattermost, Discord의 Slack 호환 엔드포인트에 그대로 표시됩니다.
점검 항목 ID와 상태만 담고 근거는 절대 담지 않습니다. `--webhook-secret-file`을 주면 본문에 서명을 붙입니다.
`X-Hostlint-Signature-256: sha256=<본문의 HMAC-SHA256 16진수>` 형식입니다. URL은 https여야 하고(루프백 주소로
보낼 때만 http 허용), `--webhook-url`이나 `VMSCTL_WEBHOOK_URL`로 줍니다. 웹훅 URL은 비밀이고 로그에도 남기지
않으므로 환경 변수를 권장합니다. 리다이렉트는 따라가지 않습니다.

전달은 최소 한 번을 보장합니다. 웹훅이 2xx로 답할 때까지 30초마다 이벤트를 다시 보내고, 웹훅을 켜기 전에 있었던
일은(이미 보고를 멈춘 호스트 포함) 알리지 않습니다. 408과 429를 뺀 4xx 응답은 이 이벤트를 영구히 거절한다는
뜻이라서 로그에 남기고 버리므로, 뒤따르는 이벤트를 막지 않습니다. 모든 이벤트에는 `id`가 있고 `X-Hostlint-Delivery`
헤더로도 보내며, 같은 이벤트를 다시 보낼 때도 값이 같습니다. 중복을 걸러 내는 데 쓰세요. 호스트의 직전 스캔에
없던 점검 항목(새 규칙이나 프로파일)은 악화로 알리지 않습니다.

## 호스트 관리

```sh
vmsctl server host list   --db server.db
vmsctl server host delete --db server.db 4 --yes
```

이미 아는 호스트 이름에는 두 번째 호스트 ID를 주지 않습니다. 다시 설치해서 호스트 ID가 바뀐 머신은 거부되고,
응답에 그 이유가 적힙니다. 이전 호스트와 그 호스트에서 받은 모든 것을 삭제하면(먼저 백업하세요) 같은 이름으로
다시 시작할 수 있습니다. 삭제는 감사 기록에 남습니다.

## 토큰 관리

```sh
vmsctl server token list   --db server.db
vmsctl server token revoke --db server.db 3
vmsctl server token create --db server.db --name ci --any-host --expires-in 2160h
vmsctl server token create --db server.db --name ops --scope operator --any-host   # 조회도 하고, 에이전트에게 스캔도 요청합니다
```
