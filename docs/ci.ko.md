<!-- translated from docs/ci.md @ 2ca0d64 -->
# CI에서 vmsctl 쓰기

vmsctl은 파이프라인에서 쓰기 좋게 만들었습니다. 점검은 데몬도 네트워크 접근도 필요 없는 명령 한 줄이고, 종료
코드는 직접 고른 심각도 기준을 따르며, 결과는 표, JSON, SARIF, JUnit으로 받을 수 있습니다. 가장 쓸모 있는 관문은
배포하기 전의 컨테이너 이미지입니다([이미지 점검](images.ko.md)).

[English](ci.md)

| 종료 코드 | 의미 |
|---|---|
| 0 | `--fail-on` 이상으로 실패한 것이 없습니다 |
| 1 | `--fail-on` 이상의 점검 항목이 실패했거나 점검하지 못했습니다(`ERROR`) |
| 2 | 사용법이 잘못되었거나 점검을 실행하지 못했습니다(읽을 수 없는 아카이브, 운영체제가 없는 이미지 등) |

## GitHub Actions

이 저장소가 그대로 가져다 쓸 수 있는 액션(`action.yml`)입니다. vmsctl 릴리스를 설치하고, 아카이브를 릴리스의
서명된 체크섬과 대조한 다음 점검하며, `fail-on` 이상의 점검 항목이 실패하면 단계를 실패 처리합니다.

```yaml
jobs:
  image:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # SARIF 보고서를 올리려면 필요합니다
    steps:
      - uses: actions/checkout@v7
      - run: docker build -t app:ci .
      - uses: with-developer/vmsctl@v0.37.0
        with:
          image: app:ci
          fail-on: high
          sarif-file: vmsctl.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always() # 관문이 실패했을 때도 보고서를 올립니다
        with:
          sarif_file: vmsctl.sarif
```

실패한 점검에는 고치는 방법이 함께 붙습니다. 코드 스캐닝의 경고에서는 규칙의 도움말로, Markdown 작업 요약에서는
실패한 점검 아래의 "How to fix"로, JSON 결과에서는 `remediation`으로 볼 수 있습니다. 모두 점검에 적힌 안내 문구
그대로이며 `vmsctl explain`의 내용과 같습니다.

| 입력 | 의미 |
|---|---|
| `image` | 러너에 있는 이미지입니다. `docker save`로 저장해 점검합니다 |
| `image-tar` | 점검할 `docker save` 또는 OCI 아카이브 |
| `root` | 러너에 마운트했거나 풀어 둔 루트 파일시스템 |
| `profile` | 프로파일. 공백으로 구분해 여러 개를 줄 수 있습니다(기본값은 `kisa-2026`이고, `config`에 지정했다면 그 값) |
| `pack` | 저장소에 있는 [정책 팩](packs.ko.md)(직접 만든 점검과 프로파일이 든 디렉터리). 팩의 프로파일은 `profile`로 고릅니다 |
| `fail-on` | `low`, `medium`, `high`(기본값), `none` |
| `config` | [`vmsctl.yaml`](configuration.ko.md): 더 엄격한 기준, 사유와 만료일을 적은 예외 |
| `summary` | `true`(기본값)이면 점검이 단계를 실패시키더라도 발견 사항을 Markdown 보고서로 실행의 작업 요약에 씁니다 |
| `sarif-file` | 점검이 단계를 실패시키더라도 SARIF를 이 경로에도 씁니다 |
| `version` | 설치할 릴리스. 기본값은 액션을 고정한 릴리스(`@v0.37.0`)입니다 |

`image`, `image-tar`, `root` 중 정확히 하나만 지정하세요. 액션은 릴리스 태그에 고정해서 쓰세요. 그 태그의 vmsctl
릴리스를 설치합니다. 커밋에 고정할 때는 `version`을 함께 지정해야 하며, 지정하지 않으면 액션이 거부합니다. Linux
러너만 지원합니다. 입력값은 스크립트 본문에 끼워 넣지 않고 변수로 셸에 전달합니다.

이미지에 대한 예외는 이미지 참조를 호스트 이름으로 취급하므로 `hosts: ["app:*"]`처럼 씁니다.

## GitLab CI

```yaml
vmsctl:
  image: docker:27
  services: [docker:27-dind]
  script:
    - apk add --no-cache curl
    - docker build -t app:ci .
    - docker save app:ci -o app.tar
    - curl -fsSL https://raw.githubusercontent.com/with-developer/vmsctl/v0.37.0/install.sh | sh -s -- -v v0.37.0 -b /usr/local/bin
    - vmsctl scan --image-tar app.tar --fail-on high --format junit --output vmsctl.xml
  artifacts:
    when: always
    reports:
      junit: vmsctl.xml
```

## 그 밖의 CI

```sh
curl -fsSL https://raw.githubusercontent.com/with-developer/vmsctl/v0.37.0/install.sh | sh -s -- -v v0.37.0
docker save app:ci -o app.tar
vmsctl scan --image-tar app.tar --fail-on high --format sarif --output vmsctl.sarif
```

`install.sh`는 아카이브를 릴리스의 SHA-256과 대조하고, `cosign`이 설치되어 있으면 체크섬의 서명도 확인합니다.
스크립트를 셸로 바로 파이프하기 전에 내용을 읽어 보고, 버전을 고정하세요.

이미지의 이력을 [서버](fleet.ko.md)에 남기고 싶다면 결과도 함께 보내세요. 토큰은 CI의 시크릿에서 가져오고,
`ghcr.io/acme/*` 같은 접두어에 묶어 둡니다([docs/images.ko.md](images.ko.md)).

```sh
VMSCTL_TOKEN="$FLEET_TOKEN" vmsctl scan --image-tar app.tar --push https://vmsctl.example.org:8443 --fail-on high
```

vmsctl이 지원하는 모든 배포판에서 이미지를 점검한 결과는 그 이미지로 띄운 컨테이너의 결과와 같습니다. 그래서
빌드가 통과했다는 것은 이미지의 파일시스템이 프로파일이 요구하는 대로 설정되어 있다는 뜻일 뿐, 컨테이너가 안전하게
강화되어 있다는 뜻은 아닙니다. 컨테이너를 실행하는 사용자, 권한(capabilities), 볼륨은 런타임이 정하기 때문입니다.
