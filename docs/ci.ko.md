<!-- translated from docs/ci.md @ f8d0985 -->
# CI에서 hostlint 쓰기

hostlint는 파이프라인에 맞춰 만들었습니다. 점검은 데몬도 네트워크 접근도 없는 명령 하나이고, 종료 코드는 고른
심각도를 따르며, 결과는 표, JSON, SARIF, JUnit으로 나옵니다. 가장 쓸모 있는 관문은 배포하기 전의 컨테이너
이미지입니다([이미지 점검](images.ko.md)).

[English](ci.md)

| 종료 코드 | 의미 |
|---|---|
| 0 | `--fail-on` 이상으로 실패한 것이 없음 |
| 1 | `--fail-on` 이상의 컨트롤이 실패했거나 점검할 수 없음(`ERROR`) |
| 2 | 사용법 오류, 또는 점검을 실행할 수 없음(읽을 수 없는 아카이브, 이미지에 운영체제가 없음) |

## GitHub Actions

저장소가 그대로 쓸 수 있는 액션(`action.yml`)입니다. hostlint 릴리스를 설치하고, 아카이브를 릴리스의 서명된
체크섬과 대조한 뒤 점검하고, `fail-on` 이상의 컨트롤이 실패하면 단계를 실패시킵니다.

```yaml
jobs:
  image:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # SARIF 보고서를 올리려면
    steps:
      - uses: actions/checkout@v7
      - run: docker build -t app:ci .
      - uses: with-developer/hostlint@v0.16.0
        with:
          image: app:ci
          fail-on: high
          sarif-file: hostlint.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always() # 관문이 실패했을 때도 보고서가 필요합니다
        with:
          sarif_file: hostlint.sarif
```

실패한 점검에는 조치 방법이 함께 담깁니다. 코드 스캐닝의 경고는 이를 규칙 도움말로 보여 주고, Markdown 작업 요약은 실패한 점검 아래에 "How to fix"로
나열하며, JSON 결과는 `remediation`에 담습니다. 점검 자체의 안내 문구이며 `hostlint explain`과 같습니다.

| 입력 | 의미 |
|---|---|
| `image` | 러너에 있는 이미지. `docker save`로 저장해 점검합니다 |
| `image-tar` | 점검할 `docker save` 또는 OCI 아카이브 |
| `root` | 러너에 마운트하거나 풀어 둔 루트 파일시스템 |
| `profile` | 프로파일, 또는 공백으로 구분한 여러 개(기본값 `kisa-2026`, 또는 `config`의 것) |
| `pack` | 저장소에 있는 [정책 팩](packs.ko.md)(직접 만든 점검과 프로파일 디렉터리), 팩의 프로파일은 `profile`로 선택 |
| `fail-on` | `low`, `medium`, `high`(기본값), `none` |
| `config` | [`hostlint.yaml`](configuration.ko.md): 더 엄격한 기준, 사유와 만료일이 있는 면제 |
| `summary` | `true`(기본값): 점검이 단계를 실패시켜도 발견 사항의 Markdown 보고서를 실행의 작업 요약에 씁니다 |
| `sarif-file` | 점검이 단계를 실패시켜도 SARIF를 여기에도 씁니다 |
| `version` | 설치할 릴리스. 기본값은 액션이 고정된 릴리스(`@v0.16.0`) |

`image`, `image-tar`, `root` 중 정확히 하나를 지정하세요. 액션은 릴리스 태그에 고정하세요. 그 태그의
hostlint 릴리스를 설치합니다. 커밋에 고정하면 `version`을 지정하세요(없으면 액션이 거부합니다). Linux 러너만 지원합니다. 입력은 스크립트의 일부가 아니라 변수로 셸에 전달됩니다.

이미지에 대한 면제는 이미지 참조를 호스트 이름으로 봅니다: `hosts: ["app:*"]`.

## GitLab CI

```yaml
hostlint:
  image: docker:27
  services: [docker:27-dind]
  script:
    - apk add --no-cache curl
    - docker build -t app:ci .
    - docker save app:ci -o app.tar
    - curl -fsSL https://raw.githubusercontent.com/with-developer/hostlint/main/install.sh | sh -s -- -v v0.16.0 -b /usr/local/bin
    - hostlint scan --image-tar app.tar --fail-on high --format junit --output hostlint.xml
  artifacts:
    when: always
    reports:
      junit: hostlint.xml
```

## 그 밖의 CI

```sh
curl -fsSL https://raw.githubusercontent.com/with-developer/hostlint/main/install.sh | sh -s -- -v v0.16.0
docker save app:ci -o app.tar
hostlint scan --image-tar app.tar --fail-on high --format sarif --output hostlint.sarif
```

`install.sh`는 아카이브를 릴리스의 SHA-256과 대조하고, `cosign`이 설치되어 있으면 체크섬의 서명도 확인합니다.
셸로 파이프하기 전에 스크립트를 읽어 보고, 버전을 고정하세요.

hostlint가 지원하는 모든 배포판에서 이미지의 결과는 그 이미지로 만든 컨테이너의 결과와 같습니다. 빌드가
통과했다는 것은 이미지 파일시스템이 프로파일이 요구하는 대로 설정되어 있다는 뜻이지, 컨테이너가 보안 강화되어
있다는 뜻이 아닙니다. 컨테이너를 실행하는 사용자, 권한(capabilities), 볼륨은 런타임이 정합니다.
