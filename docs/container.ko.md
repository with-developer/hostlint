<!-- translated from docs/container.md @ 27844bc -->
# hostlint를 컨테이너로 실행하기

릴리스마다 이미지 `ghcr.io/with-developer/hostlint`(linux/amd64, linux/arm64)도 게시됩니다. 정적 바이너리를 최소한의
베이스(CA 인증서만 있고 셸과 패키지 관리자는 없음, 약 40 MB) 위에 올린 것입니다. hostlint는 읽기만 하므로 호스트의
루트를 읽기 전용으로 마운트하고, `--root`가 마운트된 파일시스템을 점검하는 방식으로 점검합니다.

```sh
docker run --rm -v /:/host:ro ghcr.io/with-developer/hostlint:0.26.0 scan --root /host
docker run --rm -v /:/host:ro ghcr.io/with-developer/hostlint:0.26.0 scan --root /host --fail-on high --format json > web-01.json
```

보관하는 곳에서는 버전 태그(`:0.26.0`)를 쓰세요. `:latest`는 가장 새 릴리스를 따라가며 프리릴리스는 따르지 않습니다.

## 무엇을 점검하나

호스트의 파일(설정, 계정, 권한, 패키지)을 마운트를 통해 점검합니다. 실행 중인 시스템에만 있는 것(`/proc/sys`의 커널
매개변수, 열린 소켓, 실제 적용된 `sshd -T` 값)은 컨테이너에서 보이지 않으므로, 그런 점검은 `--root /mnt/image`와 똑같이
`ERROR`나 `NOT_APPLICABLE`로 보고되거나 파일의 기본값을 씁니다. 실행 중인 호스트를 빠짐없이 점검하려면 바이너리(`install.sh`,
`.deb`, `.rpm`)를 설치해 그 호스트에서 실행하세요.

이미지는 CI, 마운트한 디스크나 스냅샷 점검, 플릿 서버로 결과 보내기에 알맞습니다.

```sh
docker run --rm -v /:/host:ro -v /etc/hostlint:/etc/hostlint:ro ghcr.io/with-developer/hostlint:0.26.0 \
  scan --root /host --fail-on none --push https://hostlint.example.org:8443 --token-file /etc/hostlint/token
```

마운트한 루트의 점검은 컨테이너가 아니라 마운트된 시스템의 호스트 이름(`/host/etc/hostname`)으로 보고됩니다.

## 이미지 검증

이미지는 릴리스 파이프라인이 서명하고(Sigstore 키리스) 빌드 출처와 SBOM을 함께 담습니다.

```sh
cosign verify ghcr.io/with-developer/hostlint:0.26.0 \
  --certificate-identity-regexp '^https://github\.com/with-developer/hostlint/\.github/workflows/container\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/with-developer/hostlint:0.26.0 --repo with-developer/hostlint
```

안의 바이너리는 릴리스 아카이브의 것입니다(`checksums.txt`를 검증하고 각 파일을 확인한 뒤 이미지를 만듭니다). 이름
붙은 태그의 버전을 출력합니다. 이미지는 아무것도 쓰지 않으므로 `--read-only`로 실행해도 됩니다.
