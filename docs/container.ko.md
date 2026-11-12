<!-- translated from docs/container.md @ 2ca0d64 -->
# vmsctl을 컨테이너로 실행하기

릴리스마다 `ghcr.io/with-developer/vmsctl` 이미지(linux/amd64, linux/arm64)도 함께 게시합니다. 정적 바이너리를
최소한의 베이스 이미지(CA 인증서만 있고 셸과 패키지 관리자는 없으며, 크기는 약 40 MB) 위에 올린 것입니다.
vmsctl은 읽기만 하므로 호스트의 루트를 읽기 전용으로 마운트해 두고, `--root`로 마운트된 파일시스템을 점검할 때와
같은 방식으로 점검합니다.

```sh
docker run --rm -v /:/host:ro ghcr.io/with-developer/vmsctl:0.39.0 scan --root /host
docker run --rm -v /:/host:ro ghcr.io/with-developer/vmsctl:0.39.0 scan --root /host --fail-on high --format json > web-01.json
```

CI 설정처럼 오래 두고 쓰는 곳에는 버전 태그(`:0.27.0`)를 쓰세요. `:latest`는 가장 최근의 정식 릴리스를 따라가고,
프리릴리스는 따라가지 않습니다.

## 무엇을 점검하나요?

마운트한 곳을 통해 호스트의 파일(설정, 계정, 권한, 패키지)을 점검합니다. 실행 중인 시스템에만 있는 정보(`/proc/sys`의
커널 매개변수, 열려 있는 소켓, `sshd -T`로 확인하는 실제 적용값)는 컨테이너 안에서 볼 수 없습니다. 그래서 그런 점검은
`--root /mnt/image`로 점검할 때처럼 `ERROR`나 `NOT_APPLICABLE`로 보고되거나 파일에 적힌 기본값으로 판단합니다. 실제로
돌고 있는 호스트를 빠짐없이 점검하려면 그 호스트에 바이너리(`install.sh`, `.deb`, `.rpm`)를 설치해서 실행하세요.

이 이미지는 CI에서 쓰거나, 마운트한 디스크나 스냅샷을 점검하거나, 결과를 서버로 보낼 때 알맞습니다.

```sh
docker run --rm -v /:/host:ro -v /etc/vmsctl:/etc/vmsctl:ro ghcr.io/with-developer/vmsctl:0.39.0 \
  scan --root /host --fail-on none --push https://vmsctl.example.org:8443 --token-file /etc/vmsctl/token
```

마운트한 루트를 점검하면 컨테이너의 이름이 아니라 마운트된 시스템의 호스트 이름(`/host/etc/hostname`)으로 결과가
보고됩니다.

0.26.0까지의 이미지는 `ghcr.io/with-developer/hostlint`입니다. 이제 갱신되지 않고, 그 이름의 `:latest`도 0.26.0에 머뭅니다.

## 이미지 검증

이미지는 릴리스 파이프라인이 서명하고(Sigstore 키리스 방식) 빌드 출처 증명과 SBOM도 함께 담습니다.

```sh
cosign verify ghcr.io/with-developer/vmsctl:0.39.0 \
  --certificate-identity-regexp '^https://github\.com/with-developer/vmsctl/\.github/workflows/container\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/with-developer/vmsctl:0.39.0 --repo with-developer/vmsctl
```

이미지 안의 바이너리는 릴리스 아카이브에 든 바로 그 바이너리입니다. 이미지를 만들기 전에 `checksums.txt`를 먼저
검증하고 파일을 하나씩 확인합니다. 버전을 물으면 이미지 태그와 같은 버전을 출력합니다. 이미지는 아무것도 쓰지
않으므로 `--read-only`로 실행해도 됩니다.
