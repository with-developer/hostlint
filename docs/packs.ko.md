<!-- translated from docs/packs.md @ 8f8f335 -->
# 정책 팩: 직접 만드는 점검과 프로파일

정책 팩은 직접 만든 점검과 프로파일을 담은 디렉터리로, hostlint에 내장된 콘텐츠와 같은 형식을 씁니다. hostlint를
포크하지 않고도 팀의 기준(사내 보안 기준, 고객사의 요구 사항, `/etc`에서 하나 더 확인하고 싶은 것)을 점검할 수
있습니다. 배경이 된 결정은 [ADR 0012](adr/0012-policy-packs.md)에 있습니다.

[English](packs.md)

```sh
hostlint pack test ./acme-pack                 # 팩을 불러와서 점검의 테스트를 실행합니다
hostlint pack show ./acme-pack                 # 검토하는 사람을 위해 팩이 하는 일을 보여 줍니다
hostlint scan --pack ./acme-pack -p x-acme-baseline
hostlint scan --pack ./acme-pack -p kisa-2026 -p x-acme-baseline   # 둘을 한 번에 점검합니다
```

## 팩이 할 수 있는 것과 없는 것

팩은 **새로운 능력을 더하지 않습니다.** 팩의 점검은 내장 점검과 같은 선언형 YAML과 같은 CEL 표현식으로 쓰고,
hostlint에 컴파일되어 있는 수집기가 만든 사실을 대상으로 평가합니다. 수집기, 사실, 명령, 함수를 새로 추가할 수
없으므로 팩은 아무것도 실행할 수 없고, 내장 점검이 읽을 수 없는 것은 팩도 읽을 수 없습니다. 민감 경로 거부 목록이
팩에도 그대로 적용됩니다.

팩은 `hostlint.yaml`처럼 **신뢰하고 쓰는 입력이며, 악의적인 작성자를 막아 주는 샌드박스가 아닙니다.** 팩은 무엇을
근거로 보여 줄지(파일 점검이 나열하는 이름·소유자·권한, 표현식이 출력하는 사실), 어떤 수집기를 돌릴지, 그리고
프로파일을 통해 어떤 점검을 얼마나 높은 심각도로 셀지를 정합니다. 그러니 직접 만들지 않은 팩은 쓰기 전에
`hostlint pack show`로 읽어 보고, 믿을 수 있는 사람의 팩만 쓰세요.

hostlint는 팩이 결과를 실제보다 좋아 보이게 만들 수 없도록 내장 콘텐츠보다 더 엄격한 규칙을 적용합니다.

- 모든 점검의 영역 이름은 `x-`로 시작하고(`x-acme.motd-owned-by-root`), 모든 프로파일의 ID도 `x-`로
  시작합니다(`x-acme-baseline`). 그래서 결과에 적힌 점검 이름만 봐도 팩의 점검인지 내장 점검인지 알 수 있고,
  내장 콘텐츠나 다른 팩과 이름이 겹치지 않습니다.
- 프로파일은 다른 프로파일의 제목을 쓸 수 없습니다.
- 프로파일이 점검에 지정하는 매개변수는 점검의 기본값과 같거나 더 엄격해야 합니다. 더 느슨한 설정을 허용하고
  싶다면 직접 점검을 작성하세요. 그 밖의 종류의 매개변수는 기본값을 그대로 두어야 합니다.
- 컨트롤의 심각도는 매핑한 점검 중 가장 높은 심각도로 올라갑니다. `--fail-on`이 컨트롤의 심각도를 기준으로
  판정하기 때문이며, 점검할 때 그렇게 올렸다고 알려 줍니다.
- 파일 점검에는 경로를 최대 10개까지 쓸 수 있고, 경로 하나당 와일드카드는 최대 2개입니다. `/proc`, `/sys`, `/dev`
  아래는 쓸 수 없습니다.
- 점검의 `remediation`에는 제어 문자를 쓸 수 없고 줄바꿈과 탭만 쓸 수 있습니다. 실패한 점검의 `remediation`은
  JSON 결과, SARIF 도움말, HTML 보고서, 대시보드, `hostlint explain`에 그대로 나타나므로 글자 외의 것은 허용하지
  않습니다.
- 모든 점검에는 내장 점검과 마찬가지로(ADR 0006) PASS 테스트, FAIL 테스트, 입력이 없거나 읽을 수 없거나 불완전한
  경우의 테스트가 있어야 합니다.

## 디렉터리 구성

```text
acme-pack/
  pack.yaml
  rules/x-acme/motd-owned-by-root.yaml     # 점검 하나. rules/<영역>/<이름>.yaml이며 ID는 x-acme.motd-owned-by-root
  profiles/x-acme-baseline.yaml            # 프로파일 하나. profiles/<id>.yaml
```

`pack.yaml`:

```yaml
format: 1                  # 팩 형식의 버전
name: acme                 # 소문자와 하이픈. 결과가 팩을 이 이름으로 부릅니다
version: 1.2.0             # 영문자, 숫자, . _ + -
description: Acme's baseline            # 선택
requires_hostlint: v0.15.0              # 선택: 팩이 동작하는 가장 오래된 릴리스
```

점검과 프로파일은 [CONTRIBUTING](../CONTRIBUTING.md#how-a-check-is-built)과 [규칙 참조](rules.md)에 설명한 대로
작성합니다. [`examples/policy-pack`](../examples/policy-pack)은 실제로 동작하는 작은 팩입니다. 점검이 읽을 수 있는
사실은 `hostlint pack facts`로 나열할 수 있고 [사실 참조](facts.md)에 설명이 있습니다. 프로파일은 내장 점검과 직접
만든 점검을 함께 매핑할 수 있습니다.

```yaml
id: x-acme-baseline
revision: 1
title: Acme baseline
controls:
  - id: ACME-01
    title: Root does not log in over SSH
    severity: high
    checks: [ssh.permit-root-login, ssh.match-permit-root-login]
  - id: ACME-02
    title: Passwords are long and expire within 60 days
    severity: high
    checks: [accounts.password-min-length, accounts.password-max-age]
    params:
      accounts.password-max-age: {max_days: 60}
  - id: ACME-03
    title: The login banner belongs to root
    severity: low
    checks: [x-acme.motd-owned-by-root]
```

프로파일을 고칠 때는 `revision`을 올리세요.

## 팩 사용하기

`hostlint scan --pack DIR`은 팩을 내장 콘텐츠와 함께 불러옵니다. 여러 번 쓸 수 있고, `HOSTLINT_PACK`에
`PATH`처럼 구분한 디렉터리 목록을 줄 수도 있습니다. `--profile`로 팩의 프로파일을 고르며, 여러 번 써서 프로파일
여러 개를 한 번에 점검할 수 있습니다(겹치는 점검은 한 번만 평가합니다). 팩을 불러왔는데 그 팩의 프로파일을 하나도
고르지 않았다면, 팩을 조용히 무시하고 점검하는 대신 오류를 냅니다. 팩은 hostlint를 실행하는 머신에서 읽으며,
`--root`나 `--image-tar`를 거쳐 읽는 일은 없고, 현재 디렉터리에서 알아서 찾아 쓰는 일도 없습니다.

결과에는 어느 팩에서 나왔는지가 `scan.packs`에 이름, 버전, 다이제스트로 기록됩니다. 다이제스트는 읽은 파일의
경로와 내용을 정렬해서 구한 SHA-256입니다. `hostlint diff`와 `hostlint report`는 서로 다른 팩으로 점검한 결과를
비교하거나, 프로파일 리비전은 같은데 내용이 다른 결과를 비교하면 경고합니다.

`hostlint.yaml`에서도 팩의 점검과 컨트롤을 지정할 수 있습니다(매개변수, 예외). 팩 프로파일의 컨트롤에 예외를
두려면 프로파일의 다이제스트(`digest:`)를 적어야 합니다. 이 값은 다이제스트를 요구하는 오류 메시지, 결과,
`pack show`에서 볼 수 있습니다. 다이제스트에는 컨트롤이 매핑하는 점검 목록과, 매핑된 팩 자체 점검의 동작이 모두
반영됩니다. 팩 작성자가 리비전을 올리지 않고도 둘 다 바꿀 수 있기 때문입니다.

`--verify-pack`을 주면 점검하기 전에 팩에 든 점검의 테스트를 실행하고, 테스트에 실패하는 팩으로는 점검하지 않습니다.
테스트는 실수를 잡아낼 뿐 악의까지 잡아내지는 못합니다(로직과 테스트를 같은 사람이 쓰기 때문입니다). 또 호스트마다
실행하면 시간이 들므로, 테스트는 팩 자체의 CI에서 `hostlint pack test`로 돌리세요.

팩으로 점검한 결과도 `--push`로 보낼 수 있습니다. 결과에 팩의 이름·버전·다이제스트가 담기고, 서버는 다른 결과와
똑같이 받은 그대로 보관합니다([docs/fleet.ko.md](fleet.ko.md)). 팩의 프로파일은 대시보드에서 고를 수 있고, 호스트
페이지에 팩이 표시됩니다. 서버는 팩의 내용을 알지 못하므로 컨트롤 페이지에는 결과에 담긴 것(제목, 심각도, 상태)만
보이고 "무엇을 점검하나" 설명은 나오지 않습니다. 어떤 팩을 쓸지는 프로파일과 예외처럼 호스트가 정합니다.

## 팩을 읽는 방식

팩은 쓰기 권한이 있는 사람이면 누구나 바꿀 수 있는 디렉터리에서 읽어 오므로 조심스럽게 읽습니다.

- 벗어날 수 없는 루트를 기준으로 읽습니다. 심볼릭 링크는 따라가지 않습니다.
- 모든 디렉터리와 파일은 root 또는 본인 소유여야 하고 그룹이나 다른 사용자가 쓸 수 없어야 합니다
  (`chmod -R go-w`).
- `pack.yaml`, `rules/<영역>/<이름>.yaml`, `profiles/<id>.yaml` 외의 파일이 있으면 건너뛰지 않고 오류를 냅니다.
- 크기는 전체 4 MiB, 파일당 256 KiB까지이고, 점검은 300개, 프로파일은 50개, 디렉터리당 항목은 200개까지
  허용합니다.
- 파일은 한 번만 열며, 해시하는 내용이 곧 파싱하는 내용입니다.

그래서 다른 사용자 소유의 파일에 `sudo hostlint scan --pack ./pack`을 실행하거나, 다른 사용자의 CI 작업 공간을
root 컨테이너로 점검하거나, Kubernetes ConfigMap(링크 묶음)을 팩으로 쓰면 거부됩니다. 팩을 본인 소유의 위치로
복사해서 쓰세요.

## 형식은 아직 고정되지 않았습니다

v1.0 전에는 점검의 형식과 점검이 읽는 사실이 마이너 릴리스에서 바뀔 수 있고, 팩을 고쳐야 할 때는 릴리스 노트에
알립니다. `requires_hostlint`를 지정해 두면 너무 오래된 hostlint에서는 팩이 실행되지 않습니다.
