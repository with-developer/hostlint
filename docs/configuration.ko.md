<!-- translated from docs/configuration.md @ 2ca0d64 -->
# 설정

vmsctl은 설정 없이도 동작합니다. `vmsctl.yaml`을 두면 프로파일을 고르고, 점검 기준을 더 엄격하게 만들고,
안고 가기로 한 결과를 예외(waiver)로 처리하고, 사람만 판단할 수 있는 점검에는 사람의 판정을 증명(attestation)으로
남길 수 있습니다.

[English](configuration.md)

```yaml
# --profile을 주지 않았을 때 쓸 프로파일
profile: kisa-2026

# 프로파일보다 엄격한 기준값 (점검 ID → 매개변수 → 값)
params:
  accounts.password-max-age: {max_days: 60}
  accounts.lockout-threshold: {max_failures: 5}

waivers:
  # 점검 하나의 결과를 일부 호스트에서 받아들입니다.
  - check: files.shadow-perms
    reason: Debian's unix_chkpwd reads /etc/shadow through group shadow
    expires: 2027-06-30
    hosts: ["web-*"]
  # 프로파일의 점검 항목 하나를 받아들입니다.
  - control: U-18
    revision: 15
    reason: Accepted by the security team (SEC-142)
    expires: 2027-01-31

# MANUAL 점검에 사람이 내린 판정을 기록합니다. digest 값은 예시일 뿐이니, JSON 결과에서
# sha256:<16진수 64자리> 전체를 복사해 넣으세요.
attestations:
  - check: accounts.review-login-accounts
    status: PASS
    digest: sha256:527ee5b7d83f8…           # JSON 결과의 checks[].digest
    evidence_digest: sha256:c415c5c4f23ba…  # 같은 결과의 checks[].evidenceDigest
    by: alice
    at: 2026-11-05
    expires: 2027-02-01
    reason: Reviewed the login accounts with the team
```

## 설정 파일을 찾는 순서

1. `--config`로 지정한 파일(파일이 반드시 있어야 합니다)
2. 현재 작업 디렉터리의 `vmsctl.yaml`
3. `/etc/vmsctl/vmsctl.yaml`

처음 찾은 파일을 쓰고, 하나도 없어도 괜찮습니다. 이 파일은 vmsctl을 실행하는 머신의 것입니다. `--root`로
마운트한 파일시스템 안에서 읽지 않습니다.

예외는 결과를 가릴 수 있으므로, 다른 사람이 몰래 넣었거나 바꿨을 수 있는 파일은 거부합니다. 일반 파일이어야 하고,
소유자가 root이거나 vmsctl을 실행한 사용자여야 하며, 그룹이나 다른 사용자가 쓸 수 없어야 합니다. 그래서 내가
소유한 `vmsctl.yaml`이 있는 디렉터리에서 `sudo vmsctl scan`을 실행하면 실패합니다. 이럴 때는 소유자를 root로
바꾸세요(`sudo chown root: vmsctl.yaml`).

파일은 엄격하게 읽습니다. 모르는 키, 점검, 점검 항목, 매개변수가 있으면 오류를 내므로 오타 때문에 예외가 조용히
빠지는 일은 없습니다. 명령줄의 `--profile`은 `profile:`보다 우선합니다.

## 매개변수

일부 점검에는 기준값이 있습니다. 기준값은 [rules/](../rules/)의 점검 파일에서 `params` 아래에 선언합니다(예:
`rules/accounts/password-max-age.yaml`의 `max_days`). 프로파일이 요구하는 값을 정하고, `vmsctl.yaml`의
`params:`로 정수 매개변수를 바꿀 수 있습니다. 단, 더 엄격한 쪽으로만 바꿀 수 있습니다(점검에 `stricter: lower`
또는 `higher`로 적혀 있습니다). 더 느슨한 값은 예외를 쓰라는 안내와 함께 오류가 되므로, `PASS`는 언제나 최소한
프로파일의 기준을 만족했다는 뜻입니다.

매개변수를 바꿔서 평가한 결과는 JSON 결과에 `customized`로 표시됩니다.

## 예외(waiver)

예외는 이유를 남기고 만료일까지 결과를 받아들이는 것입니다. 점검은 그대로 실행됩니다. 결과는 이유와 함께 `WAIVED`로
표시되고, 원래의 상태와 근거도 그대로 남습니다.

| 키 | 의미 |
|---|---|
| `check` 또는 `control` | 둘 중 하나만 씁니다. 점검 ID, 또는 점검 중인 프로파일의 점검 항목 ID |
| `reason` | 필수. 결과를 받아들이는 이유 |
| `expires` | 필수. 예외가 적용되는 마지막 날(`YYYY-MM-DD`, UTC) |
| `revision` | 점검 항목 예외에서만 필수. 예외를 작성할 때의 프로파일 리비전 |
| `profile` | 점검 항목 예외에서만 씁니다. 점검 항목이 속한 프로파일이며, 점검 중인 여러 프로파일(`-p` 반복)에 같은 ID의 점검 항목이 있으면 필수입니다 |
| `digest` | [정책 팩](packs.ko.md)의 프로파일에 속한 점검 항목 예외에서만 필수. 예외를 작성할 때의 프로파일 다이제스트입니다(팩 작성자는 리비전을 올리지 않고도 점검 항목이 매핑하는 점검을 바꿀 수 있습니다). 값은 검증 오류와 결과에 나옵니다 |
| `hosts` | `web-*` 같은 호스트 이름 패턴. 생략하면 모든 호스트에 적용합니다 |
| `errors` | 점검 예외에서만 씁니다. `true`이면 `ERROR`도 받아들입니다. 그 호스트에서는 점검을 실행할 수 없다는 것을 알고 내리는 결정입니다 |

- 예외는 `FAIL`과 `MANUAL` 결과를 바꿉니다. `ERROR`는 `errors: true`일 때만 바꿉니다. `PASS`와
  `NOT_APPLICABLE`은 그대로 둡니다.
- 점검 항목 예외는 그 점검 항목의 종합 결과에 적용됩니다. 점검 항목에 속한 점검 중 하나라도 `ERROR`이면 적용되지 않고,
  프로파일 리비전이 바뀌면 적용이 멈춥니다. 나중에 점검 항목에 점검이 추가되었을 때 확인 없이 받아들여지는 일이 없도록
  하기 위해서입니다. `revision`을 빠뜨렸을 때 나오는 검증 오류에 현재 리비전이 적혀 있습니다.
- 만료되었거나 리비전이 달라진 예외는 적용되지 않습니다. 이런 예외는 스캔 결과에 목록으로 나옵니다. 표에서는 요약
  아래에, JSON 결과에서는 `waivers` 아래에 나옵니다.

## 증명(attestation)

사람이 판단해야 하는 대상만 나열해 주는 점검이 있습니다(로그인할 수 있는 계정, 사용 중인 시간 서버 등). 이런 점검은
`MANUAL`로 나옵니다. 내용을 직접 확인한 뒤 증명으로 판정(`PASS` 또는 `FAIL`)을 기록하면 점검 항목이 그 판정을
따릅니다. 결과에는 `originalStatus: MANUAL`과 `statusSource: attested`가 남고, 누가, 언제, 왜 증명했는지도
함께 담깁니다.

증명은 무조건 통하는 예외가 아니라, 확인한 대상에 묶여 있습니다.

- `digest`는 점검 로직의 다이제스트입니다. vmsctl 릴리스에서 점검이 바뀌면 값이 달라집니다.
- `evidence_digest`는 점검이 보여 주는 값 전체의 다이제스트입니다(보고서에 잘려 나오는 근거가 아닙니다). 나열된
  계정, 서버, 파일이 바뀌면 값이 달라집니다.

두 값은 스캔의 JSON 결과(`vmsctl scan --format json`)에서 해당 점검의 `checks[].digest`와
`checks[].evidenceDigest`를 읽어 옵니다. 보여 줄 값이 없는 점검에는 `evidenceDigest`가 없습니다. 이때는
`evidence_digest`를 생략하며, 증명은 만료일까지 적용됩니다.

| 키 | 의미 |
|---|---|
| `check` | 필수. 점검 ID. `MANUAL`인 점검만 증명할 수 있습니다 |
| `status` | 필수. `PASS` 또는 `FAIL` |
| `digest` | 필수. 점검의 `digest` |
| `evidence_digest` | 값을 보여 주는 점검에서는 필수이고, 보여 줄 값이 없는 점검에서는 생략합니다 |
| `by` | 필수. 확인한 사람 |
| `at` | 필수. 판정한 날(`YYYY-MM-DD`) |
| `expires` | 필수. 증명이 적용되는 마지막 날(`YYYY-MM-DD`, UTC) |
| `reason` | 필수. 무엇을 확인했고 왜 그 판정이 맞는지 |
| `hosts` | `web-*` 같은 호스트 이름 패턴. 생략하면 모든 호스트에 적용합니다 |

- 증명은 `MANUAL` 결과에만 적용합니다. 점검 결과가 `ERROR`, `FAIL`, `PASS`이면 적용하지 않습니다.
- 다음 경우에는 증명의 적용이 멈춥니다. 만료되었을 때, 점검이 바뀌었을 때(값을 보여 주기 시작하거나 멈춘 경우 포함),
  관찰한 값이 바뀌었을 때, 그 호스트에서 값을 끝까지 관찰하지 못했을 때입니다. 미래 날짜로 적은 증명은 그 날이 오기
  전에는 적용하지 않습니다. 스캔은 이런 증명을 표의 요약 아래와 JSON 결과의 `attestations`에 목록으로 보여
  주므로, 오래된 증명이 조용히 무시되는 일은 없습니다.
- 증명은 예외보다 먼저 적용합니다. 그래서 증명으로 `FAIL`이 된 결과도 예외로 받아들일 수 있습니다.
- 예외와 마찬가지로 결과를 가리는 수단이므로, 파일은 root 또는 실행한 사용자 소유여야 하고 다른 사용자가 쓸 수
  없어야 합니다.
