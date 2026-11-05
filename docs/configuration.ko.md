<!-- translated from docs/configuration.md @ f3f7b5e -->
# 설정

hostlint는 설정 없이 동작합니다. `hostlint.yaml`을 두면 프로파일을 고르고, 점검을 더 엄격하게 만들고,
받아들이기로 한 결과를 예외(waiver)로 처리하고, 사람만 판단할 수 있는 점검에는 판정을 기록(attestation)할 수 있습니다.

[English](configuration.md)

```yaml
# --profile을 주지 않았을 때 사용할 프로파일
profile: kisa-2026

# 프로파일보다 엄격한 기준값: 점검 ID → 파라미터 → 값
params:
  accounts.password-max-age: {max_days: 60}
  accounts.lockout-threshold: {max_failures: 5}

waivers:
  # 점검 하나의 결과를 일부 호스트에서 받아들임
  - check: files.shadow-perms
    reason: Debian's unix_chkpwd reads /etc/shadow through group shadow
    expires: 2027-06-30
    hosts: ["web-*"]
  # 프로파일의 컨트롤 하나를 받아들임
  - control: U-18
    revision: 8
    reason: Accepted by the security team (SEC-142)
    expires: 2027-01-31

# MANUAL 점검에 사람이 내린 판정의 기록
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

## 찾는 위치

1. `--config`로 지정한 파일 (반드시 있어야 합니다)
2. 작업 디렉터리의 `hostlint.yaml`
3. `/etc/hostlint/hostlint.yaml`

처음 찾은 파일을 사용하며, 없어도 됩니다. 이 파일은 hostlint를 실행하는 머신의 것입니다. `--root`를
쓸 때 마운트한 파일시스템에서 읽지 않습니다.

예외는 결과를 가릴 수 있으므로, 다른 사람이 심거나 바꿀 수 있었던 파일은 거부합니다. 일반 파일이어야
하고, 소유자가 root이거나 hostlint를 실행한 사용자여야 하며, 그룹이나 다른 사용자가 쓸 수 없어야
합니다. 내가 소유한 `hostlint.yaml`이 있는 디렉터리에서 `sudo hostlint scan`을 실행하면 이 때문에
실패합니다. 소유자를 root로 바꾸세요(`sudo chown root: hostlint.yaml`).

파일은 엄격하게 읽습니다. 모르는 키, 점검, 컨트롤, 파라미터는 오류이므로 오타 때문에 예외가 조용히
사라지는 일은 없습니다. 명령줄의 `--profile`이 `profile:`보다 우선합니다.

## 파라미터

일부 점검에는 기준값이 있고, [rules/](../rules/)에 있는 점검 파일의 `params` 아래에 선언되어 있습니다
(예: `rules/accounts/password-max-age.yaml`의 `max_days`). 프로파일이 요구하는 값을 정하고,
`hostlint.yaml`의 `params:`로 정수 파라미터를 바꿀 수 있지만 더 엄격한 방향으로만 가능합니다(점검의
`stricter: lower` 또는 `higher`). 더 느슨한 값은 예외를 쓰라는 안내와 함께 오류가 되므로, `PASS`는
언제나 최소한 프로파일의 기준을 충족한다는 뜻입니다.

파라미터를 바꿔 평가한 결과는 JSON 결과에 `customized`로 표시됩니다.

## 예외(waiver)

예외는 이유와 함께, 만료일까지 결과를 받아들입니다. 점검은 그대로 실행됩니다. 결과는 이유와 함께
`WAIVED`로 표시되고, 원래 상태와 근거를 그대로 가집니다.

| 키 | 의미 |
|---|---|
| `check` 또는 `control` | 둘 중 하나만: 점검 ID, 또는 점검 중인 프로파일의 컨트롤 ID |
| `reason` | 필수. 결과를 받아들이는 이유 |
| `expires` | 필수. 예외가 적용되는 마지막 날, `YYYY-MM-DD` (UTC) |
| `revision` | 컨트롤 예외에서만, 필수: 예외를 작성할 때의 프로파일 리비전 |
| `hosts` | `web-*` 같은 호스트 이름 패턴. 생략하면 모든 호스트에 적용 |
| `errors` | `true`면 `ERROR`도 받아들임: 그곳에서는 점검을 실행할 수 없다는 의도적인 결정 |

- 예외는 `FAIL`과 `MANUAL` 결과를 바꾸고, `ERROR`는 `errors: true`일 때만 바꿉니다. `PASS`와
  `NOT_APPLICABLE`은 그대로입니다.
- 컨트롤 예외는 컨트롤의 종합 결과에 적용됩니다. 컨트롤의 점검 중 하나라도 `ERROR`이면 적용되지
  않고, 프로파일 리비전이 바뀌면 더 이상 적용되지 않으므로, 나중에 컨트롤에 추가된 점검이 검토
  없이 받아들여지지 않습니다. `revision`이 없을 때의 검증 오류가 현재 리비전을 알려 줍니다.
- 만료되었거나 리비전이 맞지 않는 예외는 적용되지 않습니다. 점검 결과에 그 목록이 나옵니다. 표에서는
  요약 아래에, JSON 결과에서는 `waivers` 아래에 나옵니다.

## 증명(attestation)

어떤 점검은 사람이 판단해야 할 대상만 나열합니다(로그인할 수 있는 계정, 사용 중인 시간 서버 등). 이런 점검은
`MANUAL`입니다. 내용을 확인한 뒤 증명으로 판정(`PASS` 또는 `FAIL`)을 기록하면 컨트롤이 그 판정을 따릅니다.
결과에는 `originalStatus: MANUAL`, `statusSource: attested`와 함께 누가, 언제, 왜 증명했는지가 남습니다.

증명은 무조건적인 예외가 아니라, 확인한 대상에 묶여 있습니다.

- `digest`는 점검 로직의 다이제스트입니다. hostlint 릴리스에서 점검이 바뀌면 달라집니다.
- `evidence_digest`는 점검이 보여 주는 전체 값(보고서에 잘려 나오는 증거가 아닌)의 다이제스트입니다.
  나열된 계정, 서버, 파일이 바뀌면 달라집니다.

두 값은 스캔의 JSON 결과(`hostlint scan --format json`)에서 해당 점검의 `checks[].digest`와
`checks[].evidenceDigest`로 읽습니다. 보여 줄 값이 없는 점검에는 `evidenceDigest`가 없으니
`evidence_digest`를 생략하면, 증명은 만료될 때까지 적용됩니다.

| 키 | 의미 |
|---|---|
| `check` | 필수. 점검 ID. `MANUAL`인 점검만 증명할 수 있음 |
| `status` | 필수. `PASS` 또는 `FAIL` |
| `digest` | 필수. 점검의 `digest` |
| `evidence_digest` | 값을 보여 주는 점검은 필수, 보여 줄 값이 없는 점검은 생략 |
| `by` | 필수. 확인한 사람 |
| `at` | 필수. 판정한 날, `YYYY-MM-DD` |
| `expires` | 필수. 적용되는 마지막 날, `YYYY-MM-DD` (UTC) |
| `reason` | 필수. 무엇을 확인했고 왜 그 판정이 맞는지 |
| `hosts` | `web-*` 같은 호스트 이름 글롭. 생략하면 모든 호스트 |

- 증명은 `MANUAL` 결과에만 적용됩니다. 점검이 `ERROR`, `FAIL`, `PASS`이면 적용되지 않습니다.
- 만료되었거나, 점검이 바뀌었거나(값을 보여 주기 시작하거나 멈춘 경우 포함), 관찰한 값이 바뀌었거나, 이
  호스트에서 값을 끝까지 관찰하지 못했으면 적용이 멈춥니다. 미래 날짜로 적은 증명은 아직 적용되지 않습니다. 스캔은 이런 증명을 표의 요약 아래와 JSON 결과의 `attestations`에 나열하므로, 오래된
  증명이 조용히 무시되는 일은 없습니다.
- 증명은 예외보다 먼저 적용됩니다. 증명된 `FAIL`도 예외로 받아들일 수 있습니다.
- 예외와 마찬가지로 결과를 가리는 수단이므로, 파일은 root 또는 실행한 사용자 소유여야 하고 다른 사용자가
  쓸 수 없어야 합니다.
