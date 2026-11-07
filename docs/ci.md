# Using hostlint in CI

hostlint is made for pipelines: a scan is one command with no daemon and no network access, the exit code
follows the severity you choose, and the result comes as a table, JSON, SARIF or JUnit. The most useful
gate is a container image before it is deployed ([scanning images](images.md)).

[한국어](ci.ko.md)

| Exit code | Meaning |
|---|---|
| 0 | Nothing failed at or above `--fail-on` |
| 1 | A control at or above `--fail-on` failed or could not be checked (`ERROR`) |
| 2 | Usage error, or the scan could not run (an unreadable archive, no operating system in the image) |

## GitHub Actions

The repository is a ready-made action (`action.yml`). It installs a hostlint release, checks the archive
against the release's signed checksums, scans, and fails the step when a control at or above `fail-on`
fails:

```yaml
jobs:
  image:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # to upload the SARIF report
    steps:
      - uses: actions/checkout@v7
      - run: docker build -t app:ci .
      - uses: with-developer/hostlint@v0.16.0
        with:
          image: app:ci
          fail-on: high
          sarif-file: hostlint.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always() # the report is wanted when the gate fails, too
        with:
          sarif_file: hostlint.sarif
```

A failed check carries how to fix it: the alert in code scanning shows it as the rule's help, and the JSON result has it
in `remediation`. It is the check's own guidance text, the same as `hostlint explain`.

| Input | Meaning |
|---|---|
| `image` | An image on the runner, saved with `docker save` and scanned |
| `image-tar` | A `docker save` or OCI archive to scan |
| `root` | A root filesystem mounted or unpacked on the runner |
| `profile` | The profile, or several separated by spaces (default `kisa-2026`, or the one in `config`) |
| `pack` | A [policy pack](packs.md) in the repository (a directory of your own checks and profiles); select its profile with `profile` |
| `fail-on` | `low`, `medium`, `high` (default) or `none` |
| `config` | A [`hostlint.yaml`](configuration.md): stricter thresholds, waivers with a reason and an expiry |
| `summary` | `true` (default): write a Markdown report of the findings to the job summary of the run, even when the scan fails the step |
| `sarif-file` | Also write SARIF here, even when the scan fails the step |
| `version` | The release to install; by default the one the action is pinned to (`@v0.16.0`) |

Set exactly one of `image`, `image-tar` and `root`. Pin the action to a release tag: it installs the
hostlint release of that tag. Pinned to a commit, set `version` (the action refuses a commit pin without it).
Linux runners only. The inputs reach the shell as variables, never as part
of a script.

A waiver for an image matches the image reference as the host name: `hosts: ["app:*"]`.

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

## Any other CI

```sh
curl -fsSL https://raw.githubusercontent.com/with-developer/hostlint/main/install.sh | sh -s -- -v v0.16.0
docker save app:ci -o app.tar
hostlint scan --image-tar app.tar --fail-on high --format sarif --output hostlint.sarif
```

`install.sh` checks the archive against the SHA-256 of the release and, when `cosign` is installed, the
signature of the checksums too. Read the script before you pipe it into a shell, and pin a version.

Every distribution hostlint supports gives the same result for an image as for a container made from it,
so a green build means the image filesystem is configured as the profile asks. It does not mean the container
is hardened: the user it runs as, capabilities and volumes are decided by the runtime.
