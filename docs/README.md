# vmsctl documentation

[한국어](README.ko.md)

## Using vmsctl

| | |
|---|---|
| [Scanning container images](images.md) | `--image-tar`: what an image scan covers, the limits, sending the result to a server |
| [Using vmsctl in CI](ci.md) | exit codes, the GitHub Action, GitLab CI, any other CI |
| [Running vmsctl as a container](container.md) | the release image, what it can scan, verifying it |
| [The fleet server and dashboard](fleet.md) | pushing results, the agent for on-demand scans, tokens, signed results, the API, running the server |
| [Configuration](configuration.md) | `vmsctl.yaml`: parameters, waivers, attestations |
| [The DISA STIG profile](stig.md) | `stig-ubuntu2204`: the US baseline for Ubuntu 22.04, what it covers and what it does not |
| [Policy packs](packs.md) | your own checks and profiles |
| [Moving from hostlint](migrating-from-hostlint.md) | the rename in v0.27 |
| [How vmsctl compares](comparison.md) | with Lynis, OpenSCAP and Wazuh, and when to pick them |

## Reference

- [Rules and profiles](rules.md): every check and control, with what it looks at, why, and how to fix it (in Korean: [rules.ko.md](rules.ko.md))
- [Facts](facts.md): what the collectors read, for writing your own checks
- [Result schema](../schema/result-v1.schema.json): the JSON result, with a [valid example](../schema/result-v1.example.json)

## About the project

- [Vision](VISION.md): what vmsctl is for, and what it will not do
- [Roadmap](ROADMAP.md) and [releasing](RELEASING.md)
- [Design decisions](adr/README.md) (ADRs)
- [Contributing](../CONTRIBUTING.md) and [security policy](../SECURITY.md)
