# Policies & quality gates

Configuration that governs how strict each pipeline stage is. Keeping the gate
config in one place makes the "report vs. block" decision explicit and reviewable.

| File | Governs | How to make it blocking |
|---|---|---|
| `gitleaks.toml` | Secret scanning | Remove `continue-on-error` on the `secrets` job |
| `zap-rules.tsv` | DAST (ZAP baseline) | Change a rule's action from `WARN` to `FAIL` |
| `security-policy.yml` | **SAST (Semgrep) + SCA (Dependency-Check)** — blocking | Already blocking: edit `max_allowed` / `cvss_bands` / `exceptions` |
| `semgrep-rules.yml` | Custom Semgrep rules (one per planted VULN) | Rule `severity` maps to the policy (ERROR → HIGH) |
| — (inline) | IaC severity | Drop `continue-on-error` and set tool `--severity` / `--exit-code` |

## Gate philosophy

This demo runs every scanner in **report mode** (`continue-on-error: true`,
`allow_failure: true`, ZAP `WARN`) so findings are visible without failing every
run of an app that is vulnerable by design. In a real project you promote the
controls you trust to **blocking** incrementally — usually starting with secret
detection and critical-severity SCA, which have the lowest false-positive rates.

## Severity policy (lab)

`security-policy.yml` is enforced by `scripts/security_gate.py`:

| Source | How severity is assigned | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| Semgrep | ERROR→HIGH, WARNING→MEDIUM, INFO→LOW | 0 | 0 | ≤ 5 | no limit |
| Dependency-Check | CVSS (v4, else v3, else v2): ≥9 / ≥7 / ≥4 / >0 | 0 | 0 | no limit | no limit |

- **Fail-closed:** a missing report blocks the build (a scan that didn't run is not a pass).
- **Exceptions** (accepted risk) are listed by CVE or Semgrep rule id with an
  `expires` date; once expired they block again.
