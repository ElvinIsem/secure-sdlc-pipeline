# secure-sdlc-pipeline

> A **reference DevSecOps pipeline** wiring SAST, SCA, secret scanning, IaC
> scanning, SBOM generation and DAST around a small, **intentionally vulnerable**
> application — provided in **two portable variants**: GitHub Actions and GitLab CI.

[![Secure SDLC Pipeline](https://github.com/kbcasurf/secure-sdlc-pipeline/actions/workflows/security.yml/badge.svg)](https://github.com/kbcasurf/secure-sdlc-pipeline/actions/workflows/security.yml)

---

> 🧪 **Laboratorio (UMG – Seguridad Informática):** este fork implementa
> *pipeline de SAST + SCA con Semgrep y Dependency-Check, generación de SBOM y
> política de fallo del build por severidad*. Ver
> [`docs/laboratorio.md`](docs/laboratorio.md) para los cambios, la política y
> cómo reproducir la demostración (rama `main` bloqueada ↔ rama `remediacion` aprobada).

---

## What this project demonstrates

A complete **secure SDLC** implemented as code — the stages, their order, the
quality gates, and how a real scanner finding is surfaced (and can break the
build). Each control category maps to a widely-used open-source or free tool:

| Stage | Control | Tool(s) |
|---|---|---|
| **SAST** | Static application security testing | Semgrep |
| **SCA** | Software composition / dependency analysis | OWASP Dependency-Check (NVD + npm audit + RetireJS) |
| **Secrets** | Hardcoded credential detection | Gitleaks |
| **IaC** | Infrastructure-as-code misconfiguration | Checkov + Trivy (config) |
| **SBOM** | Software bill of materials (CycloneDX + SPDX) | Syft |
| **DAST** | Dynamic testing of the running app | OWASP ZAP (baseline) |

The **same pipeline** is expressed twice to prove platform portability:

- **GitHub Actions** — [`.github/workflows/security.yml`](.github/workflows/security.yml)
- **GitLab CI** — [`.gitlab-ci.yml`](.gitlab-ci.yml)

> ⚠️ The app under `app/` is **deliberately insecure** and exists only to give the
> scanners something real to find. **Never deploy it.** See
> [`docs/findings-walkthrough.md`](docs/findings-walkthrough.md) for each planted
> vulnerability, its CWE/OWASP mapping, and the fix.

---

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full pipeline flow
diagram (Mermaid).

```
  commit / PR
      │
      ├── SAST        (Semgrep)              ─┐
      ├── Secrets     (Gitleaks)             │
      ├── SCA         (Dependency-Check)     ├─►  findings → SARIF / reports
      ├── IaC         (Checkov + Trivy)      │        │
      ├── SBOM        (Syft, CycloneDX/SPDX) ─┘        ▼
      │                          Security Gate (policies/security-policy.yml)
      │                                    │ exit 1 → build bloqueado
      │                                    ▼
      │                          Build (imagen Docker)
      └── DAST        (OWASP ZAP baseline, app running in Docker)
```

---

## Repository layout

```
secure-sdlc-pipeline/
├── app/                     # intentionally vulnerable Node/Express service
│   ├── src/                 # server.js + db.js (planted, documented vulns)
│   ├── Dockerfile
│   └── README.md            # inventory of intentional vulnerabilities
├── .github/workflows/       # GitHub Actions variant of the pipeline
├── .gitlab-ci.yml           # GitLab CI variant of the pipeline
├── policies/                # gate config: gitleaks rules, ZAP rules, thresholds
├── docs/
│   ├── architecture.md      # pipeline flow (Mermaid)
│   └── findings-walkthrough.md   # each finding → why → how to fix
├── docker-compose.yml       # run the app locally (and for local DAST)
├── SECURITY.md
└── LICENSE
```

---

## Run it locally

```bash
# 1. Start the (vulnerable) demo app
docker compose up --build -d        # app on http://localhost:3000

# 2. Run individual scanners locally (examples)
semgrep scan --config auto app/                     # SAST
gitleaks detect --source . -c policies/gitleaks.toml # secrets
docker run --rm -v "$PWD/app:/src" -v "$PWD/reports:/report" \
  owasp/dependency-check:12.2.2 --scan /src --out /report \
  --format JSON --format HTML --disableOssIndex --nvdApiKey "$NVD_API_KEY"  # SCA
checkov -d .                                         # IaC
syft dir:app -o cyclonedx-json > sbom.json           # SBOM

# 3. DAST against the running app
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:3000
```

The CI pipeline runs all of the above automatically on every push and pull request.

---

## On the quality gate

**SAST and SCA are now blocking.** Their reports feed the `security-gate` job,
which applies [`policies/security-policy.yml`](policies/security-policy.yml)
(zero CRITICAL/HIGH by default) and exits 1 when a threshold is exceeded, so the
`build` job never runs. Secrets, IaC and DAST remain in report mode
(`continue-on-error: true`) as in the original reference pipeline.

---

## Why it exists (portfolio note)

Built to demonstrate hands-on **DevSecOps / AppSec** capability end to end:
threat-informed pipeline design, tool integration (SAST/DAST/SCA/IaC), SBOM and
supply-chain hygiene, and platform-portable CI. Part of a broader set of AppSec
reference projects.

## License

MIT — see [`LICENSE`](LICENSE).
