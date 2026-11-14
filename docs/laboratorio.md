# Laboratorio: pipeline de SAST + SCA con Semgrep y Dependency-Check, SBOM y política de fallo por severidad

Base: [kbcasurf/secure-sdlc-pipeline](https://github.com/kbcasurf/secure-sdlc-pipeline), un pipeline DevSecOps de referencia
alrededor de una app Node/Express **intencionalmente vulnerable** (`app/`).
En el repo original todos los escaneos corren en **modo reporte** (`continue-on-error: true`) y el SCA usa Trivy + `npm audit`.

## Qué se cambió para el laboratorio

| # | Cambio | Archivo |
|---|---|---|
| 1 | **SAST con Semgrep** con salida JSON + SARIF, rulesets `p/javascript`, `p/nodejs`, `p/owasp-top-ten`, `p/secrets` y **6 reglas propias** (una por cada VULN plantada) | `.github/workflows/security.yml` (job `sast`), `policies/semgrep-rules.yml` |
| 2 | **SCA con OWASP Dependency-Check 12.2.2** en lugar de Trivy: genera `package-lock.json`, usa la API del NVD con caché, y produce reportes JSON, HTML y SARIF | job `sca` |
| 3 | **SBOM** en CycloneDX **y** SPDX con Syft, ahora con el lockfile para incluir dependencias transitivas, y tabla de componentes en el resumen | job `sbom` |
| 4 | **Política de fallo por severidad**, versionada en YAML | `policies/security-policy.yml` |
| 5 | **Security Gate**: lee los reportes de Semgrep y Dependency-Check, aplica la política y termina con `exit 1` si se supera un umbral | `scripts/security_gate.py`, job `security-gate` |
| 6 | **Build** de la imagen Docker que **solo corre si el gate aprueba** | job `build` |
| 7 | Rama **`remediacion`** con las vulnerabilidades corregidas, para demostrar que el pipeline pasa | `app/` en esa rama |

Secrets (Gitleaks), IaC (Checkov/Trivy) y DAST (ZAP) se dejaron como en el original, en modo reporte.

## Flujo

```
push / PR
   ├── SAST  · Semgrep ───────────┐
   ├── SCA   · Dependency-Check ──┼──► Security Gate ──► Build (docker build)
   ├── SBOM  · Syft ──────────────┼───────────────────────┘
   ├── Secrets · Gitleaks         │  (modo reporte)
   ├── IaC   · Checkov + Trivy    │  (modo reporte)
   └── DAST  · ZAP baseline       ┘  (modo reporte)
```

## Política de severidad (`policies/security-policy.yml`)

| Herramienta | Cómo se clasifica | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| Semgrep | ERROR → HIGH, WARNING → MEDIUM, INFO → LOW | 0 | 0 | ≤ 5 | sin límite |
| Dependency-Check | CVSS v4 (si no v3, si no v2): ≥ 9 / ≥ 7 / ≥ 4 / > 0 | 0 | 0 | sin límite | sin límite |

- **Fail-closed:** si falta un reporte (el escaneo no corrió), el gate bloquea.
- **Excepciones:** riesgo aceptado por CVE o id de regla, con `reason` y fecha `expires`. Al vencer, vuelve a bloquear.
- ¿Por qué un gate propio y no `semgrep --error` + `--failOnCVSS 7`? Porque así hay **una sola política** para ambas herramientas, versionada, con excepciones que vencen y un reporte unificado en el resumen del workflow.

## Cómo reproducirlo

1. Haz **fork** de este repositorio en tu cuenta de GitHub (o crea un repo y sube este contenido).
2. Pide una API key gratuita del NVD: <https://nvd.nist.gov/developers/request-an-api-key>.
3. En el repo: **Settings → Secrets and variables → Actions → New repository secret** → `NVD_API_KEY`.
4. En **Actions**, habilita los workflows si GitHub lo pide.
5. Haz push a `main` (o **Run workflow**). Resultado esperado: **Security Gate en rojo, Build omitido**.
6. Sube la rama `remediacion` y abre un **Pull Request** hacia `main`. Resultado esperado: **Security Gate en verde, Build ejecutado**.

> La primera ejecución de Dependency-Check descarga la base del NVD (puede tardar 10–20 minutos). Las siguientes usan la caché.

## Resultados esperados en `main` (app vulnerable)

| VULN | Detectado por | Severidad en la política |
|---|---|---|
| 01 Credencial AWS hardcodeada | Semgrep (`credencial-aws-hardcodeada`, `p/secrets`) | HIGH |
| 02 Inyección SQL | Semgrep (`sqli-concatenacion`) | HIGH |
| 03 Inyección de comandos | Semgrep (`command-injection-exec`, `p/javascript`) | HIGH |
| 04 MD5 para contraseñas | Semgrep (`hash-debil-password`) | HIGH |
| 05 Contaminación de prototipo | Semgrep (`merge-profundo-entrada-no-confiable`) | HIGH |
| 06 Dependencias vulnerables | Dependency-Check: lodash 4.17.11 (p. ej. CVE-2019-10744, CVSS 9.1) y transitivas de express 4.17.1 (qs, body-parser, path-to-regexp, cookie, send…) | CRITICAL / HIGH |

## Remediación (rama `remediacion`)

| VULN | Corrección |
|---|---|
| 01 | Credenciales desde variables de entorno |
| 02 | Consulta parametrizada (`?` + valores aparte) |
| 03 | Sin shell: validación por allowlist y resolución DNS en lugar de `ping` |
| 04 | `crypto.scrypt` con sal aleatoria |
| 05 | Solo campos permitidos sobre `Object.create(null)`, sin `_.merge` |
| 06 | `express` 4.22.3 y `lodash` 4.18.1 |

## Ejecución local (opcional)

`scripts/run-local.sh` corre Semgrep, Dependency-Check, Syft y el gate con Docker:

```bash
NVD_API_KEY=tu_key ./scripts/run-local.sh
```
