#!/usr/bin/env bash
# Ejecuta localmente (con Docker) las mismas etapas que el pipeline:
# SAST (Semgrep) -> SCA (Dependency-Check) -> SBOM (Syft) -> Security Gate.
# Uso: NVD_API_KEY=xxxx ./scripts/run-local.sh
set -uo pipefail
cd "$(dirname "$0")/.."
DC_VERSION="${DC_VERSION:-12.2.2}"
mkdir -p reports dc-data

echo ">> Generando package-lock.json"
(cd app && npm install --package-lock-only --ignore-scripts)

echo ">> [1/4] SAST · Semgrep"
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:latest semgrep scan \
  --config p/javascript --config p/nodejs --config p/owasp-top-ten --config p/secrets \
  --config policies/semgrep-rules.yml --json-output=reports/semgrep.json --metrics=off app/

echo ">> [2/4] SCA · OWASP Dependency-Check ${DC_VERSION}"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/app:/src" -v "$PWD/dc-data:/usr/share/dependency-check/data" -v "$PWD/reports:/report" \
  "owasp/dependency-check:${DC_VERSION}" --scan /src --project secure-sdlc-pipeline --out /report \
  --format JSON --format HTML --disableOssIndex ${NVD_API_KEY:+--nvdApiKey "$NVD_API_KEY"}

echo ">> [3/4] SBOM · Syft"
docker run --rm -v "$PWD:/src" anchore/syft:latest dir:/src/app \
  -o cyclonedx-json=/src/reports/sbom.cyclonedx.json -o spdx-json=/src/reports/sbom.spdx.json

echo ">> [4/4] Security Gate"
python3 scripts/security_gate.py \
  --semgrep reports/semgrep.json \
  --dependency-check reports/dependency-check-report.json \
  --policy policies/security-policy.yml
rc=$?
[ $rc -eq 0 ] && echo ">> BUILD PERMITIDO" || echo ">> BUILD BLOQUEADO"
exit $rc
