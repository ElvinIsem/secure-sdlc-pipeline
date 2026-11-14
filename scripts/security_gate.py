#!/usr/bin/env python3
"""
Security Gate: aplica la politica de fallo del build por severidad.

Lee:
  - reporte de Semgrep (JSON)            -> hallazgos SAST
  - reporte de Dependency-Check (JSON)   -> vulnerabilidades SCA (CVE)
  - security-policy.yml                  -> umbrales y excepciones

Sale con codigo 1 (rompe el pipeline) si algun conteo supera el maximo permitido.

Uso:
  python scripts/security_gate.py \
      --semgrep reports/semgrep.json \
      --dependency-check reports/dependency-check-report.json \
      --policy policies/security-policy.yml
"""
import argparse
import datetime as dt
import json
import os
import sys

import yaml

NIVELES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def cargar_json(ruta):
    if not ruta or not os.path.exists(ruta):
        print(f"[!] Reporte no encontrado: {ruta}")
        return None
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def excepciones_vigentes(policy):
    hoy = dt.date.today()
    vigentes = set()
    for exc in policy.get("exceptions") or []:
        expira = exc.get("expires")
        if isinstance(expira, str):
            expira = dt.date.fromisoformat(expira)
        if expira is None or expira >= hoy:
            vigentes.add(exc["id"])
        else:
            print(f"[!] Excepcion expirada, se ignora: {exc['id']} (expiro {expira})")
    return vigentes


def analizar_semgrep(reporte, cfg, excepciones):
    hallazgos = []
    mapa = cfg.get("severity_map", {})
    for r in (reporte or {}).get("results", []):
        sev_orig = r.get("extra", {}).get("severity", "INFO").upper()
        sev = sev_orig if sev_orig in NIVELES else mapa.get(sev_orig, "LOW")
        regla = r.get("check_id", "?")
        if regla in excepciones or regla.split(".")[-1] in excepciones:
            continue
        hallazgos.append({
            "id": regla.split(".")[-1],
            "sev": sev,
            "donde": f"{r.get('path')}:{r.get('start', {}).get('line')}",
            "detalle": r.get("extra", {}).get("message", "").strip().split("\n")[0][:90],
        })
    return hallazgos


def severidad_por_cvss(score, bandas):
    for nivel in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if score >= bandas[nivel]:
            return nivel
    return "INFO"


def analizar_dependency_check(reporte, cfg, excepciones):
    hallazgos = []
    vistos = set()
    bandas = cfg["cvss_bands"]
    for dep in (reporte or {}).get("dependencies", []):
        paquete = dep.get("fileName", "?")
        if dep.get("packages"):
            paquete = dep["packages"][0].get("id", paquete)
        for v in dep.get("vulnerabilities") or []:
            cve = v.get("name", "?")
            if cve in excepciones or (paquete, cve) in vistos:
                continue
            vistos.add((paquete, cve))
            # Mismo orden de precedencia que usa Dependency-Check: CVSS v4 > v3 > v2
            score = None
            for clave, campo in (("cvssv4", "baseScore"), ("cvssv3", "baseScore"), ("cvssv2", "score")):
                if score is None and v.get(clave):
                    score = v[clave].get(campo)
            if score is not None:
                sev = severidad_por_cvss(float(score), bandas)
            else:
                # Sin CVSS (p. ej. avisos de npm audit): se usa la severidad textual
                sev = (v.get("severity") or "MEDIUM").upper()
                sev = {"MODERATE": "MEDIUM", "UNKNOWN": "MEDIUM"}.get(sev, sev)
                if sev not in NIVELES:
                    sev = "MEDIUM"
            hallazgos.append({
                "id": cve,
                "sev": sev,
                "donde": paquete,
                "detalle": f"CVSS {score}" if score is not None else "sin CVSS",
            })
    return hallazgos


def contar(hallazgos):
    c = {n: 0 for n in NIVELES}
    for h in hallazgos:
        c[h["sev"]] = c.get(h["sev"], 0) + 1
    return c


def evaluar(nombre, conteo, maximos):
    violaciones = []
    for nivel, maximo in maximos.items():
        if maximo is not None and maximo >= 0 and conteo.get(nivel, 0) > maximo:
            violaciones.append(f"{nombre}: {conteo[nivel]} hallazgo(s) {nivel} (maximo permitido {maximo})")
    return violaciones


def tabla_md(titulo, hallazgos, conteo, maximos):
    lineas = [f"### {titulo}", "", "| Severidad | Encontrados | Maximo permitido |", "|---|---|---|"]
    for n in NIVELES:
        m = maximos.get(n, -1)
        lineas.append(f"| {n} | {conteo.get(n, 0)} | {'ilimitado' if m is None or m < 0 else m} |")
    if hallazgos:
        lineas += ["", "<details><summary>Detalle</summary>", "", "| Sev | ID | Ubicacion | Detalle |", "|---|---|---|---|"]
        orden = sorted(hallazgos, key=lambda h: NIVELES.index(h["sev"]))
        for h in orden[:60]:
            lineas.append(f"| {h['sev']} | `{h['id']}` | `{h['donde']}` | {h['detalle']} |")
        lineas += ["", "</details>"]
    return "\n".join(lineas) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Gate de seguridad por severidad")
    ap.add_argument("--semgrep", default="reports/semgrep.json")
    ap.add_argument("--dependency-check", default="reports/dependency-check-report.json")
    ap.add_argument("--policy", default="policies/security-policy.yml")
    args = ap.parse_args()

    with open(args.policy, encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    excepciones = excepciones_vigentes(policy)

    rep_sast = cargar_json(args.semgrep)
    rep_sca = cargar_json(args.dependency_check)
    sast = analizar_semgrep(rep_sast, policy["sast"], excepciones)
    sca = analizar_dependency_check(rep_sca, policy["sca"], excepciones)
    c_sast, c_sca = contar(sast), contar(sca)

    # Fail-closed: si falta un reporte, el escaneo no ocurrio y el build no puede aprobarse
    violaciones = []
    if rep_sast is None:
        violaciones.append("SAST (Semgrep): no se encontro el reporte, el escaneo no se ejecuto")
    if rep_sca is None:
        violaciones.append("SCA (Dependency-Check): no se encontro el reporte, el escaneo no se ejecuto")
    violaciones += evaluar("SAST (Semgrep)", c_sast, policy["sast"]["max_allowed"])
    violaciones += evaluar("SCA (Dependency-Check)", c_sca, policy["sca"]["max_allowed"])

    # Salida en consola
    print("=" * 64)
    print(" SECURITY GATE - Politica de fallo por severidad")
    print("=" * 64)
    print(f"{'Severidad':<10} {'SAST':>6} {'SCA':>6}")
    for n in NIVELES:
        print(f"{n:<10} {c_sast[n]:>6} {c_sca[n]:>6}")
    print("-" * 64)

    estado = "FALLIDO" if violaciones else "APROBADO"
    if violaciones:
        print("[X] BUILD BLOQUEADO por politica de seguridad:")
        for v in violaciones:
            print(f"    - {v}")
    else:
        print("[OK] Build aprobado: no se superan los umbrales de la politica.")

    # Resumen en la pagina del workflow de GitHub Actions
    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen:
        with open(resumen, "a", encoding="utf-8") as f:
            icono = ":x:" if violaciones else ":white_check_mark:"
            f.write(f"## {icono} Security Gate: {estado}\n\n")
            for v in violaciones:
                f.write(f"- {v}\n")
            f.write("\n")
            f.write(tabla_md("SAST - Semgrep", sast, c_sast, policy["sast"]["max_allowed"]))
            f.write("\n")
            f.write(tabla_md("SCA - OWASP Dependency-Check", sca, c_sca, policy["sca"]["max_allowed"]))

    sys.exit(1 if violaciones else 0)


if __name__ == "__main__":
    main()
