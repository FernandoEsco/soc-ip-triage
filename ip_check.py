#!/usr/bin/env python3
"""
ip_check.py — Consulta la reputación de una IP en AbuseIPDB y VirusTotal
y muestra un veredicto en la terminal.

Uso:
    python ip_check.py 185.220.101.1

Llaves (variables de entorno, o un archivo .env junto al script):
    ABUSEIPDB_API_KEY=...
    VT_API_KEY=...

Solo usa la librería estándar de Python (3.8+): no requiere pip install.

Códigos de salida: 0 = limpia · 1 = sospechosa · 2 = maliciosa · 3 = error
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

TIMEOUT = 20
MAX_AGE_DAYS = 90  # ventana de reportes en AbuseIPDB

# Umbrales del veredicto
ABUSE_MALICIOSA, ABUSE_SOSPECHOSA = 75, 25  # abuseConfidenceScore (%)
VT_MALICIOSA, VT_SOSPECHOSA = 5, 1          # motores que la marcan como maliciosa

# https://www.abuseipdb.com/categories
CATEGORIAS_ABUSE = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


# ─── Utilidades de terminal ──────────────────────────────────────────────────

def _soporta_color() -> bool:
    if os.getenv("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # activa secuencias ANSI en la consola de Windows 10+
    return True


COLOR = _soporta_color()


def c(texto: object, codigo: str) -> str:
    return f"\033[{codigo}m{texto}\033[0m" if COLOR else str(texto)


ROJO, AMARILLO, VERDE, GRIS, NEGRITA, CIAN = "1;31", "1;33", "1;32", "2", "1", "1;36"


def linea(etiqueta: str, valor: object) -> None:
    print(f"  {c(etiqueta + ':', GRIS):<32} {valor}")


def titulo(texto: str) -> None:
    print("\n" + c(f"▌ {texto}", CIAN))


# ─── Configuración ───────────────────────────────────────────────────────────

def cargar_env() -> None:
    """Carga un .env junto al script (o en el directorio actual) sin dependencias externas.
    Las variables ya definidas en el entorno tienen prioridad."""
    for ruta in (Path(__file__).resolve().parent / ".env", Path.cwd() / ".env"):
        if not ruta.is_file():
            continue
        for raw in ruta.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            clave, valor = raw.split("=", 1)
            clave = clave.strip()
            if clave.startswith("export "):
                clave = clave[len("export "):].strip()
            os.environ.setdefault(clave, valor.strip().strip("'\""))
        break


# ─── Consultas HTTP ──────────────────────────────────────────────────────────

class ErrorConsulta(Exception):
    pass


def http_get_json(url: str, headers: dict) -> dict | None:
    """GET que devuelve JSON. Devuelve None si el recurso no existe (404)."""
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "ip-check/1.0", **headers})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        mensajes = {401: "llave inválida o no autorizada", 403: "acceso denegado (revisa tu llave)",
                    429: "límite de consultas alcanzado (cuota diaria/por minuto)"}
        raise ErrorConsulta(f"HTTP {e.code}: {mensajes.get(e.code, e.reason)}") from None
    except urllib.error.URLError as e:
        raise ErrorConsulta(f"no se pudo conectar ({e.reason})") from None
    except TimeoutError:
        raise ErrorConsulta(f"tiempo de espera agotado ({TIMEOUT}s)") from None
    except json.JSONDecodeError:
        raise ErrorConsulta("respuesta no es JSON válido") from None


def consultar_abuseipdb(ip: str, llave: str) -> dict:
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS, "verbose": ""})
    data = http_get_json(f"https://api.abuseipdb.com/api/v2/check?{query}", {"Key": llave})
    if not data or "data" not in data:
        raise ErrorConsulta("respuesta sin datos")
    return data["data"]


def consultar_virustotal(ip: str, llave: str) -> dict | None:
    data = http_get_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", {"x-apikey": llave})
    return None if data is None else data.get("data", {}).get("attributes", {})


# ─── Veredicto ───────────────────────────────────────────────────────────────

def calcular_veredicto(abuse: dict | None, vt: dict | None) -> tuple[str, list[str]]:
    """Devuelve (veredicto, motivos). Veredicto: MALICIOSA, SOSPECHOSA, LIMPIA o SIN DATOS."""
    motivos_mal, motivos_sos = [], []

    if abuse is not None:
        score = abuse.get("abuseConfidenceScore") or 0
        reportes = abuse.get("totalReports") or 0
        if score >= ABUSE_MALICIOSA:
            motivos_mal.append(f"AbuseIPDB: confianza de abuso {score}% ({reportes} reportes)")
        elif score >= ABUSE_SOSPECHOSA:
            motivos_sos.append(f"AbuseIPDB: confianza de abuso {score}% ({reportes} reportes)")
        elif reportes >= 10:
            motivos_sos.append(f"AbuseIPDB: {reportes} reportes, aunque con confianza baja ({score}%)")

    if vt is not None:
        stats = vt.get("last_analysis_stats") or {}
        mal, sos = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int))
        if mal >= VT_MALICIOSA:
            motivos_mal.append(f"VirusTotal: {mal}/{total} motores la marcan como maliciosa")
        elif mal >= VT_SOSPECHOSA or sos >= 3:
            motivos_sos.append(f"VirusTotal: {mal} maliciosa / {sos} sospechosa de {total} motores")

    if abuse is None and vt is None:
        return "SIN DATOS", ["Ninguna fuente respondió"]
    if motivos_mal:
        return "MALICIOSA", motivos_mal + motivos_sos
    if motivos_sos:
        return "SOSPECHOSA", motivos_sos
    return "LIMPIA", ["Sin detecciones relevantes en las fuentes consultadas"]


# ─── Presentación ────────────────────────────────────────────────────────────

def fmt_fecha(valor) -> str:
    if valor in (None, ""):
        return "—"
    try:
        if isinstance(valor, (int, float)):
            dt = datetime.fromtimestamp(valor, tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(valor).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OSError):
        return str(valor)


def color_score(score: int, alto: int, medio: int) -> str:
    return c(score, ROJO if score >= alto else AMARILLO if score >= medio else VERDE)


def si_no(valor) -> str:
    return "Sí" if valor else "No"


def mostrar_abuseipdb(d: dict | None, error: str | None) -> None:
    titulo("AbuseIPDB")
    if error:
        linea("Error", c(error, AMARILLO))
        return
    if d is None:
        linea("Estado", c("omitido (sin ABUSEIPDB_API_KEY)", GRIS))
        return

    score = d.get("abuseConfidenceScore") or 0
    linea("Confianza de abuso", f"{color_score(score, ABUSE_MALICIOSA, ABUSE_SOSPECHOSA)}%")
    linea(f"Reportes ({MAX_AGE_DAYS} días)",
          f"{d.get('totalReports', 0)} de {d.get('numDistinctUsers', 0)} usuarios distintos")
    linea("Último reporte", fmt_fecha(d.get("lastReportedAt")))
    linea("ISP", d.get("isp") or "—")
    linea("Dominio", d.get("domain") or "—")
    linea("Tipo de uso", d.get("usageType") or "—")
    pais = d.get("countryName") or d.get("countryCode") or "—"
    linea("País", f"{pais} ({d.get('countryCode')})" if d.get("countryName") else pais)
    if d.get("hostnames"):
        linea("Hostnames", ", ".join(d["hostnames"][:5]))
    linea("Nodo Tor / Whitelist", f"{si_no(d.get('isTor'))} / {si_no(d.get('isWhitelisted'))}")

    conteo: dict[int, int] = {}
    for rep in d.get("reports") or []:
        for cat in rep.get("categories") or []:
            conteo[cat] = conteo.get(cat, 0) + 1
    if conteo:
        top = sorted(conteo.items(), key=lambda x: -x[1])[:6]
        linea("Categorías más reportadas",
              ", ".join(f"{CATEGORIAS_ABUSE.get(k, f'Cat. {k}')} ({v})" for k, v in top))


def mostrar_virustotal(d: dict | None, error: str | None, omitido: bool) -> None:
    titulo("VirusTotal")
    if error:
        linea("Error", c(error, AMARILLO))
        return
    if omitido:
        linea("Estado", c("omitido (sin VT_API_KEY)", GRIS))
        return
    if d is None:
        linea("Estado", "IP sin registros en VirusTotal")
        return

    st = d.get("last_analysis_stats") or {}
    total = sum(v for v in st.values() if isinstance(v, int))
    mal, sos = st.get("malicious", 0), st.get("suspicious", 0)
    linea("Detecciones", f"{color_score(mal, VT_MALICIOSA, VT_SOSPECHOSA)} maliciosa · "
                         f"{c(sos, AMARILLO) if sos else 0} sospechosa · "
                         f"{st.get('harmless', 0)} inofensiva · {st.get('undetected', 0)} sin detección "
                         f"(de {total})")
    linea("Reputación", d.get("reputation", "—"))
    votos = d.get("total_votes") or {}
    linea("Votos comunidad", f"{votos.get('malicious', 0)} maliciosa / {votos.get('harmless', 0)} inofensiva")
    asn = d.get("asn")
    linea("ASN / Propietario", f"AS{asn} — {d.get('as_owner', '—')}" if asn else d.get("as_owner", "—"))
    linea("Red", d.get("network") or "—")
    linea("País", d.get("country") or "—")
    linea("Último análisis", fmt_fecha(d.get("last_analysis_date")))
    if d.get("tags"):
        linea("Etiquetas", ", ".join(d["tags"]))

    motores = [(m, r.get("result") or r.get("category"))
               for m, r in (d.get("last_analysis_results") or {}).items()
               if r.get("category") in ("malicious", "suspicious")]
    if motores:
        muestra = ", ".join(f"{m} ({res})" for m, res in sorted(motores)[:8])
        extra = f" … y {len(motores) - 8} más" if len(motores) > 8 else ""
        linea("Motores que la detectan", muestra + extra)


def mostrar_veredicto(ip: str, veredicto: str, motivos: list[str]) -> None:
    estilo = {"MALICIOSA": ROJO, "SOSPECHOSA": AMARILLO, "LIMPIA": VERDE}.get(veredicto, GRIS)
    icono = {"MALICIOSA": "✖", "SOSPECHOSA": "⚠", "LIMPIA": "✔"}.get(veredicto, "?")
    print("\n" + "═" * 64)
    print(f"  VEREDICTO para {c(ip, NEGRITA)}:  {c(f'{icono} {veredicto}', estilo)}")
    for m in motivos:
        print(f"   • {m}")
    print("═" * 64)
    print(c("  Enlaces:", GRIS))
    print(f"   https://www.abuseipdb.com/check/{ip}")
    print(f"   https://www.virustotal.com/gui/ip-address/{ip}\n")


# ─── Principal ───────────────────────────────────────────────────────────────

def validar_ip(texto: str) -> str | None:
    """Acepta IPv4/IPv6, incluso 'defangeada' (1.2.3[.]4). Devuelve None si no es válida."""
    try:
        ip = ipaddress.ip_address(texto.strip().replace("[.]", ".").replace("[", "").replace("]", ""))
    except ValueError:
        print(f"Error: '{texto}' no es una dirección IP válida.")
        return None
    if not ip.is_global:
        print(c(f"Aviso: {ip} es una IP privada/reservada; las fuentes no tendrán datos útiles.", AMARILLO))
    return str(ip)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 3

    ip = validar_ip(argv[1])
    if ip is None:
        return 3
    cargar_env()
    llave_abuse = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    llave_vt = os.getenv("VT_API_KEY", "").strip()
    if not llave_abuse and not llave_vt:
        print("Error: define ABUSEIPDB_API_KEY y/o VT_API_KEY (variables de entorno o archivo .env).")
        return 3

    print(c(f"\nConsultando reputación de {ip} …", GRIS))

    resultados: dict[str, tuple[dict | None, str | None]] = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        tareas = {}
        if llave_abuse:
            tareas["abuse"] = pool.submit(consultar_abuseipdb, ip, llave_abuse)
        if llave_vt:
            tareas["vt"] = pool.submit(consultar_virustotal, ip, llave_vt)
        for nombre, futuro in tareas.items():
            try:
                resultados[nombre] = (futuro.result(), None)
            except ErrorConsulta as e:
                resultados[nombre] = (None, str(e))

    abuse, err_abuse = resultados.get("abuse", (None, None))
    vt, err_vt = resultados.get("vt", (None, None))

    mostrar_abuseipdb(abuse, err_abuse)
    mostrar_virustotal(vt, err_vt, omitido="vt" not in tareas)

    # Para el veredicto, "VT sin registros" cuenta como fuente válida sin detecciones.
    vt_para_veredicto = vt if vt is not None else ({} if "vt" in tareas and not err_vt else None)
    veredicto, motivos = calcular_veredicto(abuse, vt_para_veredicto)
    if (err_abuse or err_vt) and veredicto != "SIN DATOS":
        motivos.append("Veredicto parcial: una de las fuentes falló")
    mostrar_veredicto(ip, veredicto, motivos)

    return {"LIMPIA": 0, "SOSPECHOSA": 1, "MALICIOSA": 2}.get(veredicto, 3)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(130)
