#!/usr/bin/env bash
#
# run_audit.sh - Script de auditoria automatizada (Evaluacion 2.4)
# Ejecuta las 5 pruebas seleccionadas del OWASP Top 10 (A01, A03, A05, A07, A08)
# contra la URL base indicada, usando curl, y guarda la evidencia cruda.
#
# Uso:
#   ./run_audit.sh http://IP_SERVIDOR:3000 fase1   # contra la API vulnerable
#   ./run_audit.sh http://IP_SERVIDOR:3001 fase2   # contra la API segura
#
# Ejecutar desde la maquina auditora (Kali), apuntando a la IP del servidor.

set -u

BASE_URL="${1:-http://localhost:3000}"
FASE="${2:-fase1}"
OUT_DIR="$(dirname "$0")/${FASE}"
mkdir -p "$OUT_DIR"

TS="$(date '+%Y-%m-%d %H:%M:%S')"
echo "=== Auditoria AgriSmart API ==="
echo "Objetivo : $BASE_URL"
echo "Fase     : $FASE"
echo "Fecha    : $TS"
echo "Salida   : $OUT_DIR"
echo

run_test () {
  local name="$1"
  local file="$OUT_DIR/${name}.txt"
  shift
  {
    echo "### Prueba: $name"
    echo "### Fecha : $TS"
    echo "### Objetivo: $BASE_URL"
    echo "### Comando: curl $*"
    echo "---------------------------------------------"
    curl -i -s "$@"
    echo
    echo "---------------------------------------------"
  } > "$file"
  echo "[OK] $name -> $file"
}

# A01 - IDOR: agricultor2 intenta apagar el riego de zona-1 (no es su zona)
run_test "A01_idor_control_acceso" \
  -X POST "$BASE_URL/api/riego/zona-1/estado" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agricultor2" \
  -d '{"activo": false}'

# A03 - Inyeccion SQL en el reporte historico
run_test "A03_sql_injection" \
  -G "$BASE_URL/api/reportes/historico" \
  --data-urlencode "zona_id=zona-1' OR '1'='1"

# A05 - Consola de administracion sin autenticacion
run_test "A05_admin_sin_auth" \
  "$BASE_URL/admin/sensores"

# A07 - Sin credenciales validas, el acceso debe rechazarse
run_test "A07a_sin_credenciales" \
  "$BASE_URL/api/sensores/datos" \
  -H "X-Api-Key: clave-adivinada-cualquiera"

# A07 - Usando la clave hardcodeada que se encontro leyendo el codigo fuente
# (AGRISMART-DEMO-KEY-1234 solo existe en src/vulnerable/server.js;
#  en la version segura esa clave ya no es valida porque viene del .env)
run_test "A07b_clave_hardcodeada_filtrada" \
  "$BASE_URL/api/sensores/datos" \
  -H "X-Api-Key: AGRISMART-DEMO-KEY-1234"

# A08 - XSS almacenado en nombre de estacion
run_test "A08_xss_estacion" \
  -X POST "$BASE_URL/api/estaciones" \
  -H "Content-Type: application/json" \
  -d '{"nombre": "<script>alert(1)</script>"}'

echo
echo "=== Auditoria finalizada. Revisa los archivos en $OUT_DIR ==="
