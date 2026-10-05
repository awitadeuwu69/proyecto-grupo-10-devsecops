# proyecto-grupo-10-devsecops — AgriSmart API (Caso 10)

Evaluación 2.4 — Ética, Gobernanza (ISO/IEC 27034) y Seguridad Aplicada (OWASP Top 10).

**Caso asignado:** AgriTech — Sistema de Monitoreo de Sensores Agrícolas y Riego (AgriSmart API).
API que recopila datos de sensores de humedad en campos agrícolas y activa sistemas de riego automático.

**Riesgos OWASP trabajados en profundidad (5 de 10):** A01, A03, A05, A07, A08.

## Estructura del repositorio

```
gobierno-seguridad/   Manifiesto ético, ONF y ASC (ISO/IEC 27034)
src/vulnerable/       API Node.js con las 10 vulnerabilidades del caso (fines académicos)
src/seguro/           API refactorizada con Zero Trust Input, mitigando A01, A03, A05, A07, A08
auditoria/            Script de pruebas con curl + evidencias crudas (fase1 = antes, fase2 = después)
```

## Cómo levantar cada versión

Requisitos: Node.js 18+.

```bash
# Versión vulnerable (puerto 3000)
cd src/vulnerable
npm install
npm start

# Versión segura (puerto 3001)
cd src/seguro
cp .env.example .env    # completar AGRISMART_API_KEY y ADMIN_TOKEN
npm install
npm start
```

## Cómo correr la auditoría

Desde la máquina auditora (Kali Linux), con el servidor accesible por red:

```bash
cd auditoria
./run_audit.sh http://IP_SERVIDOR:3000 fase1   # contra la API vulnerable
./run_audit.sh http://IP_SERVIDOR:3001 fase2   # contra la API segura (re-prueba)
```

El script ejecuta las 5 pruebas seleccionadas (A01, A03, A05, A07, A08) con `curl -i` y
guarda cada petición/respuesta cruda como `.txt` en `auditoria/fase1/` o `auditoria/fase2/`.

## Resumen de resultados (fase1 vs. fase2)

| Riesgo | Fase 1 (vulnerable) | Fase 2 (segura) |
|---|---|---|
| A01 — IDOR | `200 OK`, riego de otra zona modificado | `403 Forbidden` — valida propietario |
| A03 — SQL Injection | `200 OK`, inyección ejecutada, filas filtradas | `400 Bad Request` — zona_id inválido |
| A05 — Config. insegura | `200 OK`, panel admin sin login | `401 Unauthorized` — token requerido |
| A07 — Clave hardcodeada | `200 OK` con la clave leída del código fuente | `401 Unauthorized` — clave ya no es válida |
| A08 — XSS almacenado | `200 OK`, `<script>` guardado tal cual | `400 Bad Request` — nombre rechazado por regex |

## Documentación de gobernanza

El manifiesto ético, el Marco Normativo Organizacional (ONF) y el perfil de controles
de seguridad (ASC) bajo ISO/IEC 27034 están en `gobierno-seguridad/AxelBernalesCaso10.odt`.

## Autor

Axel
