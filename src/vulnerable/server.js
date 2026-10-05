/**
 * AgriSmart API - VERSION VULNERABLE (Caso 10 - AgriTech)
 * Fines academicos - Evaluacion 2.4 (Etica, Gobernanza ISO/IEC 27034 y OWASP Top 10)
 *
 * Contiene las 10 vulnerabilidades descritas en el caso asignado.
 * Este codigo NO debe usarse en produccion bajo ninguna circunstancia.
 *
 * Auditados en profundidad con curl (5 de 10): A01, A03, A05, A07, A08
 * Los otros 5 (A02, A04, A06, A09, A10) se dejan implementados/documentados
 * como parte del escenario, pero no forman parte del set de pruebas elegido.
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

// --- A07: clave API "hardcodeada" directamente en el codigo fuente ---
const API_KEY_HARDCODED = 'AGRISMART-DEMO-KEY-1234';

// Base de datos en memoria (SQLite) para simular el reporte historico
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE lecturas (
    id INTEGER PRIMARY KEY,
    zona_id TEXT,
    temperatura REAL,
    humedad REAL,
    fecha TEXT
  )`);
  const stmt = db.prepare('INSERT INTO lecturas (zona_id, temperatura, humedad, fecha) VALUES (?,?,?,?)');
  stmt.run('zona-1', 22.5, 38.2, '2026-09-01');
  stmt.run('zona-2', 24.1, 41.7, '2026-09-02');
  stmt.run('zona-admin-secreta', 19.9, 55.0, '2026-09-03');
  stmt.finalize();
});

// Estado simulado de zonas de riego (para A01)
const zonasRiego = {
  'zona-1': { propietario: 'agricultor1', riego_activo: true, umbral_max: 80 },
  'zona-2': { propietario: 'agricultor2', riego_activo: false, umbral_max: 80 },
};

// Estaciones meteorologicas (para A08 - XSS)
const estaciones = [
  { id: 1, nombre: 'Estacion Norte' },
  { id: 2, nombre: 'Estacion Sur' },
];

// -----------------------------------------------------------------------
// A01 - Control de acceso roto (IDOR)
// Cualquier agricultor puede apagar/alterar el riego de OTRA zona
// con solo cambiar el zona_id en la URL, sin validar propiedad/sesion.
// -----------------------------------------------------------------------
app.post('/api/riego/:zona_id/estado', (req, res) => {
  const { zona_id } = req.params;
  const { activo } = req.body;
  // VULNERABLE: no se valida que el solicitante sea dueno de la zona
  if (!zonasRiego[zona_id]) {
    return res.status(404).json({ error: 'zona no encontrada' });
  }
  zonasRiego[zona_id].riego_activo = !!activo;
  return res.json({
    mensaje: `Riego de ${zona_id} actualizado sin validar propietario`,
    zona: zonasRiego[zona_id],
  });
});

// -----------------------------------------------------------------------
// A02 - Transmision sin cifrado (se documenta: este servidor corre en
// HTTP plano a proposito, para evidenciar la falta de TLS)
// -----------------------------------------------------------------------
app.post('/api/telemetria', (req, res) => {
  // VULNERABLE: credenciales/datos de sensor viajan en texto plano por HTTP
  res.json({ recibido: true, nota: 'Transmitido sin TLS (HTTP plano)' });
});

// -----------------------------------------------------------------------
// A03 - Inyeccion SQL en el reporte historico de temperatura/humedad
// -----------------------------------------------------------------------
app.get('/api/reportes/historico', (req, res) => {
  const zona = req.query.zona_id || '';
  // VULNERABLE: concatenacion directa de SQL
  const sql = `SELECT * FROM lecturas WHERE zona_id = '${zona}'`;
  db.all(sql, (err, rows) => {
    if (err) {
      // A05 tambien: se expone el stack trace / mensaje crudo del motor
      return res.status(500).json({ error: err.message, sql_ejecutado: sql });
    }
    res.json({ sql_ejecutado: sql, resultados: rows });
  });
});

// -----------------------------------------------------------------------
// A04 - Sin validacion de rangos: permite umbrales destructivos
// -----------------------------------------------------------------------
app.post('/api/riego/:zona_id/umbral', (req, res) => {
  const { zona_id } = req.params;
  const { umbral } = req.body;
  if (!zonasRiego[zona_id]) return res.status(404).json({ error: 'zona no encontrada' });
  // VULNERABLE: no valida rango fisico seguro para la bomba
  zonasRiego[zona_id].umbral_max = umbral;
  res.json({ mensaje: 'umbral actualizado sin validar rango seguro', zona: zonasRiego[zona_id] });
});

// -----------------------------------------------------------------------
// A05 - Consola de administracion expuesta sin autenticacion obligatoria
// -----------------------------------------------------------------------
app.get('/admin/sensores', (req, res) => {
  // VULNERABLE: no se exige ningun header/token de autenticacion
  res.json({
    mensaje: 'Panel de administracion de sensores (SIN AUTENTICACION)',
    zonas: zonasRiego,
    estaciones,
  });
});

// Endpoint que fuerza un error no controlado para exhibir el stack trace (A05)
app.get('/debug/crash', (req, res) => {
  throw new Error('Fallo simulado para exponer stack trace');
});

// -----------------------------------------------------------------------
// A06 - Dependencia IoT/MQTT desactualizada (se documenta en package.json
// y README; no se simula trafico MQTT real en este alcance academico)
// -----------------------------------------------------------------------
app.get('/api/info/dependencias', (req, res) => {
  res.json({ nota: 'Usa librerias MQTT desactualizadas (ver README de vulnerabilidades)' });
});

// -----------------------------------------------------------------------
// A07 - Autenticacion mediante API key fija incrustada en el codigo
// -----------------------------------------------------------------------
app.get('/api/sensores/datos', (req, res) => {
  const key = req.header('X-Api-Key');
  // VULNERABLE: la clave esperada es un literal en el codigo fuente
  if (key !== API_KEY_HARDCODED) {
    return res.status(401).json({ error: 'API key invalida' });
  }
  res.json({ mensaje: 'Acceso concedido con clave hardcodeada', key_usada: key });
});

// -----------------------------------------------------------------------
// A08 - XSS almacenado en nombres de estaciones meteorologicas
// -----------------------------------------------------------------------
app.post('/api/estaciones', (req, res) => {
  const { nombre } = req.body;
  // VULNERABLE: no se sanitiza ni valida el nombre
  const nueva = { id: estaciones.length + 1, nombre };
  estaciones.push(nueva);
  res.json({ mensaje: 'estacion creada', estacion: nueva });
});

app.get('/api/estaciones', (req, res) => {
  // VULNERABLE: se refleja el HTML/JS sin escapar
  const filas = estaciones.map(e => `<li>${e.nombre}</li>`).join('');
  res.send(`<html><body><h1>Estaciones</h1><ul>${filas}</ul></body></html>`);
});

// -----------------------------------------------------------------------
// A09 - Sin registro de auditoria para eventos de riego
// -----------------------------------------------------------------------
// (Intencionalmente no se implementa ningun logging de estos eventos)

// -----------------------------------------------------------------------
// A10 - SSRF en actualizacion de firmware via URL provista por el usuario
// -----------------------------------------------------------------------
app.post('/api/firmware/actualizar', async (req, res) => {
  const { firmware_url } = req.body;
  try {
    // VULNERABLE: se hace fetch a cualquier URL/host, incluida red interna
    const r = await fetch(firmware_url);
    const texto = await r.text();
    res.json({ mensaje: 'firmware descargado sin restriccion de destino', bytes: texto.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Middleware de error en "modo desarrollo": imprime stack trace completo (A05)
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    nota: 'Stack trace expuesto por configuracion insegura (A05)',
  });
});

app.listen(PORT, () => {
  console.log(`AgriSmart API (VULNERABLE) escuchando en http://0.0.0.0:${PORT}`);
});
