/**
 * AgriSmart API - VERSION SEGURA (Caso 10 - AgriTech)
 * Refactorizacion aplicando Zero Trust Input, listas blancas y Regex.
 * Mitiga los 5 puntos del OWASP Top 10 seleccionados: A01, A03, A05, A07, A08
 *
 * Evaluacion 2.4 - Etica, Gobernanza ISO/IEC 27034 y Seguridad OWASP Top 10
 */

require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3001;

// --- A07 (mitigado): claves gestionadas por variables de entorno ---
const API_KEY = process.env.AGRISMART_API_KEY;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

if (!API_KEY || !ADMIN_TOKEN) {
  console.warn('ADVERTENCIA: faltan variables de entorno AGRISMART_API_KEY / ADMIN_TOKEN (ver .env.example)');
}

// Base de datos con datos de ejemplo (misma estructura que la version vulnerable)
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
  stmt.finalize();
});

// Zonas de riego, cada una con su propietario (para validar ownership)
const zonasRiego = {
  'zona-1': { propietario: 'agricultor1', riego_activo: true, umbral_max: 80 },
  'zona-2': { propietario: 'agricultor2', riego_activo: false, umbral_max: 80 },
};

const estaciones = [
  { id: 1, nombre: 'Estacion Norte' },
  { id: 2, nombre: 'Estacion Sur' },
];

// ---- Helpers de validacion (Zero Trust Input) ----

// Lista blanca estricta para IDs de zona: zona-<numero>
const REGEX_ZONA_ID = /^zona-[0-9]{1,4}$/;

// Lista blanca para nombres (letras, numeros, espacios, guiones; 1-60 chars)
const REGEX_NOMBRE_SEGURO = /^[\p{L}0-9 \-]{1,60}$/u;

// Fecha en formato YYYY-MM-DD estricto
const REGEX_FECHA = /^\d{4}-\d{2}-\d{2}$/;

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Middleware simple de "sesion": header X-User-Id simulando al agricultor autenticado
function requireUser(req, res, next) {
  const userId = req.header('X-User-Id');
  if (!userId || !/^[a-zA-Z0-9_-]{1,40}$/.test(userId)) {
    return res.status(401).json({ error: 'X-User-Id invalido o ausente' });
  }
  req.userId = userId;
  next();
}

function requireAdmin(req, res, next) {
  const token = req.header('X-Admin-Token');
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Token de administrador invalido' });
  }
  next();
}

// -----------------------------------------------------------------------
// A01 (mitigado) - Control de acceso: valida propiedad de la zona
// -----------------------------------------------------------------------
app.post('/api/riego/:zona_id/estado', requireUser, (req, res) => {
  const { zona_id } = req.params;
  const { activo } = req.body;

  if (!REGEX_ZONA_ID.test(zona_id)) {
    return res.status(400).json({ error: 'zona_id invalido (formato esperado: zona-N)' });
  }
  const zona = zonasRiego[zona_id];
  if (!zona) return res.status(404).json({ error: 'zona no encontrada' });

  // Zero Trust: se valida explicitamente que el usuario sea el propietario
  if (zona.propietario !== req.userId) {
    return res.status(403).json({ error: 'no tiene permiso sobre esta zona' });
  }
  if (typeof activo !== 'boolean') {
    return res.status(400).json({ error: 'el campo "activo" debe ser boolean' });
  }
  zona.riego_activo = activo;
  res.json({ mensaje: 'riego actualizado correctamente', zona });
});

// -----------------------------------------------------------------------
// A03 (mitigado) - Reporte historico con consultas parametrizadas
// -----------------------------------------------------------------------
app.get('/api/reportes/historico', (req, res) => {
  const zona = req.query.zona_id;

  if (!zona || !REGEX_ZONA_ID.test(zona)) {
    return res.status(400).json({ error: 'zona_id invalido (formato esperado: zona-N)' });
  }

  // Si se envia fecha, tambien se valida estrictamente
  const fecha = req.query.fecha;
  if (fecha && !REGEX_FECHA.test(fecha)) {
    return res.status(400).json({ error: 'fecha invalida (formato esperado: YYYY-MM-DD)' });
  }

  const sql = fecha
    ? 'SELECT * FROM lecturas WHERE zona_id = ? AND fecha = ?'
    : 'SELECT * FROM lecturas WHERE zona_id = ?';
  const params = fecha ? [zona, fecha] : [zona];

  // Consulta parametrizada: el motor nunca interpreta el input como SQL
  db.all(sql, params, (err, rows) => {
    if (err) {
      // No se expone el mensaje crudo del motor ni el SQL ejecutado
      return res.status(500).json({ error: 'error interno al consultar el historico' });
    }
    res.json({ resultados: rows });
  });
});

// -----------------------------------------------------------------------
// A05 (mitigado) - Consola de administracion protegida con token
// -----------------------------------------------------------------------
app.get('/admin/sensores', requireAdmin, (req, res) => {
  res.json({ zonas: zonasRiego, estaciones });
});

// Manejo de errores controlado (sin stack trace al cliente)
app.get('/debug/crash', (req, res, next) => {
  try {
    throw new Error('Fallo simulado');
  } catch (e) {
    next(e);
  }
});

// -----------------------------------------------------------------------
// A07 (mitigado) - API key desde variable de entorno (no hardcoded)
// -----------------------------------------------------------------------
app.get('/api/sensores/datos', (req, res) => {
  const key = req.header('X-Api-Key');
  if (!API_KEY || key !== API_KEY) {
    return res.status(401).json({ error: 'API key invalida' });
  }
  res.json({ mensaje: 'acceso concedido' });
});

// -----------------------------------------------------------------------
// A08 (mitigado) - XSS: whitelist al guardar + escape al renderizar
// -----------------------------------------------------------------------
app.post('/api/estaciones', (req, res) => {
  const { nombre } = req.body;
  if (typeof nombre !== 'string' || !REGEX_NOMBRE_SEGURO.test(nombre)) {
    return res.status(400).json({
      error: 'nombre invalido: solo letras, numeros, espacios y guiones (max 60 caracteres)',
    });
  }
  const nueva = { id: estaciones.length + 1, nombre };
  estaciones.push(nueva);
  res.json({ mensaje: 'estacion creada', estacion: nueva });
});

app.get('/api/estaciones', (req, res) => {
  // Output encoding: se escapa cualquier caracter HTML antes de renderizar
  const filas = estaciones.map(e => `<li>${escapeHtml(e.nombre)}</li>`).join('');
  res.send(`<html><body><h1>Estaciones</h1><ul>${filas}</ul></body></html>`);
});

// Manejador de errores: nunca expone stack trace al cliente
app.use((err, req, res, next) => {
  console.error('[server] error interno:', err.message);
  res.status(400).json({ error: 'solicitud invalida o error interno controlado' });
});

app.listen(PORT, () => {
  console.log(`AgriSmart API (SEGURA) escuchando en http://0.0.0.0:${PORT}`);
});
