'use strict';

/*
 * Version REMEDIADA de la app de demostracion (rama `remediacion`).
 * Cada correccion referencia la vulnerabilidad original [VULN-xx] documentada
 * en ../../docs/findings-walkthrough.md.
 */

const express = require('express');
const crypto = require('crypto');
const dns = require('dns').promises;
const { getUserByName } = require('./db');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

// [FIX-01] Sin credenciales en el codigo: se leen del entorno / gestor de secretos.
const AWS_CONFIG = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
};

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// [FIX-02] Consulta parametrizada: el valor viaja separado del texto SQL.
app.get('/users', (req, res) => {
  const name = String(req.query.name || '');
  getUserByName('SELECT * FROM users WHERE name = ?', [name], (err, rows) => {
    if (err) return res.status(500).json({ error: 'internal error' });
    res.json(rows);
  });
});

// [FIX-03] Sin shell: se valida el host con una allowlist y se resuelve con DNS
// en lugar de ejecutar `ping` en el sistema operativo.
const HOST_RE = /^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
app.get('/ping', async (req, res) => {
  const host = String(req.query.host || '');
  if (!HOST_RE.test(host)) return res.status(400).json({ error: 'invalid host' });
  try {
    const { address } = await dns.lookup(host);
    res.json({ host, reachable: true, address });
  } catch (_e) {
    res.json({ host, reachable: false });
  }
});

// [FIX-04] Derivacion de clave lenta y con sal (scrypt) en lugar de MD5.
app.post('/register', (req, res) => {
  const password = String(req.body.password || '');
  const salt = crypto.randomBytes(16);
  crypto.scrypt(password, salt, 64, (err, key) => {
    if (err) return res.status(500).json({ error: 'internal error' });
    res.json({
      user: String(req.body.username || ''),
      passwordHash: `scrypt$${salt.toString('hex')}$${key.toString('hex')}`,
    });
  });
});

// [FIX-05] Sin merge profundo de entrada no confiable: solo campos permitidos,
// sobre un objeto sin prototipo. Ademas lodash se actualizo (FIX-06).
const ALLOWED_FIELDS = ['displayName', 'theme', 'language'];
app.post('/merge', (req, res) => {
  const target = Object.create(null);
  for (const field of ALLOWED_FIELDS) {
    if (typeof req.body[field] === 'string') target[field] = req.body[field];
  }
  res.json({ ...target });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`demo app listening on :${PORT}`));

module.exports = { app, AWS_CONFIG };
