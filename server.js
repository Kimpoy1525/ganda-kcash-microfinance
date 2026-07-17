'use strict';

require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { stringify } = require('csv-stringify/sync');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || (IS_PRODUCTION ? '' : crypto.randomBytes(32).toString('hex'));
const DATA_DIR = path.join(__dirname, 'data');
const CSV_PATH = path.join(DATA_DIR, 'loan-applications.csv');
const CSV_HEADERS = ['ID', 'Timestamp', 'Full Name', 'Contact Number', 'Email', 'Loan Amount', 'Address', 'Loan Purpose', 'Branch', 'Status', 'Source'];
const BRANCHES = ['Camiling - Main Branch', 'Bayambang Branch', 'Malasiqui Branch', 'Moncada Branch'];
const PURPOSES = ['business', 'agriculture', 'education', 'medical', 'home', 'personal', 'other'];
const STATUSES = ['PENDING', 'APPROVED', 'DECLINED'];
const csrfTokens = new Map();

if (IS_PRODUCTION && (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12 || !SESSION_SECRET || SESSION_SECRET.length < 32)) {
  throw new Error('Production requires ADMIN_PASSWORD (12+ characters) and SESSION_SECRET (32+ characters).');
}
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(CSV_PATH)) fs.writeFileSync(CSV_PATH, stringify([CSV_HEADERS]), { encoding: 'utf8', mode: 0o600 });

app.disable('x-powered-by');
if (IS_PRODUCTION) app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], imgSrc: ["'self'", 'data:'], styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], connectSrc: ["'self'"], objectSrc: ["'none'"],
      baseUri: ["'self'"], frameAncestors: ["'none'"], formAction: ["'self'"], upgradeInsecureRequests: IS_PRODUCTION ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
app.use(express.json({ limit: '12kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '12kb' }));
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'deny', etag: true, maxAge: IS_PRODUCTION ? '1h' : 0 }));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many requests. Please try again later.' } });
const submitLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many applications from this connection. Please try again later.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, skipSuccessfulRequests: true, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many login attempts. Please wait 15 minutes.' } });
app.use('/api', apiLimiter);

function clean(value, max) {
  return typeof value === 'string' ? value.normalize('NFKC').replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max) : '';
}
function safeCsv(value) {
  const text = String(value);
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}
function validateLoan(body = {}) {
  const data = {
    fullName: clean(body.fullName, 80), contactNumber: clean(body.contactNumber, 20), email: clean(body.email, 120).toLowerCase(),
    loanAmount: clean(body.loanAmount, 20).replace(/,/g, ''), address: clean(body.address, 220),
    loanPurpose: clean(body.loanPurpose, 30).toLowerCase(), branch: clean(body.branch, 80),
  };
  const errors = [];
  if (!/^[\p{L}][\p{L}\p{M} .'-]{1,79}$/u.test(data.fullName)) errors.push('Enter a valid full name.');
  if (!/^(?:09\d{9}|\+639\d{9})$/.test(data.contactNumber.replace(/[ -]/g, ''))) errors.push('Enter a valid Philippine mobile number.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.email)) errors.push('Enter a valid email address.');
  const amount = Number(data.loanAmount);
  if (!Number.isFinite(amount) || amount < 1000 || amount > 1000000 || !/^\d+(?:\.\d{1,2})?$/.test(data.loanAmount)) errors.push('Loan amount must be between ₱1,000 and ₱1,000,000.');
  if (data.address.length < 8) errors.push('Enter a complete address.');
  if (!PURPOSES.includes(data.loanPurpose)) errors.push('Select a valid loan purpose.');
  if (!BRANCHES.includes(data.branch)) errors.push('Select a valid branch.');
  return { data, errors };
}
function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(v => v.trim().split(/=(.*)/s)).filter(v => v[0]).map(([k, v]) => [k, decodeURIComponent(v || '')]));
}
function sign(payload) { return `${payload}.${crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url')}`; }
function validSession(req) {
  const token = parseCookies(req.headers.cookie).kcash_admin;
  if (!token) return false;
  const split = token.lastIndexOf('.');
  if (split < 1) return false;
  const payload = token.slice(0, split), signature = token.slice(split + 1), expected = sign(payload).slice(split + 1);
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  const [expires, nonce] = payload.split('.');
  return Boolean(nonce) && Number(expires) > Date.now();
}
function requireAdmin(req, res, next) { return validSession(req) ? next() : res.status(401).json({ error: 'Your admin session has expired. Please sign in again.' }); }
function sameOrigin(req) {
  const origin = req.get('origin');
  if (!origin) return true;
  try { return new URL(origin).host === req.get('host'); } catch { return false; }
}
function parseCsv(text) {
  const rows = []; let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' && quoted && text[i + 1] === '"') { field += '"'; i++; }
    else if (c === '"') quoted = !quoted;
    else if (c === ',' && !quoted) { row.push(field); field = ''; }
    else if ((c === '\n' || c === '\r') && !quoted) { if (c === '\r' && text[i + 1] === '\n') i++; row.push(field); if (row.some(Boolean)) rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

setInterval(() => { const now = Date.now(); for (const [token, expiry] of csrfTokens) if (expiry < now) csrfTokens.delete(token); }, 10 * 60 * 1000).unref();

app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('base64url'); csrfTokens.set(token, Date.now() + 30 * 60 * 1000);
  res.set('Cache-Control', 'no-store').json({ token, expiresIn: 1800 });
});
app.post('/api/submit-loan', submitLimiter, (req, res) => {
  const token = req.get('x-csrf-token');
  if (!sameOrigin(req) || !token || (csrfTokens.get(token) || 0) < Date.now()) return res.status(403).json({ error: 'Security check expired. Refresh the page and try again.' });
  csrfTokens.delete(token);
  const { data, errors } = validateLoan(req.body);
  if (errors.length) return res.status(400).json({ error: 'Please check the highlighted information.', details: errors });
  const id = uuidv4().split('-')[0].toUpperCase();
  const row = [id, new Date().toISOString(), data.fullName, data.contactNumber, data.email, Number(data.loanAmount).toFixed(2), data.address, data.loanPurpose, data.branch, 'PENDING', 'Website'].map(safeCsv);
  fs.appendFileSync(CSV_PATH, stringify([row]), 'utf8');
  res.status(201).json({ success: true, message: 'Your application has been received.', referenceId: id });
});
app.post('/api/admin/login', loginLimiter, (req, res) => {
  if (!sameOrigin(req)) return res.status(403).json({ error: 'Request origin was rejected.' });
  const supplied = typeof req.body.password === 'string' ? req.body.password : '';
  const a = crypto.createHash('sha256').update(supplied).digest(), b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
  if (!ADMIN_PASSWORD || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Invalid password.' });
  const expiry = Date.now() + 8 * 60 * 60 * 1000;
  res.cookie('kcash_admin', sign(`${expiry}.${crypto.randomBytes(16).toString('hex')}`), { httpOnly: true, secure: IS_PRODUCTION, sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000, path: '/api/admin' });
  res.json({ success: true });
});
app.post('/api/admin/logout', requireAdmin, (req, res) => { res.clearCookie('kcash_admin', { httpOnly: true, secure: IS_PRODUCTION, sameSite: 'strict', path: '/api/admin' }); res.json({ success: true }); });
app.get('/api/admin/submissions', requireAdmin, (req, res) => { res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="loan-applications.csv"', 'Cache-Control': 'no-store' }); res.send(fs.readFileSync(CSV_PATH, 'utf8')); });
app.get('/api/admin/stats', requireAdmin, (req, res) => { const rows = parseCsv(fs.readFileSync(CSV_PATH, 'utf8')).slice(1); res.set('Cache-Control', 'no-store').json({ success: true, totalSubmissions: rows.length, pending: rows.filter(r => r[9] === 'PENDING').length, lastUpdated: new Date().toISOString() }); });
app.post('/api/admin/update-status', requireAdmin, (req, res) => {
  if (!sameOrigin(req)) return res.status(403).json({ error: 'Request origin was rejected.' });
  const id = clean(req.body.id, 12), status = clean(req.body.status, 20).toUpperCase();
  if (!/^[A-F0-9]{8}$/.test(id) || !STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid application or status.' });
  const rows = parseCsv(fs.readFileSync(CSV_PATH, 'utf8')); const record = rows.slice(1).find(r => r[0] === id);
  if (!record) return res.status(404).json({ error: 'Application not found.' });
  record[9] = status;
  const temp = `${CSV_PATH}.${process.pid}.tmp`; fs.writeFileSync(temp, stringify(rows), { encoding: 'utf8', mode: 0o600 }); fs.renameSync(temp, CSV_PATH);
  res.json({ success: true });
});
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => { console.error('[ERROR]', err.message); if (res.headersSent) return next(err); res.status(err.type === 'entity.too.large' ? 413 : 500).json({ error: 'The request could not be completed.' }); });

if (require.main === module) app.listen(PORT, '0.0.0.0', () => console.log(`G&A KCash listening on port ${PORT} (${IS_PRODUCTION ? 'production' : 'development'})`));
module.exports = app;
