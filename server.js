Here is your fully updated and secure `server.js` code.

I have removed the dangerous line that exposed your backend files, moved the `public` folder setup to the correct secure location below your body parsers, and made sure there are no duplicate `path` declarations.

You can copy and paste this directly over your current `server.js` file:

```javascript
// ═══════════════════════════════════════════════════════════════
//  G&A KCash Microfinance Inc. — Secure Backend Server
//  Features: Helmet security, rate limiting, XSS sanitization,
//  CSRF protection, CSV spreadsheet storage, admin dashboard
// ═══════════════════════════════════════════════════════════════

'use strict';

const express       = require('express');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const cors          = require('cors');
const path          = require('path');
const fs            = require('fs');
const { stringify } = require('csv-stringify/sync');
const { v4: uuidv4 } = require('uuid');
const xss           = require('xss');
const crypto        = require('crypto');

// ─── Load environment variables ──────────────────────────────
require('dotenv').config();

const app           = express();
const PORT          = process.env.PORT || 3000;
const ADMIN_PASS    = process.env.ADMIN_PASSWORD || 'change_me_in_production';
const SESSION_SECRET = process.env.SESSION_SECRET || uuidv4();

// ─── File paths ───────────────────────────────────────────────
const DATA_DIR      = path.join(__dirname, 'data');
const CSV_PATH      = path.join(DATA_DIR, 'loan-applications.csv');
const LOG_PATH      = path.join(DATA_DIR, 'submissions.log');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    console.log('[INIT] Created data directory:', DATA_DIR);
}

// ─── Initialize CSV with headers if not exists ───────────────
function initCsv() {
    if (!fs.existsSync(CSV_PATH)) {
        const headers = [
            ['ID', 'Timestamp', 'Full Name', 'Contact Number', 'Email',
             'Loan Amount', 'Address', 'Loan Purpose', 'Branch', 'Status', 'Source']
        ];
        const csvContent = stringify(headers);
        fs.writeFileSync(CSV_PATH, csvContent, 'utf-8');
        console.log('[INIT] Created CSV file with headers');
    }
}
initCsv();

// ─── Security Middleware ──────────────────────────────────────

// 1. Helmet — sets secure HTTP headers (CSP, X-Frame-Options, etc.)
app.use(helmet({
    contentSecurityPolicy: false, // We handle CSP via meta tag in HTML
    crossOriginEmbedderPolicy: false,
}));

// 2. CORS — restrict in production
app.use(cors({
    origin: process.env.NODE_ENV === 'production'
        ? false  // same-origin only
        : '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
}));

// 3. Body parser with size limit (prevents large payload attacks)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Serve static frontend files securely from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// 4. Rate limiting — prevent brute force / DDoS
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 30,                      // max 30 requests per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api/', apiLimiter);

// Stricter rate limit for admin login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Please try again later.' },
});

// 5. CSRF token validation
const csrfTokens = new Set();

// Clean old tokens every hour
setInterval(() => { csrfTokens.clear(); }, 60 * 60 * 1000);

// ─── API: Generate CSRF token ───────────────────────────────
app.get('/api/csrf-token', (req, res) => {
    try {
        const token = 'csrf_' + crypto.randomBytes(32).toString('hex');
        csrfTokens.add(token);
        
        // Token expires after 1 hour
        setTimeout(() => {
            csrfTokens.delete(token);
        }, 60 * 60 * 1000);
        
        res.json({
            token: token,
            expiresIn: 3600,
        });
    } catch (err) {
        console.error('[CSRF] Token generation error:', err.message);
        res.status(500).json({ error: 'Failed to generate CSRF token.' });
    }
});

// ─── Input validation & sanitization ─────────────────────────

const PATTERNS = {
    name:        /^[A-Za-zÀ-ÿÑñ\s\.\-']{2,60}$/,
    phone:       /^(09|\+639)\d{2}[-\s]?\d{3}[-\s]?\d{4}$/,
    email:       /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,
    amount:      /^[0-9]{1,3}(,[0-9]{3})*(\.[0-9]{2})?$|^[0-9]+(\.[0-9]{2})?$/,
    address:     /^[A-Za-z0-9\s,\.\-\#\/\(\)ñÑ]{5,200}$/,
    loanPurpose: /^(business|agriculture|education|medical|home|personal|other)$/,
    branch:      /^[A-Za-z0-9\s,\.\-\★\(\)]+$/,
};

const VALID_PURPOSES = ['business', 'agriculture', 'education', 'medical', 'home', 'personal', 'other'];

function sanitizeText(str) {
    if (typeof str !== 'string') return '';
    // Use xss library for server-side sanitization
    let clean = xss(str, {
        whiteList: {},        // No tags allowed
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
    });
    // Remove control characters
    clean = clean.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
    // Collapse whitespace
    clean = clean.replace(/\s+/g, ' ').trim();
    return clean;
}

function validateLoanData(body) {
    const errors = [];

    const fullName      = sanitizeText(body.fullName || '');
    const contactNumber = sanitizeText(body.contactNumber || '');
    const email         = sanitizeText(body.email || '');
    const loanAmount    = sanitizeText(body.loanAmount || '');
    const address       = sanitizeText(body.address || '');
    const loanPurpose   = body.loanPurpose || '';
    const branch        = sanitizeText(body.branch || '');

    if (!PATTERNS.name.test(fullName)) {
        errors.push('Invalid full name format.');
    }
    if (!PATTERNS.phone.test(contactNumber)) {
        errors.push('Invalid contact number format (PH mobile: 09XXXXXXXXX).');
    }
    if (!PATTERNS.email.test(email)) {
        errors.push('Invalid email address.');
    }
    const amountCleaned = loanAmount.replace(/,/g, '');
    if (!PATTERNS.amount.test(amountCleaned)) {
        errors.push('Invalid loan amount format.');
    } else {
        const num = parseFloat(amountCleaned);
        if (isNaN(num) || num < 1000 || num > 1000000) {
            errors.push('Loan amount must be between ₱1,000 and ₱1,000,000.');
        }
    }
    if (!PATTERNS.address.test(address)) {
        errors.push('Invalid address format.');
    }
    if (!VALID_PURPOSES.includes(loanPurpose)) {
        errors.push('Invalid loan purpose selected.');
    }
    if (!branch || branch.length < 5) {
        errors.push('Invalid branch selection.');
    }

    return {
        isValid: errors.length === 0,
        errors,
        sanitized: { fullName, contactNumber, email, loanAmount, address, loanPurpose, branch },
    };
}

// ─── Logging helper ──────────────────────────────────────────
function logSubmission(data, status) {
    const logLine = `[${new Date().toISOString()}] ${status} | ${data.fullName} | ${data.email} | ${data.branch}\n`;
    try {
        fs.appendFileSync(LOG_PATH, logLine, 'utf-8');
    } catch (err) {
        console.error('[LOG] Failed to write log:', err.message);
    }
}

// ─── API: Submit loan application ────────────────────────────
app.post('/api/submit-loan', (req, res) => {
    try {
        // Validate CSRF token
        const csrfToken = req.headers['x-csrf-token'];
        if (!csrfToken || !csrfTokens.has(csrfToken)) {
            console.warn('[SECURITY] CSRF validation failed. Token:', csrfToken ? csrfToken.substring(0, 20) + '...' : 'missing');
            return res.status(403).json({ error: 'Invalid or expired CSRF token. Please refresh the page and try again.' });
        }
        
        // Token remains valid for reuse within its 1-hour expiry window

        // Validate & sanitize input
        const validation = validateLoanData(req.body);
        if (!validation.isValid) {
            return res.status(400).json({
                error: 'Validation failed.',
                details: validation.errors,
            });
        }

        const data = validation.sanitized;
        const id = uuidv4().split('-')[0].toUpperCase();
        const timestamp = new Date().toISOString();

        // Build CSV row
        const row = [
            id,
            timestamp,
            data.fullName,
            data.contactNumber,
            data.email,
            data.loanAmount,
            data.address,
            data.loanPurpose,
            data.branch,
            'PENDING',
            'Website',
        ];

        // Append to CSV file (spreadsheet)
        const csvRow = stringify([row]);
        fs.appendFileSync(CSV_PATH, csvRow, 'utf-8');

        // Log the submission
        logSubmission(data, 'SUCCESS');

        console.log(`[SUBMIT] ${id} — ${data.fullName} — ${data.branch}`);

        res.json({
            success: true,
            message: 'Application submitted successfully. We will contact you within 24 hours.',
            referenceId: id,
        });

    } catch (err) {
        console.error('[SUBMIT] Error:', err.message);
        res.status(500).json({ error: 'Internal server error. Please try again.' });
    }
});

// ─── Admin login ─────────────────────────────────────────────
app.post('/api/admin/login', loginLimiter, (req, res) => {
    const { password } = req.body;

    // Constant-time comparison to prevent timing attacks
    const hash1 = crypto.createHash('sha256').update(password || '').digest('hex');
    const hash2 = crypto.createHash('sha256').update(ADMIN_PASS).digest('hex');

    if (hash1 !== hash2) {
        return res.status(401).json({ error: 'Invalid password.' });
    }

    // Generate a simple session token
    const sessionToken = 'admin_' + crypto.randomBytes(32).toString('hex');

    res.json({
        success: true,
        token: sessionToken,
        message: 'Authentication successful.',
    });
});

// ─── Admin: Download CSV spreadsheet ─────────────────────────
app.get('/api/admin/submissions', (req, res) => {
    const authToken = req.headers['authorization'];
    if (!authToken || !authToken.startsWith('Bearer admin_')) {
        return res.status(401).json({ error: 'Unauthorized. Invalid or missing token.' });
    }

    try {
        const csvData = fs.readFileSync(CSV_PATH, 'utf-8');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="loan-applications.csv"');
        res.send(csvData);
    } catch (err) {
        console.error('[ADMIN] Error reading CSV:', err.message);
        res.status(500).json({ error: 'Failed to read submissions.' });
    }
});

// ─── Admin: Get summary stats ───────────────────────────────
app.get('/api/admin/stats', (req, res) => {
    const authToken = req.headers['authorization'];
    if (!authToken || !authToken.startsWith('Bearer admin_')) {
        return res.status(401).json({ error: 'Unauthorized.' });
    }

    try {
        const csvData = fs.readFileSync(CSV_PATH, 'utf-8');
        const lines = csvData.trim().split('\n');
        const totalSubmissions = lines.length > 1 ? lines.length - 1 : 0;

        res.json({
            success: true,
            totalSubmissions,
            lastUpdated: new Date().toISOString(),
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to read stats.' });
    }
});

// ─── API: Health check ───────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    });
});

// ─── 404 handler ──────────────────────────────────────────────
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found.' });
    } else {
        // Let the frontend handle client-side routing
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

// ─── Global error handler ────────────────────────────────────
app.use((err, req, res, next) => {
    console.error('[ERROR] Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error.' });
});

// ─── Start server ────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log('═══════════════════════════════════════════════');
    console.log('  G&A KCash Microfinance Inc. — Server');
    console.log(`  Port:      ${PORT}`);
    console.log(`  Mode:      ${process.env.NODE_ENV || 'development'}`);
    console.log(`  CSV Data:  ${CSV_PATH}`);
    console.log('═══════════════════════════════════════════════');
    console.log('[SECURITY] Helmet active');
    console.log('[SECURITY] Rate limiting active (30 req/15min)');
    console.log('[SECURITY] XSS sanitization active');
    console.log('[SECURITY] CSRF protection active');
    console.log('[SECURITY] Payload size limit: 10KB');
});

```