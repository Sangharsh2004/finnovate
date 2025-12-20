// /mnt/data/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
let nodeFetch;
try {
  // handle node-fetch v3 ESM default export when required from CJS
  nodeFetch = require('node-fetch').default || require('node-fetch');
} catch (e) {
  nodeFetch = undefined;
}
const AbortController = global.AbortController || (() => {
  try { return require('abort-controller'); } catch (_) { return undefined; }
})();
const nodeCron = require('node-cron');
const { createObjectCsvWriter } = require('csv-writer');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const validator = require('validator');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const DBFILE = path.join(__dirname, 'data.sqlite');
if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is required in .env");
}
const JWT_SECRET = process.env.JWT_SECRET;

const SALT_ROUNDS = Number(process.env.SALT_ROUNDS || 10);
const ML_SERVICE = process.env.ML_SERVICE || 'http://localhost:5000';
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@datapulse.local';
const EMAIL_TRANSPORTER = {
  host: process.env.SMTP_HOST || '',
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true' || false,
  auth: process.env.SMTP_USER ? {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  } : undefined
};
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 10);
const EXPORTS_DIR = path.join(__dirname, 'exports');
if (!fs.existsSync(EXPORTS_DIR)) fs.mkdirSync(EXPORTS_DIR, { recursive: true });

// CORS origin (allow override via .env)
// CORS origin (allow override via .env)
const ALLOWED_ORIGIN = process.env.CORS_ORIGIN || '*';

app.use(cors({
  origin: ALLOWED_ORIGIN,
  credentials: true
}));


// create nodemailer transporter (if configured)
let mailer = null;
if (EMAIL_TRANSPORTER.host && EMAIL_TRANSPORTER.auth && EMAIL_TRANSPORTER.auth.user) {
  try {
    mailer = nodemailer.createTransport(EMAIL_TRANSPORTER);
    // verify transporter safely (async)
    mailer.verify().then(() => {
      console.log('✅ Email transporter ready.');
    }).catch(err => {
      console.warn('⚠️ Email transporter verification failed:', err && err.message ? err.message : err);
      mailer = null; // disable mailing if invalid
    });
  } catch (e) {
    console.warn('⚠️ Mailer setup failed:', e && e.message ? e.message : e);
    mailer = null;
  }
} else {
  console.warn('⚠️ Email transporter not configured. OTP/email will not be sent until SMTP env vars provided.');
}

// middlewares
app.use(helmet());
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json({ limit: '1mb' })); // FIXED: set reasonable body size limit
app.use(express.urlencoded({ extended: false }));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // limit each IP to 20 requests per windowMs
  message: { success: false, message: 'Too many requests, slow down.' }
});
const sensitiveLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 6, // more strict for OTP / login attempts per minute
  message: { success: false, message: 'Too many requests, try again later.' }
});
app.use('/api/login', sensitiveLimiter);
app.use('/api/verify-otp', sensitiveLimiter);
app.use('/api/resend-otp', sensitiveLimiter);
app.use('/api/signup', sensitiveLimiter);

// initialize sqlite db
const db = new sqlite3.Database(DBFILE, (err) => {
  if (err) {
    console.error('Failed to open SQLite DB:', err);
    process.exit(1);
  }
  console.log('SQLite database ready at', DBFILE);
});

// create tables + indexes
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_verified INTEGER DEFAULT 0,
      monthly_budget REAL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      category TEXT,
      amount REAL NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      otp TEXT NOT NULL,
      purpose TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      used INTEGER DEFAULT 0
  )`);
  // indexes
  db.run(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_transactions_userid ON transactions(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_otps_email ON otps(email)`);
});

// Helper: run SQL with Promise
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

// -------------------
// SSE real-time connections
// -------------------
const sseConnections = new Map(); // userId => Set of response objects

function addSseConnection(userId, res) {
  if (!sseConnections.has(userId)) sseConnections.set(userId, new Set());
  sseConnections.get(userId).add(res);
}

function removeSseConnection(userId, res) {
  if (!sseConnections.has(userId)) return;
  sseConnections.get(userId).delete(res);
  if (sseConnections.get(userId).size === 0) sseConnections.delete(userId);
}

function emitToUser(userId, eventName, data) {
  const set = sseConnections.get(userId);
  if (!set) return;
  const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const r of set) {
    try { r.write(payload); } catch (e) { removeSseConnection(userId, r); }
  }
}

// auth middleware
function auth(req, res, next) {
  const a = req.headers.authorization;
  if (!a) return res.status(401).json({ success: false, message: 'No token' });
  const parts = a.split(' ');
  if (parts.length !== 2) return res.status(401).json({ success: false, message: 'Bad auth' });
  const token = parts[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ success: false, message: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Utility: generate numeric OTP (6 digits)
function generateOtp(len = 6) {
  const max = Math.pow(10, len) - 1;
  const num = Math.floor(Math.random() * (max + 1));
  return String(num).padStart(len, '0');
}

// Utility: send email (best-effort)
async function sendEmail({ to, subject, text, html, attachments = [] }) {
  if (!mailer) {
    console.warn('Mailer not configured. Skipping email to', to);
    return { success: false, message: 'Mailer not configured' };
  }
  const mailOptions = {
    from: EMAIL_FROM,
    to,
    subject,
    text,
    html,
    attachments
  };
  try {
    const info = await mailer.sendMail(mailOptions);
    return { success: true, info };
  } catch (err) {
    console.error('sendEmail error:', err && err.message ? err.message : err);
    return { success: false, message: err && err.message ? err.message : 'Email send failed' };
  }
}

// fetch with timeout (works with node-fetch and native fetch)
async function fetchWithTimeout(url, opts = {}, timeoutMs = 3000) {
  const Controller = AbortController;
  const controller = Controller ? new Controller() : null;
  let timer;
  if (controller) timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const fetchFn = (typeof fetch === 'function') ? fetch : (nodeFetch || (() => { throw new Error('fetch not available') }));
    const res = await fetchFn(url, { ...opts, signal: controller ? controller.signal : undefined });
    return res;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// simple email validator
function isEmailLike(e) {
  return typeof e === 'string' && validator.isEmail(e);
}

// helper to format JS Date to SQLite-friendly "YYYY-MM-DD HH:MM:SS"
function toSqliteTime(d = new Date()) {
  // FIXED: Use UTC ISO trimmed to seconds (consistent) - stored as "YYYY-MM-DD HH:MM:SS" in UTC
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

// =================================================================
function generateRecommendation(totalIncome, totalExpense, netSavings) {
  const insights = [];

  // Safety checks
  totalIncome = Number(totalIncome) || 0;
  totalExpense = Number(totalExpense) || 0;
  netSavings = Number(netSavings) || 0;

  if (totalIncome <= 0) {
    return {
      healthScore: 0,
      summary: "No income recorded.",
      insights: [
        "Start by adding your income to get accurate financial insights.",
        "Track expenses daily to understand spending habits."
      ],
      advice: "Add income data to unlock smart recommendations."
    };
  }

  const expenseRatio = totalExpense / totalIncome;     // % of income spent
  const savingRatio = netSavings / totalIncome;        // % of income saved

  /* -----------------------
     HEALTH SCORE (0–100)
  ------------------------ */
  let healthScore = 100;

  if (expenseRatio > 1) healthScore -= 50;
  else if (expenseRatio > 0.9) healthScore -= 30;
  else if (expenseRatio > 0.75) healthScore -= 15;

  if (savingRatio < 0.1) healthScore -= 25;
  else if (savingRatio < 0.2) healthScore -= 10;

  healthScore = Math.max(0, Math.min(100, Math.round(healthScore)));

  /* -----------------------
     CORE INSIGHTS
  ------------------------ */
  if (totalExpense > totalIncome) {
    insights.push("🚨 Your expenses are higher than your income.");
    insights.push("Cut non-essential spending such as food delivery, shopping, and subscriptions.");
  }

  if (expenseRatio >= 0.9 && expenseRatio <= 1) {
    insights.push("⚠️ You are spending more than 90% of your income.");
    insights.push("Create strict monthly limits for top expense categories.");
  }

  if (expenseRatio >= 0.7 && expenseRatio < 0.9) {
    insights.push("📊 Expenses are between 70–90% of income.");
    insights.push("Optimizing 1–2 categories can significantly improve savings.");
  }

  if (savingRatio < 0.1) {
    insights.push("💸 Savings are very low (<10%).");
    insights.push("Aim to save at least 20% of your income.");
  }

  if (savingRatio >= 0.2) {
    insights.push("✅ Strong savings habit detected.");
    insights.push("You are financially disciplined. Keep it up!");
  }

  /* -----------------------
     SMART ACTION PLAN
  ------------------------ */
  let advice = "Track expenses regularly.";

  if (savingRatio >= 0.2) {
    advice =
      "Consider investing in mutual funds, SIPs, or building an emergency fund (6 months expenses).";
  } else if (savingRatio >= 0.1) {
    const target = Math.round(totalIncome * 0.2);
    advice = `Try increasing savings to ₹${target} per month for better financial stability.`;
  } else {
    advice =
      "Focus on reducing unnecessary expenses before thinking about investments.";
  }

  /* -----------------------
     FINAL RESPONSE
  ------------------------ */
  return {
    healthScore, // 0–100
    summary: `You spent ${Math.round(expenseRatio * 100)}% of your income and saved ${Math.round(savingRatio * 100)}%.`,
    insights,
    advice
  };
}

// =================================================================
// API: Info / Health
app.get('/api/info', (req, res) => {
  res.json({
    success: true,
    version: 'Advanced Backend - Version C.1 (fixed)',
    features: [
      'User Authentication (bcrypt + JWT)',
      'SQLite Persistence',
      'OTP-based Email Verification (signup)',
      'CSV Export & CSV-email (Nodemailer)',
      'Dashboard Summaries, Alerts, Cron Job',
      'ML Categorization Hook (best effort)'
    ],
    mlServiceUrl: ML_SERVICE,
    mailerConfigured: !!mailer
  });
});

app.get('/', (req, res) => res.json({ success: true, message: 'API OK (Advanced Backend - Version C.1)' }));

// =====================
// SIGNUP WITH EMAIL OTP VERIFICATION (English + Marathi)
// =====================

app.post('/api/send-signup-otp', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: 'All fields are required..' });

    const lowerEmail = String(email).toLowerCase().trim();

    if (!isEmailLike(lowerEmail)) return res.status(400).json({ success: false, message: 'Invalid email' });

    const existing = await dbGet('SELECT id FROM users WHERE email = ?', [lowerEmail]);
    if (existing)
      return res.status(400).json({ success: false, message: 'User already exists. Please login .' });

    const otp = generateOtp(6);
    const createdAt = toSqliteTime(new Date());
    const expiresAt = toSqliteTime(new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000));

    await dbRun(
      'INSERT INTO otps (email, otp, purpose, created_at, expires_at) VALUES (?,?,?,?,?)',
      [lowerEmail, otp, 'signup', createdAt, expiresAt]
    );

    // FIXED: Do not echo password in response. Keep only non-sensitive temp info.
    const emailRes = await sendEmail({
      to: lowerEmail,
      subject: 'DataPulse Signup OTP',
      html: `
        <p>Hello ${name},</p>
        <p>Your OTP for <b>DataPulse</b> account creation is <b>${otp}</b>.</p>
        <p>This OTP will expire in ${OTP_TTL_MINUTES} minutes.</p>
      `
    });

    // WARNING: Logging OTP in production is unsafe. Keep for dev only.
    console.log(`📨 Signup OTP (dev only): ${lowerEmail} -> ${otp} | Expires: ${expiresAt}`);

    res.json({
      success: true,
      message: 'OTP sent to your email. Please check your email and verify the otpSSS.',
      mailer: emailRes.success ? 'sent' : 'not-sent',
      temp: { name, email } // FIXED: removed password from temporary response for safety
    });
  } catch (err) {
    console.error('Signup OTP error:', err);
    res.status(500).json({ success: false, message: 'Server error (OTP send failed).' });
  }
});

// =====================
// VERIFY SIGNUP OTP → CREATE ACCOUNT
// =====================
app.post('/api/verify-signup-otp', async (req, res) => {
  try {
    const { name, email, password, otp } = req.body;
    if (!name || !email || !password || !otp)
      return res.status(400).json({ success: false, message: 'All information is required (Missing fields).' });

    const lowerEmail = String(email).toLowerCase().trim();

    const otpRow = await dbGet(
      `SELECT id, otp, expires_at, used FROM otps
       WHERE email = ? AND purpose = 'signup'
       ORDER BY id DESC LIMIT 1`,
      [lowerEmail]
    );

    if (!otpRow)
      return res.status(400).json({ success: false, message: 'OTP not found. Please request new OTP.' });

    // FIXED: parse stored UTC datetime by appending 'Z' to treat it as UTC.
    const expiry = new Date(otpRow.expires_at + 'Z');
    const now = new Date();

    if (expiry.getTime() < now.getTime())
      return res.status(400).json({ success: false, message: 'OTP is expired. Please order new.' });

    if (otpRow.used)
      return res.status(400).json({ success: false, message: 'OTP has already been used.' });

    if (String(otpRow.otp).trim() !== String(otp).trim())
      return res.status(400).json({ success: false, message: 'OTP is incorrect (Invalid OTP).' });

    // Create account securely
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const createdAt = toSqliteTime(new Date());
    const result = await dbRun(
      'INSERT INTO users (name, email, password, is_verified, created_at) VALUES (?,?,?,1,?)',
      [name, lowerEmail, hashed, createdAt]
    );

    await dbRun('UPDATE otps SET used = 1 WHERE id = ?', [otpRow.id]);

    const userId = result.lastID;
    const token = jwt.sign({ id: userId, email: lowerEmail }, JWT_SECRET, { expiresIn: '7d' });

    console.log(`✅ New user account has been created and verified: ${lowerEmail}`);

    res.json({
      success: true,
      message: 'Account created successfully 🎉. You are now logging in.',
      user: { id: userId, name, email: lowerEmail },
      token
    });
  } catch (err) {
    console.error('Verify signup OTP error:', err);
    res.status(500).json({ success: false, message: 'Server error during OTP verification.' });
  }
});

// -------------------
// Login (only allowed for verified users)
// -------------------
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Missing fields' });
    const lowerEmail = String(email).toLowerCase().trim();
    if (!isEmailLike(lowerEmail)) return res.status(400).json({ success: false, message: 'Invalid email' });

    const row = await dbGet('SELECT * FROM users WHERE email = ?', [lowerEmail]);
    if (!row) return res.status(400).json({ success: false, message: 'Invalid credentials' });
    if (!row.is_verified) return res.status(403).json({ success: false, message: 'Email not verified. Please verify via OTP.' });

    const ok = await bcrypt.compare(password, row.password);
    if (!ok) return res.status(400).json({ success: false, message: 'Invalid credentials' });

    const user = { id: row.id, name: row.name, email: row.email, monthly_budget: row.monthly_budget || 0 };
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name, monthly_budget: user.monthly_budget || 0 }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, user, token });
  } catch (err) {
    console.error('Login exception (vC.1):', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// -------------------
// Profile & Budget
// -------------------
app.get('/api/profile', auth, async (req, res) => {
  try {
    const row = await dbGet('SELECT id,name,email,monthly_budget,created_at FROM users WHERE id = ?', [req.user.id]);
    if (!row) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user: row });
  } catch (err) {
    console.error('Profile error:', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'DB error' });
  }
});

// --------------------
// SSE endpoint for real-time updates
// --------------------
app.get('/api/events', async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(401).json({ message: 'Token missing' });

    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); }
    catch { return res.status(401).json({ message: 'Invalid token' }); }

    const userId = decoded.id;

    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN
    });

    res.write("retry: 10000\n\n");
    addSseConnection(userId, res);

    // send initial snapshot (best-effort)
    (async () => {
      try {
        const sums = await dbGet(
          `SELECT 
            SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as totalIncome,
            SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as totalExpense
           FROM transactions WHERE user_id = ?`, [userId]);
        const totalIncome = Number((sums && sums.totalIncome) || 0);
        const totalExpense = Number((sums && sums.totalExpense) || 0);

        const row = await dbGet('SELECT monthly_budget FROM users WHERE id = ?', [userId]);
        const monthlyBudget = Number((row && row.monthly_budget) || 0);

        const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0,0,0,0);
        const monthStartStr = toSqliteTime(monthStart);
        const srow = await dbGet(
          `SELECT SUM(amount) as monthExpense FROM transactions WHERE user_id = ? AND type='expense' AND created_at >= ?`,
          [userId, monthStartStr]);
        const monthExpense = Number((srow && srow.monthExpense) || 0);

        const data = {
          monthlyBudget,
          monthExpense,
          remaining: Math.max(0, monthlyBudget - monthExpense),
          netSavings: totalIncome - totalExpense
        };
        res.write(`event: initial\n`);
        res.write(`data: ${JSON.stringify(data)}\n\n`);
      } catch(e) {
        // ignore snapshot errors
      }
    })();

    req.on("close", () => removeSseConnection(userId, res));
  } catch (err) {
    console.error(err);
  }
});

app.post('/api/budget', auth, async (req, res) => {
  try {
    const { userId, monthlyBudget } = req.body;
    if (!userId || Number(userId) !== Number(req.user.id)) return res.status(403).json({ success: false, message: 'Unauthorized userId' });
    const mb = Number(monthlyBudget || 0);
    if (Number.isNaN(mb)) return res.status(400).json({ success: false, message: 'Invalid monthlyBudget' });

    await dbRun('UPDATE users SET monthly_budget = ? WHERE id = ?', [mb, userId]);

    // compute month expense & totals for email + SSE
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0,0,0,0);
    const monthStartStr = toSqliteTime(monthStart);

    const srow = await dbGet(
      `SELECT SUM(amount) as monthExpense FROM transactions WHERE user_id = ? AND type='expense' AND created_at >= ?`,
      [userId, monthStartStr]);
    const monthExpense = Number((srow && srow.monthExpense) || 0);

    const sums = await dbGet(
      `SELECT 
          SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as totalIncome,
          SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as totalExpense
       FROM transactions WHERE user_id = ?`, [userId]);
    const totalIncome = Number((sums && sums.totalIncome) || 0);
    const totalExpense = Number((sums && sums.totalExpense) || 0);
    const netSavings = totalIncome - totalExpense;
    const remaining = Math.max(0, mb - monthExpense);

    // send email (if mailer configured)
    const user = await dbGet('SELECT name,email FROM users WHERE id = ?', [userId]);
    if (mailer && user && user.email) {
      try {
        await sendEmail({
          to: user.email,
          subject: 'DataPulse: Budget updated',
          html: `
            <p>Hi ${user.name || ''},</p>
            <p>Your monthly budget has been updated to <b>₹${mb.toFixed(2)}</b>.</p>
            <p><b>Spent this month:</b> ₹${monthExpense.toFixed(2)}</p>
            <p><b>Remaining:</b> ₹${remaining.toFixed(2)}</p>
            <p><b>Balance (Net Savings):</b> ₹${netSavings.toFixed(2)}</p>
          `
        });
      } catch (e) {
        console.warn('Budget update email failed:', e && e.message ? e.message : e);
      }
    }

    // emit SSE update to the user
    emitToUser(userId, 'budget-update', { monthlyBudget: mb, monthExpense, remaining, netSavings });

    res.json({ success: true, message: 'Budget updated' });
  } catch (err) {
    console.error('Budget update error:', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'DB error' });
  }
});

// -------------------
// Transactions (create)
// -------------------
app.post('/api/transactions', auth, async (req, res) => {
  try {
    const { userId, type, category, amount, description } = req.body;
    if (!userId || Number(userId) !== Number(req.user.id)) return res.status(403).json({ success: false, message: 'Unauthorized' });
    if (!type || amount === undefined || amount === null) return res.status(400).json({ success: false, message: 'Missing fields' });

    const amt = Number(amount);
    if (Number.isNaN(amt)) return res.status(400).json({ success: false, message: 'Invalid amount' });

    let finalCategory = category || '';

    if (!finalCategory && description) {
      try {
        const r = await fetchWithTimeout(`${ML_SERVICE}/predict`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: description })
        }, 3000);
        if (r && r.ok) {
          const j = await r.json();
          if (j && j.success && j.category) finalCategory = j.category;
        }
      } catch (e) {
        console.warn('ML service unreachable or failed, skipping categorization');
      }
    }

    const createdAt = toSqliteTime(new Date());
    const insertResult = await dbRun('INSERT INTO transactions (user_id,type,category,amount,description,created_at) VALUES (?,?,?,?,?,?)',
      [userId, type, finalCategory, amt, description || '', createdAt]);

    // After insert, compute updated metrics and notify
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0,0,0,0);
    const monthStartStr = toSqliteTime(monthStart);

    const srow = await dbGet(
      `SELECT SUM(amount) as monthExpense FROM transactions WHERE user_id = ? AND type='expense' AND created_at >= ?`,
      [userId, monthStartStr]);
    const monthExpense = Number((srow && srow.monthExpense) || 0);

    const sums = await dbGet(
      `SELECT 
          SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as totalIncome,
          SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as totalExpense
       FROM transactions WHERE user_id = ?`, [userId]);

    const totalIncome = Number((sums && sums.totalIncome) || 0);
    const totalExpense = Number((sums && sums.totalExpense) || 0);
    const netSavings = totalIncome - totalExpense;

    const user = await dbGet('SELECT email,name,monthly_budget FROM users WHERE id = ?', [userId]);
    const monthlyBudget = Number((user && user.monthly_budget) || 0);
    const remaining = Math.max(0, monthlyBudget - monthExpense);

    // Email user (best-effort) about the transaction + remaining budget
    if (mailer && user && user.email) {
      try {
        const subj = (type === 'expense') ? 'DataPulse: Expense recorded' : 'DataPulse: Transaction recorded';
        await sendEmail({
          to: user.email,
          subject: subj,
          html: `
            <p>Hi ${user.name || ''},</p>
            <p>Your recent <b>${type}</b> of <b>₹${amt.toFixed(2)}</b> (${finalCategory || 'Uncategorized'}) was recorded.</p>
            <p><b>Spent this month:</b> ₹${monthExpense.toFixed(2)}</p>
            <p><b>Remaining budget:</b> ₹${remaining.toFixed(2)}</p>
            <p><b>Balance (Net Savings):</b> ₹${netSavings.toFixed(2)}</p>
          `
        });
      } catch (e) {
        console.warn('Transaction email failed:', e && e.message ? e.message : e);
      }
    }

    // SSE: notify connected sessions for this user
    emitToUser(userId, 'transaction-update', {
      transactionId: insertResult.lastID || null,
      type, category: finalCategory, amount: amt, description,
      monthExpense, remaining, netSavings, monthlyBudget
    });

    res.json({ success: true, transactionId: insertResult.lastID || null });
  } catch (err) {
    console.error('Insert transaction error (vC.1):', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// -------------------
// Dashboard Summary
// -------------------
app.get('/api/dashboard/summary', auth, async (req, res) => {
  try {
    const uid = req.user.id;

    const sums = await dbGet(
      `SELECT 
          SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as totalIncome,
          SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as totalExpense
       FROM transactions WHERE user_id = ?`, [uid]);

    const totalIncome = Number((sums && sums.totalIncome) || 0);
    const totalExpense = Number((sums && sums.totalExpense) || 0);
    const netSavings = totalIncome - totalExpense;

    const rows = await dbAll(
      `SELECT id,type,category,amount,description,created_at 
       FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`, [uid]);

    const months = await dbAll(
      `SELECT strftime('%Y-%m', created_at) as month,
              SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as income,
              SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as expense
       FROM transactions WHERE user_id = ?
       GROUP BY month ORDER BY month DESC LIMIT 6`, [uid]);

    const monthlyData = (months || []).reverse().map(m => ({
      month: m.month,
      income: Number(m.income || 0),
      expense: Number(m.expense || 0)
    }));

    const recommendation = generateRecommendation(totalIncome, totalExpense, netSavings);

    res.json({
      success: true,
      summary: { totalIncome, totalExpense, netSavings },
      transactions: rows,
      recommendation,
      monthlyData
    });
  } catch (err) {
    console.error('Dashboard summary error:', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// -------------------
// Alerts endpoint
// -------------------
app.get('/api/alerts', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const row = await dbGet('SELECT monthly_budget FROM users WHERE id = ?', [uid]);
    const monthlyBudget = Number((row && row.monthly_budget) || 0);

    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    const monthStartStr = toSqliteTime(monthStart);

    const srow = await dbGet(
      `SELECT SUM(amount) as monthExpense FROM transactions WHERE user_id = ? AND type='expense' AND created_at >= ?`,
      [uid, monthStartStr]);

    const monthExpense = Number((srow && srow.monthExpense) || 0);
    const alerts = [];

    if (monthlyBudget > 0) {
      const pct = (monthExpense / monthlyBudget) || 0;
      if (pct >= 1) alerts.push(`You have exceeded your monthly budget (${monthlyBudget}).`);
      else if (pct >= 0.8) alerts.push(`Warning: You've used ${Math.round(pct * 100)}% of your monthly budget.`);
    }

    const sums = await dbGet(
      `SELECT SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as inc,
              SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as exp
       FROM transactions WHERE user_id = ? AND created_at >= ?`, [uid, monthStartStr]);

    if (sums && (Number(sums.inc || 0) - Number(sums.exp || 0) < 0)) {
      alerts.push('Your monthly cashflow is negative. Consider reducing expenses.');
    }

    res.json({ success: true, alerts });
  } catch (err) {
    console.error('Alerts error (vC.1):', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// -------------------
// Cron: daily alert evaluation (FIXED & SAFE)
// -------------------
nodeCron.schedule('0 9 * * *', async () => {
  console.log('Daily alert check running...');

  try {
    // Fetch all users (budget check handled safely below)
    const users = await dbAll(
      'SELECT id,email,monthly_budget FROM users',
      []
    );

    for (const u of users) {
      try {
        const uid = u.id;
        const monthlyBudget = Number(u.monthly_budget || 0);

        // Skip users without budget
        if (monthlyBudget <= 0) {
          console.log(`⚠️ ALERT SKIPPED: user ${uid} (${u.email}) has no budget set`);
          continue;
        }

        const monthStart = new Date();
        monthStart.setDate(1);
        monthStart.setHours(0, 0, 0, 0);
        const monthStartStr = toSqliteTime(monthStart);

        const srow = await dbGet(
          `SELECT SUM(amount) as monthExpense
           FROM transactions
           WHERE user_id = ? AND type='expense' AND created_at >= ?`,
          [uid, monthStartStr]
        );

        const monthExpense = Number((srow && srow.monthExpense) || 0);

        // SAFE percentage calculation
        const pct = monthExpense / monthlyBudget;

        if (pct >= 0.8) {
          console.log(
            `ALERT (cron): user ${uid} (${u.email}) used ${Math.round(pct * 100)}% of budget`
          );

          if (mailer) {
            await sendEmail({
              to: u.email,
              subject: 'DataPulse Budget Warning',
              html: `
                <p>Hello,</p>
                <p>You have used <strong>${Math.round(pct * 100)}%</strong> of your monthly budget.</p>
                <p>Please review your expenses to avoid overspending.</p>
              `
            });
          }
        }
      } catch (err) {
        console.error(
          'Cron user loop error:',
          err && err.stack ? err.stack : err
        );
        continue;
      }
    }
  } catch (err) {
    console.error('Cron error:', err && err.stack ? err.stack : err);
  }
});

// -------------------
// OTP cleanup cron: remove expired OTPS older than 2x TTL every hour
// -------------------
nodeCron.schedule('0 * * * *', async () => {
  try {
    const cutoff = toSqliteTime(new Date(Date.now() - OTP_TTL_MINUTES * 2 * 60 * 1000));
    const r = await dbRun('DELETE FROM otps WHERE expires_at < ?', [cutoff]);
    if (r && r.changes) console.log(`OTP cleanup removed ${r.changes} rows`);
  } catch (err) {
    console.error('OTP cleanup error:', err && err.stack ? err.stack : err);
  }
});

// -------------------
// CSV Export (save file then download)
// -------------------
app.get('/api/transactions/export', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const rows = await dbAll("SELECT id,type,category,amount,description,created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC", [userId]);
    if (!rows || rows.length === 0) return res.status(400).json({ success: false, message: 'No transactions to export' });

    const fileName = `transactions_${userId}_${Date.now()}.csv`;
    const filePath = path.join(EXPORTS_DIR, fileName);

    const csvWriter = createObjectCsvWriter({
      path: filePath,
      header: [
        { id: 'id', title: 'ID' },
        { id: 'type', title: 'Type' },
        { id: 'category', title: 'Category' },
        { id: 'amount', title: 'Amount' },
        { id: 'description', title: 'Description' },
        { id: 'created_at', title: 'Date' }
      ]
    });

    await csvWriter.writeRecords(rows);
    res.download(filePath, fileName, (err2) => {
      if (err2) {
        console.error('Download error:', err2);
        return res.status(500).json({ success: false, message: 'Download error' });
      }
      try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) { /* ignore */ }
    });
  } catch (err) {
    console.error('Export error (vC.1):', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// -------------------
// CSV Export2 (stream) - unchanged logic
// -------------------
function escapeCsvValue(v) {
  if (v === null || v === undefined) return '';
  let s = String(v);
  if (s.includes('"')) s = s.replace(/"/g, '""');
  if (/[",\n\r]/.test(s)) return `"${s}"`;
  return s;
}

app.get('/api/transactions/export2', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const rows = await dbAll("SELECT id,type,category,amount,description,created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC", [userId]);
    if (!rows || rows.length === 0) return res.status(400).json({ success: false, message: 'No transactions to export' });

    res.setHeader('Content-disposition', `attachment; filename=transactions_${userId}.csv`);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');

    res.write('ID,Type,Category,Amount,Description,Date\r\n');
    for (const r of rows) {
      const line = [
        escapeCsvValue(r.id),
        escapeCsvValue(r.type),
        escapeCsvValue(r.category),
        escapeCsvValue(r.amount),
        escapeCsvValue(r.description),
        escapeCsvValue(r.created_at)
      ].join(',') + '\r\n';
      res.write(line);
    }
    res.end();
  } catch (err) {
    console.error('Export2 error (vC.1):', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// -------------------
// Export CSV & Email to user's registered email (attachment)
// -------------------
app.post('/api/transactions/export-email', auth, async (req, res) => {
  try {
    const userId = req.body.userId;
    if (!userId || Number(userId) !== Number(req.user.id)) return res.status(403).json({ success: false, message: 'Unauthorized userId' });

    const rows = await dbAll("SELECT id,type,category,amount,description,created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC", [userId]);
    if (!rows || rows.length === 0) return res.status(400).json({ success: false, message: 'No transactions to export' });

    const fileName = `transactions_${userId}_${Date.now()}.csv`;
    const filePath = path.join(EXPORTS_DIR, fileName);

    const csvWriter = createObjectCsvWriter({
      path: filePath,
      header: [
        { id: 'id', title: 'ID' },
        { id: 'type', title: 'Type' },
        { id: 'category', title: 'Category' },
        { id: 'amount', title: 'Amount' },
        { id: 'description', title: 'Description' },
        { id: 'created_at', title: 'Date' }
      ]
    });
    await csvWriter.writeRecords(rows);

    const user = await dbGet('SELECT email,name FROM users WHERE id = ?', [userId]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    // FIXED: check mailer early
    if (!mailer) {
      try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (_) {}
      return res.status(500).json({ success: false, message: 'Email server not configured' });
    }

    const sendRes = await sendEmail({
      to: user.email,
      subject: 'Your DataPulse Transactions CSV',
      text: 'Attached is your transactions CSV export from DataPulse.',
      html: `<p>Hi ${user.name || ''},</p><p>Attached is your transactions CSV export from DataPulse.</p>`,
      attachments: [{ filename: fileName, path: filePath }]
    });

    try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) { /* ignore */ }

    if (!sendRes.success) {
      return res.status(500).json({ success: false, message: 'Failed to send email with CSV' });
    }
    res.json({ success: true, message: 'CSV emailed to your registered address' });
  } catch (err) {
    console.error('Export-email error (vC.1):', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// -------------------
// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down...');
  db.close(() => {
    console.log('DB closed.');
    process.exit(0);
  });
});


app.post('/api/voice-intent', auth, async (req, res) => {
  try {
    const { intent, payload } = req.body;

    if (intent === "ADD_TRANSACTION") {
      const { type, amount, category } = payload;

      await dbRun(
        `INSERT INTO transactions (user_id,type,category,amount,description,created_at)
         VALUES (?,?,?,?,?,?)`,
        [
          req.user.id,
          type,
          category,
          amount,
          "Voice entry",
          toSqliteTime(new Date())
        ]
      );

      emitToUser(req.user.id, 'transaction-update', {
        type, amount, category
      });

      return res.json({ success: true, message: "Transaction added via voice" });
    }

    return res.json({ success: false, message: "Unknown intent" });

  } catch (err) {
    res.status(500).json({ success: false, message: "Voice intent failed" });
  }
});
async function sendIntentToBackend(intent, payload) {
  await apiFetch('/api/voice-intent', {
    method: 'POST',
    body: { intent, payload }
  });
}

// FORGOT PASSWORD — Send OTP (auto-replaces old ones)

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ success: false, message: 'Missing email' });

    const lowerEmail = String(email).toLowerCase().trim();
    if (!isEmailLike(lowerEmail))
      return res.status(400).json({ success: false, message: 'Invalid email' });

    const user = await dbGet('SELECT id, name FROM users WHERE email = ?', [lowerEmail]);
    if (!user)
      return res.status(404).json({ success: false, message: 'No such user found' });

    // Remove any previous unused OTPs for this user (cleanup)
    await dbRun(`DELETE FROM otps WHERE email = ? AND purpose = 'reset'`, [lowerEmail]);

    const otp = generateOtp(6);
    const createdAt = toSqliteTime(new Date());
    const expiresAt = toSqliteTime(new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000));

    await dbRun(
      'INSERT INTO otps (email, otp, purpose, created_at, expires_at, used) VALUES (?,?,?,?,?,0)',
      [lowerEmail, otp, 'reset', createdAt, expiresAt]
    );

    console.log(`📨 OTP for ${lowerEmail} (dev only): ${otp}, expires at ${expiresAt}`);

    const emailRes = await sendEmail({
      to: lowerEmail,
      subject: 'DataPulse Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}. It expires in ${OTP_TTL_MINUTES} minutes.`,
      html: `
        <p>Hello ${user.name || ''},</p>
        <p>Your OTP for <b>DataPulse</b> password reset is <b>${otp}</b>.</p>
        <p>It will expire in ${OTP_TTL_MINUTES} minutes.</p>
      `
    });

    res.json({
      success: true,
      message: 'OTP sent to your registered email.',
      mailer: emailRes.success ? 'sent' : 'not-sent'
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
// =====================
// RESET PASSWORD — Verify OTP + Change Password (Universal Fix)
// =====================
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    if (!email || !otp || !password)
      return res.status(400).json({ success: false, message: 'Missing fields' });

    const lowerEmail = String(email).toLowerCase().trim();
    if (!isEmailLike(lowerEmail))
      return res.status(400).json({ success: false, message: 'Invalid email' });

    const user = await dbGet('SELECT id FROM users WHERE email = ?', [lowerEmail]);
    if (!user)
      return res.status(404).json({ success: false, message: 'No such user' });

    // Get the latest OTP (don’t filter by SQLite datetime)
    const otpRow = await dbGet(
      `SELECT id, otp, expires_at, used 
       FROM otps 
       WHERE email = ? AND purpose = 'reset' 
       ORDER BY id DESC 
       LIMIT 1`,
      [lowerEmail]
    );

    console.log("🔍 Fetched OTP row:", otpRow);

    if (!otpRow)
      return res.status(400).json({ success: false, message: 'No OTP found. Request a new one.' });

    if (otpRow.used)
      return res.status(400).json({ success: false, message: 'OTP already used.' });

    // FIXED: Parse stored UTC datetime by appending 'Z' so it is treated as UTC.
    // This aligns with how we store expires_at via toSqliteTime (UTC trimmed).
    const expiry = new Date(otpRow.expires_at + 'Z');
    const now = new Date();

    console.log("🕒 NOW:", now.toISOString(), "| EXPIRES (UTC):", expiry.toISOString(), "| Diff (ms):", expiry - now);

    if (expiry <= now) {
      console.log("⚠️ OTP expired check triggered.");
      return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
    }

    // Compare OTP values
    if (String(otpRow.otp).trim() !== String(otp).trim())
      return res.status(400).json({ success: false, message: 'Invalid OTP.' });

    // All good — reset password
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    await dbRun('UPDATE users SET password = ? WHERE email = ?', [hashed, lowerEmail]);
    await dbRun('UPDATE otps SET used = 1 WHERE id = ?', [otpRow.id]);

    console.log(`✅ Password reset successful for ${lowerEmail}`);
    return res.json({ success: true, message: 'Password reset successful.' });
  } catch (err) {
    console.error('Reset-password error (Node-time fix):', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Email CSV + Financial Summary
app.post('/api/transactions/export-summary-email', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await dbGet('SELECT id,name,email FROM users WHERE id = ?', [userId]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const rows = await dbAll(
      "SELECT id,type,category,amount,description,created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC",
      [userId]
    );
    if (!rows || rows.length === 0)
      return res.status(400).json({ success: false, message: 'No transactions to export' });

    // Financial summary
    const sums = await dbGet(
      `SELECT 
          SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as totalIncome,
          SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as totalExpense
       FROM transactions WHERE user_id = ?`,
      [userId]
    );
    const totalIncome = Number(sums.totalIncome || 0);
    const totalExpense = Number(sums.totalExpense || 0);
    const netSavings = totalIncome - totalExpense;
    const recommendation = generateRecommendation(totalIncome, totalExpense, netSavings);

    // Prepare CSV
    const fileName = `transactions_${userId}_${Date.now()}.csv`;
    const filePath = path.join(EXPORTS_DIR, fileName);

    const csvWriter = createObjectCsvWriter({
      path: filePath,
      header: [
        { id: 'id', title: 'ID' },
        { id: 'type', title: 'Type' },
        { id: 'category', title: 'Category' },
        { id: 'amount', title: 'Amount' },
        { id: 'description', title: 'Description' },
        { id: 'created_at', title: 'Date' }
      ]
    });
    await csvWriter.writeRecords(rows);

    // Email body with summary
    const htmlSummary = `
      <h2>📊 Your DataPulse Financial Summary</h2>
      <p><b>Total Income:</b> ₹${totalIncome.toFixed(2)}</p>
      <p><b>Total Expense:</b> ₹${totalExpense.toFixed(2)}</p>
      <p><b>Net Savings:</b> ₹${netSavings.toFixed(2)}</p>
      <p><b>AI Recommendation:</b> ${recommendation}</p>
      <p>CSV file attached below containing all your transactions.</p>
    `;

    // FIXED: check mailer before attempting to send
    if (!mailer) {
      try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (_) {}
      return res.status(500).json({ success: false, message: 'Email server not configured' });
    }

    const sendRes = await sendEmail({
      to: user.email,
      subject: 'Your DataPulse Financial Summary & Transactions CSV',
      html: htmlSummary,
      text: `Income: ₹${totalIncome}, Expense: ₹${totalExpense}, Savings: ₹${netSavings}`,
      attachments: [{ filename: fileName, path: filePath }]
    });

    try {
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    } catch (_) {}

    if (!sendRes.success)
      return res.status(500).json({ success: false, message: 'Failed to send email' });

    res.json({ success: true, message: 'Summary and CSV emailed successfully' });
  } catch (err) {
    console.error('Export summary email error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


// Helper: generate AI-style investment advice
function generateInvestmentAdvice(income, expenses, risk = 'moderate') {
  const savings = income - expenses;
  if (savings <= 0) {
    return [
      "Your expenses exceed your income. Reduce non-essential spending before investing.",
      "Focus on saving at least 10–20% of your monthly income first."
    ];
  }

  const allocations =
    risk === 'high'
      ? { equity: 0.6, mutual: 0.25, debt: 0.1, cash: 0.05 }
      : risk === 'low'
      ? { equity: 0.2, mutual: 0.3, debt: 0.3, cash: 0.2 }
      : { equity: 0.4, mutual: 0.3, debt: 0.2, cash: 0.1 }; // moderate

  const recs = [
    `Invest ${(allocations.equity * 100).toFixed(0)}% of your savings in stocks or equity index funds.`,
    `Allocate ${(allocations.mutual * 100).toFixed(0)}% to mutual funds or SIPs.`,
    `Keep ${(allocations.debt * 100).toFixed(0)}% in fixed deposits or government bonds.`,
    `Maintain ${(allocations.cash * 100).toFixed(0)}% as an emergency fund in savings or liquid assets.`
  ];

  return recs;
}

// Endpoint: Get personalized investment recommendations
app.get('/api/investment/recommendations', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const risk = req.query.risk || 'moderate';

    // Fetch user totals
    const sums = await dbGet(
      `SELECT 
        SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as totalIncome,
        SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as totalExpense
      FROM transactions WHERE user_id = ?`,
      [uid]
    );

    const totalIncome = Number(sums.totalIncome || 0);
    const totalExpense = Number(sums.totalExpense || 0);
    const recs = generateInvestmentAdvice(totalIncome, totalExpense, risk);

    res.json({
      success: true,
      income: totalIncome,
      expense: totalExpense,
      risk,
      recommendations: recs
    });
  } catch (err) {
    console.error('Investment advice error:', err);
    res.status(500).json({ success: false, message: 'Server error generating advice.' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend running at http://localhost:${PORT}`);
  console.log(`ML_SERVICE is set to: ${ML_SERVICE}`);
  console.log(`Mailer configured: ${!!mailer}`);
});
