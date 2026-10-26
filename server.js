'use strict';
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { db, secret, DB_PATH } = require('./db');

/* ───────────── إعدادات ───────────── */
const PORT = +process.env.PORT || 3000;
const OFFSET = 3 * 3600000;                       // الكويت UTC+3 (بدون توقيت صيفي)
const MAX_SHIFT_MS = (+process.env.MAX_SHIFT_HOURS || 20) * 3600000; // أقصى مدة لحضور مفتوح
const EMP_SESSION_MS = 16 * 3600000;
const ADMIN_SESSION_MS = 8 * 3600000;
const CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'; // بدون 0 O 1 I L

/* ───────────── أدوات الوقت (توقيت الكويت) ───────────── */
const pad = n => String(n).padStart(2, '0');
const kDate = ms => new Date(ms + OFFSET).toISOString().slice(0, 10);
const kTime = ms => (ms == null ? null : new Date(ms + OFFSET).toISOString().slice(11, 16));
const kLocalInput = ms => (ms == null ? '' : new Date(ms + OFFSET).toISOString().slice(0, 16));
const dayStartMs = d => Date.parse(d + 'T00:00:00Z') - OFFSET;
const isDate = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + 'T00:00:00Z'));
function parseLocal(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})$/.exec(String(s || ''));
  if (!m) return null;
  const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) - OFFSET;
  return kLocalInput(ms) === `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}` ? ms : null;
}
const fmtDur = ms => { const m = Math.round(ms / 60000); return `${Math.floor(m / 60)}:${pad(m % 60)}`; };

/* ───────────── تشفير وأكواد ───────────── */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hmac = s => crypto.createHmac('sha256', secret).update(s).digest('hex');
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const codeHash = c => hmac(normCode(c));
function genCode() {
  for (;;) {
    let s = '';
    for (let i = 0; i < 6; i++) s += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
    const code = 'EMP-' + s;
    if (!db.prepare('SELECT 1 FROM employees WHERE code_hash=?').get(codeHash(code))) return code;
  }
}
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [alg, saltHex, hashHex] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const h = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 64, { N: 16384, r: 8, p: 1 });
  const want = Buffer.from(hashHex, 'hex');
  return want.length === h.length && crypto.timingSafeEqual(h, want);
}
const DUMMY_HASH = hashPassword(crypto.randomBytes(8).toString('hex')); // لتقليل الفرق الزمني مع مستخدم غير موجود

/* ───────────── مُحدِّد المحاولات الفاشلة (في الذاكرة) ───────────── */
const fails = new Map();
function failState(key, max, windowMs) {
  const now = Date.now();
  const f = fails.get(key);
  if (!f || f.reset < now) return { blocked: false, retry: 0 };
  return { blocked: f.count >= max, retry: Math.ceil((f.reset - now) / 1000) };
}
function addFail(key, windowMs) {
  const now = Date.now();
  const f = fails.get(key);
  if (!f || f.reset < now) fails.set(key, { count: 1, reset: now + windowMs });
  else f.count++;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of fails) if (v.reset < now) fails.delete(k);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
}, 10 * 60000).unref();

/* ───────────── كوكيز وجلسات ───────────── */
function cookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function setCookie(req, res, name, value, maxAgeSec) {
  const secure = process.env.COOKIE_SECURE === '1' || req.secure;
  const c = `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, c) : c);
}
const clearCookie = (req, res, name) => setCookie(req, res, name, '', 0);
function newSession(kind, subjectId, ttl, deviceId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  db.prepare('INSERT INTO sessions(id,kind,subject_id,device_id,created_at,expires_at) VALUES(?,?,?,?,?,?)')
    .run(sha(token), kind, subjectId, deviceId || null, now, now + ttl);
  return token;
}
function findSession(req, kind) {
  const token = cookies(req)[kind === 'emp' ? 'sid' : 'asid'];
  if (!token) return null;
  return db.prepare('SELECT * FROM sessions WHERE id=? AND kind=? AND expires_at>?').get(sha(token), kind, Date.now()) || null;
}
const dropSessions = (kind, id) => db.prepare('DELETE FROM sessions WHERE kind=? AND subject_id=?').run(kind, id);

/* ───────────── التطبيق ───────────── */
const app = express();
app.disable('x-powered-by');
const tp = process.env.TRUST_PROXY;
app.set('trust proxy', tp === undefined ? 1 : (tp === '0' ? false : (isNaN(+tp) ? tp : +tp)));

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

// حماية CSRF: SameSite=Strict + JSON فقط + فحص Origin
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.headers.origin;
  if (origin) {
    let host = '';
    try { host = new URL(origin).host; } catch { /* ignore */ }
    if (host !== req.headers.host) return res.status(403).json({ error: 'طلب مرفوض' });
  }
  if (!req.is('application/json')) return res.status(415).json({ error: 'طلب غير صالح' });
  next();
});
app.use(express.json({ limit: '20kb' }));

const asyncSafe = fn => (req, res, next) => { try { Promise.resolve(fn(req, res, next)).catch(next); } catch (e) { next(e); } };
const text = (v, max) => { const s = typeof v === 'string' ? v.trim().replace(/\s+/g, ' ') : ''; return s.length > max ? null : s; };

/* ───────────── الصفحات ───────────── */
const PUB = path.join(__dirname, 'public');
app.get('/', (req, res) => res.redirect('/attendance'));
app.get('/attendance', (req, res) => res.sendFile(path.join(PUB, 'attendance.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(PUB, 'admin.html')));
app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /\n'));
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.use('/assets', express.static(path.join(PUB, 'assets'), { maxAge: '5m' }));

/* ═══════════════ منطق الحضور ═══════════════ */
const expireOpen = now =>
  db.prepare("UPDATE attendance SET status='missing_out', updated_at=? WHERE status='open' AND check_in < ?").run(now, now - MAX_SHIFT_MS);

const Q_OPEN = "SELECT * FROM attendance WHERE employee_id=? AND status='open' ORDER BY check_in DESC LIMIT 1";

const doCheckIn = db.transaction((emp, ctx) => {
  const now = Date.now();
  const today = kDate(now);
  expireOpen(now);
  const open = db.prepare(Q_OPEN).get(emp.id);
  if (open) {
    return open.date === today
      ? { err: 'سبق أن سجّلت حضورك اليوم', code: 'ALREADY_IN' }
      : { err: `لديك حضور مفتوح بتاريخ ${open.date} بدون انصراف — سجّل الانصراف أولًا`, code: 'OPEN_PREVIOUS' };
  }
  if (db.prepare('SELECT 1 FROM attendance WHERE employee_id=? AND date=?').get(emp.id, today))
    return { err: 'سبق أن سجّلت حضورك اليوم', code: 'ALREADY_IN' };
  db.prepare(`INSERT INTO attendance(employee_id,date,check_in,status,ip,device_id,user_agent,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?)`)
    .run(emp.id, today, now, 'open', ctx.ip, ctx.device, ctx.ua, now, now);
  return { ok: true, time: kTime(now) };
});

const doCheckOut = db.transaction(emp => {
  const now = Date.now();
  const today = kDate(now);
  expireOpen(now);
  const open = db.prepare(Q_OPEN).get(emp.id);
  if (!open) {
    const last = db.prepare('SELECT * FROM attendance WHERE employee_id=? AND date=?').get(emp.id, today);
    if (last && last.status === 'completed') return { err: 'سبق أن سجّلت انصرافك اليوم', code: 'ALREADY_OUT' };
    if (last && last.status === 'missing_out') return { err: 'تجاوز حضورك المدة المسموحة — راجع المشرف', code: 'EXPIRED' };
    return { err: 'لا يمكن تسجيل الانصراف قبل تسجيل الحضور', code: 'NO_IN' };
  }
  const r = db.prepare("UPDATE attendance SET check_out=?, status='completed', updated_at=? WHERE id=? AND status='open'")
    .run(now, now, open.id);
  if (r.changes !== 1) return { err: 'تعذّر تسجيل الانصراف، حاول مرة أخرى', code: 'RACE' };
  return { ok: true, time: kTime(now) };
});

function stateFor(empId) {
  const now = Date.now();
  const today = kDate(now);
  expireOpen(now);
  const open = db.prepare(Q_OPEN).get(empId);
  const todayRec = db.prepare('SELECT * FROM attendance WHERE employee_id=? AND date=?').get(empId, today);
  // وردية ليلية بدأت أمس وانتهت اليوم: تُعرض كآخر سجل ولا تمنع حضور اليوم الجديد
  const rec = open || todayRec ||
    db.prepare('SELECT * FROM attendance WHERE employee_id=? AND check_out>=? ORDER BY check_out DESC LIMIT 1').get(empId, dayStartMs(today));
  let state = 'none';
  if (rec) state = rec.status === 'open' ? 'present' : (rec.status === 'completed' ? 'done' : 'missing');
  return {
    state,
    can_checkin: !open && !todayRec,
    can_checkout: !!open,
    record_date: rec ? rec.date : null,
    check_in: rec ? kTime(rec.check_in) : null,
    check_out: rec ? kTime(rec.check_out) : null,
    out_next_day: !!(rec && rec.check_out && kDate(rec.check_out) !== rec.date),
    today,
    server_ms: now,
    tz_offset_ms: OFFSET
  };
}

/* ═══════════════ واجهة الموظف ═══════════════ */
function empAuth(req, res, next) {
  const s = findSession(req, 'emp');
  const emp = s && db.prepare("SELECT * FROM employees WHERE id=? AND status='active' AND deleted_at IS NULL").get(s.subject_id);
  if (!emp) return res.status(401).json({ error: 'انتهت الجلسة' });
  req.emp = emp;
  next();
}

app.post('/api/login', (req, res) => {
  const key = 'emp:' + req.ip;
  const st = failState(key, 8, 15 * 60000);
  if (st.blocked) return res.status(429).json({ error: `محاولات كثيرة. أعد المحاولة بعد ${Math.ceil(st.retry / 60)} دقيقة` });
  const n = normCode(req.body && req.body.code);
  const emp = n.length === 9 && n.startsWith('EMP')
    ? db.prepare("SELECT * FROM employees WHERE code_hash=? AND status='active' AND deleted_at IS NULL").get(hmac(n))
    : null;
  if (!emp) {
    addFail(key, 15 * 60000);
    return res.status(401).json({ error: 'الكود غير صالح أو الحساب موقوف — راجع المشرف' });
  }
  fails.delete(key);
  let device = cookies(req).did;
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(device || '')) {
    device = crypto.randomBytes(16).toString('base64url');
    setCookie(req, res, 'did', device, 365 * 86400);
  }
  dropSessions('emp', emp.id);
  setCookie(req, res, 'sid', newSession('emp', emp.id, EMP_SESSION_MS, device), EMP_SESSION_MS / 1000);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const s = findSession(req, 'emp');
  if (s) db.prepare('DELETE FROM sessions WHERE id=?').run(s.id);
  clearCookie(req, res, 'sid');
  res.json({ ok: true });
});

app.get('/api/me', empAuth, (req, res) => {
  const e = req.emp;
  res.json({ employee: { name: e.name, employee_number: e.employee_number, department: e.department, center: e.center }, ...stateFor(e.id) });
});

function empCtx(req) {
  const s = findSession(req, 'emp');
  return { ip: req.ip, device: s && s.device_id, ua: String(req.headers['user-agent'] || '').slice(0, 200) };
}
app.post('/api/checkin', empAuth, (req, res) => {
  const r = doCheckIn.immediate(req.emp, empCtx(req));
  if (r.err) return res.status(409).json({ error: r.err, code: r.code });
  res.json({ ok: true, time: r.time });
});
app.post('/api/checkout', empAuth, (req, res) => {
  const r = doCheckOut.immediate(req.emp);
  if (r.err) return res.status(409).json({ error: r.err, code: r.code });
  res.json({ ok: true, time: r.time });
});

/* ═══════════════ واجهة المشرف ═══════════════ */
function adminAuth(req, res, next) {
  const s = findSession(req, 'admin');
  const adm = s && db.prepare('SELECT * FROM admins WHERE id=?').get(s.subject_id);
  if (!adm) return res.status(401).json({ error: 'يلزم تسجيل الدخول' });
  req.admin = adm;
  if (adm.must_change_password && !req.path.startsWith('/password') && req.path !== '/me' && req.path !== '/logout')
    return res.status(403).json({ error: 'يجب تغيير كلمة المرور أولًا', must_change: true });
  next();
}
const A = express.Router();
app.use('/api/admin', A);

function audit(req, action, target, details) {
  const a = req.admin;
  db.prepare('INSERT INTO audit_logs(admin_id,admin_username,action,target,details,ip,timestamp) VALUES(?,?,?,?,?,?,?)')
    .run(a ? a.id : null, a ? a.username : (req.body && String(req.body.username || '').slice(0, 50)) || null,
      action, target || null, details ? JSON.stringify(details) : null, req.ip, Date.now());
}

A.post('/login', (req, res) => {
  const key = 'adm:' + req.ip;
  const st = failState(key, 8, 15 * 60000);
  if (st.blocked) return res.status(429).json({ error: `محاولات كثيرة. أعد المحاولة بعد ${Math.ceil(st.retry / 60)} دقيقة` });
  const u = text(req.body.username, 50) || '';
  const pw = typeof req.body.password === 'string' ? req.body.password.slice(0, 200) : '';
  const adm = db.prepare('SELECT * FROM admins WHERE username=?').get(u);
  const ok = verifyPassword(pw, adm ? adm.password_hash : DUMMY_HASH) && !!adm;
  if (!ok) {
    addFail(key, 15 * 60000);
    audit(req, 'admin.login_failed', u);
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  fails.delete(key);
  req.admin = adm;
  dropSessions('admin', adm.id);
  setCookie(req, res, 'asid', newSession('admin', adm.id, ADMIN_SESSION_MS), ADMIN_SESSION_MS / 1000);
  audit(req, 'admin.login', adm.username);
  res.json({ ok: true, must_change: !!adm.must_change_password });
});
A.post('/logout', (req, res) => {
  const s = findSession(req, 'admin');
  if (s) db.prepare('DELETE FROM sessions WHERE id=?').run(s.id);
  clearCookie(req, res, 'asid');
  res.json({ ok: true });
});
A.use(adminAuth);

A.get('/me', (req, res) => res.json({ username: req.admin.username, role: req.admin.role, must_change: !!req.admin.must_change_password }));

A.post('/password', (req, res) => {
  const cur = String(req.body.current || ''), nw = String(req.body.next || '');
  if (!verifyPassword(cur, req.admin.password_hash)) return res.status(400).json({ error: 'كلمة المرور الحالية غير صحيحة' });
  if (nw.length < 10) return res.status(400).json({ error: 'كلمة المرور الجديدة يجب ألا تقل عن 10 أحرف' });
  if (nw === cur) return res.status(400).json({ error: 'اختر كلمة مرور مختلفة عن الحالية' });
  db.prepare('UPDATE admins SET password_hash=?, must_change_password=0 WHERE id=?').run(hashPassword(nw), req.admin.id);
  const keep = findSession(req, 'admin');
  db.prepare("DELETE FROM sessions WHERE kind='admin' AND subject_id=? AND id<>?").run(req.admin.id, keep.id);
  audit(req, 'admin.password_change', req.admin.username);
  res.json({ ok: true });
});

/* ── لوحة التحكم ── */
A.get('/dashboard', (req, res) => {
  const now = Date.now();
  const today = kDate(now);
  const dStart = dayStartMs(today);
  expireOpen(now);
  const active = db.prepare("SELECT id FROM employees WHERE deleted_at IS NULL AND status='active'").all().map(r => r.id);
  const activeSet = new Set(active);
  const presentSet = new Set(db.prepare("SELECT employee_id FROM attendance WHERE status='open'").all().map(r => r.employee_id).filter(i => activeSet.has(i)));
  const doneSet = new Set(db.prepare(
    `SELECT employee_id FROM attendance WHERE status IN ('completed','missing_out') AND (date=? OR check_out>=?)`
  ).all(today, dStart).map(r => r.employee_id).filter(i => activeSet.has(i) && !presentSet.has(i)));
  const notIn = active.length - presentSet.size - doneSet.size;

  const recent = db.prepare(`
    SELECT * FROM (
      SELECT e.name AS name, 'in'  AS kind, a.check_in  AS ts FROM attendance a JOIN employees e ON e.id=a.employee_id
      UNION ALL
      SELECT e.name, 'out', a.check_out FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE a.check_out IS NOT NULL
    ) ORDER BY ts DESC LIMIT 15`).all().map(r => ({ name: r.name, kind: r.kind, date: kDate(r.ts), time: kTime(r.ts) }));

  const d7 = []; for (let i = 6; i >= 0; i--) d7.push(kDate(now - i * 86400000));
  const counts = Object.fromEntries(db.prepare('SELECT date, COUNT(*) c FROM attendance WHERE date>=? AND date<=? GROUP BY date').all(d7[0], today).map(r => [r.date, r.c]));
  const agg = (from) => {
    const r = db.prepare(`SELECT COUNT(*) records, COUNT(DISTINCT employee_id) people,
        COALESCE(SUM(CASE WHEN status='completed' THEN check_out-check_in END),0) ms,
        SUM(status='missing_out') missing FROM attendance WHERE date>=? AND date<=?`).get(from, today);
    return { records: r.records, people: r.people, hours: Math.round(r.ms / 360000) / 10, missing: r.missing || 0 };
  };
  res.json({
    today, total: active.length, present: presentSet.size, left: doneSet.size, not_in: notIn,
    recent, days: d7.map(d => ({ date: d, count: counts[d] || 0 })),
    stats: { day: agg(today), week: agg(d7[0]), month: agg(today.slice(0, 8) + '01') }
  });
});

/* ── الموظفون ── */
const likeEsc = s => '%' + s.replace(/[\\%_]/g, m => '\\' + m) + '%';
const empPublic = e => ({
  id: e.id, name: e.name, employee_number: e.employee_number, department: e.department, center: e.center,
  status: e.status, records: e.records, code_issued_at: e.code_issued_at ? kLocalInput(e.code_issued_at).replace('T', ' ') : null
});
function empInput(b, partial) {
  const out = {};
  const name = text(b.name, 100), num = text(b.employee_number, 30), dep = text(b.department, 60), cen = text(b.center, 60);
  if (name === null || (!partial && !name) || (partial && b.name !== undefined && !name)) return { error: 'الاسم مطلوب (حتى 100 حرف)' };
  if (num === null || dep === null || cen === null) return { error: 'قيمة طويلة جدًا في أحد الحقول' };
  out.name = name; out.employee_number = num || null; out.department = dep || null; out.center = cen || null;
  return { v: out };
}
function uniqueErr(e, res) {
  if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'الرقم الوظيفي مستخدم لموظف آخر' });
  throw e;
}

A.get('/employees', (req, res) => {
  const where = ['e.deleted_at IS NULL'], args = [];
  const q = text(req.query.q || '', 100);
  if (q) { where.push("(e.name LIKE ? ESCAPE '\\' OR e.employee_number LIKE ? ESCAPE '\\')"); args.push(likeEsc(q), likeEsc(q)); }
  if (req.query.department) { where.push('e.department=?'); args.push(String(req.query.department)); }
  if (req.query.center) { where.push('e.center=?'); args.push(String(req.query.center)); }
  if (['active', 'suspended'].includes(req.query.status)) { where.push('e.status=?'); args.push(req.query.status); }
  const rows = db.prepare(`SELECT e.*, (SELECT COUNT(*) FROM attendance a WHERE a.employee_id=e.id) AS records
                           FROM employees e WHERE ${where.join(' AND ')} ORDER BY e.name`).all(...args);
  const dist = col => db.prepare(`SELECT DISTINCT ${col} v FROM employees WHERE deleted_at IS NULL AND ${col} IS NOT NULL ORDER BY v`).all().map(r => r.v);
  res.json({ employees: rows.map(empPublic), departments: dist('department'), centers: dist('center') });
});

A.post('/employees', (req, res) => {
  const p = empInput(req.body, false);
  if (p.error) return res.status(400).json({ error: p.error });
  const code = genCode(), now = Date.now();
  try {
    const r = db.prepare(`INSERT INTO employees(name,employee_number,department,center,code_hash,status,code_issued_at,created_at)
                          VALUES(?,?,?,?,?,'active',?,?)`)
      .run(p.v.name, p.v.employee_number, p.v.department, p.v.center, codeHash(code), now, now);
    audit(req, 'employee.create', `${p.v.name} (#${r.lastInsertRowid})`, p.v);
    res.json({ ok: true, id: r.lastInsertRowid, code });
  } catch (e) { uniqueErr(e, res); }
});

function loadEmp(req, res) {
  const e = db.prepare('SELECT * FROM employees WHERE id=? AND deleted_at IS NULL').get(+req.params.id);
  if (!e) res.status(404).json({ error: 'الموظف غير موجود' });
  return e;
}

A.put('/employees/:id', (req, res) => {
  const e = loadEmp(req, res); if (!e) return;
  const p = empInput(req.body, false);
  if (p.error) return res.status(400).json({ error: p.error });
  try {
    db.prepare('UPDATE employees SET name=?, employee_number=?, department=?, center=? WHERE id=?')
      .run(p.v.name, p.v.employee_number, p.v.department, p.v.center, e.id);
    const before = {}, after = {};
    for (const k of ['name', 'employee_number', 'department', 'center']) if (e[k] !== p.v[k]) { before[k] = e[k]; after[k] = p.v[k]; }
    audit(req, 'employee.update', `${e.name} (#${e.id})`, { before, after });
    res.json({ ok: true });
  } catch (err) { uniqueErr(err, res); }
});

A.post('/employees/:id/status', (req, res) => {
  const e = loadEmp(req, res); if (!e) return;
  const st = req.body.status;
  if (!['active', 'suspended'].includes(st)) return res.status(400).json({ error: 'حالة غير صالحة' });
  db.prepare('UPDATE employees SET status=? WHERE id=?').run(st, e.id);
  if (st === 'suspended') dropSessions('emp', e.id);
  audit(req, st === 'suspended' ? 'employee.suspend' : 'employee.activate', `${e.name} (#${e.id})`);
  res.json({ ok: true });
});

A.post('/employees/:id/code', (req, res) => {
  const e = loadEmp(req, res); if (!e) return;
  const code = genCode();
  db.prepare('UPDATE employees SET code_hash=?, code_issued_at=? WHERE id=?').run(codeHash(code), Date.now(), e.id);
  dropSessions('emp', e.id);
  audit(req, 'employee.reissue_code', `${e.name} (#${e.id})`);
  res.json({ ok: true, code });
});

A.delete('/employees/:id', (req, res) => {
  const e = loadEmp(req, res); if (!e) return;
  // حذف ناعم: يبقى سجل الحضور التاريخي، ويُبطَل الكود فورًا
  db.prepare("UPDATE employees SET deleted_at=?, status='suspended', code_hash=? WHERE id=?")
    .run(Date.now(), 'deleted:' + e.id + ':' + crypto.randomBytes(8).toString('hex'), e.id);
  dropSessions('emp', e.id);
  audit(req, 'employee.delete', `${e.name} (#${e.id})`);
  res.json({ ok: true });
});

/* ── السجلات ── */
function fetchRecords(q, limit, offset) {
  const now = Date.now();
  expireOpen(now);
  const where = [], args = [];
  const from = isDate(q.from) ? q.from : '', to = isDate(q.to) ? q.to : '';
  if (from) { where.push('a.date>=?'); args.push(from); }
  if (to) { where.push('a.date<=?'); args.push(to); }
  if (+q.employee_id) { where.push('a.employee_id=?'); args.push(+q.employee_id); }
  if (q.department) { where.push('e.department=?'); args.push(String(q.department)); }
  const sq = text(q.q || '', 100);
  if (sq) { where.push("(e.name LIKE ? ESCAPE '\\' OR e.employee_number LIKE ? ESCAPE '\\')"); args.push(likeEsc(sq), likeEsc(sq)); }
  const status = String(q.status || '');
  const base = where.slice(), baseArgs = args.slice();

  const wantNone = from && from === to && (status === '' || status === 'none');
  let noneRows = [];
  if (wantNone) {
    const w = ["e.deleted_at IS NULL", "e.status='active'"], a2 = [];
    if (+q.employee_id) { w.push('e.id=?'); a2.push(+q.employee_id); }
    if (q.department) { w.push('e.department=?'); a2.push(String(q.department)); }
    if (sq) { w.push("(e.name LIKE ? ESCAPE '\\' OR e.employee_number LIKE ? ESCAPE '\\')"); a2.push(likeEsc(sq), likeEsc(sq)); }
    noneRows = db.prepare(`SELECT e.* FROM employees e WHERE ${w.join(' AND ')}
        AND NOT EXISTS (SELECT 1 FROM attendance a WHERE a.employee_id=e.id AND (a.date=? OR a.status='open')) ORDER BY e.name`)
      .all(...a2, from).map(e => ({
        id: null, employee_id: e.id, name: e.name, employee_number: e.employee_number, department: e.department, center: e.center,
        deleted: false, date: from, check_in: null, check_out: null, duration: null, status: 'none', edited: false, note: null, shared_device: false
      }));
  }
  if (status === 'none') return { rows: noneRows.slice(offset, offset + limit), total: noneRows.length };

  if (['open', 'completed', 'missing_out'].includes(status)) { base.push('a.status=?'); baseArgs.push(status); }
  const W = base.length ? 'WHERE ' + base.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) c FROM attendance a JOIN employees e ON e.id=a.employee_id ${W}`).get(...baseArgs).c;
  const rows = db.prepare(`
    SELECT a.*, e.name, e.employee_number, e.department, e.center, e.deleted_at,
      EXISTS(SELECT 1 FROM attendance b WHERE b.device_id IS NOT NULL AND b.device_id=a.device_id AND b.date=a.date AND b.employee_id<>a.employee_id) AS shared_device
    FROM attendance a JOIN employees e ON e.id=a.employee_id ${W}
    ORDER BY a.date DESC, a.check_in DESC LIMIT ? OFFSET ?`).all(...baseArgs, limit, offset).map(a => ({
    id: a.id, employee_id: a.employee_id, name: a.name, employee_number: a.employee_number, department: a.department, center: a.center,
    deleted: !!a.deleted_at, date: a.date, check_in: kTime(a.check_in), check_out: kTime(a.check_out),
    out_next_day: !!(a.check_out && kDate(a.check_out) !== a.date),
    check_in_local: kLocalInput(a.check_in), check_out_local: kLocalInput(a.check_out),
    duration: a.check_out ? fmtDur(a.check_out - a.check_in) : null,
    status: a.status, edited: !!a.edited, note: a.note, shared_device: !!a.shared_device
  }));
  let all = rows;
  if (noneRows.length && offset + rows.length >= total) all = rows.concat(noneRows);
  return { rows: all, total: total + noneRows.length };
}

A.get('/records', (req, res) => {
  const limit = Math.min(Math.max(+req.query.limit || 100, 1), 500);
  const offset = Math.max(+req.query.offset || 0, 0);
  res.json(fetchRecords(req.query, limit, offset));
});

const STATUS_AR = { open: 'حاضر', completed: 'انصرف', missing_out: 'لم يسجل انصراف', none: 'لم يسجل حضور' };
const csvCell = v => {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;      // منع حقن الصيغ في Excel
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
A.get('/records.csv', (req, res) => {
  const { rows } = fetchRecords(req.query, 50000, 0);
  const head = ['الموظف', 'الرقم الوظيفي', 'القسم', 'المركز', 'التاريخ', 'الحضور', 'الانصراف', 'المدة (ساعة:دقيقة)', 'الحالة', 'ملاحظة'];
  const lines = [head.map(csvCell).join(',')].concat(rows.map(r => [
    r.name, r.employee_number, r.department, r.center, r.date, r.check_in, r.check_out ? r.check_out + (r.out_next_day ? ' (+1)' : '') : '',
    r.duration, STATUS_AR[r.status] + (r.edited ? ' (معدّل)' : ''), r.note
  ].map(csvCell).join(',')));
  audit(req, 'records.export', `${rows.length} سجل`, { from: req.query.from || null, to: req.query.to || null });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="attendance-${kDate(Date.now())}.csv"`);
  res.send('﻿' + lines.join('\r\n') + '\r\n');
});

function recordInput(b) {
  const inMs = parseLocal(b.check_in);
  const outMs = b.check_out ? parseLocal(b.check_out) : null;
  const reason = text(b.reason, 300);
  if (inMs === null) return { error: 'وقت الحضور غير صالح' };
  if (b.check_out && outMs === null) return { error: 'وقت الانصراف غير صالح' };
  if (outMs !== null && outMs < inMs) return { error: 'وقت الانصراف يجب أن يكون بعد وقت الحضور' };
  if (outMs !== null && outMs - inMs > 24 * 3600000) return { error: 'المدة تتجاوز 24 ساعة' };
  if (inMs > Date.now() + 60000 || (outMs !== null && outMs > Date.now() + 60000)) return { error: 'لا يمكن تسجيل وقت في المستقبل' };
  if (!reason || reason.length < 3) return { error: 'سبب التعديل مطلوب' };
  const status = outMs !== null ? 'completed' : (Date.now() - inMs > MAX_SHIFT_MS ? 'missing_out' : 'open');
  return { v: { inMs, outMs, reason, status, date: kDate(inMs) } };
}

A.post('/records', (req, res) => {
  const e = db.prepare('SELECT * FROM employees WHERE id=? AND deleted_at IS NULL').get(+req.body.employee_id);
  if (!e) return res.status(404).json({ error: 'الموظف غير موجود' });
  const p = recordInput(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const now = Date.now();
  try {
    const r = db.prepare(`INSERT INTO attendance(employee_id,date,check_in,check_out,status,edited,note,ip,created_at,updated_at)
                          VALUES(?,?,?,?,?,1,?,?,?,?)`)
      .run(e.id, p.v.date, p.v.inMs, p.v.outMs, p.v.status, 'إضافة يدوية: ' + p.v.reason, req.ip, now, now);
    audit(req, 'record.create', `${e.name} — ${p.v.date}`, { check_in: req.body.check_in, check_out: req.body.check_out || null, reason: p.v.reason });
    res.json({ ok: true, id: r.lastInsertRowid });
  } catch (err) {
    if (String(err.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'يوجد سجل لهذا الموظف في نفس التاريخ' });
    throw err;
  }
});

A.put('/records/:id', (req, res) => {
  const old = db.prepare('SELECT a.*, e.name FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE a.id=?').get(+req.params.id);
  if (!old) return res.status(404).json({ error: 'السجل غير موجود' });
  const p = recordInput(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  try {
    db.prepare('UPDATE attendance SET date=?, check_in=?, check_out=?, status=?, edited=1, note=?, updated_at=? WHERE id=?')
      .run(p.v.date, p.v.inMs, p.v.outMs, p.v.status, 'تعديل: ' + p.v.reason, Date.now(), old.id);
    audit(req, 'record.update', `${old.name} — ${old.date}`, {
      before: { check_in: kLocalInput(old.check_in), check_out: kLocalInput(old.check_out) },
      after: { check_in: req.body.check_in, check_out: req.body.check_out || null }, reason: p.v.reason
    });
    res.json({ ok: true });
  } catch (err) {
    if (String(err.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'يوجد سجل لهذا الموظف في نفس التاريخ' });
    throw err;
  }
});

/* ── سجل التدقيق ── */
A.get('/audit', (req, res) => {
  const limit = Math.min(Math.max(+req.query.limit || 50, 1), 200), offset = Math.max(+req.query.offset || 0, 0);
  const total = db.prepare('SELECT COUNT(*) c FROM audit_logs').get().c;
  const rows = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?').all(limit, offset).map(r => ({
    id: r.id, admin: r.admin_username, action: r.action, target: r.target, details: r.details ? JSON.parse(r.details) : null,
    ip: r.ip, time: kLocalInput(r.timestamp).replace('T', ' ')
  }));
  res.json({ rows, total });
});

/* ── نسخة احتياطية ── */
A.get('/backup', asyncSafe(async (req, res) => {
  const tmp = path.join(path.dirname(DB_PATH), `backup-${Date.now()}.db`);
  await db.backup(tmp);
  audit(req, 'backup.download', null);
  res.download(tmp, `attendance-backup-${kDate(Date.now())}.db`, () => fs.unlink(tmp, () => {}));
}));

A.use((req, res) => res.status(404).json({ error: 'غير موجود' }));

/* ───────────── معالج الأخطاء ───────────── */
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') return res.status(400).json({ error: 'طلب غير صالح' });
  console.error(err);
  res.status(500).json({ error: 'خطأ في الخادم' });
});

/* ───────────── إنشاء المشرف الأول ───────────── */
function bootstrapAdmin() {
  if (db.prepare('SELECT COUNT(*) c FROM admins').get().c > 0) return;
  const user = process.env.ADMIN_USER || 'admin';
  let pw = process.env.ADMIN_PASS, mustChange = 0;
  if (!pw || pw.length < 10) {
    pw = crypto.randomBytes(9).toString('base64url');
    mustChange = 1;
    console.log('\n==============================================================');
    console.log(' تم إنشاء حساب المشرف الأول (تُعرض كلمة المرور مرة واحدة فقط)');
    console.log(`   username: ${user}`);
    console.log(`   password: ${pw}`);
    console.log(' ستُطلب منك كلمة مرور جديدة عند أول دخول.');
    console.log('==============================================================\n');
  }
  db.prepare("INSERT INTO admins(username,password_hash,role,must_change_password,created_at) VALUES(?,?,'admin',?,?)")
    .run(user, hashPassword(pw), mustChange, Date.now());
}

if (require.main === module) {
  bootstrapAdmin();
  app.listen(PORT, () => console.log(`الحضور والانصراف يعمل على المنفذ ${PORT}  —  /attendance  و  /admin`));
}
module.exports = app;
