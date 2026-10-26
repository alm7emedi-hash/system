'use strict';
/* اختبار شامل للخادم الحقيقي بقاعدة بيانات مؤقتة:  npm test */
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const assert = require('assert');

const PORT = 3100 + Math.floor(Math.random() * 500);
const BASE = `http://127.0.0.1:${PORT}`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-'));
const DB_PATH = path.join(dir, 't.db');
const env = { ...process.env, PORT, DB_PATH, ADMIN_USER: 'boss', ADMIN_PASS: 'StrongPass123', TRUST_PROXY: '1', MAX_SHIFT_HOURS: '30' };

class Client {
  constructor(ip) { this.jar = {}; this.ip = ip; }
  async req(method, url, body, extra = {}) {
    const headers = { 'X-Forwarded-For': this.ip, ...extra };
    const ck = Object.entries(this.jar).map(([k, v]) => `${k}=${v}`).join('; ');
    if (ck) headers.Cookie = ck;
    if (body !== undefined && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const r = await fetch(BASE + url, { method, headers, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)), redirect: 'manual' });
    for (const c of r.headers.getSetCookie()) {
      const [kv] = c.split(';'); const i = kv.indexOf('=');
      const k = kv.slice(0, i), v = kv.slice(i + 1);
      if (/Max-Age=0/.test(c)) delete this.jar[k]; else this.jar[k] = v;
    }
    const ct = r.headers.get('content-type') || '';
    const data = ct.includes('json') ? await r.json() : new TextDecoder('utf-8', { ignoreBOM: true }).decode(await r.arrayBuffer());
    return { status: r.status, data, headers: r.headers };
  }
  get(u) { return this.req('GET', u); }
  post(u, b) { return this.req('POST', u, b === undefined ? {} : b); }
}

let passed = 0;
const ok = (name, fn) => fn().then(() => { passed++; console.log('  ✓', name); }, e => { console.error('  ✗', name, '\n   ', e.message); process.exitCode = 1; });

async function main() {
  const srv = spawn('node', [path.join(__dirname, '..', 'server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = ''; srv.stdout.on('data', d => (log += d)); srv.stderr.on('data', d => (log += d));
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + '/healthz'); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const { db } = (() => { process.env.DB_PATH = DB_PATH; return require('../db'); })();
  const admin = new Client('10.0.0.1'), anon = new Client('10.0.0.2');
  const dbg = {};

  try {
    await ok('الصفحات متاحة ورؤوس الأمان موجودة', async () => {
      for (const p of ['/attendance', '/admin', '/assets/admin.js']) assert.strictEqual((await anon.get(p)).status, 200, p);
      const r = await anon.get('/attendance');
      assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
      assert.strictEqual(r.headers.get('x-frame-options'), 'DENY');
    });

    await ok('الوصول بدون تسجيل دخول مرفوض (موظف + مشرف)', async () => {
      for (const u of ['/api/me', '/api/admin/dashboard', '/api/admin/employees', '/api/admin/records', '/api/admin/records.csv', '/api/admin/audit', '/api/admin/backup'])
        assert.strictEqual((await anon.get(u)).status, 401, u);
      assert.strictEqual((await anon.post('/api/checkin')).status, 401);
    });

    await ok('دخول المشرف: خطأ ثم صحيح', async () => {
      assert.strictEqual((await admin.post('/api/admin/login', { username: 'boss', password: 'wrong' })).status, 401);
      const r = await admin.post('/api/admin/login', { username: 'boss', password: 'StrongPass123' });
      assert.strictEqual(r.status, 200); assert.strictEqual(r.data.must_change, false);
    });

    await ok('CSRF: رفض غير JSON وOrigin غريب', async () => {
      assert.strictEqual((await admin.req('POST', '/api/admin/employees', 'name=x', { 'Content-Type': 'text/plain' })).status, 415);
      assert.strictEqual((await admin.req('POST', '/api/admin/employees', { name: 'x' }, { Origin: 'https://evil.example' })).status, 403);
    });

    await ok('إضافة موظف: كود فريد بصيغة صحيحة ولا يظهر في القوائم', async () => {
      const r = await admin.post('/api/admin/employees', { name: 'أحمد علي', employee_number: '1001', department: 'النظافة', center: 'الأحمدي' });
      assert.strictEqual(r.status, 200); assert.match(r.data.code, /^EMP-[2-9A-HJKMNP-Z]{6}$/);
      dbg.a = { id: r.data.id, code: r.data.code };
      const l = await admin.get('/api/admin/employees');
      const s = JSON.stringify(l.data);
      assert.ok(!s.includes(dbg.a.code) && !/code_hash|access_code/.test(s));
      assert.strictEqual((await admin.post('/api/admin/employees', { name: 'مكرر', employee_number: '1001' })).status, 409);
      const b = await admin.post('/api/admin/employees', { name: 'سارة', employee_number: '1002', department: 'التفتيش', center: 'الفروانية' });
      dbg.b = { id: b.data.id, code: b.data.code };
      assert.notStrictEqual(dbg.a.code, dbg.b.code);
      const raw = db.prepare('SELECT code_hash FROM employees WHERE id=?').get(dbg.a.id).code_hash;
      assert.ok(!raw.includes(dbg.a.code.slice(4)), 'الكود مخزّن مجزّأ');
    });

    const ea = new Client('10.0.1.1');
    await ok('دخول الموظف: كود خاطئ يُرفض، الصحيح (بأي حالة أحرف/مسافات) يعمل', async () => {
      assert.strictEqual((await ea.post('/api/login', { code: 'EMP-AAAAAA' })).status, 401);
      assert.strictEqual((await ea.post('/api/login', { code: ' ' + dbg.a.code.toLowerCase() + ' ' })).status, 200);
      const me = await ea.get('/api/me');
      assert.strictEqual(me.data.employee.name, 'أحمد علي'); assert.strictEqual(me.data.state, 'none');
    });

    await ok('منطق الحضور: لا انصراف قبل حضور، لا تكرار، لا انصراف ثانٍ', async () => {
      assert.strictEqual((await ea.post('/api/checkout')).data.code, 'NO_IN');
      const i = await ea.post('/api/checkin'); assert.strictEqual(i.status, 200); assert.match(i.data.time, /^\d\d:\d\d$/);
      assert.strictEqual((await ea.post('/api/checkin')).data.code, 'ALREADY_IN');
      assert.strictEqual((await ea.get('/api/me')).data.state, 'present');
      assert.strictEqual((await ea.post('/api/checkout')).status, 200);
      assert.strictEqual((await ea.post('/api/checkout')).data.code, 'ALREADY_OUT');
      assert.strictEqual((await ea.post('/api/checkin')).data.code, 'ALREADY_IN');
      assert.strictEqual((await ea.get('/api/me')).data.state, 'done');
    });

    await ok('ضغطات متزامنة: سجل حضور واحد فقط', async () => {
      const eb = new Client('10.0.1.2'); await eb.post('/api/login', { code: dbg.b.code });
      const rs = await Promise.all(Array.from({ length: 8 }, () => eb.post('/api/checkin')));
      assert.strictEqual(rs.filter(r => r.status === 200).length, 1);
      assert.strictEqual(db.prepare('SELECT COUNT(*) c FROM attendance WHERE employee_id=?').get(dbg.b.id).c, 1);
      assert.strictEqual((await eb.post('/api/checkout')).status, 200);
    });

    await ok('الوقت من الخادم: الوقت المرسل من العميل يُتجاهل', async () => {
      const r = db.prepare('SELECT check_in FROM attendance WHERE employee_id=?').get(dbg.a.id);
      assert.ok(Math.abs(r.check_in - Date.now()) < 60000);
      const c = new Client('10.0.1.3'); await c.post('/api/login', { code: dbg.a.code });
      assert.strictEqual((await c.post('/api/checkin', { check_in: '2000-01-01T00:00', time: '03:00' })).data.code, 'ALREADY_IN');
    });

    await ok('إيقاف الموظف يبطل الجلسة والكود فورًا، والتفعيل يعيده', async () => {
      assert.strictEqual((await admin.post(`/api/admin/employees/${dbg.a.id}/status`, { status: 'suspended' })).status, 200);
      assert.strictEqual((await ea.get('/api/me')).status, 401);
      assert.strictEqual((await new Client('10.0.1.4').post('/api/login', { code: dbg.a.code })).status, 401);
      await admin.post(`/api/admin/employees/${dbg.a.id}/status`, { status: 'active' });
      assert.strictEqual((await new Client('10.0.1.5').post('/api/login', { code: dbg.a.code })).status, 200);
    });

    await ok('إعادة إصدار الكود: القديم يبطل والجلسة القديمة تنتهي', async () => {
      const s = new Client('10.0.1.6'); await s.post('/api/login', { code: dbg.b.code });
      const r = await admin.post(`/api/admin/employees/${dbg.b.id}/code`);
      assert.match(r.data.code, /^EMP-/); assert.notStrictEqual(r.data.code, dbg.b.code);
      assert.strictEqual((await s.get('/api/me')).status, 401);
      assert.strictEqual((await new Client('10.0.1.7').post('/api/login', { code: dbg.b.code })).status, 401);
      dbg.b.code = r.data.code;
      assert.strictEqual((await new Client('10.0.1.8').post('/api/login', { code: dbg.b.code })).status, 200);
    });

    await ok('وردية ليلية: حضور من الأمس يُنهى اليوم ولا يسمح بحضور جديد قبله', async () => {
      const r = await admin.post('/api/admin/employees', { name: 'ناصر الليلي', employee_number: '1003', department: 'التفتيش', center: 'الأحمدي' });
      const n = { id: r.data.id, code: r.data.code };
      const now = Date.now(), ci = Math.floor((now + 3 * 3600000) / 86400000) * 86400000 - 3 * 3600000 - 2 * 3600000; // أمس 22:00 بتوقيت الكويت
      const d = new Date(ci + 3 * 3600000).toISOString().slice(0, 10);
      db.prepare("INSERT INTO attendance(employee_id,date,check_in,status,created_at,updated_at) VALUES(?,?,?,'open',?,?)").run(n.id, d, ci, now, now);
      const c = new Client('10.0.2.1'); await c.post('/api/login', { code: n.code });
      const me = (await c.get('/api/me')).data; assert.strictEqual(me.state, 'present'); assert.strictEqual(me.record_date, d);
      assert.strictEqual((await c.post('/api/checkin')).data.code, 'OPEN_PREVIOUS');
      assert.strictEqual((await c.post('/api/checkout')).status, 200);
      const rec = (await c.get('/api/me')).data; assert.strictEqual(rec.out_next_day, true);
      dbg.n = n;
    });

    await ok('حضور مفتوح تجاوز الحد الأقصى يُغلق كـ«لم يسجل انصراف» ولا يمنع حضور اليوم', async () => {
      const r = await admin.post('/api/admin/employees', { name: 'خالد المنسي', employee_number: '1004' });
      const k = { id: r.data.id, code: r.data.code };
      const now = Date.now(), ci = now - 40 * 3600000;
      db.prepare("INSERT INTO attendance(employee_id,date,check_in,status,created_at,updated_at) VALUES(?,?,?,'open',?,?)").run(k.id, new Date(ci + 3 * 3600000).toISOString().slice(0, 10), ci, now, now);
      const c = new Client('10.0.2.2'); await c.post('/api/login', { code: k.code });
      assert.strictEqual((await c.get('/api/me')).data.state, 'none');
      assert.strictEqual((await c.post('/api/checkin')).status, 200);
      const rs = await admin.get('/api/admin/records?status=missing_out&from=2000-01-01&to=2100-01-01');
      assert.ok(rs.data.rows.some(x => x.name === 'خالد المنسي'));
    });

    await ok('لوحة التحكم: الأعداد متسقة', async () => {
      const d = (await admin.get('/api/admin/dashboard')).data;
      assert.strictEqual(d.present + d.left + d.not_in, d.total);
      assert.ok(d.recent.length > 0 && d.days.length === 7 && d.stats.month.records >= 3);
    });

    await ok('السجلات: فلترة بالتاريخ والحالة «لم يسجل حضور» ليوم واحد', async () => {
      const t = new Date(Date.now() + 3 * 3600000).toISOString().slice(0, 10);
      const all = (await admin.get(`/api/admin/records?from=${t}&to=${t}`)).data;
      assert.ok(all.rows.length >= 3);
      const none = (await admin.get(`/api/admin/records?from=${t}&to=${t}&status=none`)).data;
      assert.ok(none.rows.every(r => r.status === 'none'));
      const byDep = (await admin.get(`/api/admin/records?from=${t}&to=${t}&department=${encodeURIComponent('النظافة')}&status=completed`)).data;
      assert.ok(byDep.rows.every(r => r.department === 'النظافة'));
      const q = (await admin.get(`/api/admin/records?from=${t}&to=${t}&q=1002`)).data;
      assert.ok(q.rows.every(r => r.employee_number === '1002'));
    });

    await ok('تعديل يدوي: السبب إلزامي، المستقبل مرفوض، ويُسجَّل في التدقيق', async () => {
      const t = new Date(Date.now() + 3 * 3600000).toISOString().slice(0, 10);
      const rows = (await admin.get(`/api/admin/records?from=${t}&to=${t}&employee_id=${dbg.a.id}`)).data.rows;
      const rec = rows[0];
      const bad = await admin.req('PUT', '/api/admin/records/' + rec.id, { check_in: rec.check_in_local, check_out: '', reason: '' });
      assert.strictEqual(bad.status, 400);
      assert.strictEqual((await admin.req('PUT', '/api/admin/records/' + rec.id, { check_in: '2999-01-01T10:00', reason: 'تجربة' })).status, 400);
      const y = new Date(Date.now() + 3 * 3600000 - 86400000).toISOString().slice(0, 10);
      const good = await admin.req('PUT', '/api/admin/records/' + rec.id, { check_in: y + 'T05:00', check_out: y + 'T06:00', reason: 'تصحيح من المشرف' });
      assert.strictEqual(good.status, 200);
      const after = (await admin.get(`/api/admin/records?from=${y}&to=${y}&employee_id=${dbg.a.id}`)).data.rows[0];
      assert.strictEqual(after.check_in, '05:00'); assert.strictEqual(after.edited, true); assert.strictEqual(after.duration, '1:00');
      const au = (await admin.get('/api/admin/audit')).data.rows;
      assert.ok(au.some(x => x.action === 'record.update' && x.details.reason === 'تصحيح من المشرف' && x.details.before));
    });

    await ok('تصدير CSV: BOM + ترميز عربي + منع حقن الصيغ', async () => {
      const evil = await admin.post('/api/admin/employees', { name: '=HYPERLINK("http://x","y")', employee_number: '9999' });
      const t = new Date(Date.now() + 3 * 3600000 - 86400000).toISOString().slice(0, 10);
      assert.strictEqual((await admin.post('/api/admin/records', { employee_id: evil.data.id, check_in: t + 'T01:00', check_out: t + 'T02:00', reason: 'اختبار' })).status, 200);
      const r = await admin.get(`/api/admin/records.csv?from=${t}&to=${t}`);
      assert.strictEqual(r.status, 200); assert.ok(r.data.startsWith('\uFEFF'));
      assert.ok(r.data.includes('الموظف,الرقم الوظيفي'));
      assert.ok(r.data.includes(`"'=HYPERLINK(""http://x"",""y"")"`), 'الصيغة معطّلة');
      assert.ok(!/^=/m.test(r.data));
    });

    await ok('حذف الموظف: الكود يبطل ويبقى السجل التاريخي', async () => {
      assert.strictEqual((await admin.req('DELETE', '/api/admin/employees/' + dbg.n.id, {})).status, 200);
      assert.strictEqual((await new Client('10.0.3.1').post('/api/login', { code: dbg.n.code })).status, 401);
      const rs = (await admin.get('/api/admin/records?from=2000-01-01&to=2100-01-01&employee_id=' + dbg.n.id)).data.rows;
      assert.ok(rs.length === 1 && rs[0].deleted === true);
      assert.ok(!(await admin.get('/api/admin/employees')).data.employees.some(e => e.id === dbg.n.id));
      assert.strictEqual((await admin.post('/api/admin/employees', { name: 'جديد', employee_number: '1003' })).status, 200, 'الرقم الوظيفي المحذوف قابل لإعادة الاستخدام');
    });

    await ok('سجل التدقيق يغطي العمليات الإدارية', async () => {
      const acts = new Set((await admin.get('/api/admin/audit?limit=200')).data.rows.map(r => r.action));
      for (const a of ['admin.login', 'admin.login_failed', 'employee.create', 'employee.suspend', 'employee.activate', 'employee.reissue_code', 'employee.delete', 'record.update', 'record.create', 'records.export'])
        assert.ok(acts.has(a), a);
    });

    await ok('نسخة احتياطية صالحة (SQLite)', async () => {
      const r = await fetch(BASE + '/api/admin/backup', { headers: { Cookie: `asid=${admin.jar.asid}`, 'X-Forwarded-For': '10.0.0.1' } });
      assert.strictEqual(r.status, 200);
      const buf = Buffer.from(await r.arrayBuffer()); assert.strictEqual(buf.subarray(0, 15).toString(), 'SQLite format 3');
    });

    await ok('تغيير كلمة المرور: يلزم 10 أحرف، وتُبطَل الجلسات الأخرى', async () => {
      const other = new Client('10.0.0.9'); await other.post('/api/admin/login', { username: 'boss', password: 'StrongPass123' });
      assert.strictEqual((await admin.get('/api/admin/me')).status, 401, 'الدخول الجديد يُبطل القديم (جلسة واحدة)');
      await admin.post('/api/admin/login', { username: 'boss', password: 'StrongPass123' });
      assert.strictEqual((await admin.post('/api/admin/password', { current: 'StrongPass123', next: 'short' })).status, 400);
      assert.strictEqual((await admin.post('/api/admin/password', { current: 'StrongPass123', next: 'AnotherPass456' })).status, 200);
      assert.strictEqual((await new Client('10.0.0.10').post('/api/admin/login', { username: 'boss', password: 'StrongPass123' })).status, 401);
      assert.strictEqual((await admin.get('/api/admin/me')).status, 200);
    });

    await ok('تحديد المحاولات: بعد 8 فاشلة يُحظر الـIP (موظف ومشرف)، وIP آخر غير متأثر', async () => {
      const x = new Client('10.9.9.9');
      for (let i = 0; i < 8; i++) assert.strictEqual((await x.post('/api/login', { code: 'EMP-ZZZZZ' + i })).status, 401);
      assert.strictEqual((await x.post('/api/login', { code: dbg.a.code })).status, 429);
      assert.strictEqual((await new Client('10.9.9.8').post('/api/login', { code: dbg.a.code })).status, 200);
      const y = new Client('10.9.9.7');
      for (let i = 0; i < 8; i++) await y.post('/api/admin/login', { username: 'boss', password: 'bad' + i });
      assert.strictEqual((await y.post('/api/admin/login', { username: 'boss', password: 'AnotherPass456' })).status, 429);
    });

    await ok('الموظف لا يصل إلى أي واجهة مشرف', async () => {
      const c = new Client('10.0.4.1'); await c.post('/api/login', { code: dbg.a.code });
      for (const u of ['/api/admin/me', '/api/admin/dashboard', '/api/admin/employees', '/api/admin/records', '/api/admin/audit'])
        assert.strictEqual((await c.get(u)).status, 401, u);
    });
  } finally {
    srv.kill();
    console.log(`\n${passed} اختبارًا ناجحًا${process.exitCode ? ' — توجد إخفاقات' : ''}`);
    if (process.exitCode) console.log('--- server log ---\n' + log);
    fs.rmSync(dir, { recursive: true, force: true });
    process.exit(process.exitCode || 0);
  }
}
main();
