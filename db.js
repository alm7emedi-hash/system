'use strict';
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'attendance.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS employees (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT    NOT NULL,
  employee_number TEXT,
  department      TEXT,
  center          TEXT,
  code_hash       TEXT    NOT NULL UNIQUE,
  status          TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  deleted_at      INTEGER,
  code_issued_at  INTEGER NOT NULL,
  created_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_emp_number
  ON employees(employee_number)
  WHERE deleted_at IS NULL AND employee_number IS NOT NULL;

CREATE TABLE IF NOT EXISTS attendance (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  date        TEXT    NOT NULL,              -- تاريخ الحضور بتوقيت الكويت YYYY-MM-DD
  check_in    INTEGER NOT NULL,              -- epoch ms (وقت الخادم)
  check_out   INTEGER,                       -- epoch ms (وقت الخادم)
  status      TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open','completed','missing_out')),
  edited      INTEGER NOT NULL DEFAULT 0,
  note        TEXT,
  ip          TEXT,
  device_id   TEXT,
  user_agent  TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE (employee_id, date),
  CHECK (check_out IS NULL OR check_out >= check_in)
);
CREATE INDEX IF NOT EXISTS ix_att_date   ON attendance(date);
CREATE INDEX IF NOT EXISTS ix_att_open   ON attendance(employee_id, status);
CREATE INDEX IF NOT EXISTS ix_att_device ON attendance(device_id, date);

CREATE TABLE IF NOT EXISTS admins (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  username             TEXT NOT NULL UNIQUE,
  password_hash        TEXT NOT NULL,
  role                 TEXT NOT NULL DEFAULT 'admin',
  must_change_password INTEGER NOT NULL DEFAULT 0,
  created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id       INTEGER,
  admin_username TEXT,
  action         TEXT NOT NULL,
  target         TEXT,
  details        TEXT,
  ip             TEXT,
  timestamp      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_logs(timestamp);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,               -- SHA-256 للتوكن (التوكن نفسه لا يُخزَّن)
  kind       TEXT NOT NULL CHECK (kind IN ('emp','admin')),
  subject_id INTEGER NOT NULL,
  device_id  TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sess_subject ON sessions(kind, subject_id);
`);

// مفتاح سري لتجزئة الأكواد — يُولَّد مرة واحدة ويُحفظ في القاعدة (أو من APP_SECRET)
let secret = process.env.APP_SECRET;
if (!secret) {
  const row = db.prepare("SELECT value FROM meta WHERE key='secret'").get();
  if (row) secret = row.value;
  else {
    secret = crypto.randomBytes(32).toString('hex');
    db.prepare("INSERT INTO meta(key,value) VALUES('secret',?)").run(secret);
  }
}

module.exports = { db, secret, DB_PATH };
