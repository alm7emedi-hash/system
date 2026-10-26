'use strict';
/* مساعدات مشتركة — لا نستخدم innerHTML أبدًا لمنع XSS من بيانات الموظفين */
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (['value', 'checked', 'disabled', 'selected', 'hidden'].includes(k)) n[k] = v;
    else n.setAttribute(k, v === true ? '' : v);
  }
  const add = c => {
    if (c == null || c === false) return;
    if (Array.isArray(c)) return c.forEach(add);
    n.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  };
  kids.forEach(add);
  return n;
}

async function api(path, opts) {
  const o = opts || {};
  const method = o.method || 'GET';
  const init = { method, credentials: 'same-origin', headers: {} };
  if (method !== 'GET') { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(o.body || {}); }
  let r;
  try { r = await fetch(path, init); } catch (e) { const err = new Error('تعذّر الاتصال بالخادم — تحقق من الإنترنت'); err.status = 0; throw err; }
  let data = null;
  try { data = await r.json(); } catch (e) { /* ignore */ }
  if (!r.ok) { const err = new Error((data && data.error) || 'حدث خطأ غير متوقع'); err.status = r.status; err.data = data; throw err; }
  return data;
}

function toast(msg) {
  const t = el('div', { class: 'toast', role: 'status' }, msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3200);
}
