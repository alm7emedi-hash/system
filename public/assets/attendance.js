'use strict';
const app = document.getElementById('app');
let me = null, flash = null, delta = 0, clockTimer = null;

function head() {
  return el('div', { class: 'brand' }, el('h1', null, 'الحضور والانصراف'));
}

function renderLogin(err) {
  clearInterval(clockTimer);
  const input = el('input', {
    id: 'code', type: 'text', inputmode: 'text', autocomplete: 'off', autocapitalize: 'characters',
    autocorrect: 'off', spellcheck: 'false', placeholder: 'EMP-XXXXXX', maxlength: '20', 'aria-label': 'كود الموظف'
  });
  const msg = el('div', { class: 'msg err' + (err ? '' : ' hidden'), role: 'alert' }, err || '');
  const btn = el('button', { class: 'btn block', type: 'submit' }, 'دخول');
  const form = el('form', { class: 'card', onsubmit: async ev => {
    ev.preventDefault();
    if (!input.value.trim()) return;
    btn.disabled = true; msg.classList.add('hidden');
    try {
      await api('/api/login', { method: 'POST', body: { code: input.value } });
      await boot();
    } catch (e) {
      msg.textContent = e.message; msg.classList.remove('hidden'); btn.disabled = false; input.select();
    }
  } },
  el('div', { class: 'field' }, el('label', { for: 'code' }, 'أدخل كود الموظف'), input),
  msg, btn);
  app.replaceChildren(head(), form);
  input.focus();
}

const STATE = {
  none: ['لم يسجّل حضور', 'pill'],
  present: ['حاضر', 'pill ok'],
  done: ['انصرف', 'pill info'],
  missing: ['لم يسجّل انصراف — راجع المشرف', 'pill warn']
};

function clockText() {
  const t = new Date(Date.now() + delta + me.tz_offset_ms).toISOString();
  return t.slice(0, 10) + '  ' + t.slice(11, 19);
}

function renderCard() {
  const e = me.employee;
  const [stLabel, stClass] = STATE[me.state];
  const sub = [e.employee_number && ('الرقم الوظيفي: ' + e.employee_number), e.department, e.center].filter(Boolean).join(' • ');
  const canIn = me.can_checkin, canOut = me.can_checkout;
  const msg = el('div', { class: 'msg hidden', role: 'status', 'aria-live': 'polite' });
  if (flash) { msg.textContent = flash.text; msg.className = 'msg ' + (flash.ok ? 'ok' : 'err'); flash = null; }

  const act = (path, label) => async ev => {
    const btns = app.querySelectorAll('.big-actions .btn');
    btns.forEach(b => (b.disabled = true));
    try {
      const r = await api(path, { method: 'POST' });
      flash = { ok: true, text: `تم تسجيل ${label} بنجاح — الساعة ${r.time}` };
    } catch (err) {
      flash = { ok: false, text: err.message };
      if (err.status === 401) return boot();
    }
    boot();
  };

  const clock = el('div', { class: 'clock' });
  const tick = () => { clock.textContent = 'توقيت الخادم: ' + clockText(); };
  tick(); clearInterval(clockTimer); clockTimer = setInterval(tick, 1000);

  const openNote = me.record_date && me.record_date !== me.today
    ? el('p', { class: 'muted loading' }, `السجل المعروض بتاريخ ${me.record_date}`) : null;

  app.replaceChildren(
    head(),
    el('div', { class: 'card' },
      el('div', { class: 'who' }, el('h2', null, e.name), el('div', { class: 'sub' }, sub)),
      el('div', { class: 'status-line' }, el('span', { class: stClass }, stLabel)),
      openNote,
      el('div', { class: 'times' },
        el('div', { class: 'time-box' }, el('small', null, 'وقت الحضور'), el('b', null, me.check_in || '—')),
        el('div', { class: 'time-box' }, el('small', null, 'وقت الانصراف'), el('b', null, me.check_out ? me.check_out + (me.out_next_day ? ' (+1)' : '') : '—'))),
      msg,
      el('div', { class: 'big-actions' },
        el('button', { class: 'btn ok', type: 'button', disabled: !canIn, onclick: act('/api/checkin', 'الحضور') }, 'تسجيل حضور'),
        el('button', { class: 'btn', type: 'button', disabled: !canOut, onclick: act('/api/checkout', 'الانصراف') }, 'تسجيل انصراف')),
      clock),
    el('div', { class: 'loading' }, el('button', { class: 'link', type: 'button', onclick: logout }, 'تسجيل الخروج'))
  );
}

async function logout() {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
  me = null; renderLogin();
}

async function boot() {
  try {
    me = await api('/api/me');
    delta = me.server_ms - Date.now();
    renderCard();
  } catch (e) {
    if (e.status === 401) renderLogin(flash && !flash.ok ? flash.text : null);
    else app.replaceChildren(head(), el('div', { class: 'msg err' }, e.message), el('button', { class: 'btn block', onclick: boot }, 'إعادة المحاولة'));
  }
}
boot();
