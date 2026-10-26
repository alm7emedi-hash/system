'use strict';
const app = document.getElementById('app');
let admin = null, view = 'dashboard';

const STATUS = {
  open: ['حاضر', 'pill ok'], completed: ['انصرف', 'pill info'],
  missing_out: ['لم يسجل انصراف', 'pill warn'], none: ['لم يسجل حضور', 'pill']
};
const ACTIONS = {
  'admin.login': 'دخول مشرف', 'admin.login_failed': 'محاولة دخول فاشلة', 'admin.password_change': 'تغيير كلمة المرور',
  'employee.create': 'إضافة موظف', 'employee.update': 'تعديل موظف', 'employee.suspend': 'إيقاف موظف',
  'employee.activate': 'تفعيل موظف', 'employee.reissue_code': 'إصدار كود جديد', 'employee.delete': 'حذف موظف',
  'record.create': 'إضافة سجل يدويًا', 'record.update': 'تعديل سجل', 'records.export': 'تصدير سجلات', 'backup.download': 'تنزيل نسخة احتياطية'
};
const todayLocal = () => new Date(Date.now() + 3 * 3600000).toISOString().slice(0, 10);
const qs = o => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== '' && v != null)).toString();
const fail = e => { if (e.status === 401) { admin = null; boot(); } else toast(e.message); };
const opt = (v, t, sel) => el('option', { value: v, selected: sel }, t);

/* ───────── دخول / تغيير كلمة المرور ───────── */
function renderLogin(err) {
  const u = el('input', { id: 'u', type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false' });
  const p = el('input', { id: 'p', type: 'password', autocomplete: 'current-password' });
  const msg = el('div', { class: 'msg err' + (err ? '' : ' hidden'), role: 'alert' }, err || '');
  const btn = el('button', { class: 'btn block', type: 'submit' }, 'دخول');
  app.replaceChildren(el('form', { class: 'card login', onsubmit: async ev => {
    ev.preventDefault(); btn.disabled = true; msg.classList.add('hidden');
    try { await api('/api/admin/login', { method: 'POST', body: { username: u.value, password: p.value } }); boot(); }
    catch (e) { msg.textContent = e.message; msg.classList.remove('hidden'); btn.disabled = false; }
  } },
  el('h1', null, 'لوحة المشرف'), el('p', { class: 'muted' }, 'تسجيل الدخول'),
  el('div', { class: 'field' }, el('label', { for: 'u' }, 'اسم المستخدم'), u),
  el('div', { class: 'field' }, el('label', { for: 'p' }, 'كلمة المرور'), p), msg, btn));
  u.focus();
}

function passwordForm(forced) {
  const cur = el('input', { type: 'password', autocomplete: 'current-password', id: 'cp' });
  const nw = el('input', { type: 'password', autocomplete: 'new-password', id: 'np' });
  const msg = el('div', { class: 'msg hidden', role: 'alert' });
  return el('form', { class: 'card' + (forced ? ' login' : ''), onsubmit: async ev => {
    ev.preventDefault();
    try {
      await api('/api/admin/password', { method: 'POST', body: { current: cur.value, next: nw.value } });
      cur.value = nw.value = ''; toast('تم تغيير كلمة المرور');
      if (forced) boot();
    } catch (e) { msg.textContent = e.message; msg.className = 'msg err'; }
  } },
  el('h3', null, forced ? 'يجب تغيير كلمة المرور قبل المتابعة' : 'تغيير كلمة المرور'),
  el('div', { class: 'field' }, el('label', { for: 'cp' }, 'كلمة المرور الحالية'), cur),
  el('div', { class: 'field' }, el('label', { for: 'np' }, 'كلمة المرور الجديدة (10 أحرف على الأقل)'), nw),
  msg, el('button', { class: 'btn', type: 'submit' }, 'حفظ'));
}

/* ───────── الهيكل ───────── */
const TABS = [['dashboard', 'الرئيسية'], ['employees', 'الموظفون'], ['records', 'السجلات'], ['audit', 'سجل التدقيق'], ['settings', 'الإعدادات']];
function shell() {
  const body = el('div', { id: 'view' });
  app.replaceChildren(
    el('div', { class: 'topbar' },
      el('h1', null, 'لوحة المشرف'),
      el('div', null, el('span', { class: 'muted' }, admin.username + ' '),
        el('button', { class: 'btn ghost small', onclick: async () => { try { await api('/api/admin/logout', { method: 'POST' }); } catch (e) { /* ignore */ } admin = null; boot(); } }, 'خروج'))),
    el('nav', { class: 'tabs', 'aria-label': 'الأقسام' }, TABS.map(([k, t]) =>
      el('button', { class: 'tab', 'aria-current': k === view ? 'page' : null, onclick: () => { view = k; shell(); } }, t))),
    body);
  ({ dashboard: vDashboard, employees: vEmployees, records: vRecords, audit: vAudit, settings: vSettings })[view](body);
}

/* ───────── لوحة التحكم ───────── */
async function vDashboard(body) {
  let d;
  try { d = await api('/api/admin/dashboard'); } catch (e) { return fail(e); }
  const kpi = (n, t, c) => el('div', { class: 'card kpi ' + (c || '') }, el('b', null, n), el('span', null, t));
  const max = Math.max(1, ...d.days.map(x => x.count));
  const stat = (title, s) => el('div', { class: 'card' }, el('h3', null, title),
    el('p', { class: 'muted' }, `${s.records} سجل حضور — ${s.people} موظف`),
    el('p', { class: 'muted' }, `ساعات العمل المكتملة: ${s.hours}`),
    s.missing ? el('p', null, el('span', { class: 'pill warn' }, `${s.missing} بدون انصراف`)) : null);
  body.replaceChildren(
    el('div', { class: 'grid c4' }, kpi(d.total, 'عدد الموظفين الفعّالين'), kpi(d.present, 'حاضرون الآن (لم ينصرفوا)', 'ok'),
      kpi(d.left, 'المنصرفون', 'info'), kpi(d.not_in, 'لم يسجلوا حضور', 'warn')),
    el('div', { class: 'grid c3 section' }, stat('اليوم', d.stats.day), stat('آخر 7 أيام', d.stats.week), stat('الشهر الحالي', d.stats.month)),
    el('div', { class: 'section card' }, el('h3', null, 'الحضور خلال آخر 7 أيام'),
      el('div', { class: 'bars' }, d.days.map(x => {
        const i = el('i'); i.style.height = Math.round(x.count / max * 78) + '%';
        return el('div', { class: 'bar' }, el('b', null, x.count), i, el('span', null, x.date.slice(5)));
      }))),
    el('div', { class: 'section card' }, el('h3', null, 'آخر العمليات'),
      d.recent.length ? el('ul', { class: 'feed' }, d.recent.map(r => el('li', null,
        el('span', null, r.name), el('span', null, el('span', { class: r.kind === 'in' ? 'pill ok' : 'pill info' }, r.kind === 'in' ? 'حضور' : 'انصراف'),
          ' ', el('span', { class: 't muted' }, r.date + ' ' + r.time))))) : el('div', { class: 'empty' }, 'لا توجد عمليات بعد')));
}

/* ───────── الموظفون ───────── */
function showDialog(build) {
  const dlg = el('dialog');
  dlg.addEventListener('close', () => dlg.remove());
  build(dlg, () => dlg.close());
  document.body.appendChild(dlg); dlg.showModal();
}
function revealCode(name, code, title) {
  showDialog((dlg, close) => dlg.append(
    el('h3', null, title), el('p', null, 'كود الموظف: ' + name),
    el('div', { class: 'code-box' }, code),
    el('p', { class: 'muted' }, 'يُعرض هذا الكود مرة واحدة فقط ولا يمكن استرجاعه لاحقًا. سلّمه للموظف الآن؛ وإن فُقد أصدر كودًا جديدًا.'),
    el('div', { class: 'dlg-actions' },
      el('button', { class: 'btn ghost', onclick: async () => { try { await navigator.clipboard.writeText(code); toast('تم النسخ'); } catch (e) { toast('انسخه يدويًا'); } } }, 'نسخ'),
      el('button', { class: 'btn', onclick: close }, 'تم'))));
}
function empDialog(emp, lists, done) {
  const f = {
    name: el('input', { id: 'f1', value: emp ? emp.name : '', maxlength: '100', required: true }),
    num: el('input', { id: 'f2', value: emp ? emp.employee_number || '' : '', maxlength: '30', inputmode: 'text' }),
    dep: el('input', { id: 'f3', value: emp ? emp.department || '' : '', maxlength: '60', list: 'dl-dep' }),
    cen: el('input', { id: 'f4', value: emp ? emp.center || '' : '', maxlength: '60', list: 'dl-cen' })
  };
  showDialog((dlg, close) => {
    const msg = el('div', { class: 'msg err hidden', role: 'alert' });
    dlg.append(el('form', { onsubmit: async ev => {
      ev.preventDefault();
      const body = { name: f.name.value, employee_number: f.num.value, department: f.dep.value, center: f.cen.value };
      try {
        if (emp) { await api('/api/admin/employees/' + emp.id, { method: 'PUT', body }); close(); toast('تم الحفظ'); done(); }
        else { const r = await api('/api/admin/employees', { method: 'POST', body }); close(); done(); revealCode(body.name, r.code, 'تمت إضافة الموظف'); }
      } catch (e) { msg.textContent = e.message; msg.classList.remove('hidden'); }
    } },
    el('h3', null, emp ? 'تعديل بيانات الموظف' : 'إضافة موظف'),
    el('div', { class: 'field' }, el('label', { for: 'f1' }, 'الاسم'), f.name),
    el('div', { class: 'field' }, el('label', { for: 'f2' }, 'الرقم الوظيفي (اختياري)'), f.num),
    el('div', { class: 'field' }, el('label', { for: 'f3' }, 'القسم'), f.dep),
    el('div', { class: 'field' }, el('label', { for: 'f4' }, 'المركز'), f.cen),
    el('datalist', { id: 'dl-dep' }, lists.departments.map(x => el('option', { value: x }))),
    el('datalist', { id: 'dl-cen' }, lists.centers.map(x => el('option', { value: x }))),
    msg,
    el('div', { class: 'dlg-actions' }, el('button', { type: 'button', class: 'btn ghost', onclick: close }, 'إلغاء'), el('button', { type: 'submit', class: 'btn' }, 'حفظ'))));
  });
}

async function vEmployees(body) {
  const flt = { q: '', department: '', center: '', status: '' };
  const list = el('div');
  const depSel = el('select'), cenSel = el('select');
  let lists = { departments: [], centers: [] }, timer;

  async function load() {
    let r;
    try { r = await api('/api/admin/employees?' + qs(flt)); } catch (e) { return fail(e); }
    lists = r;
    const fill = (sel, items, label, cur) => sel.replaceChildren(opt('', label, !cur), ...items.map(x => opt(x, x, x === cur)));
    fill(depSel, r.departments, 'كل الأقسام', flt.department); fill(cenSel, r.centers, 'كل المراكز', flt.center);
    const act = (t, fn, cls) => el('button', { class: 'btn small ' + (cls || 'ghost'), onclick: fn }, t);
    list.replaceChildren(r.employees.length ? el('div', { class: 'tablewrap' }, el('table', { class: 'resp' },
      el('thead', null, el('tr', null, ['الاسم', 'الرقم الوظيفي', 'القسم', 'المركز', 'الحالة', 'آخر إصدار للكود', ''].map(h => el('th', null, h)))),
      el('tbody', null, r.employees.map(e => el('tr', null,
        el('td', { 'data-label': 'الاسم' }, e.name), el('td', { 'data-label': 'الرقم الوظيفي' }, e.employee_number || '—'),
        el('td', { 'data-label': 'القسم' }, e.department || '—'), el('td', { 'data-label': 'المركز' }, e.center || '—'),
        el('td', { 'data-label': 'الحالة' }, el('span', { class: e.status === 'active' ? 'pill ok' : 'pill bad' }, e.status === 'active' ? 'فعّال' : 'موقوف')),
        el('td', { 'data-label': 'آخر إصدار للكود' }, el('span', { class: 't muted' }, e.code_issued_at || '—')),
        el('td', { class: 'acts-cell' }, el('div', { class: 'acts' },
          act('تعديل', () => empDialog(e, lists, load)),
          act(e.status === 'active' ? 'إيقاف' : 'تفعيل', async () => {
            try { await api(`/api/admin/employees/${e.id}/status`, { method: 'POST', body: { status: e.status === 'active' ? 'suspended' : 'active' } }); load(); } catch (x) { fail(x); }
          }),
          act('كود جديد', () => { if (confirm(`إصدار كود جديد لـ ${e.name}؟ سيبطل الكود الحالي فورًا.`)) api(`/api/admin/employees/${e.id}/code`, { method: 'POST' }).then(x => { revealCode(e.name, x.code, 'تم إصدار كود جديد'); load(); }).catch(fail); }),
          act('حذف', () => { if (confirm(`حذف ${e.name}؟ يبقى سجل حضوره التاريخي ولا يمكن التراجع عن الحذف.`)) api('/api/admin/employees/' + e.id, { method: 'DELETE' }).then(() => { toast('تم الحذف'); load(); }).catch(fail); }, 'danger'))))))))
      : el('div', { class: 'empty card' }, 'لا يوجد موظفون مطابقون'));
  }
  const field = (label, node, cls) => el('div', { class: 'f ' + (cls || '') }, el('label', null, label), node);
  body.replaceChildren(
    el('div', { class: 'toolbar' },
      field('بحث بالاسم أو الرقم الوظيفي', el('input', { type: 'search', oninput: ev => { flt.q = ev.target.value; clearTimeout(timer); timer = setTimeout(load, 250); } }), 'wide'),
      field('القسم', depSel), field('المركز', cenSel),
      field('الحالة', el('select', { onchange: ev => { flt.status = ev.target.value; load(); } }, opt('', 'الكل'), opt('active', 'فعّال'), opt('suspended', 'موقوف'))),
      el('button', { class: 'btn', onclick: () => empDialog(null, lists, load) }, '+ إضافة موظف')),
    list);
  depSel.addEventListener('change', () => { flt.department = depSel.value; load(); });
  cenSel.addEventListener('change', () => { flt.center = cenSel.value; load(); });
  load();
}

/* ───────── السجلات ───────── */
async function vRecords(body) {
  const t = todayLocal();
  const flt = { from: t, to: t, employee_id: '', department: '', status: '', q: '' };
  const PAGE = 100; let offset = 0, timer;
  const list = el('div'), printHead = el('div', { class: 'print-only' });
  const empSel = el('select'), depSel = el('select');
  try {
    const r = await api('/api/admin/employees');
    empSel.replaceChildren(opt('', 'كل الموظفين'), ...r.employees.map(e => opt(e.id, e.name)));
    depSel.replaceChildren(opt('', 'كل الأقسام'), ...r.departments.map(x => opt(x, x)));
  } catch (e) { return fail(e); }

  async function load() {
    let r;
    try { r = await api('/api/admin/records?' + qs({ ...flt, limit: PAGE, offset })); } catch (e) { return fail(e); }
    printHead.replaceChildren(el('h2', null, 'تقرير الحضور والانصراف'), el('p', null, `الفترة: ${flt.from || '—'} إلى ${flt.to || '—'} — تاريخ الطباعة: ${t}`));
    const rows = r.rows;
    list.replaceChildren(rows.length ? el('div', { class: 'tablewrap' }, el('table', { class: 'resp' },
      el('thead', null, el('tr', null, ['الموظف', 'التاريخ', 'الحضور', 'الانصراف', 'المدة', 'الحالة'].map(h => el('th', null, h)).concat(el('th', { class: 'col-act' }, '')))),
      el('tbody', null, rows.map(x => {
        const [sl, sc] = STATUS[x.status];
        return el('tr', null,
          el('td', { 'data-label': 'الموظف' }, x.name, x.deleted ? el('span', { class: 'muted' }, ' (محذوف)') : null, x.shared_device ? el('span', { class: 'flag', title: 'سُجّل الحضور من جهاز استُخدم لموظف آخر في نفس اليوم — للمراجعة' }, ' ⚠') : null),
          el('td', { 'data-label': 'التاريخ' }, el('span', { class: 't' }, x.date)),
          el('td', { 'data-label': 'الحضور' }, el('span', { class: 't' }, x.check_in || '—')),
          el('td', { 'data-label': 'الانصراف' }, el('span', { class: 't' }, x.check_out ? x.check_out + (x.out_next_day ? ' (+1)' : '') : '—')),
          el('td', { 'data-label': 'المدة' }, el('span', { class: 't' }, x.duration || '—')),
          el('td', { 'data-label': 'الحالة' }, el('span', { class: sc }, sl), x.edited ? el('span', { class: 'pill', title: x.note || '' }, 'معدّل') : null),
          el('td', { class: 'acts-cell col-act' }, x.id ? el('button', { class: 'btn ghost small', onclick: () => recordDialog(x, load) }, 'تعديل') : null));
      })))) : el('div', { class: 'empty card' }, 'لا توجد سجلات'),
    el('div', { class: 'pager no-print' },
      el('span', null, `${r.total} سجل`),
      el('span', null, el('button', { class: 'btn ghost small', disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - PAGE); load(); } }, 'السابق'), ' ',
        el('button', { class: 'btn ghost small', disabled: offset + PAGE >= r.total, onclick: () => { offset += PAGE; load(); } }, 'التالي'))));
  }
  const set = k => ev => { flt[k] = ev.target.value; offset = 0; clearTimeout(timer); timer = setTimeout(load, 200); };
  const field = (label, node, cls) => el('div', { class: 'f ' + (cls || '') }, el('label', null, label), node);
  empSel.addEventListener('change', set('employee_id')); depSel.addEventListener('change', set('department'));
  body.replaceChildren(
    el('div', { class: 'toolbar' },
      field('من تاريخ', el('input', { type: 'date', value: flt.from, onchange: set('from') })),
      field('إلى تاريخ', el('input', { type: 'date', value: flt.to, onchange: set('to') })),
      field('الموظف', empSel), field('القسم', depSel),
      field('الحالة', el('select', { onchange: set('status') }, opt('', 'الكل'), opt('open', 'حاضر'), opt('completed', 'انصرف'), opt('missing_out', 'لم يسجل انصراف'), opt('none', 'لم يسجل حضور (يوم واحد)'))),
      field('بحث', el('input', { type: 'search', placeholder: 'الاسم أو الرقم الوظيفي', oninput: set('q') }), 'wide')),
    el('div', { class: 'toolbar' },
      el('a', { class: 'btn ghost', href: '#', onclick: ev => { ev.preventDefault(); location.href = '/api/admin/records.csv?' + qs(flt); } }, 'تصدير Excel / CSV'),
      el('button', { class: 'btn ghost', onclick: () => window.print() }, 'طباعة التقرير'),
      el('button', { class: 'btn', onclick: () => recordDialog(null, load) }, '+ سجل يدوي')),
    printHead, list);
  load();
}

async function recordDialog(rec, done) {
  let emps = [];
  if (!rec) { try { emps = (await api('/api/admin/employees')).employees; } catch (e) { return fail(e); } }
  const sel = el('select', { id: 'r0' }, emps.map(e => opt(e.id, e.name)));
  const inn = el('input', { id: 'r1', type: 'datetime-local', value: rec ? rec.check_in_local : '', required: true });
  const out = el('input', { id: 'r2', type: 'datetime-local', value: rec ? rec.check_out_local : '' });
  const why = el('input', { id: 'r3', maxlength: '300', required: true, placeholder: 'مثال: نسي الانصراف — بتوجيه المشرف' });
  showDialog((dlg, close) => {
    const msg = el('div', { class: 'msg err hidden', role: 'alert' });
    dlg.append(el('form', { onsubmit: async ev => {
      ev.preventDefault();
      const b = { check_in: inn.value, check_out: out.value, reason: why.value };
      try {
        if (rec) await api('/api/admin/records/' + rec.id, { method: 'PUT', body: b });
        else await api('/api/admin/records', { method: 'POST', body: { ...b, employee_id: +sel.value } });
        close(); toast('تم الحفظ وتسجيله في سجل التدقيق'); done();
      } catch (e) { msg.textContent = e.message; msg.classList.remove('hidden'); }
    } },
    el('h3', null, rec ? 'تعديل سجل: ' + rec.name : 'إضافة سجل يدوي'),
    rec ? null : el('div', { class: 'field' }, el('label', { for: 'r0' }, 'الموظف'), sel),
    el('div', { class: 'field' }, el('label', { for: 'r1' }, 'وقت الحضور (توقيت الكويت)'), inn),
    el('div', { class: 'field' }, el('label', { for: 'r2' }, 'وقت الانصراف (اتركه فارغًا إن لم ينصرف)'), out),
    el('div', { class: 'field' }, el('label', { for: 'r3' }, 'سبب التعديل (إلزامي)'), why),
    msg,
    el('div', { class: 'dlg-actions' }, el('button', { type: 'button', class: 'btn ghost', onclick: close }, 'إلغاء'), el('button', { type: 'submit', class: 'btn' }, 'حفظ'))));
  });
}

/* ───────── سجل التدقيق ───────── */
async function vAudit(body) {
  const PAGE = 50; let offset = 0;
  const list = el('div');
  async function load() {
    let r;
    try { r = await api('/api/admin/audit?' + qs({ limit: PAGE, offset })); } catch (e) { return fail(e); }
    const det = d => {
      if (!d) return '';
      if (d.before || d.after) return Object.keys(d.after || {}).map(k => `${k}: ${(d.before || {})[k] ?? '—'} ← ${d.after[k] ?? '—'}`).join(' | ') + (d.reason ? ' | السبب: ' + d.reason : '');
      return d.reason ? 'السبب: ' + d.reason : '';
    };
    list.replaceChildren(r.rows.length ? el('div', { class: 'tablewrap' }, el('table', { class: 'resp' },
      el('thead', null, el('tr', null, ['الوقت', 'المشرف', 'العملية', 'الهدف', 'تفاصيل', 'IP'].map(h => el('th', null, h)))),
      el('tbody', null, r.rows.map(x => el('tr', null,
        el('td', { 'data-label': 'الوقت' }, el('span', { class: 't' }, x.time)), el('td', { 'data-label': 'المشرف' }, x.admin || '—'),
        el('td', { 'data-label': 'العملية' }, el('span', { class: x.action === 'admin.login_failed' ? 'pill bad' : 'pill' }, ACTIONS[x.action] || x.action)),
        el('td', { 'data-label': 'الهدف' }, x.target || '—'), el('td', { 'data-label': 'تفاصيل' }, det(x.details)),
        el('td', { 'data-label': 'IP' }, el('span', { class: 't muted' }, x.ip || '')))))))
      : el('div', { class: 'empty card' }, 'لا توجد عمليات'),
    el('div', { class: 'pager' }, el('span', null, `${r.total} عملية`),
      el('span', null, el('button', { class: 'btn ghost small', disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - PAGE); load(); } }, 'السابق'), ' ',
        el('button', { class: 'btn ghost small', disabled: offset + PAGE >= r.total, onclick: () => { offset += PAGE; load(); } }, 'التالي'))));
  }
  body.replaceChildren(list); load();
}

/* ───────── الإعدادات ───────── */
function vSettings(body) {
  body.replaceChildren(el('div', { class: 'grid c3' }, passwordForm(false),
    el('div', { class: 'card' }, el('h3', null, 'نسخة احتياطية'),
      el('p', { class: 'muted' }, 'تنزيل نسخة كاملة من قاعدة البيانات. احتفظ بها في مكان آمن وخذها دوريًا.'),
      el('button', { class: 'btn', onclick: () => { location.href = '/api/admin/backup'; } }, 'تنزيل النسخة الاحتياطية'))));
}

/* ───────── البداية ───────── */
async function boot() {
  try {
    admin = await api('/api/admin/me');
    if (admin.must_change) return app.replaceChildren(passwordForm(true));
    shell();
  } catch (e) {
    if (e.status === 401) renderLogin(); else app.replaceChildren(el('div', { class: 'msg err' }, e.message));
  }
}
boot();
