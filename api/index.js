const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const SECRET = process.env.AUTH_SECRET || '';
let FINE_PER_DAY = 20;
// Borrowing rules: change the numbers here if you want different limits
const LIMITS = { Student: { max: 3, days: 14 }, Teacher: { max: 10, days: 30 }, Librarian: { max: 10, days: 30 } };
let READ_GOAL = 10; // books per year for the reading certificate
let settingsAt = 0;
async function loadSettings(force) {
  if (!force && Date.now() - settingsAt < 30000) return;
  settingsAt = Date.now();
  const { data } = await db.from('settings').select('*');
  const v = {}; (data || []).forEach(r => v[r.key] = +r.value);
  const hol = await db.from('holidays').select('day'); HOLIDAYS = new Set((hol.data || []).map(x => x.day));
  if (v.fine_per_day >= 0) FINE_PER_DAY = v.fine_per_day;
  if (v.read_goal > 0) READ_GOAL = v.read_goal;
  if (v.student_max > 0) LIMITS.Student.max = v.student_max;
  if (v.student_days > 0) LIMITS.Student.days = v.student_days;
  if (v.teacher_max > 0) LIMITS.Teacher.max = LIMITS.Librarian.max = v.teacher_max;
  if (v.teacher_days > 0) LIMITS.Teacher.days = LIMITS.Librarian.days = v.teacher_days;
}
const toTrash = async (kind, table, col, val, who) => {
  const rows = await q(db.from(table).select('*').eq(col, val));
  if (rows[0]) await q(db.from('trash').insert({ kind, data: rows[0], deleted_by: who }));
};
const limFor = m => LIMITS[(m || {}).role] || LIMITS.Student;
const app = express();
app.use(express.json());
app.use(async (_req, _res, next) => { try { await loadSettings(); } catch (e) { /* settings table is optional */ } next(); });

// activity log: every successful change is recorded
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.path !== '/api/login' && req.path !== '/api/parent') {
    res.on('finish', () => {
      if (res.statusCode >= 400) return;
      const u = verify((req.headers.authorization || '').replace('Bearer ', ''));
      const b = req.body || {};
      db.from('audit').insert({ who: u ? u.name : '?', action: req.method + ' ' + req.path, detail: String(b.title || b.name || b.borrowerId || '').slice(0, 80) }).then(() => {}, () => {});
    });
  }
  next();
});

// ---- helpers ----
const mac = b => crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return `${b}.${mac(b)}`; };
const verify = t => {
  try {
    const [b, s] = (t || '').split('.');
    if (!SECRET || s !== mac(b)) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url'));
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
};
const auth = role => (req, res, next) => {
  const u = verify((req.headers.authorization || '').replace('Bearer ', ''));
  if (!u) return res.status(401).json({ error: 'Please sign in.' });
  if (role === 'admin' && u.role !== 'admin') {
    if (u.role !== 'viewer') return res.status(401).json({ error: 'Please sign in with an admin account.' });
    if (req.method !== 'GET') return res.status(403).json({ error: 'This is a view-only account. You cannot change data.' });
  }
  req.user = u; next();
};
const h = fn => (req, res) => fn(req, res).catch(e => res.status(500).json({ error: e.message }));
const q = async p => { const { data, error } = await p; if (error) throw new Error(error.message); return data; };
// Supabase returns max 1000 rows per request, so read in pages
const fetchAll = async build => {
  let out = [], from = 0;
  for (;;) {
    const rows = await q(build().range(from, from + 999));
    out = out.concat(rows);
    if (rows.length < 1000) return out;
    from += 1000;
  }
};
const hashPw = p => { const salt = crypto.randomBytes(8).toString('hex'); return salt + ':' + crypto.scryptSync(p, salt, 32).toString('hex'); };
const checkPw = (p, hs) => {
  const [salt, hx] = (hs || '').split(':');
  return !!hx && crypto.timingSafeEqual(Buffer.from(hx, 'hex'), crypto.scryptSync(p, salt, 32));
};
const today = () => new Date().toISOString().slice(0, 10);
const openCount = async id => {
  const { count, error } = await db.from('history').select('*', { count: 'exact', head: true }).eq('borrower_id', id).is('return_date', null);
  if (error) throw new Error(error.message);
  return count || 0;
};
const lateDays = d => d ? Math.max(0, Math.ceil((new Date(today()) - new Date(d)) / 864e5)) : 0;
let HOLIDAYS = new Set();
// next working day: skips Saturday, Sunday and the holidays set by the librarian
const workday = d => {
  let t = new Date(d + 'T00:00:00Z');
  for (let i = 0; i < 30; i++) {
    const k = t.toISOString().slice(0, 10), wd = t.getUTCDay();
    if (wd !== 0 && wd !== 6 && !HOLIDAYS.has(k)) return k;
    t = new Date(t.getTime() + 864e5);
  }
  return d;
};
const addDays = n => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

// ---- auth ----
app.post('/api/login', h(async (req, res) => {
  const { username = '', password = '' } = req.body;
  const who = username.toLowerCase().trim().slice(0, 60);
  const since = new Date(Date.now() - 10 * 60000).toISOString();
  const { count } = await db.from('login_attempts').select('*', { count: 'exact', head: true }).eq('who', who).gt('at', since);
  if ((count || 0) >= 5) return res.status(429).json({ error: 'Too many wrong attempts. Please try again in 10 minutes.' });
  const token = (name, role, id) => ({ success: true, name, role, memberId: id, token: sign({ name, role, id, exp: Date.now() + 12 * 36e5 }) });
  const ok = async r => { await db.from('login_attempts').delete().eq('who', who); return res.json(r); };
  if (process.env.ADMIN_USER && username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) return ok(token(username, 'admin'));
  const members = await q(db.from('members').select('*').or(`id.ilike.${username.replace(/[,()]/g, '')},name.ilike.${username.replace(/[,()]/g, '')}`));
  const m = members.find(x => x.status === 'Active' && (x.pw_hash ? checkPw(password, x.pw_hash) : x.id.toLowerCase() === password.toLowerCase()));
  if (!m) { await db.from('login_attempts').insert({ who }); return res.status(401).json({ error: 'Name or member ID or password is incorrect.' }); }
  return ok(token(m.name, m.role === 'Librarian' ? 'admin' : m.role === 'Viewer' ? 'viewer' : 'user', m.id));
}));


// ---- books ----
app.get('/api/books', h(async (_req, res) => res.json(await fetchAll(() => db.from('books').select('*').order('id')))));

app.post('/api/books', auth('admin'), h(async (req, res) => {
  const { title, author, category, ledger_info, quantity, pdf_url, barcode } = req.body;
  if (!title || !author || !category) return res.status(400).json({ error: 'Title, author and category are required.' });
  const rows = await q(db.from('books').insert({
    title, author, category, ledger_info: ledger_info || 'N/A', quantity: parseInt(quantity) || 1,
    pdf_url: pdf_url || '', barcode: barcode || 'KCC-' + Math.floor(100000 + Math.random() * 900000)
  }).select());
  res.status(201).json(rows[0]);
}));

// bulk import from Excel (admin)
app.post('/api/books/bulk', auth('admin'), h(async (req, res) => {
  const rows = (req.body.books || []).filter(b => b.title && String(b.title).trim()).slice(0, 500).map(b => ({
    title: String(b.title).trim(),
    author: String(b.author || 'N/A').trim(),
    category: String(b.category || 'General').trim(),
    ledger_info: String(b.ledger_info || 'N/A').trim(),
    quantity: parseInt(b.quantity) || 1,
    barcode: 'KCC-' + Math.floor(100000 + Math.random() * 900000)
  }));
  if (!rows.length) return res.status(400).json({ error: 'No valid rows found.' });
  await q(db.from('books').insert(rows));
  res.json({ added: rows.length });
}));

app.delete('/api/books/:id', auth('admin'), h(async (req, res) => {
  await toTrash('book', 'books', 'id', req.params.id, req.user.name);
  await q(db.from('books').delete().eq('id', req.params.id));
  res.json({ ok: true });
}));

// ---- issue / return (copy by copy) ----
const sync = async id => {
  const [b] = await q(db.from('books').select('quantity,lost_count').eq('id', id));
  if (!b) return;
  const { count, error } = await db.from('history').select('*', { count: 'exact', head: true }).eq('book_id', id).is('return_date', null);
  if (error) throw new Error(error.message);
  const n = count || 0;
  await q(db.from('books').update({ borrowed_count: n, status: n + (b.lost_count || 0) >= (b.quantity || 1) ? 'Borrowed' : 'Available' }).eq('id', id));
};

app.post('/api/books/:id/issue', auth('admin'), h(async (req, res) => {
  const [book] = await q(db.from('books').select('*').eq('id', req.params.id));
  if (!book) return res.status(404).json({ error: 'Book not found.' });
  if ((book.borrowed_count || 0) + (book.lost_count || 0) >= (book.quantity || 1)) return res.status(400).json({ error: 'No copy of this book is available.' });
  const [m] = await q(db.from('members').select('*').ilike('id', req.body.borrowerId || ''));
  if (!m) return res.status(400).json({ error: 'No member found with that ID.' });
  const lim = limFor(m);
  if (await openCount(m.id) >= lim.max) return res.status(400).json({ error: `${m.name} already has ${lim.max} books (the limit for a ${m.role}).` });
  const open = await q(db.from('history').select('id').eq('book_id', book.id).eq('borrower_id', m.id).is('return_date', null));
  if (open.length) return res.status(400).json({ error: 'This member already has a copy of this book.' });
  await q(db.from('history').insert({ book_id: book.id, book_title: book.title, borrower_name: m.name, borrower_id: m.id, issue_date: today(), due_date: workday(addDays(lim.days)) }));
  await db.from('reservations').update({ status: 'Fulfilled' }).eq('book_id', book.id).eq('member_id', m.id).eq('status', 'Waiting');
  await sync(book.id);
  res.json({ ok: true });
}));

app.get('/api/books/:id/loans', auth('admin'), h(async (req, res) => {
  const loans = await q(db.from('history').select('*').eq('book_id', req.params.id).is('return_date', null).order('id'));
  if (!loans.length) await sync(req.params.id); // fixes a book that wrongly shows as borrowed
  res.json(loans.map(l => ({ ...l, rate: FINE_PER_DAY })));
}));

app.post('/api/loans/:id/return', auth('admin'), h(async (req, res) => {
  const [l] = await q(db.from('history').select('*').eq('id', req.params.id));
  if (!l || l.return_date) return res.status(404).json({ error: 'Loan not found.' });
  const fine = lateDays(l.due_date) * FINE_PER_DAY;
  await q(db.from('history').update({ return_date: today(), fine_amount: fine, fine_paid: fine === 0 || !!req.body.finePaid }).eq('id', l.id));
  await sync(l.book_id);
  res.json({ ok: true });
}));

app.get('/api/history', auth('admin'), h(async (req, res) =>
  res.json(req.query.all ? await fetchAll(() => db.from('history').select('*').order('id')) : await q(db.from('history').select('*').order('id', { ascending: false }).limit(200)))));

// ---- members ----
app.get('/api/members', auth('admin'), h(async (_req, res) =>
  res.json((await q(db.from('members').select('*').order('name'))).map(({ pw_hash, ...m }) => ({ ...m, has_password: !!pw_hash })))));

app.post('/api/members', auth('admin'), h(async (req, res) => {
  const { id, name, email, phone, role, class_name } = req.body;
  if (!id || !name) return res.status(400).json({ error: 'Member ID and name are required.' });
  const rows = await q(db.from('members').insert({ id, name, email: email || '', phone: phone || '', role: role || 'Student', class_name: class_name || '' }).select());
  res.status(201).json(rows[0]);
}));

app.delete('/api/members/:id', auth('admin'), h(async (req, res) => {
  await toTrash('member', 'members', 'id', req.params.id, req.user.name);
  await q(db.from('members').delete().eq('id', req.params.id));
  res.json({ ok: true });
}));

// ---- book requests ----
app.get('/api/requests', auth('admin'), h(async (_req, res) => res.json(await q(db.from('requests').select('*').order('id')))));

app.post('/api/requests', auth(), h(async (req, res) => {
  if (!req.body.title) return res.status(400).json({ error: 'Book title is required.' });
  await q(db.from('requests').insert({ title: req.body.title, author: req.body.author || 'N/A', username: req.user.name }));
  res.status(201).json({ ok: true });
}));

app.post('/api/requests/:id/approve', auth('admin'), h(async (req, res) => {
  const [r] = await q(db.from('requests').select('*').eq('id', req.params.id));
  if (!r) return res.status(404).json({ error: 'Request not found.' });
  await q(db.from('books').insert({ title: r.title, author: r.author, category: 'General', barcode: 'KCC-' + Math.floor(100000 + Math.random() * 900000) }));
  await q(db.from('requests').delete().eq('id', r.id));
  res.json({ ok: true });
}));

app.delete('/api/requests/:id', auth('admin'), h(async (req, res) => {
  await q(db.from('requests').delete().eq('id', req.params.id));
  res.json({ ok: true });
}));

// ---- edit books / members, change password ----
app.put('/api/books/:id', auth('admin'), h(async (req, res) => {
  const { title, author, category, ledger_info, quantity, pdf_url, lost_count, isbn } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required.' });
  const qty = Math.max(1, parseInt(quantity) || 1);
  await q(db.from('books').update({ title, author: author || 'N/A', category: category || 'General', ledger_info: ledger_info || 'N/A', quantity: qty, lost_count: Math.min(qty, Math.max(0, parseInt(lost_count) || 0)), pdf_url: pdf_url || '', isbn: String(isbn || '').replace(/[^0-9Xx]/g, '') }).eq('id', req.params.id));
  await sync(req.params.id);
  res.json({ ok: true });
}));

app.put('/api/members/:id', auth('admin'), h(async (req, res) => {
  const { name, email, phone, role, status, password, class_name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  const upd = { name, email: email || '', phone: phone || '', role: role || 'Student', status: status || 'Active', class_name: class_name || '' };
  if (password) upd.pw_hash = hashPw(password);
  await q(db.from('members').update(upd).eq('id', req.params.id));
  res.json({ ok: true });
}));

app.post('/api/password', auth(), h(async (req, res) => {
  const { current = '', next = '' } = req.body;
  if (!req.user.id) return res.status(400).json({ error: 'The main admin password is changed in Vercel settings.' });
  if (next.length < 4) return res.status(400).json({ error: 'New password needs at least 4 characters.' });
  const [m] = await q(db.from('members').select('*').eq('id', req.user.id));
  const ok = m && (m.pw_hash ? checkPw(current, m.pw_hash) : current.toLowerCase() === m.id.toLowerCase());
  if (!ok) return res.status(400).json({ error: 'Current password is wrong.' });
  await q(db.from('members').update({ pw_hash: hashPw(next) }).eq('id', m.id));
  res.json({ ok: true });
}));

// ---- members Excel import, my books, renew, fines paid ----
app.post('/api/members/bulk', auth('admin'), h(async (req, res) => {
  const rows = (req.body.members || []).filter(m => m.id && m.name).slice(0, 500).map(m => ({
    id: String(m.id).trim(), name: String(m.name).trim(), email: String(m.email || '').trim(),
    phone: String(m.phone || '').replace(/\s/g, ''), role: ['Student', 'Teacher', 'Librarian', 'Viewer'].includes(m.role) ? m.role : 'Student', class_name: String(m.class_name || '').trim()
  }));
  if (!rows.length) return res.status(400).json({ error: 'No valid rows. Each row needs a Member ID and a Name.' });
  await q(db.from('members').upsert(rows, { onConflict: 'id' }));
  res.json({ added: rows.length });
}));

app.get('/api/my', auth(), h(async (req, res) => {
  if (!req.user.id) return res.json({ open: [], past: [] });
  const rows = await q(db.from('history').select('*').eq('borrower_id', req.user.id).order('id', { ascending: false }).limit(100));
  const open = rows.filter(r => !r.return_date).map(r => ({ ...r, late: lateDays(r.due_date), fine: lateDays(r.due_date) * FINE_PER_DAY }));
  const [mem] = await q(db.from('members').select('role').eq('id', req.user.id));
  const reservations = await q(db.from('reservations').select('*').eq('member_id', req.user.id).eq('status', 'Waiting'));
  res.json({ open, past: rows.filter(r => r.return_date).slice(0, 20), reservations, limit: limFor(mem) });
}));

app.post('/api/loans/:id/renew', auth(), h(async (req, res) => {
  const [l] = await q(db.from('history').select('*').eq('id', req.params.id));
  if (!l || l.return_date) return res.status(404).json({ error: 'Loan not found.' });
  const admin = req.user.role === 'admin';
  if (!admin && l.borrower_id !== req.user.id) return res.status(403).json({ error: 'Not your book.' });
  if (!admin && (l.renewals || 0) >= 2) return res.status(400).json({ error: 'A book can be renewed only 2 times.' });
  if (!admin && lateDays(l.due_date) > 0) return res.status(400).json({ error: 'This book is overdue. Please return it to the library.' });
  const base = l.due_date && l.due_date > today() ? l.due_date : today();
  const [mem] = await q(db.from('members').select('role').eq('id', l.borrower_id));
  const due = workday(new Date(new Date(base).getTime() + limFor(mem).days * 864e5).toISOString().slice(0, 10));
  await q(db.from('history').update({ due_date: due, renewals: (l.renewals || 0) + 1 }).eq('id', l.id));
  res.json({ ok: true, due_date: due });
}));

app.get('/api/fines/unpaid', auth('admin'), h(async (_req, res) =>
  res.json(await q(db.from('history').select('*').gt('fine_amount', 0).eq('fine_paid', false).order('id', { ascending: false })))));

app.post('/api/loans/:id/paid', auth('admin'), h(async (req, res) => {
  await q(db.from('history').update({ fine_paid: true }).eq('id', req.params.id));
  res.json({ ok: true });
}));

// ---- reserve, scan, reports, activity ----
app.post('/api/books/:id/reserve', auth(), h(async (req, res) => {
  if (!req.user.id) return res.status(400).json({ error: 'Only members can reserve books.' });
  const [b] = await q(db.from('books').select('*').eq('id', req.params.id));
  if (!b) return res.status(404).json({ error: 'Book not found.' });
  if ((b.borrowed_count || 0) + (b.lost_count || 0) < (b.quantity || 1)) return res.status(400).json({ error: 'A copy is available now. Please ask the librarian.' });
  const dup = await q(db.from('reservations').select('id').eq('book_id', b.id).eq('member_id', req.user.id).eq('status', 'Waiting'));
  if (dup.length) return res.status(400).json({ error: 'You already reserved this book.' });
  const held = await q(db.from('history').select('id').eq('book_id', b.id).eq('borrower_id', req.user.id).is('return_date', null));
  if (held.length) return res.status(400).json({ error: 'You already have this book.' });
  await q(db.from('reservations').insert({ book_id: b.id, book_title: b.title, member_id: req.user.id, member_name: req.user.name }));
  res.json({ ok: true });
}));

app.get('/api/reservations', auth('admin'), h(async (_req, res) => {
  const rows = await q(db.from('reservations').select('*').eq('status', 'Waiting').order('id'));
  const ph = {}; (await q(db.from('members').select('id,phone'))).forEach(m => ph[m.id] = m.phone);
  res.json(rows.map(r => ({ ...r, phone: ph[r.member_id] || '' })));
}));

app.delete('/api/reservations/:id', auth(), h(async (req, res) => {
  const [r] = await q(db.from('reservations').select('*').eq('id', req.params.id));
  if (!r) return res.status(404).json({ error: 'Reservation not found.' });
  if (req.user.role !== 'admin' && r.member_id !== req.user.id) return res.status(403).json({ error: 'Not your reservation.' });
  await q(db.from('reservations').update({ status: 'Cancelled' }).eq('id', r.id));
  res.json({ ok: true });
}));

// one scan: returns the book if this member has it, otherwise issues it
app.post('/api/books/:id/scan', auth('admin'), h(async (req, res) => {
  const [book] = await q(db.from('books').select('*').eq('id', req.params.id));
  if (!book) return res.status(404).json({ error: 'Book not found.' });
  const [m] = await q(db.from('members').select('*').ilike('id', req.body.borrowerId || ''));
  if (!m) return res.status(400).json({ error: 'No member found with that ID.' });
  const [loan] = await q(db.from('history').select('*').eq('book_id', book.id).eq('borrower_id', m.id).is('return_date', null));
  if (loan) {
    const fine = lateDays(loan.due_date) * FINE_PER_DAY;
    await q(db.from('history').update({ return_date: today(), fine_amount: fine, fine_paid: fine === 0 }).eq('id', loan.id));
    await sync(book.id);
    return res.json({ action: 'returned', name: m.name, fine });
  }
  if ((book.borrowed_count || 0) + (book.lost_count || 0) >= (book.quantity || 1)) return res.status(400).json({ error: 'No copy of this book is available.' });
  const lim = limFor(m);
  if (await openCount(m.id) >= lim.max) return res.status(400).json({ error: `${m.name} already has ${lim.max} books (the limit for a ${m.role}).` });
  const due = workday(addDays(lim.days));
  await q(db.from('history').insert({ book_id: book.id, book_title: book.title, borrower_name: m.name, borrower_id: m.id, issue_date: today(), due_date: due }));
  await db.from('reservations').update({ status: 'Fulfilled' }).eq('book_id', book.id).eq('member_id', m.id).eq('status', 'Waiting');
  await sync(book.id);
  res.json({ action: 'issued', name: m.name, due });
}));

app.get('/api/reports', auth('admin'), h(async (_req, res) => {
  const rows = await fetchAll(() => db.from('history').select('book_title,borrower_name,borrower_id,issue_date,fine_amount,fine_paid').order('id'));
  const top = key => { const m = {}; rows.forEach(r => { const k = key(r); if (k) m[k] = (m[k] || 0) + 1; }); return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count })); };
  const months = {}; rows.forEach(r => { const k = (r.issue_date || '').slice(0, 7); if (k) months[k] = (months[k] || 0) + 1; });
  res.json({
    loans: rows.length, collected: rows.filter(r => r.fine_paid).reduce((a, r) => a + (r.fine_amount || 0), 0),
    topBooks: top(r => r.book_title), topReaders: top(r => r.borrower_name ? `${r.borrower_name} (${r.borrower_id})` : ''),
    monthly: Object.entries(months).sort().slice(-12).map(([name, count]) => ({ name, count }))
  });
}));

app.get('/api/audit', auth('admin'), h(async (_req, res) =>
  res.json(await q(db.from('audit').select('*').order('id', { ascending: false }).limit(200)))));

// ---- PDF e-book upload (signed URL into the public "ebooks" bucket) ----
app.post('/api/upload-url', auth('admin'), h(async (req, res) => {
  const name = String(req.body.filename || 'book.pdf').replace(/[^\w.\-]+/g, '_');
  const path = `${Date.now()}-${name}`;
  const { data, error } = await db.storage.from('ebooks').createSignedUploadUrl(path);
  if (error) throw new Error(error.message + ' (create a public Storage bucket named "ebooks" in Supabase)');
  res.json({ path, token: data.token, publicUrl: db.storage.from('ebooks').getPublicUrl(path).data.publicUrl, url: process.env.SUPABASE_URL, anon: process.env.SUPABASE_ANON_KEY || '' });
}));

// ---- past papers and notes ----
app.get('/api/papers', h(async (_req, res) => res.json(await fetchAll(() => db.from('papers').select('*').order('id', { ascending: false })))));
app.post('/api/papers', auth('admin'), h(async (req, res) => {
  const { title, grade, subject, year, kind, pdf_url } = req.body;
  if (!title || !pdf_url) return res.status(400).json({ error: 'A title and a PDF (file or link) are required.' });
  await q(db.from('papers').insert({ title, grade: grade || '', subject: subject || '', year: year || '', kind: kind || 'Past paper', pdf_url }));
  res.status(201).json({ ok: true });
}));
app.delete('/api/papers/:id', auth('admin'), h(async (req, res) => {
  await q(db.from('papers').delete().eq('id', req.params.id));
  res.json({ ok: true });
}));

// ---- stock check: scan every book on the shelf, then list what is missing ----
const stockCheck = async () => {
  const open = await q(db.from('stock_checks').select('*').is('closed_at', null).order('id', { ascending: false }).limit(1));
  if (open[0]) return open[0];
  return (await q(db.from('stock_checks').select('*').order('id', { ascending: false }).limit(1)))[0] || null;
};
const scanCount = async (id, bookId) => {
  let r = db.from('stock_scans').select('*', { count: 'exact', head: true }).eq('check_id', id);
  if (bookId) r = r.eq('book_id', bookId);
  const { count, error } = await r;
  if (error) throw new Error(error.message);
  return count || 0;
};
app.get('/api/stock', auth('admin'), h(async (_req, res) => {
  const check = await stockCheck();
  res.json({ check, scanned: check ? await scanCount(check.id) : 0 });
}));
app.post('/api/stock/start', auth('admin'), h(async (req, res) => {
  const c = await stockCheck();
  if (c && !c.closed_at) return res.json({ check: c });
  const rows = await q(db.from('stock_checks').insert({ name: String(req.body.name || '').trim() || 'Stock check ' + today() }).select());
  res.json({ check: rows[0] });
}));
app.post('/api/stock/scan', auth('admin'), h(async (req, res) => {
  const check = await stockCheck();
  if (!check || check.closed_at) return res.status(400).json({ error: 'Start a stock check first.' });
  const code = String(req.body.code || '').trim().replace(/[,()*%]/g, '');
  if (!code) return res.status(400).json({ error: 'Scan or type a barcode / ledger number.' });
  const [book] = await q(db.from('books').select('*').or(`barcode.ilike.${code},ledger_info.ilike.${code}`).limit(1));
  if (!book) return res.status(404).json({ error: `No book found for "${code}".` });
  const onShelf = Math.max(0, (book.quantity || 1) - (book.borrowed_count || 0) - (book.lost_count || 0));
  let status = 'ok';
  if (await scanCount(check.id, book.id) >= onShelf) status = 'dup';
  else await q(db.from('stock_scans').insert({ check_id: check.id, book_id: book.id }));
  res.json({ title: book.title, ledger: book.ledger_info, status, scanned: await scanCount(check.id) });
}));
app.get('/api/stock/missing', auth('admin'), h(async (_req, res) => {
  const check = await stockCheck();
  if (!check) return res.json({ check: null, missing: [] });
  const [bks, scans] = await Promise.all([
    fetchAll(() => db.from('books').select('id,title,ledger_info,category,quantity,borrowed_count,lost_count').order('id')),
    fetchAll(() => db.from('stock_scans').select('book_id').eq('check_id', check.id).order('id'))
  ]);
  const got = {}; scans.forEach(x => got[x.book_id] = (got[x.book_id] || 0) + 1);
  const missing = bks.map(b => ({ id: b.id, title: b.title, ledger_info: b.ledger_info, category: b.category, missing: Math.max(0, (b.quantity || 1) - (b.borrowed_count || 0) - (b.lost_count || 0)) - (got[b.id] || 0) })).filter(b => b.missing > 0);
  res.json({ check, missing });
}));
app.post('/api/stock/close', auth('admin'), h(async (_req, res) => {
  const c = await stockCheck();
  if (c && !c.closed_at) await q(db.from('stock_checks').update({ closed_at: new Date().toISOString() }).eq('id', c.id));
  res.json({ ok: true });
}));

// ---- announcements, popular books, duplicates ----
app.get('/api/announcements', h(async (_req, res) => res.json(await q(db.from('announcements').select('*').eq('active', true).order('id', { ascending: false }).limit(5)))));
app.post('/api/announcements', auth('admin'), h(async (req, res) => {
  if (!req.body.title) return res.status(400).json({ error: 'A title is required.' });
  await q(db.from('announcements').insert({ title: req.body.title, body: req.body.body || '' }));
  res.status(201).json({ ok: true });
}));
app.delete('/api/announcements/:id', auth('admin'), h(async (req, res) => {
  await q(db.from('announcements').delete().eq('id', req.params.id));
  res.json({ ok: true });
}));

app.get('/api/popular', h(async (_req, res) => {
  const rows = await fetchAll(() => db.from('history').select('book_id').order('id'));
  const c = {}; rows.forEach(r => { if (r.book_id) c[r.book_id] = (c[r.book_id] || 0) + 1; });
  res.json(Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([id, count]) => ({ id: +id, count })));
}));

const normTitle = t => String(t || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
app.get('/api/duplicates', auth('admin'), h(async (_req, res) => {
  const bks = await fetchAll(() => db.from('books').select('id,title,author,ledger_info,quantity,borrowed_count').order('id'));
  const g = {}; bks.forEach(b => { const k = normTitle(b.title); if (k) (g[k] = g[k] || []).push(b); });
  res.json(Object.values(g).filter(a => a.length > 1).slice(0, 300));
}));
app.post('/api/books/merge', auth('admin'), h(async (req, res) => {
  const { keepId, removeIds } = req.body;
  if (!keepId || !Array.isArray(removeIds) || !removeIds.length) return res.status(400).json({ error: 'Nothing to merge.' });
  const bks = await q(db.from('books').select('*').in('id', [keepId, ...removeIds]));
  const keep = bks.find(b => b.id == keepId);
  if (!keep) return res.status(404).json({ error: 'Book not found.' });
  const ledger = [...new Set(bks.map(b => b.ledger_info).filter(l => l && l !== 'N/A'))].join(', ') || 'N/A';
  await q(db.from('history').update({ book_id: keep.id }).in('book_id', removeIds));
  await q(db.from('reservations').update({ book_id: keep.id }).in('book_id', removeIds));
  await q(db.from('books').update({ quantity: bks.reduce((a, b) => a + (b.quantity || 1), 0), lost_count: bks.reduce((a, b) => a + (b.lost_count || 0), 0), ledger_info: ledger }).eq('id', keep.id));
  await q(db.from('books').delete().in('id', removeIds));
  await sync(keep.id);
  res.json({ ok: true });
}));

// ---- reviews, saved books, leaderboard ----
app.get('/api/ratings', h(async (_req, res) => {
  const rows = await fetchAll(() => db.from('reviews').select('book_id,rating').order('id'));
  const m = {}; rows.forEach(r => { const o = m[r.book_id] || (m[r.book_id] = { sum: 0, count: 0 }); o.sum += r.rating; o.count++; });
  res.json(Object.fromEntries(Object.entries(m).map(([k, v]) => [k, { avg: Math.round(v.sum / v.count * 10) / 10, count: v.count }])));
}));
app.get('/api/books/:id/reviews', h(async (req, res) =>
  res.json(await q(db.from('reviews').select('*').eq('book_id', req.params.id).order('id', { ascending: false }).limit(30)))));
app.post('/api/books/:id/review', auth(), h(async (req, res) => {
  if (!req.user.id) return res.status(400).json({ error: 'Only members can write reviews.' });
  const rating = Math.round(+req.body.rating);
  if (!(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'Choose 1 to 5 stars.' });
  const read = await q(db.from('history').select('id').eq('book_id', req.params.id).eq('borrower_id', req.user.id).limit(1));
  if (!read.length) return res.status(400).json({ error: 'You can review a book after you have borrowed it.' });
  await q(db.from('reviews').delete().eq('book_id', req.params.id).eq('member_id', req.user.id));
  await q(db.from('reviews').insert({ book_id: +req.params.id, member_id: req.user.id, member_name: req.user.name, rating, comment: String(req.body.comment || '').slice(0, 300) }));
  res.json({ ok: true });
}));
app.get('/api/wishlist', auth(), h(async (req, res) =>
  res.json(req.user.id ? (await q(db.from('wishlist').select('book_id').eq('member_id', req.user.id))).map(r => r.book_id) : [])));
app.post('/api/books/:id/wish', auth(), h(async (req, res) => {
  if (!req.user.id) return res.status(400).json({ error: 'Only members can save books.' });
  const ex = await q(db.from('wishlist').select('id').eq('book_id', req.params.id).eq('member_id', req.user.id));
  if (ex.length) { await q(db.from('wishlist').delete().eq('id', ex[0].id)); return res.json({ saved: false }); }
  await q(db.from('wishlist').insert({ book_id: +req.params.id, member_id: req.user.id }));
  res.json({ saved: true });
}));
app.get('/api/leaderboard', auth(), h(async (req, res) => {
  const year = new Date().getFullYear();
  const rows = await fetchAll(() => db.from('history').select('borrower_id,borrower_name').gte('issue_date', year + '-01-01').order('id'));
  const c = {}; rows.forEach(r => { if (!r.borrower_id) return; const o = c[r.borrower_id] || (c[r.borrower_id] = { name: r.borrower_name, count: 0 }); o.count++; });
  const all = Object.entries(c).map(([id, v]) => ({ id, ...v })).sort((a, b) => b.count - a.count);
  const i = all.findIndex(x => x.id === req.user.id);
  res.json({ top: all.slice(0, 10).map(({ name, count }) => ({ name, count })), me: { count: i < 0 ? 0 : all[i].count, rank: i < 0 ? null : i + 1 }, goal: READ_GOAL, year });
}));

// ---- email reminders and weekly backup (Gmail) ----
const mailer = () => process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD
  ? nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD } }) : null;
const from = () => `"KCC Library" <${process.env.GMAIL_USER}>`;
const reminderText = (m, l, days) => days > 0
  ? `வணக்கம் ${m.name},\n\nநீங்கள் எடுத்த "${l.book_title}" புத்தகம் ${l.due_date} அன்று திருப்பித் தர வேண்டியது. ${days} நாட்கள் தாமதமாகிவிட்டது (அபராதம் ரூ. ${days * FINE_PER_DAY}). தயவுசெய்து விரைவில் திருப்பித் தரவும்.\n\nHello ${m.name},\nYour library book "${l.book_title}" was due on ${l.due_date} and is ${days} day(s) late (fine Rs. ${days * FINE_PER_DAY}). Please return it soon.\n\n- Kilinochchi Central College Library`
  : `வணக்கம் ${m.name},\n\n"${l.book_title}" புத்தகத்தை ${l.due_date} அன்று திருப்பித் தர வேண்டும்.\n\nHello ${m.name},\nYour library book "${l.book_title}" is due on ${l.due_date}. Please return or renew it.\n\n- Kilinochchi Central College Library`;
async function sendReminders(all) {
  const mail = mailer();
  if (!mail) throw new Error('Email is not set up. Add GMAIL_USER and GMAIL_APP_PASSWORD in Vercel settings.');
  const loans = await fetchAll(() => db.from('history').select('*').is('return_date', null).not('due_date', 'is', null).order('id'));
  const mem = {}; (await q(db.from('members').select('id,name,email'))).forEach(m => mem[m.id] = m);
  const tomorrow = addDays(1), jobs = [];
  for (const l of loans) {
    const m = mem[l.borrower_id]; if (!m || !/.+@.+\..+/.test(m.email || '')) continue;
    const days = lateDays(l.due_date);
    if (!(all ? days > 0 : (l.due_date === tomorrow || [1, 7, 14].includes(days)))) continue;
    jobs.push(() => mail.sendMail({ from: from(), to: m.email, subject: days > 0 ? `Overdue library book: ${l.book_title}` : `Library book due soon: ${l.book_title}`, text: reminderText(m, l, days) }));
  }
  const list = jobs.slice(0, 100);
  for (let i = 0; i < list.length; i += 10) await Promise.all(list.slice(i, i + 10).map(f => f()));
  return list.length;
}
const csv = rows => {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]), e = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  return '\uFEFF' + [cols.join(','), ...rows.map(r => cols.map(c => e(r[c])).join(','))].join('\n');
};
async function emailBackup() {
  const mail = mailer(), to = process.env.ADMIN_EMAIL;
  if (!mail || !to) throw new Error('Add GMAIL_USER, GMAIL_APP_PASSWORD and ADMIN_EMAIL in Vercel settings.');
  const [bk, mm, hh] = await Promise.all([
    fetchAll(() => db.from('books').select('*').order('id')),
    q(db.from('members').select('id,name,email,phone,role,status')),
    fetchAll(() => db.from('history').select('*').order('id'))
  ]);
  await mail.sendMail({ from: from(), to, subject: 'KCC Library backup ' + today(), text: 'Books, members and loans are attached (CSV files, open them in Excel).',
    attachments: [{ filename: 'books.csv', content: csv(bk) }, { filename: 'members.csv', content: csv(mm) }, { filename: 'loans.csv', content: csv(hh) }] });
}
app.post('/api/reminders/send', auth('admin'), h(async (_req, res) => res.json({ sent: await sendReminders(true) })));
app.post('/api/backup/email', auth('admin'), h(async (_req, res) => { await emailBackup(); res.json({ ok: true }); }));
app.get('/api/cron/daily', h(async (req, res) => {
  if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) return res.status(401).json({ error: 'Not allowed.' });
  const out = {};
  try { out.reminders = await sendReminders(false); } catch (e) { out.reminderError = e.message; }
  if (new Date().getUTCDay() === 1) { try { await emailBackup(); out.backup = 'sent'; } catch (e) { out.backupError = e.message; } }
  res.json(out);
}));

// ---- settings, categories, recycle bin ----
app.get('/api/settings', auth('admin'), h(async (_req, res) => {
  await loadSettings(true);
  res.json({ fine_per_day: FINE_PER_DAY, read_goal: READ_GOAL, student_max: LIMITS.Student.max, student_days: LIMITS.Student.days, teacher_max: LIMITS.Teacher.max, teacher_days: LIMITS.Teacher.days });
}));
app.put('/api/settings', auth('admin'), h(async (req, res) => {
  const keys = ['fine_per_day', 'read_goal', 'student_max', 'student_days', 'teacher_max', 'teacher_days'];
  const rows = keys.filter(k => req.body[k] !== undefined && req.body[k] !== '' && +req.body[k] >= 0).map(k => ({ key: k, value: String(Math.round(+req.body[k])) }));
  if (rows.length) await q(db.from('settings').upsert(rows, { onConflict: 'key' }));
  await loadSettings(true);
  res.json({ ok: true });
}));

app.get('/api/categories', auth('admin'), h(async (_req, res) => {
  const bks = await fetchAll(() => db.from('books').select('category').order('id'));
  const c = {}; bks.forEach(b => { const k = b.category || 'General'; c[k] = (c[k] || 0) + 1; });
  res.json(Object.entries(c).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count));
}));
app.post('/api/categories/rename', auth('admin'), h(async (req, res) => {
  const to = String(req.body.to || '').trim();
  if (!to) return res.status(400).json({ error: 'Enter the new name.' });
  await q(db.from('books').update({ category: to }).eq('category', String(req.body.from || '')));
  res.json({ ok: true });
}));

app.get('/api/trash', auth('admin'), h(async (_req, res) => {
  const rows = await q(db.from('trash').select('*').order('id', { ascending: false }).limit(100));
  res.json(rows.map(r => ({ id: r.id, kind: r.kind, label: r.kind === 'book' ? r.data.title : `${r.data.name} (${r.data.id})`, deleted_by: r.deleted_by, deleted_at: r.deleted_at })));
}));
app.post('/api/trash/:id/restore', auth('admin'), h(async (req, res) => {
  const [t] = await q(db.from('trash').select('*').eq('id', req.params.id));
  if (!t) return res.status(404).json({ error: 'Item not found.' });
  const d = { ...t.data };
  if (t.kind === 'book') {
    const oldId = d.id; delete d.id; d.borrowed_count = 0; d.status = 'Available';
    const [nb] = await q(db.from('books').insert(d).select());
    await q(db.from('history').update({ book_id: nb.id }).eq('book_id', oldId));
    await q(db.from('reservations').update({ book_id: nb.id }).eq('book_id', oldId));
    await sync(nb.id);
  } else {
    if ((await q(db.from('members').select('id').eq('id', d.id))).length) return res.status(400).json({ error: 'A member with this ID already exists.' });
    await q(db.from('members').insert(d));
  }
  await q(db.from('trash').delete().eq('id', t.id));
  res.json({ ok: true });
}));
app.delete('/api/trash/:id', auth('admin'), h(async (req, res) => {
  await q(db.from('trash').delete().eq('id', req.params.id));
  res.json({ ok: true });
}));

// ---- holidays, parent view, book of the week ----
app.get('/api/holidays', auth('admin'), h(async (_req, res) => res.json(await q(db.from('holidays').select('*').order('day')))));
app.post('/api/holidays', auth('admin'), h(async (req, res) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(req.body.day || '')) return res.status(400).json({ error: 'Choose a date.' });
  await q(db.from('holidays').upsert({ day: req.body.day, name: req.body.name || 'Holiday' }, { onConflict: 'day' }));
  await loadSettings(true);
  res.status(201).json({ ok: true });
}));
app.delete('/api/holidays/:id', auth('admin'), h(async (req, res) => {
  await q(db.from('holidays').delete().eq('id', req.params.id));
  await loadSettings(true);
  res.json({ ok: true });
}));

app.post('/api/parent', h(async (req, res) => {
  const id = String(req.body.memberId || '').trim().replace(/[%_]/g, ''), p4 = String(req.body.phone4 || '').replace(/\D/g, '').slice(-4);
  const who = 'parent:' + id.toLowerCase().slice(0, 40);
  const since = new Date(Date.now() - 10 * 60000).toISOString();
  const { count } = await db.from('login_attempts').select('*', { count: 'exact', head: true }).eq('who', who).gt('at', since);
  if ((count || 0) >= 5) return res.status(429).json({ error: 'Too many wrong attempts. Please try again in 10 minutes.' });
  const [m] = id ? await q(db.from('members').select('*').ilike('id', id)) : [];
  const phone = String((m && m.phone) || '').replace(/\D/g, '');
  if (!m || m.status === 'Inactive' || p4.length !== 4 || !phone.endsWith(p4)) {
    await db.from('login_attempts').insert({ who });
    return res.status(401).json({ error: 'Member ID or phone digits are not correct.' });
  }
  const loans = await q(db.from('history').select('*').eq('borrower_id', m.id).order('id', { ascending: false }).limit(30));
  res.json({
    name: m.name, class_name: m.class_name || '',
    open: loans.filter(l => !l.return_date).map(l => ({ title: l.book_title, due_date: l.due_date, late: lateDays(l.due_date), fine: lateDays(l.due_date) * FINE_PER_DAY })),
    unpaid: loans.filter(l => l.fine_amount > 0 && !l.fine_paid).reduce((a, l) => a + l.fine_amount, 0),
    recent: loans.filter(l => l.return_date).slice(0, 5).map(l => ({ title: l.book_title, return_date: l.return_date }))
  });
}));

app.get('/api/featured', h(async (_req, res) => {
  const rows = await q(db.from('settings').select('*').in('key', ['featured_book', 'featured_note']));
  const o = {}; rows.forEach(r => o[r.key] = r.value);
  res.json({ book_id: +o.featured_book || 0, note: o.featured_note || '' });
}));
app.put('/api/featured', auth('admin'), h(async (req, res) => {
  const id = +req.body.bookId || 0;
  if (!id) await q(db.from('settings').delete().in('key', ['featured_book', 'featured_note']));
  else await q(db.from('settings').upsert([{ key: 'featured_book', value: String(id) }, { key: 'featured_note', value: String(req.body.note || '').slice(0, 200) }], { onConflict: 'key' }));
  res.json({ ok: true });
}));

// ---- dashboard numbers ----
app.get('/api/stats', auth('admin'), h(async (_req, res) => {
  const cnt = async p => { const { count, error } = await p; if (error) throw new Error(error.message); return count || 0; };
  const head = t => db.from(t).select('*', { count: 'exact', head: true });
  const [titles, borrowed, overdue, members, requests, qty] = await Promise.all([
    cnt(head('books')),
    cnt(head('history').is('return_date', null)),
    cnt(head('history').is('return_date', null).lt('due_date', today())),
    cnt(head('members')),
    cnt(head('requests')),
    fetchAll(() => db.from('books').select('quantity,lost_count').order('id'))
  ]);
  const copies = qty.reduce((a, b) => a + (b.quantity || 1), 0);
  const lost = qty.reduce((a, b) => a + (b.lost_count || 0), 0);
  res.json({ titles, copies, borrowed, lost, available: copies - borrowed - lost, overdue, members, requests });
}));

// ---- overdue fines ----
app.get('/api/fines', auth('admin'), h(async (_req, res) => {
  const loans = await q(db.from('history').select('*').is('return_date', null).lt('due_date', today()).order('due_date'));
  const ph = {};
  (await q(db.from('members').select('id,phone,class_name'))).forEach(m => ph[m.id.toLowerCase()] = m);
  res.json(loans.map(l => {
    const days = Math.ceil((new Date(today()) - new Date(l.due_date)) / 864e5);
    return { id: l.id, title: l.book_title, borrower_name: l.borrower_name, borrower_id: l.borrower_id, due_date: l.due_date, days, fine: days * FINE_PER_DAY, phone: (ph[(l.borrower_id || '').toLowerCase()] || {}).phone || '', class_name: (ph[(l.borrower_id || '').toLowerCase()] || {}).class_name || '' };
  }));
}));

module.exports = app;
