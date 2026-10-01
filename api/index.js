const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const SECRET = process.env.AUTH_SECRET || '';
const FINE_PER_DAY = 20;
// Borrowing rules: change the numbers here if you want different limits
const LIMITS = { Student: { max: 3, days: 14 }, Teacher: { max: 10, days: 30 }, Librarian: { max: 10, days: 30 } };
const limFor = m => LIMITS[(m || {}).role] || LIMITS.Student;
const app = express();
app.use(express.json());

// activity log: every successful change is recorded
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.path !== '/api/login') {
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
  if (!u || (role === 'admin' && u.role !== 'admin')) return res.status(401).json({ error: 'Please sign in with an admin account.' });
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
const addDays = n => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

// ---- auth ----
app.post('/api/login', h(async (req, res) => {
  const { username = '', password = '' } = req.body;
  const token = (name, role, id) => ({ success: true, name, role, memberId: id, token: sign({ name, role, id, exp: Date.now() + 12 * 36e5 }) });
  if (process.env.ADMIN_USER && username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS)
    return res.json(token(username, 'admin'));
  const members = await q(db.from('members').select('*').or(`id.ilike.${username.replace(/[,()]/g, '')},name.ilike.${username.replace(/[,()]/g, '')}`));
  const m = members.find(x => x.status === 'Active' && (x.pw_hash ? checkPw(password, x.pw_hash) : x.id.toLowerCase() === password.toLowerCase()));
  if (!m) return res.status(401).json({ error: 'Name or member ID is incorrect.' });
  res.json(token(m.name, m.role === 'Librarian' ? 'admin' : 'user', m.id));
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
  await q(db.from('books').delete().eq('id', req.params.id));
  res.json({ ok: true });
}));

// ---- issue / return (copy by copy) ----
const sync = async id => {
  const [b] = await q(db.from('books').select('quantity').eq('id', id));
  if (!b) return;
  const { count, error } = await db.from('history').select('*', { count: 'exact', head: true }).eq('book_id', id).is('return_date', null);
  if (error) throw new Error(error.message);
  const n = count || 0;
  await q(db.from('books').update({ borrowed_count: n, status: n >= (b.quantity || 1) ? 'Borrowed' : 'Available' }).eq('id', id));
};

app.post('/api/books/:id/issue', auth('admin'), h(async (req, res) => {
  const [book] = await q(db.from('books').select('*').eq('id', req.params.id));
  if (!book) return res.status(404).json({ error: 'Book not found.' });
  if ((book.borrowed_count || 0) >= (book.quantity || 1)) return res.status(400).json({ error: 'All copies of this book are already borrowed.' });
  const [m] = await q(db.from('members').select('*').ilike('id', req.body.borrowerId || ''));
  if (!m) return res.status(400).json({ error: 'No member found with that ID.' });
  const lim = limFor(m);
  if (await openCount(m.id) >= lim.max) return res.status(400).json({ error: `${m.name} already has ${lim.max} books (the limit for a ${m.role}).` });
  const open = await q(db.from('history').select('id').eq('book_id', book.id).eq('borrower_id', m.id).is('return_date', null));
  if (open.length) return res.status(400).json({ error: 'This member already has a copy of this book.' });
  await q(db.from('history').insert({ book_id: book.id, book_title: book.title, borrower_name: m.name, borrower_id: m.id, issue_date: today(), due_date: addDays(lim.days) }));
  await db.from('reservations').update({ status: 'Fulfilled' }).eq('book_id', book.id).eq('member_id', m.id).eq('status', 'Waiting');
  await sync(book.id);
  res.json({ ok: true });
}));

app.get('/api/books/:id/loans', auth('admin'), h(async (req, res) =>
  res.json(await q(db.from('history').select('*').eq('book_id', req.params.id).is('return_date', null).order('id')))));

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
  const { id, name, email, phone, role } = req.body;
  if (!id || !name) return res.status(400).json({ error: 'Member ID and name are required.' });
  const rows = await q(db.from('members').insert({ id, name, email: email || '', phone: phone || '', role: role || 'Student' }).select());
  res.status(201).json(rows[0]);
}));

app.delete('/api/members/:id', auth('admin'), h(async (req, res) => {
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
  const { title, author, category, ledger_info, quantity, pdf_url } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required.' });
  await q(db.from('books').update({ title, author: author || 'N/A', category: category || 'General', ledger_info: ledger_info || 'N/A', quantity: Math.max(1, parseInt(quantity) || 1), pdf_url: pdf_url || '' }).eq('id', req.params.id));
  await sync(req.params.id);
  res.json({ ok: true });
}));

app.put('/api/members/:id', auth('admin'), h(async (req, res) => {
  const { name, email, phone, role, status, password } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  const upd = { name, email: email || '', phone: phone || '', role: role || 'Student', status: status || 'Active' };
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
    phone: String(m.phone || '').replace(/\s/g, ''), role: ['Student', 'Teacher', 'Librarian'].includes(m.role) ? m.role : 'Student'
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
  const due = new Date(new Date(base).getTime() + limFor(mem).days * 864e5).toISOString().slice(0, 10);
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
  if ((b.borrowed_count || 0) < (b.quantity || 1)) return res.status(400).json({ error: 'A copy is available now. Please ask the librarian.' });
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
  if ((book.borrowed_count || 0) >= (book.quantity || 1)) return res.status(400).json({ error: 'All copies of this book are borrowed.' });
  const lim = limFor(m);
  if (await openCount(m.id) >= lim.max) return res.status(400).json({ error: `${m.name} already has ${lim.max} books (the limit for a ${m.role}).` });
  const due = addDays(lim.days);
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
    monthly: Object.entries(months).sort().slice(-6).map(([name, count]) => ({ name, count }))
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
    fetchAll(() => db.from('books').select('quantity').order('id'))
  ]);
  const copies = qty.reduce((a, b) => a + (b.quantity || 1), 0);
  res.json({ titles, copies, borrowed, available: copies - borrowed, overdue, members, requests });
}));

// ---- overdue fines ----
app.get('/api/fines', auth('admin'), h(async (_req, res) => {
  const loans = await q(db.from('history').select('*').is('return_date', null).lt('due_date', today()).order('due_date'));
  const ph = {};
  (await q(db.from('members').select('id,phone'))).forEach(m => ph[m.id.toLowerCase()] = m.phone);
  res.json(loans.map(l => {
    const days = Math.ceil((new Date(today()) - new Date(l.due_date)) / 864e5);
    return { id: l.id, title: l.book_title, borrower_name: l.borrower_name, borrower_id: l.borrower_id, due_date: l.due_date, days, fine: days * FINE_PER_DAY, phone: ph[(l.borrower_id || '').toLowerCase()] || '' };
  }));
}));

module.exports = app;
