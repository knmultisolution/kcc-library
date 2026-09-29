const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const SECRET = process.env.AUTH_SECRET || '';
const FINE_PER_DAY = 20;
const app = express();
app.use(express.json());

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
const today = () => new Date().toISOString().slice(0, 10);
const addDays = n => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

// ---- auth ----
app.post('/api/login', h(async (req, res) => {
  const { username = '', password = '' } = req.body;
  const token = (name, role) => ({ success: true, name, role, token: sign({ name, role, exp: Date.now() + 12 * 36e5 }) });
  if (process.env.ADMIN_USER && username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS)
    return res.json(token(username, 'admin'));
  const members = await q(db.from('members').select('*').or(`id.ilike.${username.replace(/[,()]/g, '')},name.ilike.${username.replace(/[,()]/g, '')}`));
  const m = members.find(x => x.status === 'Active' && x.id.toLowerCase() === password.toLowerCase());
  if (!m) return res.status(401).json({ error: 'Name or member ID is incorrect.' });
  res.json({ ...token(m.name, 'user'), memberId: m.id });
}));

// ---- books ----
app.get('/api/books', h(async (_req, res) => res.json(await q(db.from('books').select('*').order('id')))));

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

// issue or return
app.post('/api/books/:id/toggle', auth('admin'), h(async (req, res) => {
  const [book] = await q(db.from('books').select('*').eq('id', req.params.id));
  if (!book) return res.status(404).json({ error: 'Book not found.' });
  if (book.status === 'Available') {
    const [m] = await q(db.from('members').select('*').ilike('id', req.body.borrowerId || ''));
    if (!m) return res.status(400).json({ error: 'No member found with that ID.' });
    const upd = { status: 'Borrowed', borrower_name: m.name, borrower_id: m.id, issue_date: today(), due_date: addDays(14) };
    await q(db.from('books').update(upd).eq('id', book.id));
    await q(db.from('history').insert({ book_id: book.id, book_title: book.title, borrower_name: m.name, borrower_id: m.id, issue_date: upd.issue_date }));
  } else {
    await q(db.from('history').update({ return_date: today() }).eq('book_id', book.id).is('return_date', null));
    await q(db.from('books').update({ status: 'Available', borrower_name: null, borrower_id: null, issue_date: null, due_date: null }).eq('id', book.id));
  }
  res.json({ ok: true });
}));

app.get('/api/history', auth('admin'), h(async (_req, res) =>
  res.json(await q(db.from('history').select('*').order('id', { ascending: false }).limit(200)))));

// ---- members ----
app.get('/api/members', auth('admin'), h(async (_req, res) => res.json(await q(db.from('members').select('*').order('name')))));

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

// ---- overdue fines ----
app.get('/api/fines', auth('admin'), h(async (_req, res) => {
  const books = await q(db.from('books').select('*').eq('status', 'Borrowed').lt('due_date', today()));
  res.json(books.map(b => {
    const days = Math.ceil((new Date(today()) - new Date(b.due_date)) / 864e5);
    return { id: b.id, title: b.title, borrower_name: b.borrower_name, borrower_id: b.borrower_id, due_date: b.due_date, days, fine: days * FINE_PER_DAY };
  }));
}));

module.exports = app;
