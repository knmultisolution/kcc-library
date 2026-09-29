-- Run this once in Supabase: SQL Editor > New query > paste > Run

create table if not exists books (
  id bigint generated always as identity primary key,
  barcode text,
  title text not null,
  author text not null,
  category text not null default 'General',
  ledger_info text default 'N/A',
  quantity int default 1,
  pdf_url text default '',
  status text not null default 'Available',
  rating int default 4,
  borrower_name text,
  borrower_id text,
  issue_date date,
  due_date date
);

create table if not exists members (
  id text primary key,
  name text not null,
  email text default '',
  phone text default '',
  role text default 'Student',
  status text default 'Active'
);

create table if not exists history (
  id bigint generated always as identity primary key,
  book_id bigint,
  book_title text,
  borrower_name text,
  borrower_id text,
  issue_date date,
  return_date date
);

create table if not exists requests (
  id bigint generated always as identity primary key,
  title text not null,
  author text default 'N/A',
  username text,
  status text default 'Pending'
);

-- The API uses the service key, so lock the tables against the public anon key
alter table books enable row level security;
alter table members enable row level security;
alter table history enable row level security;
alter table requests enable row level security;

-- Starter data from your old database.json
insert into members (id, name, email, phone, role) values
  ('ST101', 'Kishan Kumar', 'kishan@kcc.lk', '+94771234567', 'Student'),
  ('ST102', 'Sujitha Ram', 'sujitha@kcc.lk', '+94779876543', 'Student'),
  ('TC201', 'Dr. Ramesh Prasad', 'ramesh@kcc.lk', '+94775551234', 'Teacher')
on conflict do nothing;

insert into books (title, author, category, ledger_info) values
  ('Advanced JavaScript', 'Ramesh Prasad', 'Programming', 'N/A');
