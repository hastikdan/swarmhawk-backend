-- SwarmHawk Database Schema
-- Paste this into Supabase → SQL Editor → Run

create table if not exists users (
  id            uuid primary key default gen_random_uuid(),
  google_id     text unique not null,
  email         text unique not null,
  name          text,
  avatar        text,
  password_hash text,
  auth_type     text default 'google',
  created_at    timestamptz default now(),
  last_login    timestamptz default now()
);

-- Migration: add columns if table already exists without them
alter table users add column if not exists password_hash text;
alter table users add column if not exists auth_type text default 'google';

create table if not exists sessions (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid references users(id) on delete cascade,
  token      text unique not null,
  created_at timestamptz default now()
);

create table if not exists domains (
  id                 uuid primary key default gen_random_uuid(),
  user_id            uuid references users(id) on delete cascade,
  domain             text not null,
  country            text not null,
  full_scan_enabled  boolean default false,
  created_at         timestamptz default now(),
  unique(user_id, domain)
);

create table if not exists scans (
  id          uuid primary key default gen_random_uuid(),
  domain_id   uuid references domains(id) on delete cascade,
  risk_score  integer not null,
  critical    integer default 0,
  warnings    integer default 0,
  checks      jsonb,
  scanned_at  timestamptz default now()
);

create table if not exists purchases (
  id                 uuid primary key default gen_random_uuid(),
  user_id            uuid references users(id),
  domain_id          uuid references domains(id),
  stripe_session_id  text unique,
  amount_usd         numeric(10,2),
  paid_at            timestamptz default now()
);

create index if not exists idx_domains_user     on domains(user_id);
create index if not exists idx_scans_domain     on scans(domain_id);
create index if not exists idx_purchases_domain on purchases(domain_id);
create index if not exists idx_sessions_token   on sessions(token);

-- Disable RLS so the anon/service key can read/write all rows.
-- The backend handles its own auth via session tokens.
alter table users     disable row level security;
alter table sessions  disable row level security;
alter table domains   disable row level security;
alter table scans     disable row level security;
alter table purchases disable row level security;
