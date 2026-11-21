-- APEX certificate registry — initial schema
create extension if not exists pgcrypto;

create table users (
  id            uuid primary key default gen_random_uuid(),
  email         text not null unique check (email = lower(email)),
  display_name  text not null,
  password_hash text not null,                 -- argon2id
  totp_secret   text,                          -- base32; required for approvers when REQUIRE_TOTP=true
  roles         text[] not null default '{}' check (roles <@ array['issuer','approver','admin']::text[]),
  disabled      boolean not null default false,
  failed_logins int not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now()
);

create table sessions (
  token_hash text primary key,                 -- sha256 of the cookie token; raw token never stored
  user_id    uuid not null references users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  ip         inet
);
create index on sessions(expires_at);

create table signing_keys (
  kid        text primary key,
  alg        text not null default 'Ed25519' check (alg = 'Ed25519'),
  public_key text not null unique,             -- raw 32-byte key, base64url
  env        text not null check (env in ('production','staging','sample','test')),
  status     text not null check (status in ('active','retired','compromised')),
  created_at timestamptz not null default now(),
  retired_at timestamptz
);
create unique index one_active_key_per_env on signing_keys(env) where status = 'active';

create table certificates (
  id              text primary key check (id ~ '^APX-[0-9]{4}-[A-Z]{2}-[0-9A-HJKMNP-TV-Z]{5,12}$'),
  state           text not null check (state in ('draft','in_review','approved','rejected','signed','published','revoked','superseded')),
  name            text not null check (char_length(name) between 2 and 120),
  department      text not null check (char_length(department) between 2 and 120),
  role            text not null check (char_length(role) between 2 and 120),
  period_start    char(7) not null check (period_start ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  period_end      char(7) not null check (period_end ~ '^[0-9]{4}-(0[1-9]|1[0-2])$' and period_end >= period_start),
  hours           int not null check (hours between 1 and 10000),
  issued_at       date,
  volunteer_email text,                        -- private contact; never exposed publicly or signed
  supersedes      text references certificates(id),
  review_note     text,
  created_by      uuid not null references users(id),
  submitted_by    uuid references users(id),
  approved_by     uuid references users(id),
  signed_by       uuid references users(id),
  published_by    uuid references users(id),
  payload         jsonb,
  signature       text,
  record_hash     text,
  kid             text references signing_keys(kid),
  pdf             bytea,
  pdf_sha256      text check (pdf_sha256 ~ '^[0-9a-f]{64}$'),
  pdf_statement   jsonb,
  pdf_signature   text,
  status_statement jsonb,
  status_signature text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint independent_approval check (approved_by is null or (approved_by <> created_by and approved_by is distinct from submitted_by)),
  constraint signed_is_complete check (state in ('draft','in_review','approved','rejected')
    or (payload is not null and signature is not null and record_hash is not null and pdf is not null and pdf_sha256 is not null and pdf_signature is not null))
);
create unique index one_successor on certificates(supersedes) where supersedes is not null and state <> 'rejected';

-- Signed records are permanent: data, signature and PDF can never change; rows can never be deleted.
create function certificates_guard() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    if old.signature is not null then raise exception 'signed certificates cannot be deleted'; end if;
    return old;
  end if;
  if old.signature is not null and (
       new.payload is distinct from old.payload or new.signature is distinct from old.signature
    or new.record_hash is distinct from old.record_hash or new.pdf is distinct from old.pdf
    or new.pdf_sha256 is distinct from old.pdf_sha256 or new.pdf_statement is distinct from old.pdf_statement
    or new.name is distinct from old.name or new.department is distinct from old.department or new.role is distinct from old.role
    or new.period_start is distinct from old.period_start or new.period_end is distinct from old.period_end
    or new.hours is distinct from old.hours or new.issued_at is distinct from old.issued_at or new.kid is distinct from old.kid) then
    raise exception 'signed certificate % is immutable', old.id;
  end if;
  if old.state in ('revoked','superseded') and new.state is distinct from old.state then
    raise exception 'certificate % is in terminal state %', old.id, old.state;
  end if;
  new.updated_at := now();
  return new;
end $$;
create trigger certificates_guard before update or delete on certificates for each row execute function certificates_guard();

-- Tamper-evident audit log: each row's hash covers the previous hash; table is append-only.
create table audit_events (
  seq       bigserial primary key,
  at        timestamptz not null,
  actor     uuid references users(id),
  action    text not null,
  cert_id   text,
  details   jsonb not null default '{}',
  prev_hash text not null,
  hash      text not null unique
);
create index on audit_events(cert_id);
create function audit_append_only() returns trigger language plpgsql as $$
begin raise exception 'audit_events is append-only'; end $$;
create trigger audit_no_update before update or delete or truncate on audit_events for each statement execute function audit_append_only();
