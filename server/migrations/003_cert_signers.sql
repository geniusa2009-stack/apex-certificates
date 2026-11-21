-- Admin-configurable certificate signers (name + title shown on the
-- printed certificate). Previously these were baked in from env vars
-- (APEX_SIGNER1/APEX_SIGNER2 in config.js) with the title hardcoded
-- directly in "APEX Certificate.dc.html" ("Founder" / "Volunteer
-- Program Coordinator") -- neither was editable without a deploy.
--
-- Two fixed rows (one per printed signature block), never more --
-- this is not a template system, it is exactly the two signer slots
-- the existing single certificate design already has.
create table cert_signers (
  slot       text primary key check (slot in ('signer1', 'signer2')),
  name       text not null check (char_length(name) between 2 and 120),
  title      text not null check (char_length(title) between 2 and 120),
  updated_by uuid references users(id),
  updated_at timestamptz not null default now()
);

-- Seed with the same defaults config.js already falls back to, so a
-- fresh install renders identically to before this migration until an
-- admin changes them.
insert into cert_signers (slot, name, title) values
  ('signer1', 'G. Ahmed I. Ragab', 'Founder'),
  ('signer2', 'Asmaa Hassan', 'Volunteer Program Coordinator');
