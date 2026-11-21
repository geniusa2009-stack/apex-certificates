-- APEX Volunteer Passport, contributions, badges, bulk issuance. Additive only; no existing data changed.
alter table users drop constraint if exists users_roles_check;
alter table users add constraint users_roles_check check (roles <@ array['issuer','approver','admin','volunteer']::text[]);

create table volunteers (
  id             uuid primary key default gen_random_uuid(),
  public_id      text not null unique check (public_id ~ '^v-[0-9a-hjkmnp-tv-z]{10,16}$'),
  user_id        uuid unique references users(id),           -- the volunteer's own login (role 'volunteer')
  display_name   text not null check (char_length(display_name) between 2 and 120),
  email          text,                                       -- private
  phone          text,                                       -- private
  birth_date     date,                                       -- private
  address        text,                                       -- private
  internal_notes text,                                       -- private, staff only
  photo_url      text,
  photo_approved boolean not null default false,
  privacy        jsonb not null default '{}',                -- normalised by shared/passport-rules.js; private by default
  disabled       boolean not null default false,
  created_by     uuid references users(id),
  created_at     timestamptz not null default now()
);

create table contributions (
  id           uuid primary key default gen_random_uuid(),
  volunteer_id uuid not null references volunteers(id),
  project      text not null check (char_length(project) between 2 and 160),
  role         text not null check (char_length(role) between 2 and 120),
  period_start char(7) not null check (period_start ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  period_end   char(7) not null check (period_end ~ '^[0-9]{4}-(0[1-9]|1[0-2])$' and period_end >= period_start),
  hours        int not null check (hours between 1 and 5000),
  summary      text not null check (char_length(summary) between 10 and 2000),
  evidence     jsonb not null default '[]',                  -- [{label,url,public}]
  status       text not null default 'pending' check (status in ('pending','verified','rejected','withdrawn')),
  submitted_by uuid not null references users(id),
  reviewed_by  uuid references users(id),
  review_note  text,
  reviewed_at  timestamptz,
  created_at   timestamptz not null default now(),
  constraint independent_review check (reviewed_by is null or reviewed_by <> submitted_by),
  constraint reviewed_complete check (status in ('pending','withdrawn') or (reviewed_by is not null and reviewed_at is not null))
);
create index on contributions(volunteer_id, status);

create function contributions_guard() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then raise exception 'contributions cannot be deleted; withdraw instead'; end if;
  if old.status in ('verified','rejected','withdrawn') and (
       new.project is distinct from old.project or new.role is distinct from old.role or new.hours is distinct from old.hours
    or new.period_start is distinct from old.period_start or new.period_end is distinct from old.period_end
    or new.summary is distinct from old.summary or new.reviewed_by is distinct from old.reviewed_by) then
    raise exception 'reviewed contribution % is immutable', old.id;
  end if;
  if old.status in ('rejected','withdrawn') and new.status is distinct from old.status then
    raise exception 'contribution % is closed', old.id;
  end if;
  return new;
end $$;
create trigger contributions_guard before update or delete on contributions for each row execute function contributions_guard();

alter table certificates add column volunteer_id uuid references volunteers(id);
alter table certificates add column contribution_id uuid references contributions(id);
alter table certificates add column batch_id uuid;

create table badge_classes (
  id          text primary key check (id ~ '^[a-z-]{3,40}$'),
  category    text not null check (category in ('leadership','research','community-management','event-organization','communication',
                'teamwork','mentorship','project-coordination','innovation','outstanding-contribution')),
  name        text not null,
  description text not null,
  criteria    text not null,
  active      boolean not null default true
);
insert into badge_classes(id, category, name, description, criteria) values
 ('leadership','leadership','Leadership','Led a team or initiative to a documented outcome.','Verified contribution in a lead role, or an authorised assessment by a programme coordinator.'),
 ('research','research','Research','Produced documented research for an APEX initiative.','A verified contribution with a research deliverable.'),
 ('community-management','community-management','Community Management','Sustained and moderated a volunteer or member community.','Verified contribution covering at least one full programme period.'),
 ('event-organization','event-organization','Event Organization','Planned and delivered an APEX event.','Verified contribution naming the event delivered.'),
 ('communication','communication','Communication','Produced communications for an APEX initiative.','Verified contribution with a published deliverable.'),
 ('teamwork','teamwork','Teamwork','Contributed reliably within a project team.','Authorised assessment by the team coordinator.'),
 ('mentorship','mentorship','Mentorship','Mentored participants through a structured programme.','Verified mentoring contribution.'),
 ('project-coordination','project-coordination','Project Coordination','Coordinated schedules, people and deliverables for a project.','Verified coordination contribution.'),
 ('innovation','innovation','Innovation','Introduced a documented improvement adopted by an initiative.','Verified contribution with evidence of adoption.'),
 ('outstanding-contribution','outstanding-contribution','Outstanding Contribution','Recognised by APEX leadership for exceptional service.','Authorised assessment by an approver; never automatic.');

create table badge_awards (
  id             text primary key check (id ~ '^BDG-[0-9]{4}-[0-9A-HJKMNP-TV-Z]{8}$'),
  badge_class_id text not null references badge_classes(id),
  volunteer_id   uuid not null references volunteers(id),
  evidence       uuid[] not null default '{}',
  assessment     jsonb,
  awarded_by     uuid not null references users(id),
  status         text not null default 'active' check (status in ('active','revoked')),
  revoked_reason text,
  issued_at      date not null default current_date,
  created_at     timestamptz not null default now(),
  constraint has_basis check (cardinality(evidence) > 0 or assessment is not null)
);
create unique index one_active_badge on badge_awards(badge_class_id, volunteer_id) where status = 'active';
create function badge_awards_guard() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then raise exception 'badge awards cannot be deleted; revoke instead'; end if;
  if old.status = 'revoked' then raise exception 'badge % is revoked', old.id; end if;
  if new.badge_class_id is distinct from old.badge_class_id or new.volunteer_id is distinct from old.volunteer_id
     or new.evidence is distinct from old.evidence or new.awarded_by is distinct from old.awarded_by then
    raise exception 'badge % is immutable', old.id;
  end if;
  return new;
end $$;
create trigger badge_awards_guard before update or delete on badge_awards for each row execute function badge_awards_guard();

create table bulk_batches (
  id              uuid primary key default gen_random_uuid(),
  idempotency_key text not null unique check (char_length(idempotency_key) between 16 and 80),
  csv_sha256      text not null check (csv_sha256 ~ '^[0-9a-f]{64}$'),
  state           text not null default 'validated' check (state in ('validated','drafted')),
  report          jsonb not null,
  created_by      uuid not null references users(id),
  created_at      timestamptz not null default now(),
  drafted_at      timestamptz
);
alter table certificates add constraint certificates_batch_fk foreign key (batch_id) references bulk_batches(id);
