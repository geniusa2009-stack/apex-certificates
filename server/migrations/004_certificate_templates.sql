-- Template selection for NEW certificates. Existing rows are Classic V1.
-- No changes to already signed payloads, PDF bytes, signing keys or audit rows.
alter table certificates add column template_id text not null default 'classic_v1'
  check (template_id in ('classic_v1', 'hybrid_v4'));

-- The selected design is frozen once a certificate is digitally signed.
-- This additive trigger supplements the original certificates_guard.
create function certificates_template_guard() returns trigger language plpgsql as $$
begin
  if old.signature is not null and new.template_id is distinct from old.template_id then
    raise exception 'signed certificate % template is immutable', old.id;
  end if;
  return new;
end $$;
create trigger certificates_template_guard before update on certificates
  for each row execute function certificates_template_guard();
