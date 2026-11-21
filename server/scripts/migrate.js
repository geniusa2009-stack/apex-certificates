import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
await client.query('create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null default now())');
for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.sql')).sort()) {
  const done = await client.query('select 1 from schema_migrations where name=$1', [f]);
  if (done.rowCount) continue;
  await client.query('begin');
  try { await client.query(fs.readFileSync(path.join(dir, f), 'utf8')); await client.query('insert into schema_migrations(name) values ($1)', [f]); await client.query('commit'); console.log('applied', f); }
  catch (e) { await client.query('rollback'); console.error('failed', f, e.message); process.exit(1); }
}
await client.end();
