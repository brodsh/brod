// SPDX-License-Identifier: AGPL-3.0-only
// The migration Brod runs (brod.json "migrate") in a one-off container of the new image before it serves.
import pg from 'pg';

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
await client.query('CREATE TABLE IF NOT EXISTS notes (id serial PRIMARY KEY, text text NOT NULL)');
await client.query('CREATE TABLE IF NOT EXISTS migrations (id serial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now())');
await client.query('INSERT INTO migrations DEFAULT VALUES');
await client.end();
console.log('migrated: notes and migrations are there');
