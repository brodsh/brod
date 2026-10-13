// A D1-compatible database over libSQL (Turso, or a local SQLite file), for hosts other than Cloudflare.
// It implements only what Brod calls: prepare/bind, first, all, run (with meta.changes), batch and exec.
// libSQL is SQLite, so migrations/*.sql and every query run unchanged.

type Value = null | number | string | bigint | ArrayBuffer | Uint8Array;
interface Rs { columns: string[]; rows: ArrayLike<unknown>[]; rowsAffected: number; lastInsertRowid?: bigint | number }
/** The part of a @libsql/client Client this adapter uses. Both the Node and the web client fit. */
export interface SqlClient {
  execute(stmt: { sql: string; args: Value[] }): Promise<Rs>;
  batch(stmts: { sql: string; args: Value[] }[], mode: 'write'): Promise<Rs[]>;
  executeMultiple(sql: string): Promise<void>;
}

function value(v: unknown, sql: string): Value {
  if (v === undefined) throw new Error(`D1_TYPE_ERROR: undefined bound to "${sql.slice(0, 60)}"`);   // D1 refuses it too
  if (typeof v === 'boolean') return v ? 1 : 0;
  return v as Value;
}

function result(rs: Rs) {
  const results = rs.rows.map(r => {
    const o: Record<string, unknown> = {};
    rs.columns.forEach((c, i) => { o[c] = r[i]; });
    return o;
  });
  const last = Number(rs.lastInsertRowid ?? 0);
  return { results, success: true as const, meta: { changes: rs.rowsAffected, last_row_id: last, changed_db: rs.rowsAffected > 0, duration: 0, rows_read: results.length, rows_written: rs.rowsAffected } };
}

class Statement {
  constructor(private client: SqlClient, readonly sql: string, readonly args: Value[] = []) {}
  bind(...args: unknown[]) { return new Statement(this.client, this.sql, args.map(a => value(a, this.sql))); }
  get stmt() { return { sql: this.sql, args: this.args }; }
  async all() { return result(await this.client.execute(this.stmt)); }
  async run() { return this.all(); }
  async first(column?: string) {
    const row = (await this.all()).results[0] ?? null;
    if (!column || !row) return row;
    if (!(column in row)) throw new Error(`D1_COLUMN_NOTFOUND: ${column}`);
    return row[column];
  }
  async raw() { const rs = await this.client.execute(this.stmt); return rs.rows.map(r => Array.from(r)); }
}

/** Wrap a libSQL client as env.DB. `batch` runs in one write transaction, so it is all-or-nothing as on D1. */
export function libsqlD1(client: SqlClient): D1Database {
  const db = {
    prepare: (sql: string) => new Statement(client, sql),
    batch: async (stmts: Statement[]) => (await client.batch(stmts.map(s => s.stmt), 'write')).map(result),
    exec: async (sql: string) => { await client.executeMultiple(sql); return { count: 0, duration: 0 }; },
  };
  // Structurally a subset of D1Database: the methods Brod does not call (dump, withSession) are left out.
  return db as unknown as D1Database;
}
