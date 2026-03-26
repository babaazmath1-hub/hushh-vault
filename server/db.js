/**
 * ╔══════════════════════════════════════╗
 * ║   HUSHH VAULT — db.js               ║
 * ║   DB connection + schema bootstrap  ║
 * ╚══════════════════════════════════════╝
 */

'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const crypto   = require('crypto');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'hushh.db');
const db = new Database(DB_PATH);

// ── Performance & safety pragmas ────────────────────────────
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('temp_store = MEMORY');
db.pragma('mmap_size = 268435456');   // 256 MB mmap

// ── Schema ──────────────────────────────────────────────────
db.exec(`

  /* ─── Organisations ─── */
  CREATE TABLE IF NOT EXISTS orgs (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    reg_number         TEXT NOT NULL UNIQUE,
    industry           TEXT NOT NULL,
    admin_email        TEXT NOT NULL UNIQUE,
    master_key_hash    TEXT NOT NULL,        -- SHA-384 commitment (never the key itself)
    vault_policy       TEXT NOT NULL,        -- JSON array of policy flags
    zk_on              INTEGER NOT NULL DEFAULT 1,
    e2e_on             INTEGER NOT NULL DEFAULT 1,
    chain_on           INTEGER NOT NULL DEFAULT 1,
    redact_on          INTEGER NOT NULL DEFAULT 1,
    created_at         INTEGER NOT NULL,
    consent_expires_at INTEGER NOT NULL
  );

  /* ─── Members ─── */
  CREATE TABLE IF NOT EXISTS members (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    email          TEXT NOT NULL,
    dept           TEXT NOT NULL,
    level          INTEGER NOT NULL CHECK(level IN (1,2,3)),
    status         TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','suspended')),
    pw_hash        TEXT NOT NULL,            -- bcrypt
    perms          TEXT NOT NULL,            -- JSON array: ['financial','hr', …]
    public_key     TEXT,                     -- ECDH P-384 public key hex (from client)
    consent_given  INTEGER NOT NULL DEFAULT 1,
    consent_ts     INTEGER,
    added_at       INTEGER NOT NULL,
    color          TEXT NOT NULL DEFAULT '#00e87a'
  );

  CREATE UNIQUE INDEX IF NOT EXISTS idx_members_org_email
    ON members(org_id, email);

  /* ─── Sessions ─── */
  CREATE TABLE IF NOT EXISTS sessions (
    token_id   TEXT PRIMARY KEY,
    member_id  TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    org_id     TEXT NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    revoked    INTEGER NOT NULL DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_member
    ON sessions(member_id, revoked);

  /* ─── Immutable Audit Chain ─── */
  CREATE TABLE IF NOT EXISTS audit_chain (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     TEXT NOT NULL,
    event      TEXT NOT NULL,       -- ACCESS | DENY | CHANGE | SUSPEND | LOGIN | REGISTER | EXPORT
    actor      TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    block_hash TEXT NOT NULL UNIQUE,
    ts         INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_audit_org_event
    ON audit_chain(org_id, event, seq DESC);

  /* ─── Vault Document Metadata ─── */
  CREATE TABLE IF NOT EXISTS vault_metadata (
    doc_id     TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    category   TEXT NOT NULL,
    iv_hint    TEXT NOT NULL,        -- first 8 bytes of IV only (non-reversible)
    created_at INTEGER NOT NULL,
    PRIMARY KEY (doc_id, org_id)
  );

  /* ─── Revoked JWTs ─── */
  CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
  );

`);

// ── Helpers ─────────────────────────────────────────────────

/**
 * SHA-384 (synchronous, Node-only)
 */
function sha384(data) {
  return crypto.createHash('sha384').update(String(data)).digest('hex');
}

/**
 * Append a new block to the audit chain.
 * block_hash = SHA-384( prevHash | ts | event | actor | target | detail )
 * This is the ONLY write to audit_chain — no UPDATE or DELETE ever.
 */
function buildBlock(orgId, event, actor, target, detail) {
  const prev = db.prepare(
    `SELECT block_hash FROM audit_chain
     WHERE org_id = ? ORDER BY seq DESC LIMIT 1`
  ).get(orgId);

  const prevHash = prev ? prev.block_hash : '0'.repeat(96);   // genesis sentinel
  const ts       = Date.now();
  const raw      = `${prevHash}|${ts}|${event}|${actor}|${target}|${detail}`;
  const hash     = sha384(raw);

  db.prepare(`
    INSERT INTO audit_chain
      (org_id, event, actor, target, detail, prev_hash, block_hash, ts)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(orgId, event, String(actor), String(target), String(detail),
         prevHash, hash, ts);

  return hash;
}

/**
 * Verify the entire hash chain for an org.
 * Re-computes every hash from scratch; any tampering is detected.
 * Returns { valid: bool, brokenAt: seq | null }
 */
function verifyChain(orgId) {
  const blocks = db.prepare(
    `SELECT * FROM audit_chain WHERE org_id = ? ORDER BY seq ASC`
  ).all(orgId);

  if (!blocks.length) return { valid: true, brokenAt: null };

  for (let i = 0; i < blocks.length; i++) {
    const b   = blocks[i];
    const raw = `${b.prev_hash}|${b.ts}|${b.event}|${b.actor}|${b.target}|${b.detail}`;
    const expected = sha384(raw);
    if (expected !== b.block_hash)         return { valid: false, brokenAt: b.seq };
    if (i > 0 && b.prev_hash !== blocks[i - 1].block_hash)
                                           return { valid: false, brokenAt: b.seq };
  }
  return { valid: true, brokenAt: null };
}

/**
 * Generate a cryptographically random hex string.
 */
function randHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = { db, sha384, buildBlock, verifyChain, randHex };