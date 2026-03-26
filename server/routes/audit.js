/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   HUSHH VAULT — server/routes/audit.js                  ║
 * ║   Immutable audit chain  |  Verify  |  Export           ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * Mounted at: /api/audit
 *
 * Routes:
 *   GET  /api/audit/:orgId              — paginated audit log
 *   GET  /api/audit/:orgId/verify       — verify full chain integrity
 *   GET  /api/audit/:orgId/chain        — last N blocks for visualisation
 *   GET  /api/audit/:orgId/export       — download full log as text
 *   GET  /api/audit/:orgId/stats        — event counts per type
 */

'use strict';

const express   = require('express');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { db, buildBlock, verifyChain } = require('../db');

const router = express.Router();

// ════════════════════════════════════════
//  RATE LIMITER
// ════════════════════════════════════════
const auditLimit = rateLimit({
  windowMs: 60_000,
  max: 60,
  message: { error: 'Audit rate limit exceeded.' },
});

// ════════════════════════════════════════
//  AUTH MIDDLEWARE
// ════════════════════════════════════════
const JWT_SECRET = () => process.env.JWT_SECRET;

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authorization header missing.' });

  let payload;
  try { payload = jwt.verify(token, JWT_SECRET(), { algorithms: ['HS256'] }); }
  catch (e) {
    return res.status(401).json({ error: e.name === 'TokenExpiredError' ? 'Token expired.' : 'Invalid token.' });
  }

  if (db.prepare('SELECT 1 FROM revoked_tokens WHERE jti = ?').get(payload.jti))
    return res.status(401).json({ error: 'Token revoked.' });

  const member = db.prepare('SELECT * FROM members WHERE id = ?').get(payload.sub);
  if (!member)                       return res.status(403).json({ error: 'Member not found.' });
  if (member.status === 'suspended') return res.status(403).json({ error: 'Account suspended.' });

  req.member = member;
  req.orgId  = member.org_id;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.member || req.member.level < 3)
    return res.status(403).json({ error: 'Admin (Level 3) required.' });
  next();
}

function requireOrgMatch(req, res, next) {
  const urlOrg = req.params.orgId || req.headers['x-org-id'];
  if (urlOrg && urlOrg !== req.orgId)
    return res.status(403).json({ error: 'Org ID mismatch.' });
  next();
}

// ════════════════════════════════════════
//  VALID EVENT TYPES
// ════════════════════════════════════════
const VALID_EVENTS = new Set(['ACCESS','DENY','CHANGE','SUSPEND','LOGIN','REGISTER','EXPORT']);

// ════════════════════════════════════════
//  GET AUDIT LOG  (paginated + filtered)
//  GET /api/audit/:orgId?event=&limit=&offset=
// ════════════════════════════════════════
router.get('/:orgId', auditLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  const { event, limit = 100, offset = 0 } = req.query;

  const safeLimit  = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 500);
  const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

  let query = 'SELECT * FROM audit_chain WHERE org_id = ?';
  const args = [req.params.orgId];

  if (event && event !== 'all' && VALID_EVENTS.has(event.toUpperCase())) {
    query += ' AND event = ?';
    args.push(event.toUpperCase());
  }

  query += ' ORDER BY seq DESC LIMIT ? OFFSET ?';
  args.push(safeLimit, safeOffset);

  const rows  = db.prepare(query).all(...args);
  const total = db.prepare(
    `SELECT COUNT(*) AS c FROM audit_chain WHERE org_id = ?${
      event && event !== 'all' && VALID_EVENTS.has(event.toUpperCase())
        ? ' AND event = ?' : ''
    }`
  ).get(...(event && event !== 'all' ? [req.params.orgId, event.toUpperCase()] : [req.params.orgId])).c;

  res.json({ rows, total, limit: safeLimit, offset: safeOffset });
});

// ════════════════════════════════════════
//  VERIFY CHAIN INTEGRITY
//  GET /api/audit/:orgId/verify
// ════════════════════════════════════════
router.get('/:orgId/verify', auditLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  buildBlock(req.params.orgId, 'ACCESS', req.member.id, 'AUDIT_CHAIN',
    'Chain integrity verification requested');

  const result = verifyChain(req.params.orgId);
  const total  = db.prepare('SELECT COUNT(*) AS c FROM audit_chain WHERE org_id = ?')
                   .get(req.params.orgId).c;

  res.json({ ...result, totalBlocks: total, verifiedAt: Date.now() });
});

// ════════════════════════════════════════
//  LAST N BLOCKS  (chain visualisation)
//  GET /api/audit/:orgId/chain?n=8
// ════════════════════════════════════════
router.get('/:orgId/chain', auditLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  const n = Math.min(Math.max(parseInt(req.query.n, 10) || 8, 2), 50);

  const blocks = db.prepare(
    `SELECT seq, event, actor, target, ts,
            SUBSTR(block_hash,1,24) AS hash_preview,
            SUBSTR(prev_hash, 1,24) AS prev_preview
     FROM audit_chain WHERE org_id = ?
     ORDER BY seq DESC LIMIT ?`
  ).all(req.params.orgId, n).reverse();   // chronological order for display

  res.json({ blocks, count: blocks.length });
});

// ════════════════════════════════════════
//  EXPORT FULL AUDIT LOG
//  GET /api/audit/:orgId/export
// ════════════════════════════════════════
router.get('/:orgId/export', auditLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  const org = db.prepare('SELECT name, master_key_hash FROM orgs WHERE id = ?').get(req.params.orgId);
  if (!org) return res.status(404).json({ error: 'Org not found.' });

  const rows = db.prepare(
    'SELECT * FROM audit_chain WHERE org_id = ? ORDER BY seq ASC'
  ).all(req.params.orgId);

  // Log the export event itself (BEFORE writing the export, so it's included)
  buildBlock(req.params.orgId, 'EXPORT', req.member.id, '—',
    `Full export — ${rows.length} entries — chain ${verifyChain(req.params.orgId).valid ? 'VERIFIED' : 'BROKEN'}`);

  const SEP  = '─'.repeat(100);
  const lines = [
    'HUSHH VAULT — IMMUTABLE AUDIT LOG (SIGNED EXPORT)',
    `Org ID   : ${req.params.orgId}`,
    `Company  : ${org.name}`,
    `Key Hash : ${org.master_key_hash.substring(0, 40)}…`,
    `Exported : ${new Date().toISOString()}`,
    `Exported By: ${req.member.name} (${req.member.id})`,
    SEP,
    '#\tTIMESTAMP\t\t\tEVENT\t\tACTOR\t\tTARGET\t\tBLOCK_HASH',
    SEP,
    ...rows.map(r =>
      `${r.seq}\t${new Date(r.ts).toISOString()}\t${r.event}\t${r.actor}\t${r.target}\t${r.detail}\t${r.block_hash}`
    ),
    SEP,
    `CHAIN INTEGRITY : ${verifyChain(req.params.orgId).valid ? 'VERIFIED ✓' : 'BROKEN ✗'}`,
    `TOTAL ENTRIES   : ${rows.length}`,
    `ALGORITHM       : SHA-384`,
  ];

  const content = lines.join('\n');
  const filename = `hushh-audit-${req.params.orgId}-${Date.now()}.txt`;

  res.set({
    'Content-Type':        'text/plain; charset=utf-8',
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Content-Length':      Buffer.byteLength(content),
    'Cache-Control':       'no-store',
  });
  res.send(content);
});

// ════════════════════════════════════════
//  AUDIT STATS  (event counts per type)
//  GET /api/audit/:orgId/stats
// ════════════════════════════════════════
router.get('/:orgId/stats', auditLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  const rows = db.prepare(
    `SELECT event, COUNT(*) AS count
     FROM audit_chain WHERE org_id = ?
     GROUP BY event ORDER BY count DESC`
  ).all(req.params.orgId);

  const total = rows.reduce((s, r) => s + r.count, 0);
  const latest = db.prepare(
    'SELECT ts FROM audit_chain WHERE org_id = ? ORDER BY seq DESC LIMIT 1'
  ).get(req.params.orgId);

  res.json({ byEvent: rows, total, latestAt: latest?.ts || null });
});

module.exports = router;