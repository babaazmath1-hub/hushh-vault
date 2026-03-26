/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   HUSHH VAULT — server/routes/access.js                 ║
 * ║   Vault metadata  |  ABAC doc access  |  Key exchange   ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * Mounted at: /api/access
 *
 * Routes:
 *   GET    /api/access/vault/:orgId/:docId   — fetch doc metadata (perm-gated)
 *   POST   /api/access/vault/:orgId          — register doc metadata (admin)
 *   DELETE /api/access/vault/:orgId/:docId   — remove doc (admin)
 *   GET    /api/access/vault/:orgId          — list accessible docs for member
 *   POST   /api/access/keys/:orgId           — register ECDH public key
 *   GET    /api/access/keys/:orgId/:memberId — get member's public key
 *   GET    /api/access/preview/:orgId        — full vault preview for a member (admin)
 */

'use strict';

const express   = require('express');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { db, buildBlock, randHex } = require('../db');

const router = express.Router();

// ════════════════════════════════════════
//  RATE LIMITERS
// ════════════════════════════════════════
const vaultLimit = rateLimit({
  windowMs: 60_000,
  max: 60,
  message: { error: 'Vault rate limit exceeded.' },
});

const sensitiveLimit = rateLimit({
  windowMs: 60_000,
  max: 30,
  message: { error: 'Rate limit on sensitive endpoint.' },
});

// ════════════════════════════════════════
//  AUTH MIDDLEWARE  (shared)
// ════════════════════════════════════════
const JWT_SECRET = () => process.env.JWT_SECRET;

// In-memory revocation mirror (same set managed in members.js)
// In production, use a shared Redis store instead.
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
//  HELPERS
// ════════════════════════════════════════
function sanitize(s) { return typeof s === 'string' ? s.trim().replace(/[<>]/g, '') : ''; }

/**
 * Check if a member has permission for a given doc category.
 * Returns true / false.
 */
function hasPerm(member, category) {
  const perms = JSON.parse(member.perms || '[]');
  return perms.includes(category);
}

// ════════════════════════════════════════
//  GET SINGLE DOC METADATA  (ABAC gated)
//  GET /api/access/vault/:orgId/:docId
// ════════════════════════════════════════
router.get('/vault/:orgId/:docId', vaultLimit, requireAuth, requireOrgMatch, (req, res) => {
  const { orgId, docId } = req.params;

  const meta = db.prepare(
    'SELECT * FROM vault_metadata WHERE doc_id = ? AND org_id = ?'
  ).get(sanitize(docId), orgId);

  if (!meta) return res.status(404).json({ error: 'Document not found.' });

  // ── ABAC check ──────────────────────────────────────────
  if (!hasPerm(req.member, meta.category)) {
    buildBlock(orgId, 'DENY', req.member.id, sanitize(docId),
      `Access denied — category: ${meta.category} not in member perms`);

    // Zero-knowledge denial: no information about the doc is returned
    const org = db.prepare('SELECT redact_on FROM orgs WHERE id = ?').get(orgId);
    if (org?.redact_on) {
      return res.status(403).json({ error: 'Access denied.' });
    }
    return res.status(403).json({
      error:    'Access denied.',
      category: meta.category,   // only leaked if redact_on = false
    });
  }

  buildBlock(orgId, 'ACCESS', req.member.id, sanitize(docId),
    `Doc accessed — category: ${meta.category}`);

  res.json({
    docId:     meta.doc_id,
    category:  meta.category,
    ivHint:    meta.iv_hint,       // first 8 bytes only — non-reversible
    createdAt: meta.created_at,
    // In full ZK: include `encryptedBlob` or S3 presigned URL here
  });
});

// ════════════════════════════════════════
//  LIST ACCESSIBLE DOCS FOR MEMBER
//  GET /api/access/vault/:orgId
// ════════════════════════════════════════
router.get('/vault/:orgId', vaultLimit, requireAuth, requireOrgMatch, (req, res) => {
  const perms = JSON.parse(req.member.perms || '[]');
  const org   = db.prepare('SELECT redact_on FROM orgs WHERE id = ?').get(req.orgId);

  const allDocs = db.prepare(
    'SELECT doc_id, category, iv_hint, created_at FROM vault_metadata WHERE org_id = ?'
  ).all(req.orgId);

  const result = allDocs.map(doc => {
    const accessible = perms.includes(doc.category);
    if (accessible) {
      return {
        docId:      doc.doc_id,
        category:   doc.category,
        ivHint:     doc.iv_hint,
        createdAt:  doc.created_at,
        accessible: true,
      };
    }
    // Denied: redact or expose minimal info based on org policy
    if (org?.redact_on) {
      return { accessible: false, redacted: true };
    }
    return { docId: doc.doc_id, category: doc.category, accessible: false };
  });

  buildBlock(req.orgId, 'ACCESS', req.member.id, '—',
    `Vault list — ${result.filter(d => d.accessible).length}/${allDocs.length} docs accessible`);

  res.json({ docs: result, total: allDocs.length });
});

// ════════════════════════════════════════
//  REGISTER DOC METADATA  (admin)
//  POST /api/access/vault/:orgId
// ════════════════════════════════════════
router.post('/vault/:orgId', sensitiveLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  const { docId, category, ivHint } = req.body;

  const VALID_CATS = ['financial','hr','roadmap','technical','legal','investor'];
  if (!docId || !VALID_CATS.includes(category) || !ivHint)
    return res.status(400).json({ error: `docId, category (${VALID_CATS.join('|')}), ivHint required.` });

  // ivHint: only store first 16 hex chars (8 bytes) — non-recoverable
  db.prepare(`
    INSERT OR IGNORE INTO vault_metadata (doc_id, org_id, category, iv_hint, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(sanitize(docId), req.params.orgId, category,
         sanitize(ivHint).substring(0, 16), Date.now());

  buildBlock(req.params.orgId, 'CHANGE', req.member.id, sanitize(docId),
    `Doc registered — category: ${category}`);

  res.status(201).json({ ok: true, docId: sanitize(docId), category });
});

// ════════════════════════════════════════
//  DELETE DOC METADATA  (admin)
//  DELETE /api/access/vault/:orgId/:docId
// ════════════════════════════════════════
router.delete('/vault/:orgId/:docId', sensitiveLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  const { orgId, docId } = req.params;

  const exists = db.prepare('SELECT 1 FROM vault_metadata WHERE doc_id = ? AND org_id = ?')
                   .get(sanitize(docId), orgId);
  if (!exists) return res.status(404).json({ error: 'Document not found.' });

  db.prepare('DELETE FROM vault_metadata WHERE doc_id = ? AND org_id = ?')
    .run(sanitize(docId), orgId);

  buildBlock(orgId, 'CHANGE', req.member.id, sanitize(docId), 'Doc metadata removed from vault');
  res.json({ ok: true });
});

// ════════════════════════════════════════
//  REGISTER ECDH PUBLIC KEY
//  POST /api/access/keys/:orgId
// ════════════════════════════════════════
router.post('/keys/:orgId', sensitiveLimit, requireAuth, requireOrgMatch, (req, res) => {
  const { publicKey } = req.body;

  if (!publicKey || typeof publicKey !== 'string' || publicKey.length > 500)
    return res.status(400).json({ error: 'Valid publicKey required (hex or PEM, max 500 chars).' });

  db.prepare('UPDATE members SET public_key = ? WHERE id = ? AND org_id = ?')
    .run(sanitize(publicKey), req.member.id, req.params.orgId);

  buildBlock(req.params.orgId, 'CHANGE', req.member.id, req.member.name,
    'ECDH P-384 public key registered — ZK channel ready');

  res.json({
    ok:      true,
    message: 'Public key stored. Use ECDH shared-key derivation client-side for ZK channels.',
  });
});

// ════════════════════════════════════════
//  GET MEMBER PUBLIC KEY
//  GET /api/access/keys/:orgId/:memberId
// ════════════════════════════════════════
router.get('/keys/:orgId/:memberId', vaultLimit, requireAuth, requireOrgMatch, (req, res) => {
  const { orgId, memberId } = req.params;

  const target = db.prepare(
    `SELECT id, name, public_key, status FROM members WHERE id = ? AND org_id = ?`
  ).get(memberId, orgId);

  if (!target)                        return res.status(404).json({ error: 'Member not found.' });
  if (target.status === 'suspended')  return res.status(403).json({ error: 'Member suspended.' });
  if (!target.public_key)             return res.status(404).json({ error: 'No public key registered.' });

  // Any active member of the same org can fetch another member's public key
  // (needed for client-side ECDH shared-key derivation)
  res.json({ memberId: target.id, name: target.name, publicKey: target.public_key });
});

// ════════════════════════════════════════
//  ADMIN: FULL VAULT PREVIEW FOR A MEMBER
//  GET /api/access/preview/:orgId?memberId=MEM-001
// ════════════════════════════════════════
router.get('/preview/:orgId', vaultLimit, requireAuth, requireOrgMatch, requireAdmin, (req, res) => {
  const { memberId } = req.query;
  if (!memberId) return res.status(400).json({ error: 'memberId query param required.' });

  const target = db.prepare('SELECT * FROM members WHERE id = ? AND org_id = ?')
                   .get(memberId, req.params.orgId);
  if (!target) return res.status(404).json({ error: 'Member not found.' });

  const perms   = JSON.parse(target.perms || '[]');
  const allDocs = db.prepare('SELECT * FROM vault_metadata WHERE org_id = ?').all(req.params.orgId);
  const org     = db.prepare('SELECT redact_on FROM orgs WHERE id = ?').get(req.params.orgId);

  const preview = allDocs.map(doc => {
    const accessible = perms.includes(doc.category);
    return {
      docId:      doc.doc_id,
      category:   doc.category,
      accessible,
      // Redact name/size for inaccessible docs if redact_on
      ...(accessible
        ? { ivHint: doc.iv_hint, createdAt: doc.created_at }
        : org?.redact_on ? { redacted: true } : { reason: 'no_perm' }),
    };
  });

  buildBlock(req.params.orgId, 'ACCESS', req.member.id, target.name,
    `Admin vault preview — ${preview.filter(d => d.accessible).length}/${allDocs.length} accessible`);

  res.json({
    member: { id: target.id, name: target.name, level: target.level, status: target.status },
    docs:   preview,
    total:  allDocs.length,
  });
});

module.exports = router;