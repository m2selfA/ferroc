// Independent Node/OpenSSL setup-v1 oracle; PUBLIC cfg(test) identities ONLY.
// No network/npm. Reconstructs job/grant/auth and all three new domains, rather
// than trusting the Rust-exported byte arrays. Fixture integers are small/safe.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
assert.equal(process.argv.length, 3, 'usage: node scripts/fleet-setup-oracle.mjs <public-rust-export.json>');
const raw = readFileSync(process.argv[2]);
const v = JSON.parse(raw);
assert.equal(v.warning, 'PUBLIC cfg(test) identities, never operational keys');
const { offer: o, response: r, confirmation: c } = v;
const sha = b => createHash('sha256').update(b).digest();
const cat = (...parts) => Buffer.concat(parts);
const bytes = (v, n) => { assert(Array.isArray(v)); assert.equal(v.length, n); assert(v.every(x => Number.isInteger(x) && x >= 0 && x <= 255)); return Buffer.from(v); };
function u16(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }
function u64(n) { assert(Number.isSafeInteger(n) && n >= 0); const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
const text = s => cat(u16(Buffer.byteLength(s)), Buffer.from(s));
const uuid = s => { assert.match(s, /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/); return Buffer.from(s.replaceAll('-', ''), 'hex'); };
function keys(byte) {
  const key = createPrivateKey({ key: cat(Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, byte)), type: 'pkcs8', format: 'der' });
  const pub = createPublicKey(key);
  return { key, pub, raw: pub.export({ type: 'spki', format: 'der' }).subarray(-32) };
}
const a = keys(0x11), b = keys(0x22);
assert.equal(o.version, 1); assert.equal(r.version, 1); assert.equal(c.version, 1); assert.equal(o.profile, 0);
assert.deepEqual(a.raw, bytes(o.sourceIdentity, 32)); assert.deepEqual(b.raw, bytes(o.targetIdentity, 32));
const j = o.job, g = o.grant, q = g.binding;
assert.equal(j.version, 2); assert.equal(j.route, 'relayOnly'); assert.equal(j.overwrite, false); assert.equal(j.preImageSha256, null);
assert.equal(g.permission, 'sendFileNoClobber');
const binding = cat(uuid(q.fleetId), bytes(q.sourceDevice, 32), bytes(q.targetDevice, 32), ...['sourceSession', 'targetSession', 'transferId', 'fileId', 'authorizationId', 'keyEpoch'].map(k => uuid(q[k])));
assert.equal(binding.length, 176);
const request = cat(Buffer.from('ferroc:fleet:request:v1\0'), u16(j.version), uuid(j.fleetId), bytes(j.sourceDevice, 32), bytes(j.targetDevice, 32), text(j.sourcePath), text(j.destinationPath), u64(j.bytesTotal), bytes(j.sha256, 32), Buffer.from([0, 0, 0]), u64(j.deadlineMs));
const job = cat(Buffer.from('ferroc:fleet:job:v1\0'), uuid(j.transferId), uuid(j.fileId), text(j.idempotencyKey), request);
const jobDigest = sha(job);
assert.deepEqual(jobDigest, bytes(g.jobDigest, 32));
const grant = cat(Buffer.from('ferroc:fleet:grant:v1\0'), binding, jobDigest, Buffer.from([1]), u32(g.chunkBytes), u64(g.issuedAtMs), u64(g.expiresAtMs));
const grantDigest = sha(grant);
const old = JSON.parse(readFileSync(new URL('../tests/fixtures/fleet-p0-control-vectors.json', import.meta.url), 'utf8'));
assert.equal(grantDigest.toString('hex'), old.grant_digest_hex);
const auth = role => cat(Buffer.from('ferroc:fleet:auth:v2\0'), u16(2), Buffer.from([role]), binding, jobDigest, grantDigest, a.raw, b.raw, bytes(o.sourceEphemeral, 32), bytes(r.targetEphemeral, 32), u64(j.bytesTotal), u32(g.chunkBytes), u64(g.issuedAtMs), u64(g.expiresAtMs));
for (const [role, key, signature, expected] of [[0, a, c.grantSignature, old.source_signature_hex], [1, b, r.grantSignature, old.target_signature_hex]]) {
  assert.equal(auth(role).length, 420);
  assert.deepEqual(sign(null, auth(role), key.key), bytes(signature, 64));
  assert.equal(bytes(signature, 64).toString('hex'), expected);
  assert(verify(null, auth(role), key.pub, bytes(signature, 64)));
}
const ob = cat(Buffer.from('ferroc:fleet:setup-offer:v1\0'), u16(1), Buffer.from([o.profile]), jobDigest, grantDigest, a.raw, b.raw, bytes(o.sourceEphemeral, 32));
assert.deepEqual(ob, Buffer.from(v.offerBytes));
assert.deepEqual(sign(null, ob, a.key), bytes(o.signature, 64));
assert(verify(null, ob, a.pub, bytes(o.signature, 64)));
const od = sha(cat(ob, bytes(o.signature, 64)));
assert.deepEqual(od, bytes(r.offerDigest, 32));
const rb = cat(Buffer.from('ferroc:fleet:setup-response:v1\0'), u16(1), od, bytes(r.targetEphemeral, 32), bytes(r.grantSignature, 64));
assert.deepEqual(rb, Buffer.from(v.responseBytes));
assert.deepEqual(sign(null, rb, b.key), bytes(r.signature, 64));
assert(verify(null, rb, b.pub, bytes(r.signature, 64)));
const rd = sha(cat(rb, bytes(r.signature, 64)));
assert.deepEqual(rd, bytes(c.responseDigest, 32));
const cb = cat(Buffer.from('ferroc:fleet:setup-confirm:v1\0'), u16(1), rd, bytes(c.grantSignature, 64));
assert.deepEqual(cb, Buffer.from(v.confirmationBytes));
assert.deepEqual(sign(null, cb, a.key), bytes(c.signature, 64));
assert(verify(null, cb, a.pub, bytes(c.signature, 64)));
assert(!verify(null, auth(0), a.pub, bytes(o.signature, 64)));
assert(!verify(null, rb, a.pub, bytes(r.signature, 64)));
assert(!verify(null, cb, b.pub, bytes(c.signature, 64)));
console.log(JSON.stringify({ status: 'passed', oracle: 'independent Node/OpenSSL', node: process.version, fixtureSha256: sha(raw).toString('hex'), signatures: 5, canonicalMessages: 3, messageBytes: [ob.length, rb.length, cb.length], unchangedAuthSuite: 2, scope: 'deterministic setup domains only, not an agent or network transfer' }, null, 2));
