// Independent Node/OpenSSL golden oracle. No npm dependencies or network access.
// These fixed seeds/keys are PUBLIC TEST MATERIAL, never operational identities.
import assert from 'node:assert/strict';
import { createHash, createCipheriv, createDecipheriv, hkdfSync, createPrivateKey, createPublicKey, sign, verify, diffieHellman } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const fixture = new URL('../tests/fixtures/fleet-p0-control-vectors.json', import.meta.url);
const sha = data => createHash('sha256').update(data).digest();
const id = text => sha(Buffer.concat([Buffer.from('ferroc:fleet:device-id:v1\0'), u16(Buffer.byteLength(text)), Buffer.from(text)]));
function u16(value) { const b = Buffer.alloc(2); b.writeUInt16BE(value); return b; }
function u32(value) { const b = Buffer.alloc(4); b.writeUInt32BE(value); return b; }
function u64(value) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(value)); return b; }
const repeat = (value, count) => Buffer.alloc(count, value);
const binding = Buffer.concat([repeat(1,16), id('source-A'), id('target-B'), ...[3,4,5,6,7,8].map(v => repeat(v,16))]);
assert.equal(binding.length, 176);
const plain = Buffer.from('abc');
const header = Buffer.concat([Buffer.from('FRCFL001'), u16(1), Buffer.from([3,0]), u16(0), u16(216), u32(19), binding, u64(0), u64(0), u32(3)]);
assert.equal(header.length, 216);
function record(root, direction, h, data, seq = 0) {
  const info = Buffer.concat([Buffer.from('ferroc:fleet:record-key:v1\0'), binding, Buffer.from([direction])]);
  const key = Buffer.from(hkdfSync('sha256', root, Buffer.from('ferroc:fleet:hkdf-salt:v1'), info, 32));
  const nonce = Buffer.concat([Buffer.alloc(4), u64(seq)]);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(h);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  const frame = Buffer.concat([h, encrypted, tag]);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(h); decipher.setAuthTag(tag);
  assert.deepEqual(Buffer.concat([decipher.update(encrypted), decipher.final()]), data);
  return { frame, key, nonce };
}
const lowLevel = record(repeat(0x42,32), 0, header, plain);
function keys(oid, byte) {
  const seed = repeat(byte,32);
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from(`302e020100300506032b65${oid}04220420`, 'hex'), seed]), type:'pkcs8', format:'der' });
  const publicKey = createPublicKey(privateKey);
  const raw = publicKey.export({type:'spki',format:'der'}).subarray(-32);
  assert.equal(raw.length,32);
  return { seed, privateKey, publicKey, raw };
}
const sourceId = keys('70', 0x11), targetId = keys('70', 0x22);
const sourceX = keys('6e', 0x33), targetX = keys('6e', 0x44);
// Independently encoded canonical UTF-8 request/job/grant; do not import Rust.
const text = value => Buffer.concat([u16(Buffer.byteLength(value)), Buffer.from(value)]);
const request = Buffer.concat([Buffer.from('ferroc:fleet:request:v1\0'), u16(1), repeat(1,16), id('source-A'), id('target-B'), text('/source/α.bin'), text('/target/β.bin'), u64(1048576), sha(plain), Buffer.from([0,0]), u64(5000)]);
const stableJob = Buffer.concat([Buffer.from('ferroc:fleet:job:v1\0'), repeat(5,16), repeat(6,16), text('request-1'), request]);
const jobDigest = sha(stableJob);
const grantBytes = Buffer.concat([Buffer.from('ferroc:fleet:grant:v1\0'), binding, jobDigest, Buffer.from([1]), u32(262144), u64(100), u64(1000)]);
const grantDigest = sha(grantBytes);
const auth = role => Buffer.concat([Buffer.from('ferroc:fleet:auth:v2\0'), u16(2), Buffer.from([role]), binding, jobDigest, grantDigest, sourceId.raw, targetId.raw, sourceX.raw, targetX.raw, u64(1048576), u32(262144), u64(100), u64(1000)]);
assert.equal(auth(0).length,420);
const sourceSig = sign(null, auth(0), sourceId.privateKey);
const targetSig = sign(null, auth(1), targetId.privateKey);
assert(verify(null, auth(0), sourceId.publicKey, sourceSig));
assert(verify(null, auth(1), targetId.publicKey, targetSig));
const shared = diffieHellman({privateKey:sourceX.privateKey, publicKey:targetX.publicKey});
assert.deepEqual(shared, diffieHellman({privateKey:targetX.privateKey, publicKey:sourceX.publicKey}));
const root = Buffer.from(hkdfSync('sha256', shared, sha(auth(0)), Buffer.from('ferroc:fleet:authenticated-root:v2'), 32));
const authenticated = record(root, 0, header, plain);
const vector = {
  request_hex:request.toString('hex'), parameter_digest_hex:sha(request).toString('hex'), job_hex:stableJob.toString('hex'), job_digest_hex:jobDigest.toString('hex'), grant_hex:grantBytes.toString('hex'), grant_digest_hex:grantDigest.toString('hex'),
  format:'ferroc-fleet-p0-control-public-v2', warning:'PUBLIC FIXTURE SEEDS: NEVER USE AS REAL DEVICE KEYS',
  binding_hex:binding.toString('hex'), header_hex:header.toString('hex'), plaintext_hex:plain.toString('hex'),
  root_hex:repeat(0x42,32).toString('hex'), record_key_hex:lowLevel.key.toString('hex'), nonce_hex:lowLevel.nonce.toString('hex'),
  record_hex:lowLevel.frame.toString('hex'), record_sha256:sha(lowLevel.frame).toString('hex'),
  source_identity_seed_hex:sourceId.seed.toString('hex'), target_identity_seed_hex:targetId.seed.toString('hex'),
  source_identity_public_hex:sourceId.raw.toString('hex'), target_identity_public_hex:targetId.raw.toString('hex'),
  source_x25519_seed_hex:sourceX.seed.toString('hex'), target_x25519_seed_hex:targetX.seed.toString('hex'),
  source_x25519_public_hex:sourceX.raw.toString('hex'), target_x25519_public_hex:targetX.raw.toString('hex'),
  source_auth_hex:auth(0).toString('hex'), target_auth_hex:auth(1).toString('hex'),
  source_signature_hex:sourceSig.toString('hex'), target_signature_hex:targetSig.toString('hex'),
  shared_secret_hex:shared.toString('hex'), authenticated_root_hex:root.toString('hex'),
  authenticated_record_hex:authenticated.frame.toString('hex')
};
if (process.argv.slice(2).length === 1 && process.argv[2] === '--write-fixture') {
  mkdirSync(new URL('../tests/fixtures/', import.meta.url), {recursive:true});
  writeFileSync(fixture, JSON.stringify(vector,null,2) + '\n');
  console.log(`Wrote PUBLIC test fixture: ${fileURLToPath(fixture)}`);
} else {
  assert.equal(process.argv.length,2,'usage: node scripts/fleet-p0-oracle.mjs [--write-fixture]');
  assert.deepEqual(JSON.parse(readFileSync(fixture,'utf8')),vector,'frozen fixture differs from independent crypto/wire oracle');
  console.log(JSON.stringify({status:'passed',oracle:'Node built-in crypto/OpenSSL',node:process.version,fixture_sha256:sha(readFileSync(fixture)).toString('hex'),record_sha256:vector.record_sha256,authenticated_record_sha256:sha(authenticated.frame).toString('hex'),suite:2,scope:'P0 deterministic vectors only; not a network/production transfer'},null,2));
}
