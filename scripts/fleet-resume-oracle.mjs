import assert from 'node:assert/strict';
import { createHash,createPublicKey,verify } from 'node:crypto';
import {readFileSync} from 'node:fs';
assert.equal(process.argv.length,3,'usage: node scripts/fleet-resume-oracle.mjs <public-rust-export.json>');
const raw=readFileSync(process.argv[2]);const v=JSON.parse(raw);
const B=x=>Buffer.from(x);const C=(...xs)=>Buffer.concat(xs);const S=x=>createHash('sha256').update(x).digest();const str=x=>Buffer.from(x,'utf8');
const u16=x=>{const b=Buffer.alloc(2);b.writeUInt16BE(x);return b;};const u32=x=>{const b=Buffer.alloc(4);b.writeUInt32BE(x);return b;};const u64=x=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(x));return b;};
const uuid=x=>{assert.match(x,/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);return Buffer.from(x.replaceAll('-',''),'hex');};
const text=x=>C(u16(Buffer.byteLength(x)),str(x));
const binding=b=>C(uuid(b.fleetId),B(b.sourceDevice),B(b.targetDevice),uuid(b.sourceSession),uuid(b.targetSession),uuid(b.transferId),uuid(b.fileId),uuid(b.authorizationId),uuid(b.keyEpoch));
function job(j){assert.equal(j.version,2);assert.equal(j.route,'relayOnly');const pre=j.preImageSha256==null?B([0]):C(B([1]),B(j.preImageSha256));const request=C(str('ferroc:fleet:request:v1\0'),u16(j.version),uuid(j.fleetId),B(j.sourceDevice),B(j.targetDevice),text(j.sourcePath),text(j.destinationPath),u64(j.bytesTotal),B(j.sha256),B([Number(j.overwrite)]),pre,B([0]),u64(j.deadlineMs));return C(str('ferroc:fleet:job:v1\0'),uuid(j.transferId),uuid(j.fileId),text(j.idempotencyKey),request);}
function grant(g){const tag=g.permission==='sendFileNoClobber'?1:g.permission==='replaceExistingFile'?2:0;assert.notEqual(tag,0);return C(str('ferroc:fleet:grant:v1\0'),binding(g.binding),B(g.jobDigest),B([tag]),u32(g.chunkBytes),u64(g.issuedAtMs),u64(g.expiresAtMs));}
const cp=v.checkpoint;const oldDigest=S(job(v.oldJob));const newDigest=S(job(v.newJob));const grantDigest=S(grant(v.newGrant));assert.deepEqual(oldDigest,B(cp.job_digest));assert.deepEqual(newDigest,B(v.newGrant.jobDigest));assert.deepEqual(grantDigest,B(v.newGrantDigest));
const condition=x=>C(str('ferroc:fleet:resume-condition:v1\0'),u16(1),B([1]),oldDigest,B(x.grant_digest),binding(x.binding),u64(x.revision),u64(x.bytes),B(x.sha256),newDigest,grantDigest,binding(v.newGrant.binding));
const cb=condition(cp);const cd=S(cb);assert.deepEqual(cb,B(v.conditionBytes));assert.deepEqual(cd,B(v.conditionDigest));
const t=v.transcript;function auth(role){return C(str('ferroc:fleet:auth:v2\0'),u16(2),B([role]),binding(t.binding),B(t.jobDigest),B(t.grantDigest),B(t.sourceIdentity),B(t.targetIdentity),B(t.sourceEphemeral),B(t.targetEphemeral),u64(t.maxFileBytes),u32(t.chunkBytes),u64(t.issuedAtMs),u64(t.expiresAtMs));}
function proof(role,digest=cd){return C(str('ferroc:fleet:resume-proof:v1\0'),B([role]),digest,S(auth(role)));}
const a=proof(0);const b=proof(1);assert.deepEqual(a,B(v.sourceProof));assert.deepEqual(b,B(v.targetProof));
const spki=key=>createPublicKey({format:'der',type:'spki',key:C(Buffer.from('302a300506032b6570032100','hex'),B(key))});const source=spki(t.sourceIdentity);const target=spki(t.targetIdentity);
assert(verify(null,a,source,B(v.sourceSignature)));assert(verify(null,b,target,B(v.targetSignature)));
let negatives=0;for(const [body,key,sig] of [[b,source,v.sourceSignature],[a,target,v.targetSignature],[auth(0),source,v.sourceSignature]]){assert.equal(verify(null,body,key,B(sig)),false);negatives++;}
for(const field of ['bytes','revision','sha256']){const changed=structuredClone(cp);if(field==='sha256')changed.sha256[0]^=1;else changed[field]++;const changedDigest=S(condition(changed));assert.notDeepEqual(changedDigest,cd);assert.equal(verify(null,proof(0,changedDigest),source,B(v.sourceSignature)),false);negatives++;}
const result={status:'passed',scope:'independent Node/OpenSSL canonical bytes + PUBLIC test signatures; no Runtime or network resume',canonicalMessages:3,signaturesVerified:2,negativeControls:negatives,fixtureSha256:S(raw).toString('hex'),conditionDigest:cd.toString('hex')};console.log(JSON.stringify(result));
