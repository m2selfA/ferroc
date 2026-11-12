// TEST ONLY. Executes pinned upstream transfer functions, not a reimplemented crypto oracle.
// Sole source hook replaces filesystem policy import with a fixture-path identity function.
// Provider fetch is a memory fixture: NO external upload and NO Node runtime in ferroc.
import {stripTypeScriptTypes} from 'node:module';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import path from 'node:path';
import readline from 'node:readline';
import assert from 'node:assert/strict';
const root=path.resolve(process.argv[2]);
assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),'cbe511702dd0147650353c29ac6ab1decd8afda1');
const source=readFileSync(path.join(root,'packages/agent/src/core/file-transfer.ts'),'utf8');
assert.equal(execFileSync('git',['hash-object','packages/agent/src/core/file-transfer.ts'],{cwd:root,encoding:'utf8'}).trim(),'d541a49af6a0c3371e1d6726a6b80de84d3e3997');
const hook="import { validatePath } from './tools/filesystem.js';";
assert.equal(source.split(hook).length,2);
const module=await import('data:text/javascript;base64,'+Buffer.from(stripTypeScriptTypes(source.replace(hook,'const validatePath = async p => p;'),{mode:'transform'})).toString('base64'));
let ciphertext=Buffer.alloc(0);
globalThis.fetch=async(url,options)=>{
  const u=new URL(url);assert.equal(u.hostname,'tmpfiles.org');
  if(options?.method==='POST'){
    assert.equal(u.pathname,'/api/v1/upload');
    ciphertext=Buffer.from(await options.body.get('file').arrayBuffer());
    return Response.json({status:'success',data:{url:'https://tmpfiles.org/dl/oracle'}});
  }
  if(u.pathname==='/page')return new Response('<a class="download" href="/dl/oracle">download</a>');
  assert.ok(u.pathname.startsWith('/dl/'));return new Response(ciphertext);
};
const input=readline.createInterface({input:process.stdin});
for await(const line of input){
  try{
    const q=JSON.parse(line);let out;
    if(q.action==='prepare')out=module.prepareFileReceive(3600);
    else if(q.action==='send'){const result=await module.sendFileTransfer(q.path,q.recipient,3600);out={...result,ciphertext:ciphertext.toString('base64')};}
    else if(q.action==='receive'){ciphertext=Buffer.from(q.ciphertext,'base64');out=await module.receiveFileTransfer(q.id,q.token,q.path,false);}
    else if(q.action==='identity')out={sourceSha256:createHash('sha256').update(source).digest('hex'),sourceGitBlob:'d541a49af6a0c3371e1d6726a6b80de84d3e3997',mocked:['filesystem validatePath','provider fetch'],crypto:'original pinned module'};
    else if(q.action==='stop'){process.stdout.write('{}\n');break;}
    else throw Error('unknown oracle action');
    process.stdout.write(JSON.stringify(out)+'\n');
  }catch(error){process.stdout.write(JSON.stringify({error:String(error)})+'\n');}
}
input.close();process.stdin.destroy();
