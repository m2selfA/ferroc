// Optional interoperability test only; Node is NOT part of the ferroc runtime.
// Uses the unmodified, separately checked-out BRC relay at a pinned revision.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const PIN='cbe511702dd0147650353c29ac6ab1decd8afda1';
const root=path.resolve(fileURLToPath(new URL('..',import.meta.url)));
const upstream=path.resolve(process.argv[2] ?? '');
const binary=path.resolve(process.argv[3] ?? path.join(root,'target','debug',process.platform==='win32'?'ferroc.exe':'ferroc'));
assert.ok(process.argv[2], 'usage: node scripts/upstream-e2e.mjs <upstream-checkout> [ferroc-binary]');
assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:upstream,encoding:'utf8'}).trim(),PIN);
assert.equal(execFileSync('git',['status','--porcelain','--untracked-files=no'],{cwd:upstream,encoding:'utf8'}).trim(),'','upstream tracked source must be clean');
const {buildRelay}=await import(pathToFileURL(path.join(upstream,'packages/relay/dist/app.js')).href);
const scratch=mkdtempSync(path.join(tmpdir(),'ferroc-upstream-e2e-'));
const work=path.join(scratch,'work');mkdirSync(work);
const password=randomBytes(24).toString('hex');
const relay=buildRelay({port:0,host:'127.0.0.1',publicUrl:'http://127.0.0.1',trustProxy:false,dbFile:path.join(scratch,'relay.sqlite'),sessionSecret:randomBytes(32).toString('hex'),adminUser:'admin',adminPassword:password,relayVersion:'2.0.2'},()=>{});
// Listen first with port=0, then reconstruct with the real origin. No public bind.
await new Promise((resolve,reject)=>{relay.http.once('error',reject);relay.http.listen(0,'127.0.0.1',resolve);});
const port=relay.http.address().port;await relay.close();
const base=`http://127.0.0.1:${port}`;
const live=buildRelay({port,host:'127.0.0.1',publicUrl:base,trustProxy:false,dbFile:path.join(scratch,'relay.sqlite'),sessionSecret:randomBytes(32).toString('hex'),adminUser:'admin',adminPassword:password,relayVersion:'2.0.2'},()=>{});
await new Promise((resolve,reject)=>{live.http.once('error',reject);live.http.listen(port,'127.0.0.1',resolve);});
let agent;let agentLog='';let agentExit;
const controller=new AbortController();
const watchdog=setTimeout(()=>controller.abort(new Error('e2e deadline exceeded')),60000);
const signal=controller.signal;
const waitFor=async(fn,label)=>{
    for(let i=0;i<150;i++){signal.throwIfAborted();const value=await fn();if(value)return value;await delay(100,null,{signal});}
    throw new Error(`timeout: ${label}; agent exit=${agentExit ?? 'running'}`);
};
const request=(url,opts={})=>fetch(url,{...opts,signal});
const unbox=(r)=>{assert.notEqual(r.isError,true,r.content?.[0]?.text);return JSON.parse(r.content[0].text);};
const results=[];const pass=(name)=>{results.push(name);console.log(`PASS ${name}`);};
let success=false;
try {
    agent=spawn(binary,['--allow-dir',work,'--allow-shell','agent','--relay',base,'--name','ferroc-native-probe','--home',path.join(scratch,'ferroc-home'),'--once'],{cwd:work,stdio:['ignore','pipe','pipe']});
    agent.on('error',e=>{agentLog+=e.message;agentExit='spawn-error';});
    agent.on('exit',code=>{agentExit=code;});
    agent.stdout.on('data',d=>{agentLog+=d.toString();});agent.stderr.on('data',d=>{agentLog+=d.toString();});
    const code=await waitFor(()=>agentLog.match(/Code: ([A-Z0-9]{4}-[A-Z0-9]{4})/)?.[1],'pairing code');
    let response=await request(`${base}/auth/login`,{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({username:'admin',password,returnTo:'/'})});
    assert.equal(response.status,302);const cookie=response.headers.get('set-cookie').split(';')[0];
    response=await request(`${base}/device/approve`,{method:'POST',headers:{cookie,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({user_code:code,decision:'allow'})});assert.equal(response.status,200);
    const device=await waitFor(()=>live.hub.list().find(d=>d.name==='ferroc-native-probe'),'paired agent hello');assert.equal(device.toolCount,25);pass('native device pairing + token-authenticated WS hello');
    const call=async(name,args)=>live.hub.call(device.deviceId,name,args,{timeoutMs:10000});
    const prepared=unbox(await call('prepare_file_transfer',{ttlSeconds:60}));assert.equal(Buffer.from(prepared.recipientPublicKey,'base64').length,44);assert.equal(prepared.receiveId.length,32);
    assert.equal((await call('send_file_transfer',{sourcePath:work,recipientPublicKey:'invalid-public-key'})).isError,true);
    assert.equal((await call('receive_file_transfer',{receiveId:prepared.receiveId,transferToken:'invalid-token',destinationPath:path.join(work,'must-not-exist')})).isError,true);
    pass('original relay -> Rust transfer prepare + invalid-input denials (no provider network)');
    const file=path.join(work,'roundtrip.txt');
    unbox(await call('write_file',{path:file,content:'native rust\nold\n'}));
    unbox(await call('edit_block',{file_path:file,old_string:'old',new_string:'verified'}));
    assert.equal(unbox(await call('read_file',{path:file})).text,'native rust\nverified');assert.equal(readFileSync(file,'utf8'),'native rust\nverified\n');pass('unmodified upstream DeviceHub -> Rust file write/edit/read roundtrip');
    const escaped=await call('read_file',{path:path.join(scratch,'relay.sqlite')});assert.equal(escaped.isError,true);pass('remote file-root escape rejected');
    const search=unbox(await call('start_search',{path:work,pattern:'verified',searchType:'content',literalSearch:true,contextLines:0}));
    const found=await waitFor(async()=>{const v=unbox(await call('get_more_search_results',{sessionId:search.sessionId}));return v.done?v:null;},'search completion');assert.equal(found.totalResults,1);assert.equal(found.results[0].lineNumber,2);pass('upstream relay -> Rust background content search');
    // Run the canonical OAuth/MCP suite unchanged, but inspect every PASS/FAIL line, not just its exit code.
    const suite=spawn(process.execPath,[path.join(upstream,'scripts/e2e-oauth.mjs'),base,'admin',password],{cwd:upstream,stdio:['ignore','pipe','pipe'],signal});
    let suiteOut='';suite.stdout.on('data',d=>{suiteOut+=d;});suite.stderr.on('data',d=>{suiteOut+=d;});
    const suiteExit=await new Promise((resolve,reject)=>{suite.once('error',reject);suite.once('close',resolve);});
    assert.equal(suiteExit,0,suiteOut);assert.doesNotMatch(suiteOut,/^FAIL/m);assert.equal((suiteOut.match(/^PASS/gm)??[]).length,14,suiteOut);assert.match(suiteOut,/^PASS\s+mcp start_process via device/m);
    for(const line of suiteOut.split('\n').filter(l=>l.startsWith('PASS'))) {
        const label=line.match(/^PASS\s+(.+?)(?:\s{2,}|$)/)?.[1];
        assert.ok(label, 'canonical test label must be retained');
        console.log(`PASS canonical: ${label}`);
    }
    pass('canonical 14-check OAuth + remote MCP suite with ferroc replacing Node agent');
    response=await request(`${base}/admin/device`,{method:'POST',redirect:'manual',headers:{cookie,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({device_id:device.deviceId,action:'delete'})});assert.equal(response.status,302);
    await waitFor(()=>agentExit!==undefined,'agent exits after revoke');assert.notEqual(agentExit,0);assert.equal(live.hub.list().length,0);pass('upstream admin revocation disconnects Rust agent without re-pairing');
    success=true;
} finally {
    clearTimeout(watchdog);controller.abort();
    if(agent && agentExit===undefined){agent.kill();await Promise.race([new Promise(r=>agent.once('exit',r)),delay(3000)]);if(agentExit===undefined)agent.kill('SIGKILL');}
    await live.close();
    const report={success,harness:'scripts/upstream-e2e.mjs',harnessSha256:createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex'),upstream:PIN,binary:path.relative(root,binary),binarySha256:createHash('sha256').update(readFileSync(binary)).digest('hex'),checks:results,node:process.version,platform:process.platform,
        provenance:'Native Rust agent against canonical unmodified Node relay on loopback. This does NOT verify a Rust relay, public TLS, claude.ai or chatgpt.com.',cleanup:'agent and relay stopped; ephemeral pairing credentials/database removed'};
    mkdirSync(path.join(root,'artifacts'),{recursive:true});writeFileSync(path.join(root,'artifacts','upstream-e2e.json'),JSON.stringify(report,null,2));
    // Scratch contains only this test's random credentials/database, never user data.
    rmSync(scratch,{recursive:true,force:true});assert.equal(existsSync(scratch),false);console.log('CLEANUP verified: scratch removed; no persistent relay service');
}
assert.ok(success);console.log(`PASS upstream interoperability (${results.length} groups + 14 canonical checks)`);
