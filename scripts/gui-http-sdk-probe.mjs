// Optional SDK oracle only. Node is NOT part of the GUI runtime.
// Secret config is received in an environment variable and never written/logged.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, writeFileSync, readFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
const root = resolve(process.argv[2]);
const upstream = resolve(process.argv[3]);
const require = createRequire(join(upstream, 'packages/relay/package.json'));
const {Client} = require('@modelcontextprotocol/sdk/client/index.js');
const {StreamableHTTPClientTransport} = require('@modelcontextprotocol/sdk/client/streamableHttp.js');
const config = JSON.parse(process.env.FERROC_GUI_CLIENT_CONFIG ?? '{}').mcpServers?.ferroc;
delete process.env.FERROC_GUI_CLIENT_CONFIG;
assert.ok(config?.url && config.headers?.Authorization, 'Copy this GUI instance MCP config first');
const reportPath = process.env.FERROC_GUI_PROBE_REPORT ?? join(root, 'artifacts/gui-sdk-live.json');
const sdkModule = require.resolve('@modelcontextprotocol/sdk/client/index.js');
const sdkVersion = JSON.parse(readFileSync(resolve(dirname(sdkModule),'../../../package.json'),'utf8')).version;
const report = {kind:process.env.FERROC_GUI_PROBE_KIND ?? 'actual-GUI-copy-path', binarySha256:process.env.FERROC_GUI_BINARY_SHA256, sdkVersion, endpoint:config.url, state:'starting', checks:[]};
const watchdog = setTimeout(()=>{console.error('SDK probe overall deadline exceeded');process.exit(2)},process.argv.includes('--hold')?225000:20000);
watchdog.unref();
const client = new Client({name:'ferroc-gui-native-sdk-probe',version:'1'});
const transport = new StreamableHTTPClientTransport(new URL(config.url), {requestInit:{headers:config.headers}});
try {
  await client.connect(transport);
  const tools = await client.listTools();
  assert.equal(tools.tools.length, 25);
  report.checks.push('SDK initialize + initialized + tools/list:25');
  const path = join(process.env.FERROC_GUI_PROBE_WORKDIR ?? join(root,'artifacts/gui-live-root'),'sdk-roundtrip.txt');
  const write = await client.callTool({name:'write_file',arguments:{path,content:'native GUI registry SDK roundtrip',mode:'rewrite'}});
  assert.notEqual(write.isError,true);
  const read = await client.callTool({name:'read_file',arguments:{path}});
  assert.ok(JSON.stringify(read).includes('native GUI registry SDK roundtrip'));
  report.checks.push('HTTP write/read roundtrip');
  const denied = await client.callTool({name:'start_process',arguments:{command:'echo forbidden'}});
  assert.equal(denied.isError,true);
  report.checks.push('shell denied by default');
  const unauthenticated = await fetch(config.url);
  assert.equal(unauthenticated.status,401);
  report.checks.push('HTTP rejects unauthenticated requests');
  report.state='connected';
  writeFileSync(reportPath,JSON.stringify(report,null,2));
  if(process.argv.includes('--hold')) {
    const deadline=Date.now()+180000;
    while(!existsSync(join(root,'artifacts/gui-sdk-release')) && Date.now()<deadline) await delay(100);
    assert.ok(existsSync(join(root,'artifacts/gui-sdk-release')), 'native inspection hold deadline exceeded');
  }
  await transport.terminateSession();
  report.checks.push('SDK DELETE session');
  report.state='passed';
} catch(error) {
  report.state='failed';
  report.error=error?.message ?? 'SDK probe failed';
  process.exitCode=1;
} finally {
  await client.close().catch(()=>{});
  clearTimeout(watchdog);
  writeFileSync(reportPath,JSON.stringify(report,null,2));
}
console.log(JSON.stringify(report));
