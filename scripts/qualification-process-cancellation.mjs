// Explicit opt-in non-model integration fixture. Use ONLY a fresh isolated source
// instance. This creates its own company and never reads another company's data.
// Each child has a five-second lifetime; cleanup grace is one second. No models.
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
const base = new URL(process.argv[2] ?? '');
assert.equal(base.hostname, '127.0.0.1');
assert.notEqual(base.port, '3100', 'Refuse the conventional owner instance');
async function api(method, path, body) {
  const r = await fetch(new URL(`/api${path}`, base), { method, headers: {'Content-Type':'application/json'}, body: body === undefined ? undefined : JSON.stringify(body), signal:AbortSignal.timeout(15000) });
  return {status:r.status, body:await r.json()};
}
async function ok(method,path,body) { const r=await api(method,path,body); assert(r.status<300,`${method} ${path}: ${r.status}`); return r.body; }
const company=await ok('POST','/companies',{name:'Finite process cancellation source fixture',description:'Non-model commands; max5s children,1s grace; timers disabled.'});
const code="const{spawn}=require('node:child_process');spawn(process.execPath,['-e','setTimeout(()=>{},5000)'],{detached:true,stdio:'ignore'});process.on('SIGTERM',()=>process.exit(0));setTimeout(()=>{},5000);";
for (const [name,timeout] of [['cancel',0],['timeout',0.4]]) {
  const agent=await ok('POST',`/companies/${company.id}/agents`,{name:`finite-${name}`,adapterType:'process',adapterConfig:{command:process.execPath,args:['-e',code],cwd:process.cwd(),timeoutSec:timeout,graceSec:1},runtimeConfig:{heartbeat:{enabled:false,intervalSec:0,wakeOnDemand:true,maxConcurrentRuns:1}}});
  const first=await ok('POST',`/agents/${agent.id}/heartbeat/invoke`,{reason:`bounded_nonmodel_${name}`});
  await sleep(name==='cancel'?500:250);
  if(name==='cancel') await ok('POST',`/heartbeat-runs/${first.id}/cancel`,{});
  let run; const deadline=Date.now()+12000;
  do { run=await ok('GET',`/heartbeat-runs/${first.id}`); if(!['queued','running'].includes(run.status))break;await sleep(100); } while(Date.now()<deadline);
  const state=await ok('GET',`/agents/${agent.id}`);
  assert.equal(run.status,name==='cancel'?'cancelled':'timed_out');
  assert.equal(state.status,'paused');assert(state.metadata.processCleanupHold);
  assert.equal((await api('POST',`/agents/${agent.id}/resume`,{})).status,409);
  assert.equal((await api('PATCH',`/agents/${agent.id}`,{metadata:{},status:'idle'})).status,409);
  assert.equal(run.resultJson.processCleanup.state,'observed_gone');
  assert(run.resultJson.processCleanup.observed>=2);
  console.log(JSON.stringify({case:name,status:run.status,exitCode:run.exitCode,cleanup:run.resultJson.processCleanup,agentStatus:state.status,resumeHTTP:409,clearHoldHTTP:409}));
}
