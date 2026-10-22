import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {once} from 'node:events';
import {createApp} from '../server.mjs';

// Ephemeral loopback only; the scanner is a trusted in-memory fixture, so these
// tests never resolve a target hostname or connect to the public internet.
const report=url=>({schemaVersion:'2.0',target:url,status:'complete',findings:[],coverage:[],requests:[],limitations:[]});
async function fixture(t,options={}){
 const server=createApp({scanner:async url=>report(url),...options});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
 const port=server.address().port;
 async function request(path,{method='GET',headers={},body,chunked=false}={}){
  if(body!==undefined&&typeof body!=='string')body=JSON.stringify(body);
  return new Promise((resolve,reject)=>{
   const req=http.request({host:'127.0.0.1',port,path,method,headers:{...(body!==undefined?{'Content-Type':'application/json',...(chunked?{'Transfer-Encoding':'chunked'}:{'Content-Length':Buffer.byteLength(body)})}:{}),...headers}},res=>{
    const chunks=[];res.on('data',x=>chunks.push(x));res.on('end',()=>{const text=Buffer.concat(chunks).toString();let data;try{data=JSON.parse(text);}catch{}resolve({status:res.statusCode,headers:res.headers,text,data});});res.on('error',reject);
   });req.setTimeout(3000,()=>req.destroy(new Error('Fixture request timed out')));req.on('error',reject);req.end(body);
  });
 }
 return {server,port,request};
}
async function create(request,url='https://example.com/'){
 const response=await request('/api/scans',{method:'POST',body:{url}});assert.equal(response.status,201,response.text);return response.data;
}
async function completed(request,job){
 for(let n=0;n<30;n++){const response=await request(`/api/scans/${job.id}`,{headers:{'X-Scan-Token':job.token}});if(response.data?.status==='complete'||response.data?.status==='failed')return response;await new Promise(resolve=>setTimeout(resolve,5));}
 assert.fail('Fixture scan did not settle');
}

test('Host is exact, including port, and hostile Origin/cross-site API are denied',async t=>{
 const {request,port}=await fixture(t);
 for(const host of ['evil.example',`localhost:${port+1}`,`localhost:${port}.evil.example`,`127.0.0.1:${port}@evil.example`])assert.equal((await request('/api/health',{headers:{Host:host}})).status,403,host);
 assert.equal((await request('/api/health',{headers:{Host:`localhost:${port}`,Origin:`http://localhost:${port}`}})).status,200);
 assert.equal((await request('/api/health',{headers:{Origin:'https://evil.example'}})).status,403);
 assert.equal((await request('/api/health',{headers:{Origin:'null'}})).status,403);
 assert.equal((await request('/api/health',{headers:{'Sec-Fetch-Site':'cross-site'}})).status,403);
});

test('static allowlist excludes source, tokens, traversal and query paths',async t=>{
 const {request}=await fixture(t);
 const page=await request('/');assert.equal(page.status,200);assert.match(page.headers['content-security-policy'],/frame-ancestors 'none'/);assert.equal(page.headers['access-control-allow-origin'],undefined);
 for(const path of ['/server.mjs','/backend/safe-fetch.mjs','/README.md','/../server.mjs','/%2e%2e/server.mjs','/api/health?x=1','/app.js?cache=1'])assert.ok([400,404].includes((await request(path)).status),path);
 const head=await request('/styles.css',{method:'HEAD'});assert.equal(head.status,200);assert.equal(head.text,'');
});

test('scan writes require JSON and bounded, valid, exact input',async t=>{
 const {request}=await fixture(t);
 assert.equal((await request('/api/scans',{method:'POST',headers:{'Content-Type':'text/plain'},body:'{}'})).status,415);
 assert.equal((await request('/api/scans',{method:'POST',body:'{broken'})).status,400);
 for(const body of [null,[],{}, {url:4},{url:'https://example.com',resolve:'127.0.0.1'},{url:'http://127.0.0.1'},{url:'https://example.com/?token=x'}])assert.equal((await request('/api/scans',{method:'POST',body:JSON.stringify(body)})).status,400);
 assert.equal((await request('/api/scans',{method:'POST',body:' '.repeat(2049)})).status,413);
 assert.equal((await request('/api/scans',{method:'POST',body:' '.repeat(2049),chunked:true})).status,413);
});

test('scan token missing, wrong, duplicate and non-ASCII values fail uniformly',async t=>{
 const {request}=await fixture(t);const job=await create(request);
 for(const value of [undefined,'0'.repeat(64),'é'.repeat(64),[job.token,job.token]]){
  const headers=value===undefined?{}:{'X-Scan-Token':value};const response=await request(`/api/scans/${job.id}`,{headers});assert.equal(response.status,401,response.text);
 }
 assert.equal((await request(`/api/scans/${job.id}`,{method:'DELETE',headers:{'X-Scan-Token':'x'}})).status,401);
 assert.equal((await request('/api/health')).status,200);
});

test('job completion retains report, server job ID and a final stage',async t=>{
 const {request}=await fixture(t,{scanner:async(url,{onProgress})=>{onProgress('Inspecting fixture');return {...report(url),id:'untrusted-report-id'};}});
 const job=await create(request),response=await completed(request,job);
 assert.equal(response.status,200);assert.equal(response.data.status,'complete');assert.equal(response.data.stage,'Scan complete');assert.equal(response.data.report.id,job.id);assert.equal(response.data.report.target,'https://example.com/');
});

test('scanner failures are sanitized and do not expose internal error text',async t=>{
 const {request}=await fixture(t,{scanner:async()=>{throw new Error('SECRET_INTERNAL_DETAIL');}});const job=await create(request),response=await completed(request,job);
 assert.equal(response.data.status,'failed');assert.equal(response.data.error.code,'SCAN_FAILED');assert.doesNotMatch(response.text,/SECRET_INTERNAL_DETAIL/);
});

test('cancellation aborts the fixture and deletes the bearer-protected report',async t=>{
 let aborted=false;
 const {request}=await fixture(t,{scanner:(_url,{signal})=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>{aborted=true;reject(signal.reason);},{once:true}))});
 const job=await create(request);await new Promise(resolve=>setImmediate(resolve));
 const response=await request(`/api/scans/${job.id}`,{method:'DELETE',headers:{'X-Scan-Token':job.token}});assert.equal(response.status,200);assert.equal(response.data.status,'cancelled');assert.equal(aborted,true);
 assert.equal((await request(`/api/scans/${job.id}`,{headers:{'X-Scan-Token':job.token}})).status,404);
});

test('concurrency blocks excess admission and cancellation frees a slot',async t=>{
 const {request}=await fixture(t,{maxConcurrent:1,scanner:(_url,{signal})=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}))});
 const job=await create(request);
 assert.equal((await request('/api/scans',{method:'POST',body:{url:'https://other.example.com/'}})).status,503);
 await request(`/api/scans/${job.id}`,{method:'DELETE',headers:{'X-Scan-Token':job.token}});await new Promise(resolve=>setImmediate(resolve));
 await create(request,'https://other.example.com/');
});

test('per-target rate window and report TTL expire under the injected clock',async t=>{
 let clock=1_000_000;const {request}=await fixture(t,{now:()=>clock});let first;
 for(let i=0;i<4;i++){const job=await create(request);first??=job;await completed(request,job);}
 const limited=await request('/api/scans',{method:'POST',body:{url:'https://example.com/'}});assert.equal(limited.status,429);assert.equal(limited.headers['retry-after'],'600');
 clock+=600001;
 assert.equal((await request(`/api/scans/${first.id}`,{headers:{'X-Scan-Token':first.token}})).status,404);
 await create(request);
});

test('public deployment config requires an exact HTTPS origin',async t=>{
 for(const publicOrigin of ['http://app.example.com','https://app.example.com/','https://user:pass@app.example.com','https://app.example.com/path'])assert.throws(()=>createApp({publicOrigin}));
 const {request}=await fixture(t,{publicOrigin:'https://app.example.com'});
 const allowed=await request('/api/health',{headers:{Host:'app.example.com',Origin:'https://app.example.com'}});assert.equal(allowed.status,200);
 assert.equal((await request('/api/health',{headers:{Host:'app.example.com:443',Origin:'https://app.example.com'}})).status,403);
});
