import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {isPublicIP,validateUrl,resolvePublic,createFetcher,requestPinned,LIMITS} from '../backend/safe-fetch.mjs';
import {checkCookies,checkHeaders,checkContent,checkBanners,compareVersions} from '../backend/checks.mjs';
import {runScan} from '../backend/scan.mjs';
const publicDNS=async()=>[{address:'93.184.216.34',family:4}];
const response=(headers={},body='')=>({status:200,headers,body,bytes:Buffer.byteLength(body)});
test('reject nonpublic and transition IP ranges',()=>{
 for(const ip of ['2::1','200::1','192.88.99.1'])assert.equal(isPublicIP(ip),false,ip);
 for(const ip of ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.0.1','169.254.169.254','100.64.0.1','192.0.2.1','198.18.0.1','198.51.100.1','203.0.113.1','224.1.1.1','0.0.0.0','255.255.255.255','::1','::ffff:8.8.8.8','::ffff:127.0.0.1','64:ff9b::7f00:1','2002:7f00::1','2001::1','2001:db8::1','fc00::1','fe80::1','ff00::1','3fff::1'])assert.equal(isPublicIP(ip),false,ip);
 for(const ip of ['8.8.8.8','93.184.216.34','2606:4700:4700::1111','2001:4860:4860::8888'])assert.equal(isPublicIP(ip),true,ip);
});
test('validate URL rejects credentials, local names, literal IPs, queries and ports',()=>{
 for(const url of ['file:///etc/passwd','http://127.1','http://2130706433','http://[::1]','http://user:pass@example.com','http://example.local','http://localhost','https://example.com:444','http://example.com/?token=secret'])assert.throws(()=>validateUrl(url),url);
 assert.equal(validateUrl('https://example.com/path#secret').href,'https://example.com/path');
});
test('mixed DNS answer fails before any request',async()=>{
 await assert.rejects(resolvePublic('example.com',async()=>[{address:'8.8.8.8',family:4},{address:'10.0.0.1',family:4}]),/private or reserved/);
});
test('redirect destinations revalidated including metadata and credentials',async()=>{
 for(const location of ['http://169.254.169.254/latest','https://user:pass@example.com','http://example.com']){
 let calls=0;const fetch=createFetcher({resolve:publicDNS,request:async()=>{calls++;return {...response(),status:302,headers:{location}};}});
 await assert.rejects(fetch('https://example.com'));assert.equal(calls,1);
 }
});
test('redirect DNS cannot rebind into private range',async()=>{
 let calls=0;const fetch=createFetcher({resolve:async host=>host==='example.com'?publicDNS():[{address:'127.0.0.1',family:4}],request:async()=>{calls++;return {...response(),status:302,headers:{location:'https://other.example.com'}};}});
 await assert.rejects(fetch('https://example.com'),/private or reserved/);assert.equal(calls,1);
});
test('redirect and request budgets are bounded',async()=>{
 let calls=0;const budget={count:0};const fetch=createFetcher({resolve:publicDNS,budget,request:async()=>{calls++;return {...response(),status:302,headers:{location:'https://example.com/again'}};}});
 await assert.rejects(fetch('https://example.com'),/Redirect limit/);assert.equal(calls,4);
 await assert.rejects(fetch('https://example.com'),/budget/);assert.equal(calls,6);
});
test('selected vetted address reaches transport per request',async()=>{
 const fetch=createFetcher({resolve:publicDNS,request:async(url,address)=>{assert.equal(url.hostname,'example.com');assert.deepEqual(address,{address:'93.184.216.34',family:4});return response();}});
 assert.equal((await fetch('https://example.com')).status,200);
});
test('body cap enforced by transport independently of Content-Length',async()=>{
 const server=http.createServer((req,res)=>{res.writeHead(200);res.end('x'.repeat(4096));});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{await assert.rejects(requestPinned(new URL(`http://example.com:${server.address().port}`),{address:'127.0.0.1',family:4},{maxBytes:100}),/limit/);}finally{await new Promise(r=>server.close(r));}
});
test('transport timeout stops a stalled server',async()=>{
 const server=http.createServer(()=>{});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{await assert.rejects(requestPinned(new URL(`http://example.com:${server.address().port}`),{address:'127.0.0.1',family:4},{timeout:30}),/timed out/);}finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
test('cookie secrets never enter output and flags are contextual',()=>{
 const results=checkCookies({'set-cookie':['session=TOPSECRET; Secure; HttpOnly; SameSite=Lax','pref=HIDDEN; Path=/']},'https://example.com');
 assert.equal(results[0].status,'pass');assert.equal(results[1].status,'action');assert.ok(!JSON.stringify(results).includes('TOPSECRET'));assert.ok(!JSON.stringify(results).includes('HIDDEN'));
});
test('cookie identity survives reordering and value rotation but separates scope',()=>{
 const first=checkCookies({'set-cookie':['session=old; Path=/; Secure; HttpOnly; SameSite=Lax','prefs=old; Path=/']},'https://example.com/account');
 const second=checkCookies({'set-cookie':['prefs=new; Path=/','session=new; Path=/; Secure; HttpOnly; SameSite=Lax']},'https://example.com/account');
 assert.equal(first[0].id,second[1].id);assert.equal(first[1].id,second[0].id);
 const scoped=checkCookies({'set-cookie':['session=x; Path=/admin','session=x; Domain=other.example.com; Path=/']},'https://example.com');
 assert.notEqual(first[0].id,scoped[0].id);assert.notEqual(first[0].id,scoped[1].id);
 assert.ok(!JSON.stringify(first).includes('session='));assert.ok(!JSON.stringify(second).includes('new;'));
});
test('duplicate cookie identities are unknown and cannot produce a passing comparison',()=>{
 const results=checkCookies({'set-cookie':['session=a; Path=/; Secure; HttpOnly; SameSite=Lax','session=b; Path=/']},'https://example.com');
 assert.ok(results.every(x=>x.status==='unknown'&&x.confidence==='unknown'));
 assert.notEqual(results[0].id,results[1].id);assert.ok(results.every(x=>x.evidence.some(y=>y.includes('cannot be safely compared'))));
});
test('default cookie path and normalized domain produce stable scope identity',()=>{
 const a=checkCookies({'set-cookie':'sid=a; Domain=.EXAMPLE.COM'},'https://example.com/account/settings')[0];
 const b=checkCookies({'set-cookie':'sid=b; Path=/account; Domain=example.com'},'https://example.com/account/profile')[0];
 assert.equal(a.id,b.id);
});
test('transport cancels an in-flight response and closes connection',async()=>{
 const controller=new AbortController();let closed;const disconnected=new Promise(r=>closed=r);
 const server=http.createServer((req,res)=>{res.writeHead(200);res.write('partial');res.on('close',closed);setTimeout(()=>controller.abort(),20);});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{await assert.rejects(requestPinned(new URL(`http://example.com:${server.address().port}`),{address:'127.0.0.1',family:4},{signal:controller.signal}),/abort/i);await disconnected;}finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
test('HSTS zero is not enforcement and report-only CSP is not counted',()=>{
 const results=checkHeaders({'strict-transport-security':'max-age=0','content-security-policy-report-only':"default-src 'self'"},'https://example.com');
 assert.equal(results.find(x=>x.id==='hsts').status,'action');assert.equal(results.find(x=>x.id==='csp').status,'action');
});
test('static mixed content and insecure forms found without leaking URL query',()=>{
 const result=checkContent('<img src="http://assets.example/a?secret=abc"><form action="http://example.com/login?token=x">','https://example.com');assert.equal(result.filter(x=>x.status==='action').length,2);assert.ok(!JSON.stringify(result).includes('secret=abc'));
});
test('raw text and quoted attribute examples do not become form findings',()=>{
 for(const body of ['<script>const html="<form action=\"http://example.com\">"</script>','<style>/* <form action="http://example.com"> */</style>','<textarea><form action="http://example.com"></textarea>','<div data-example=\'<form action="http://example.com">\'>hello</div>']){
 const results=checkContent(body,'https://example.com');assert.ok(results.every(x=>x.status!=='action'),body);
 }
});
test('malformed markup, inert templates and tag cap cannot yield content all-clear',()=>{
 for(const body of ['<form action="http://example.com','<template><form action="http://example.com"></template>','<div>'.repeat(20001)]){
 const results=checkContent(body,'https://example.com');assert.ok(results.every(x=>x.status==='unknown'),body.slice(0,60));
 }
 const good=checkContent('<form action="http://example.com"><img src="http://example.com/a">','https://example.com');assert.ok(good.every(x=>x.status==='action'));
});
test('HTTP probe denial is unknown, unresolved redirect is partial, nonHTML coverage limited',async()=>{
 const denied=await runScan('https://example.com',{resolve:publicDNS,request:async url=>({...response({'content-type':'text/plain'}),status:url.protocol==='http:'?403:200})});
 assert.equal(denied.findings.find(x=>x.id==='http-upgrade').status,'unknown');assert.equal(denied.status,'partial');assert.equal(denied.coverage.find(x=>x.id==='browser-policy').status,'limited');
 const redirect=await runScan('http://example.com',{resolve:publicDNS,request:async()=>({...response(),status:302})});assert.equal(redirect.status,'partial');assert.equal(redirect.findings.find(x=>x.id==='http-status').status,'unknown');
});
test('version hints never confirm CVE and branch comparisons are numeric',()=>{
 assert.equal(compareVersions('8.3.9','8.3.36'),-1);const hints=checkBanners({'x-powered-by':'PHP/8.3.35'});assert.equal(hints[0].confidence,'inferred');assert.match(hints[0].why,/does not confirm a CVE/);
 assert.equal(checkBanners({'x-powered-by':'PHP/8.3.36'})[0].status,'unknown');
});
test('real scan report keeps backend coverage unknown even with strong headers',async()=>{
 const report=await runScan('https://example.com',{resolve:publicDNS,request:async(url)=>url.protocol==='http:'?{...response(),status:301,headers:{location:'https://example.com'}}:response({'content-type':'text/html','strict-transport-security':'max-age=31536000','x-content-type-options':'nosniff','content-security-policy':"default-src 'self'; frame-ancestors 'none'"},'<p>Hi</p>')});
 assert.equal(report.schemaVersion,'2.0');assert.equal(report.status,'complete');assert.equal(report.requests.length,3);assert.equal(report.findings.find(x=>x.id==='runtime-coverage').status,'unknown');assert.equal(report.summary.actionItems,0);assert.ok(!('score' in report));
});
test('encoded and error responses do not get a fake content pass',async()=>{
 const report=await runScan('http://example.com',{resolve:publicDNS,request:async()=>({...response({'content-encoding':'gzip','content-type':'text/html'}),status:403})});
 assert.equal(report.status,'partial');assert.equal(report.findings.find(x=>x.id==='content-unavailable').status,'unknown');assert.ok(!report.findings.some(x=>x.id==='mixed-content'));
});
test('external cancellation rejects rather than publishing completed scan',async()=>{
 const controller=new AbortController();controller.abort();await assert.rejects(runScan('https://example.com',{signal:controller.signal,resolve:publicDNS,request:async()=>response()}));
});
