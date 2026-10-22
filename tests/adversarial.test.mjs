// Focused, deterministic regressions. No sockets, DNS, or third-party code run.
import test from 'node:test';
import assert from 'node:assert/strict';
import {isPublicIP,validateUrl,resolvePublic,createFetcher} from '../backend/safe-fetch.mjs';
import {checkHeaders,checkCookies,checkContent,checkBanners} from '../backend/checks.mjs';

test('public-address invariant rejects shortened reserved IPv6 hextets and transition space',()=>{
 for(const ip of ['2::1','20::1','200::1','3::1','300::1','2001:db8::1','2001::1','2002:7f00:1::1','::ffff:127.0.0.1','64:ff9b::7f00:1','192.88.99.1','100.64.0.1','198.18.0.1']) assert.equal(isPublicIP(ip),false,ip);
 assert.equal(isPublicIP('2606:4700:4700::1111'),true);
 assert.equal(isPublicIP('1.1.1.1'),true);
});

test('URL parsing rejects canonicalized IP tricks, credentials and nonstandard ports',()=>{
 for(const input of ['http://2130706433','http://0177.0.0.1','http://0x7f000001','http://[::ffff:127.0.0.1]','https://user:pass@example.com','https://example.com:8443','https://example.com/?token=secret','file:///etc/passwd']) assert.throws(()=>validateUrl(input),undefined,input);
});

test('one nonpublic DNS answer rejects the whole answer set',async()=>{
 await assert.rejects(resolvePublic('example.com',async()=>[{address:'1.1.1.1',family:4},{address:'127.0.0.1',family:4}]));
});

test('redirect destination is revalidated and never sent to a private DNS address',async()=>{
 const sent=[];
 const fetch=createFetcher({resolve:async host=>[{address:host==='private.example.com'?'10.1.2.3':'1.1.1.1',family:4}],request:async(url,address)=>{sent.push([url.hostname,address.address]);return {status:302,headers:{location:'https://private.example.com/'},body:'',bytes:0};}});
 await assert.rejects(fetch('https://example.com/'));
 assert.deepEqual(sent,[['example.com','1.1.1.1']]);
});

test('TLS downgrade redirect is rejected before another request',async()=>{
 let count=0;
 const fetch=createFetcher({resolve:async()=>[{address:'1.1.1.1',family:4}],request:async()=>{count++;return {status:302,headers:{location:'http://example.com/'},body:'',bytes:0};}});
 await assert.rejects(fetch('https://example.com/'));
 assert.equal(count,1);
});

test('arbitrary framing wildcard is not reported as an effective restriction',()=>{
 const f=checkHeaders({'content-security-policy':'frame-ancestors *'},'https://example.com').find(x=>x.id==='framing');
 assert.doesNotMatch(f.title,/restriction observed/i);
});

test('cookie report redacts attacker-controlled cookie names and values',()=>{
 const result=JSON.stringify(checkCookies({'set-cookie':['SECRET_NAME=SECRET_VALUE; Path=/']},'https://example.com'));
 assert.doesNotMatch(result,/SECRET_NAME|SECRET_VALUE/);
});

test('banner comparison never certifies a deployed version as patched',()=>{
 const f=checkBanners({'x-powered-by':'PHP/8.3.36'})[0];
 assert.equal(f.status,'unknown');assert.equal(f.confidence,'inferred');
});

test('static content ignores commented examples and canonical navigation links',()=>{
 const html='<!-- example <form action="http://not-real.example"></form> --><link rel="canonical" href="http://example.com">';
 const findings=checkContent(html,'https://example.com');
 assert.equal(findings.find(x=>x.id==='insecure-forms').status,'pass');
 assert.equal(findings.find(x=>x.id==='mixed-content').status,'pass');
});

test('unterminated repeated tags produce a bounded unknown static observation',()=>{
 const findings=checkContent('<script '.repeat(100000),'https://example.com');
 assert.equal(findings.find(x=>x.id==='mixed-content').status,'unknown');
});
