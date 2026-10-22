#!/usr/bin/env node
// Aftershock reader — single-file local companion for aftershock.html.
//
// Browsers deliberately hide one site's response headers from another page
// (CORS), so no HTML file can scan a live site alone. The reader is the honest
// bridge: the same bounded, passive scanner as the repository server, run by
// you, on this machine, gated by a one-time pairing code.
//
// Use:  node aftershock-reader.mjs
//   It listens on 127.0.0.1 only (loopback), prints a one-time pairing code,
//   and asks the Aftershock page for that code once. It refuses requests that
//   do not carry the code and stops itself after 5 wrong attempts.
//
// This file is generated from the repository modules (backend/safe-fetch.mjs,
// backend/checks.mjs, backend/scan.mjs, reader.mjs). The scanner code below is
// the repository code byte-for-byte apart from import/export wiring needed to
// fit in one file. Read it in one sitting; there is nothing else.

import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import {isIP} from 'node:net';
import {createHash,randomUUID,randomBytes,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

// ==== backend/safe-fetch.mjs (verbatim) ====

const LIMITS={requests:6,redirects:3,bytes:1048576,timeout:8000,duration:25000};
function isPublicIP(address){
 const family=isIP(address); if(!family)return false;
 if(family===4){const [a,b,c]=address.split('.').map(Number);return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0||b===2||b===88&&c===99)||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19||b===51&&c===100)||a===203&&b===0&&c===113);}
 // Only globally routable unicast 2000::/3; exclude documentation, transition,
 // mapped IPv4, ORCHID and special-purpose blocks rather than decode gateways.
 const normalized=address.toLowerCase();
 if(!/^[23][0-9a-f]{0,3}:/.test(normalized))return false;
 const first=parseInt(normalized.split(':')[0],16), second=parseInt(normalized.split(':')[1]||'0',16);
 return first>=0x2000&&first<=0x3fff&&!(first===0x2001&&(second<=0x1ff||second===0xdb8)||first===0x2002||first===0x3fff);
}
function validateUrl(input){
 const value=new URL(input);
 if(!['http:','https:'].includes(value.protocol))throw new Error('Only HTTP and HTTPS URLs are supported.');
 if(value.username||value.password)throw new Error('URLs with credentials are not supported.');
 if(value.port && value.port!==(value.protocol==='https:'?'443':'80'))throw new Error('Only standard web ports are supported.');
 const host=value.hostname.toLowerCase().replace(/\.$/,'');
 if(isIP(host.replace(/^\[|\]$/g,''))||!host.includes('.')||/(?:^|\.)(?:localhost|local|internal|test|invalid|onion|home|lan|arpa)$/.test(host))throw new Error('Enter a public DNS website hostname.');
 if(value.search)throw new Error('Remove query parameters before scanning; URLs may contain private tokens.');
 value.hash='';return value;
}
async function resolvePublic(hostname,resolve=dns.lookup){
 const addresses=await resolve(hostname,{all:true,verbatim:true});
 if(!addresses.length||addresses.some(x=>!isPublicIP(x.address)))throw new Error('Destination DNS includes a private or reserved address.');
 return addresses[0];
}
function requestPinned(url,address,{signal,timeout=LIMITS.timeout,maxBytes=LIMITS.bytes}={}){
 return new Promise((resolve,reject)=>{
  let settled=false; const finish=(err,value)=>{if(settled)return;settled=true;clearTimeout(timer);err?reject(err):resolve(value);};
  const req=(url.protocol==='https:'?https:http).request(url,{method:'GET',signal,agent:false,rejectUnauthorized:true,lookup:(_host,options,cb)=>options.all?cb(null,[address]):cb(null,address.address,address.family),headers:{'User-Agent':'Aftershock/0.3 (passive security posture check)','Accept':'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1','Accept-Encoding':'identity'}},res=>{
   let bytes=0;const chunks=[]; const socket=res.socket;
   const cert=url.protocol==='https:'?socket.getPeerCertificate():null;
   const tls=cert?{protocol:socket.getProtocol(),issuer:cert.issuer?.O||cert.issuer?.CN||'Unknown',validTo:cert.valid_to}:undefined;
   res.on('data',chunk=>{bytes+=chunk.length;if(bytes>maxBytes){const error=new Error('Response exceeded the 1 MiB scan limit.');error.code='BODY_LIMIT';res.destroy(error);req.destroy(error);finish(error);}else chunks.push(chunk);});
   res.on('end',()=>finish(null,{status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8'),bytes,tls}));res.on('error',err=>finish(err));
  });
  const timer=setTimeout(()=>req.destroy(new Error('Request timed out.')),timeout);
  req.on('error',err=>finish(err));req.end();
 });
}
function createFetcher({resolve=dns.lookup,request=requestPinned,signal,budget={count:0},onRequest=()=>{}}={}){
 return async function fetchPublic(input){
  let url=validateUrl(input);
  for(let redirects=0;;redirects++){
   signal?.throwIfAborted();if(budget.count>=LIMITS.requests)throw new Error('Request budget exhausted.');budget.count++;
   const address=await resolvePublic(url.hostname,resolve);signal?.throwIfAborted();
   const response=await request(url,address,{signal});onRequest({url:url.href,status:response.status,bytes:response.bytes});
   if([301,302,303,307,308].includes(response.status)&&response.headers.location){
    if(redirects>=LIMITS.redirects)throw new Error('Redirect limit exceeded.');
    const next=validateUrl(new URL(response.headers.location,url).href);
    if(url.protocol==='https:'&&next.protocol==='http:')throw new Error('HTTPS redirect downgraded to HTTP.');
    url=next;continue;
   }
   return {...response,url:url.href};
  }
 };
}

// ==== backend/checks.mjs (verbatim) ====
const mdn='https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/';
const finding=(id,title,category,status,priority,evidence,why,fix,source)=>({id,title,category,status,priority,confidence:status==='unknown'?'unknown':'observed',evidence,why,fix,...(source?{source}:{})});
function checkHeaders(headers,url){
 const https=new URL(url).protocol==='https:';const h=headers;const out=[];
 if(https){const raw=h['strict-transport-security'];const age=raw?.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i);const valid=age&&Number(age[1])>0;
 out.push(finding('hsts',valid?'HSTS is enabled':'HSTS is missing or disabled','configuration',valid?'pass':'action',valid?'info':'medium',[raw?`Strict-Transport-Security: ${raw}`:'No Strict-Transport-Security response header.'],'HSTS tells returning browsers to enforce HTTPS. It does not prove origin runtime security.','Set Strict-Transport-Security with a suitable positive max-age after verifying HTTPS across your deployment.',mdn+'Strict-Transport-Security'));}
 const csp=h['content-security-policy'];
 out.push(finding('csp',csp?'Content Security Policy observed':'No enforcing CSP header observed','configuration',csp?'pass':'action',csp?'info':'low',[csp?`Content-Security-Policy: ${csp}`:'No Content-Security-Policy header.'],'A policy can reduce browser injection impact; its presence does not establish an effective XSS defense.','Review a restrictive policy against your application; deploy in report-only mode first when needed.',mdn+'Content-Security-Policy'));
 const framing=/(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(csp||'')||/^(DENY|SAMEORIGIN)$/i.test(h['x-frame-options']||'');
 out.push(finding('framing',framing?'Framing policy directive observed':'No framing policy observed','configuration',framing?'pass':'action',framing?'info':'low',[h['x-frame-options']?`X-Frame-Options: ${h['x-frame-options']}`:'No valid X-Frame-Options header.',csp&&/frame-ancestors/i.test(csp)?'CSP frame-ancestors directive present.':'No CSP frame-ancestors directive observed.'],'A framing policy can reduce clickjacking; presence does not establish restrictive or valid values. Wildcards may intentionally permit embedding.','Review an appropriate CSP frame-ancestors policy if this page should not be embedded.',mdn+'Content-Security-Policy/frame-ancestors'));
 const nosniff=String(h['x-content-type-options']||'').toLowerCase()==='nosniff';
 out.push(finding('nosniff',nosniff?'MIME sniffing disabled':'MIME sniffing protection not observed','configuration',nosniff?'pass':'action',nosniff?'info':'low',[`X-Content-Type-Options: ${h['x-content-type-options']||'(absent)'}`],'The nosniff header helps browsers honor declared MIME types. Missing it alone is not a demonstrated exploit.','Set X-Content-Type-Options: nosniff and serve accurate content types.',mdn+'X-Content-Type-Options'));
 return out;
}
function checkCookies(headers,url){
 const cookies=headers['set-cookie'];if(!cookies)return [];
 const entries=Array.isArray(cookies)?cookies:[cookies];const parsedUrl=new URL(url);
 const identities=entries.map(raw=>{const parts=raw.split(';');const name=parts[0].slice(0,parts[0].indexOf('=')).trim();const attrs=parts.slice(1).map(x=>x.trim());const domain=attrs.find(x=>/^domain=/i.test(x))?.slice(7).toLowerCase().replace(/^\./,'')||parsedUrl.hostname.toLowerCase();const declaredPath=attrs.find(x=>/^path=/i.test(x))?.slice(5);const defaultPath=parsedUrl.pathname.slice(0,parsedUrl.pathname.lastIndexOf('/'))||'/';const path=declaredPath?.startsWith('/')?declaredPath:defaultPath;return createHash('sha256').update(JSON.stringify([name,domain,path])).digest('hex').slice(0,24);});
 const counts=new Map();for(const id of identities)counts.set(id,(counts.get(id)||0)+1);
 return entries.map((raw,index)=>{
 const attributes=raw.split(';').slice(1).map(x=>x.trim().toLowerCase());const secure=attributes.includes('secure'),httpOnly=attributes.includes('httponly'),sameSite=attributes.find(x=>/^samesite=(strict|lax|none)$/.test(x));
 const issues=[];if(!secure)issues.push('Secure absent');if(!httpOnly)issues.push('HttpOnly absent (may be intentional for non-session cookies)');if(!sameSite)issues.push('explicit SameSite absent');if(sameSite==='samesite=none'&&!secure)issues.push('SameSite=None requires Secure');
 const duplicate=counts.get(identities[index])>1;
 return finding(`cookie-${identities[index]}${duplicate?'-duplicate-'+index:''}`,duplicate?'Repeated cookie identity needs verification':issues.length?'Review response cookie flags':'Response cookie flags observed','configuration',duplicate?'unknown':issues.length?'action':'pass',duplicate?'info':issues.length?'low':'info',[`Cookie identity ${identities[index]}: name and value redacted; Secure=${secure}; HttpOnly=${httpOnly}; SameSite=${sameSite?.split('=')[1]||'unspecified'}`,...(duplicate?['Multiple Set-Cookie headers target the same name, domain and path. Their ordering or replacement cannot be safely compared between scans.']:[]),...issues],'Cookie purpose is unknown. Sensitive session cookies usually need stronger flags than application-readable preference cookies.','Review each cookie purpose; use Secure, HttpOnly where appropriate, and an explicit SameSite policy. Never include cookie values in reports.',mdn+'Set-Cookie');
 });
}
function checkContent(body,url){
 if(new URL(url).protocol!=='https:')return [];
 const mixed=[];const forms=[];let cursor=0,tags=0,limited=false;const lower=body.toLowerCase();
 while(cursor<body.length){
  if(tags++>=20000){limited=true;break;}
  const start=body.indexOf('<',cursor);if(start<0)break;
  if(body.startsWith('<!--',start)){const close=body.indexOf('-->',start+4);if(close<0){limited=true;break;}cursor=close+3;continue;}
  let quote='',end=start+1;
  for(;end<body.length;end++){const char=body[end];if(quote){if(char===quote)quote='';}else if(char==='"'||char==="'")quote=char;else if(char==='>')break;else if(char==='<'){limited=true;break;}}
  if(end>=body.length||limited){limited=true;break;}
  cursor=end+1;const tag=body.slice(start,end+1);const opening=/^<([a-z][a-z0-9:-]*)\b/i.exec(tag);if(!opening)continue;
  const name=opening[1].toLowerCase();
  if(name==='template'){limited=true;break;}
  if(['script','style','textarea','title','xmp','iframe','noembed','noframes','noscript'].includes(name)){
   // Inspect a script/iframe source attribute, then skip inert/raw text bodies.
   const close=lower.indexOf('</'+name,cursor);if(close<0){limited=true;break;}
   const closeEnd=body.indexOf('>',close);if(closeEnd<0){limited=true;break;}cursor=closeEnd+1;
  }
  if(!['script','img','iframe','link','audio','video','source','form'].includes(name))continue;
  const attrs=new Map();let pos=opening[0].length;const text=tag.slice(0,-1);
  while(pos<text.length){while(/\s|\//.test(text[pos]||'')&&pos<text.length)pos++;if(pos>=text.length)break;const attrStart=pos;while(pos<text.length&&!/[\s=/>]/.test(text[pos]))pos++;if(pos===attrStart){limited=true;break;}const attrName=text.slice(attrStart,pos).toLowerCase();while(/\s/.test(text[pos]||'')&&pos<text.length)pos++;let value='';if(text[pos]==='='){pos++;while(/\s/.test(text[pos]||'')&&pos<text.length)pos++;const q=text[pos];if(q==='"'||q==="'"){pos++;const close=text.indexOf(q,pos);if(close<0){limited=true;break;}value=text.slice(pos,close);pos=close+1;}else{const valueStart=pos;while(pos<text.length&&!/\s/.test(text[pos]))pos++;value=text.slice(valueStart,pos);}}if(attrs.has(attrName)){limited=true;break;}attrs.set(attrName,value);}
  if(limited)break;
  if(name==='link'&&!/(?:^|\s)(stylesheet|preload|modulepreload)(?:\s|$)/i.test(attrs.get('rel')||''))continue;
  const values=name==='form'?[attrs.get('action')]:[attrs.get('src'),...(name==='link'?[attrs.get('href')]:[]),attrs.get('srcset')];
  if(values.some(value=>value&&/(?:^|[,\s])http:\/\//i.test(value))){if(name==='form')forms.push('Form action uses http:// (URL redacted).');else mixed.push(`${name} resource uses http:// (URL redacted).`);}
 }
 const make=(id,title,items,priority,why,fix)=>finding(id,items.length?title:limited?'Static HTML check incomplete':id==='mixed-content'?'No HTTP resource references in sampled markup':'No HTTP form actions in sampled markup','content',items.length?'action':limited?'unknown':'pass',items.length?priority:'info',items.length?items.slice(0,12):[limited?'Markup was malformed, contained a template, or exceeded the bounded parser budget.':'No explicit HTTP references found in the supported static attributes.'],why+' This bounded token inspection skips raw-text bodies; it does not execute JavaScript, expand templates, decode entity-obfuscated URLs, or inspect CSS.',''+fix);
 return [make('mixed-content','HTTP resource references found',mixed,'medium','Static attribute references are not proof of a browser request.','Use HTTPS resource URLs; confirm behavior in browser developer tools.'),make('insecure-forms','HTTP form action reference found',forms,'high','A real HTTP form action can expose submitted data.','Change form actions to HTTPS and verify the submission endpoint.')];
}

const floors={PHP:{'8.2':'8.2.35','8.3':'8.3.36','8.4':'8.4.27','8.5':'8.5.12'},NGINX:{'1.30':'1.30.6','1.31':'1.31.7'},'Node.js':{'22':'22.23.4','24':'24.22.1','26':'26.12.1'}};
const sources={PHP:'https://www.php.net/archive/2026.php#2026-10-21-5',NGINX:'https://nginx.org/en/security_advisories.html','Node.js':'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases'};
function compareVersions(a,b){const x=a.split('.').map(Number),y=b.split('.').map(Number);for(let i=0;i<3;i++){if(x[i]!==y[i])return x[i]<y[i]?-1:1;}return 0;}
function checkBanners(headers){
 const text=[headers.server,headers['x-powered-by']].filter(Boolean).join(' ');const out=[];
 for(const [runtime,pattern] of [['PHP',/\bPHP\/(\d+\.\d+\.\d+)/i],['NGINX',/\bnginx\/(\d+\.\d+\.\d+)/i],['Node.js',/\bnode(?:\.js)?\/(\d+\.\d+\.\d+)/i]]){
 const match=text.match(pattern);if(!match)continue;const version=match[1];const branch=runtime==='Node.js'?version.split('.')[0]:version.split('.').slice(0,2).join('.');const floor=floors[runtime][branch];const below=floor&&compareVersions(version,floor)<0;
 const f=finding('banner-'+runtime,below?`${runtime} banner is below an advisory patch floor`:`${runtime} version banner needs runtime verification`,'advisory',below?'action':'unknown',below?'medium':'info',[`Unverified response banner advertises ${runtime} ${version}.`,floor?`October 2026 advisory patch floor for branch: ${floor}.`:'This runtime branch is outside the bundled comparison rules.'],'Headers can be stale, spoofed, or maintained with vendor backports. This does not confirm a CVE or reveal all backend deployments.','Verify the actual running binary and vendor patch status across every production instance.',sources[runtime]);f.confidence='inferred';out.push(f);
 }return out;
}

// ==== backend/scan.mjs (verbatim) ====

async function scanWebsite(input,{signal,onProgress}={}){return runScan(input,{signal,onProgress});}
// Explicit dependency injection is confined to this test entrypoint; HTTP API
// calls scanWebsite and cannot select DNS or transport implementations.
async function runScan(input,{signal,onProgress,resolve,request}={}){
 const target=validateUrl(input).href;const start=Date.now();const startedAt=new Date(start).toISOString();const requests=[];const findings=[];let finalUrl=target,tls,status='complete',htmlChecked=false;
 const deadline=AbortSignal.timeout(LIMITS.duration);const combined=signal?AbortSignal.any([signal,deadline]):deadline;
 const notify=message=>{try{onProgress?.(message);}catch{}};
 const fetch=createFetcher({resolve,request,signal:combined,onRequest:entry=>requests.push(entry)});
 try{
  notify('Resolving public destination and inspecting response');
  // Race DNS too: a hung resolver must not exceed the overall scan deadline.
  const abortable=promise=>new Promise((accept,reject)=>{const abort=()=>reject(combined.reason);combined.addEventListener('abort',abort,{once:true});promise.then(value=>{combined.removeEventListener('abort',abort);accept(value);},error=>{combined.removeEventListener('abort',abort);reject(error);});if(combined.aborted)abort();});
  const response=await abortable(fetch(target));finalUrl=response.url;tls=response.tls;
  const secure=new URL(finalUrl).protocol==='https:';
  findings.push(finding('transport',secure?'HTTPS connection established':'Page served over HTTP','transport',secure?'pass':'action',secure?'info':'high',[`Final response: ${response.status} over ${secure?'HTTPS':'HTTP'}.`,...(tls?[`TLS protocol: ${tls.protocol}; certificate issuer: ${tls.issuer}; expires: ${tls.validTo}.`]:[])],'HTTPS protects traffic in transit. TLS trust and hostname checks are enforced by the HTTP client.','Serve the page over HTTPS with a valid certificate; redirect HTTP entry points to HTTPS.'));
  if(response.status>=300){status='partial';findings.push(finding('http-status','Target returned an error or unresolved redirect','transport','unknown','info',[`HTTP ${response.status}; findings describe this error response only.`],'An error page may have different security policies from the application.','Confirm the URL and repeat against an accessible application page.'));}
  findings.push(...checkHeaders(response.headers,finalUrl),...checkCookies(response.headers,finalUrl),...checkBanners(response.headers));
  const encoded=response.headers['content-encoding']&&response.headers['content-encoding']!=='identity';
  if(!encoded&&/\b(?:text\/html|application\/xhtml\+xml)\b/i.test(response.headers['content-type']||'')){const content=checkContent(response.body,finalUrl);findings.push(...content);htmlChecked=content.length>0&&content.every(x=>x.status!=='unknown');}
  else findings.push(finding('content-unavailable','HTML inspection unavailable','content','unknown','info',[encoded?'Server returned an encoded body despite identity preference; decompression was intentionally skipped.':`Content-Type is ${response.headers['content-type']||'not declared'}; HTML checks skipped.`],'Only declared, uncompressed HTML is inspected.','Review the page using browser developer tools or provide a public HTML page.'));
  if(tls?.validTo){const days=Math.floor((Date.parse(tls.validTo)-Date.now())/86400000);findings.push(finding('certificate-expiry',days<14?'TLS certificate expires soon':'TLS certificate expiry observed','transport',days<14?'action':'pass',days<14?'medium':'info',[`Certificate expires ${tls.validTo} (${days} days remaining).`],'A certificate close to expiration can cause availability problems.','Verify automated certificate renewal and deployment.'));}
  if(secure){
   notify('Checking HTTP entry-point redirect');const httpUrl=new URL(target);httpUrl.protocol='http:';httpUrl.port='';
   try{const probe=await abortable(fetch(httpUrl.href));const upgraded=new URL(probe.url).protocol==='https:';if(probe.status>=300){status='partial';findings.push(finding('http-upgrade','HTTP entry-point check inconclusive','transport','unknown','info',[`HTTP probe ended with status ${probe.status}; redirect enforcement on normal application responses is unverified.`],'Denied, error, or unresolved redirect responses do not establish normal HTTP behavior.','Verify redirect policy in deployment configuration.'));}else findings.push(finding('http-upgrade',upgraded?'HTTP entry point redirects to HTTPS':'HTTP entry point remains unencrypted','transport',upgraded?'pass':'action',upgraded?'info':'medium',[`HTTP probe ended at ${probe.url} with status ${probe.status}.`],'First-time visitors may use HTTP before HSTS has been learned.','Redirect the HTTP entry point to HTTPS.'));}catch(error){if(signal?.aborted)throw error;status='partial';findings.push(finding('http-upgrade','HTTP entry-point check inconclusive','transport','unknown','info',[safeError(error)],'A timeout, denied connection, redirect limit, or safety rule prevented completion.','Verify HTTP redirects from your deployment configuration.'));}
  }
 }catch(error){if(signal?.aborted)throw error;status='partial';findings.push(finding('fetch-incomplete','Website response could not be fully inspected','transport','unknown','info',[safeError(error)],'The scan stopped before it could establish complete response observations.','Check the URL, TLS configuration, and public availability, then retry.'));}
 findings.push(finding('runtime-coverage','Backend vulnerability status remains unverified','advisory','unknown','info',['No runtime inventory, authenticated scan, source code, or deployment evidence was collected.'],'A public response cannot prove backend patch levels, absence of compromise, or the security of every route.','Collect running runtime/package versions and configuration; compare with relevant vendor advisories.'));
 const order={high:0,medium:1,low:2,info:3};findings.sort((a,b)=>order[a.priority]-order[b.priority]);
 const completedAt=new Date().toISOString();return {schemaVersion:'2.0',id:randomUUID(),target,finalUrl,startedAt,completedAt,durationMs:Date.now()-start,status,summary:{observations:findings.length,actionItems:findings.filter(x=>x.status==='action').length,passed:findings.filter(x=>x.status==='pass').length,unknown:findings.filter(x=>x.status==='unknown').length},findings,coverage:[{id:'public-response',label:'Public response',status:requests.length?'checked':'limited',detail:'Bounded GET requests, with public DNS validation and TLS trust enforcement.'},{id:'browser-policy',label:'Response headers and static HTML',status:status==='complete'&&htmlChecked?'checked':'limited',detail:'Checks apply only to the sampled response and supported HTML attributes.'},{id:'runtime',label:'Runtime CVEs and compromise',status:'not-checked',detail:'Requires deployment evidence; version banners are unverified hints.'},{id:'authenticated',label:'Authenticated routes and application logic',status:'not-checked',detail:'No login, JavaScript execution, exploit tests, or hidden-path enumeration.'}],requests,...(tls?{tls}:{}),limitations:['A passive posture check is not a penetration test or an all-clear.','Only the submitted page and bounded redirects were requested; no subresources or hidden paths were fetched.','Bundled banner comparison rules are a dated October 2026 snapshot, not a live vulnerability feed.','No credentials, cookie values, request bodies, or query parameters are accepted or retained.','JavaScript-generated content, CSS, authenticated areas and backend inventory are outside coverage.']};
}
function safeError(error){const code=error?.code;return code&&/CERT|TLS|SSL|CERTIFICATE/.test(code)?`TLS trust check failed (${code}).`:String(error?.message||'Request failed').replace(/https?:\/\/\S+/g,'[URL redacted]').slice(0,220);}

// ==== reader.mjs (verbatim) ====

const VERSION='0.4.2';
export const READER_PORTS=[4176,4177,4178,4179,4180];
const WINDOW=600000,TTL=600000,MAX_CODE_ATTEMPTS=5;
const securityHeaders={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
const errorBody=(code,message)=>({error:{code,message}});
function send(res,status,body,extra={}){if(res.writableEnded||res.destroyed)return;res.writeHead(status,{...securityHeaders,'Content-Type':'application/json; charset=utf-8',...extra});res.end(JSON.stringify(body));}
async function readJson(req){
 if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))throw Object.assign(new Error('Send application/json.'),{status:415,code:'CONTENT_TYPE'});
 let size=0;const chunks=[];
 for await(const chunk of req){size+=chunk.length;if(size>2048)throw Object.assign(new Error('Request body is limited to 2 KiB.'),{status:413,code:'BODY_LIMIT'});chunks.push(chunk);}
 try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Object.assign(new Error('Request body must be valid JSON.'),{status:400,code:'INVALID_JSON'});}
}

export function createReaderApp({scanner=scanWebsite,now=Date.now,code=''}={}){
 if(!/^[0-9a-f]{8,64}$/.test(code))throw new Error('The reader code must be 8-64 hex characters.');
 const known=Buffer.from(code);
 let attempts=MAX_CODE_ATTEMPTS,active=0,globalWindow={start:now(),count:0};
 const jobs=new Map(),targets=new Map();
 const prune=()=>{const time=now();for(const [id,job]of jobs)if(time-job.created>TTL){job.controller.abort();jobs.delete(id);}for(const [key,value]of targets)if(time-value.start>=WINDOW)targets.delete(key);};
 function consume(key,limit){const time=now();let entry=targets.get(key);if(!entry||time-entry.start>=WINDOW){entry={start:time,count:0};targets.set(key,entry);}if(entry.count>=limit)return false;entry.count++;return true;}
 const snapshot=job=>({id:job.id,status:job.status,stage:job.stage,...(job.report?{report:job.report}:{}),...(job.error?{error:job.error}:{})});
 const server=http.createServer({maxHeaderSize:8192},async(req,res)=>{
  try{
   const origin=req.headers.origin;
   if(origin)res.setHeader('Access-Control-Allow-Origin',origin);
   res.setHeader('Vary','Origin');
   res.setHeader('Access-Control-Allow-Methods','GET,POST,DELETE,OPTIONS');
   res.setHeader('Access-Control-Allow-Headers','content-type,x-scan-token,x-reader-code');
   res.setHeader('Access-Control-Max-Age','600');
   if(req.method==='OPTIONS'&&req.url?.startsWith('/api/')){res.writeHead(204);return res.end();}
   const url=new URL(req.url,'http://reader.local');
   const pinnedHost=`127.0.0.1:${server.address()?.port}`;
   if(req.headers.host!==pinnedHost)return send(res,403,errorBody('HOST_DENIED','The reader accepts loopback requests for its own host only.'));
   if(url.search)return send(res,400,errorBody('QUERY_DENIED','Reader URLs do not accept query parameters.'));
   if(url.pathname==='/api/health'&&req.method==='GET')return send(res,200,{ok:true,version:VERSION,mode:'reader'});
   const supplied=req.headers['x-reader-code'];
   const codeOk=typeof supplied==='string'&&supplied.length===code.length&&timingSafeEqual(Buffer.from(supplied),known);
   if(!codeOk){
    attempts--;
    if(attempts<=0){send(res,401,errorBody('CODE_EXHAUSTED','Too many invalid pairing attempts. Restart the reader for a fresh code.'));server.close();server.closeAllConnections();server.emit('exhausted');return;}
    return send(res,401,errorBody('CODE_REQUIRED',`A valid pairing code is required (${attempts} attempt${attempts===1?'':'s'} left).`));
   }
   if(url.pathname==='/api/scans'&&req.method==='POST'){
    prune();const body=await readJson(req);
    if(!body||typeof body!=='object'||Array.isArray(body)||typeof body.url!=='string'||body.url.length>2048||Object.keys(body).some(key=>key!=='url'))return send(res,400,errorBody('INVALID_INPUT','Provide one public website URL.'));
    let target;try{target=validateUrl(body.url);}catch(error){return send(res,400,errorBody('INVALID_URL',error.message));}
    if(active>=1)return send(res,503,errorBody('BUSY','A scan is already running. Try again shortly.'),{'Retry-After':'5'});
    if(now()-globalWindow.start>=WINDOW)globalWindow={start:now(),count:0};
    if(globalWindow.count>=50||!consume(target.hostname,4))return send(res,429,errorBody('RATE_LIMIT','Scan limit reached. Try again in ten minutes.'),{'Retry-After':'600'});
    globalWindow.count++;
    const id=randomUUID(),token=randomBytes(32).toString('hex'),controller=new AbortController();
    const job={id,token,status:'queued',stage:'Waiting for scanner',created:now(),controller};jobs.set(id,job);active++;
    send(res,201,{id,token,status:'queued'});
    const timer=setTimeout(()=>controller.abort(new Error('Scan deadline exceeded.')),30000);timer.unref();
    void Promise.resolve().then(async()=>{
     job.status='running';job.stage='Resolving public destination';
     const report=await scanner(target.href,{signal:controller.signal,onProgress:stage=>{job.stage=String(stage).slice(0,160);}});
     controller.signal.throwIfAborted();job.report={...report,id};job.status='complete';job.stage=report.status==='partial'?'Finished with coverage gaps':'Scan complete';
    }).catch(()=>{job.status='failed';job.stage='Scan stopped';job.error=errorBody(controller.signal.aborted?'CANCELLED':'SCAN_FAILED',controller.signal.aborted?'The scan was cancelled or exceeded its deadline.':'The scanner could not complete. Check the URL and try again.').error;}).finally(()=>{clearTimeout(timer);active--;});
    return;
   }
   const match=/^\/api\/scans\/([0-9a-f-]{36})$/.exec(url.pathname);
   if(match&&['GET','DELETE'].includes(req.method)){
    prune();const job=jobs.get(match[1]);if(!job)return send(res,404,errorBody('NOT_FOUND','This scan expired or does not exist.'));
    const supplied=req.headers['x-scan-token'];
    if(typeof supplied!=='string'||!/^[0-9a-f]{64}$/.test(supplied)||!timingSafeEqual(Buffer.from(supplied),Buffer.from(job.token)))return send(res,401,errorBody('TOKEN_REQUIRED','A valid scan token is required.'));
    if(req.method==='DELETE'){job.controller.abort(new Error('User cancelled'));jobs.delete(job.id);return send(res,200,{id:job.id,status:'cancelled'});}
    return send(res,200,snapshot(job));
   }
   if(url.pathname.startsWith('/api/'))return send(res,404,errorBody('NOT_FOUND','Reader route not found.'));
   return send(res,404,errorBody('NOT_FOUND','Reader route not found.'));
  }catch(error){return send(res,error.status||400,errorBody(error.code||'BAD_REQUEST',error.status?error.message:'The request could not be read.'),error.code==='BODY_LIMIT'?{'Connection':'close'}:{});}
 });
 server.requestTimeout=10000;server.headersTimeout=10000;server.timeout=15000;server.keepAliveTimeout=5000;server.maxRequestsPerSocket=100;
 const cleanup=setInterval(prune,60000);cleanup.unref();
 server.on('close',()=>{clearInterval(cleanup);for(const job of jobs.values())job.controller.abort();jobs.clear();});
 return server;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const code=randomBytes(4).toString('hex');
 const tryPort=port=>new Promise((accept,reject)=>{const s=createReaderApp({code});s.once('error',reject);s.listen(port,'127.0.0.1',()=>accept(s));});
 let server=null,port=null;
 for(const candidate of READER_PORTS){try{server=await tryPort(candidate);port=candidate;break;}catch{}}
 if(!server){console.error('Aftershock reader: no free port in 4176-4180.');process.exit(1);}
 console.log(`Aftershock reader ${VERSION} — passive public-surface scanner`);
 console.log(`Listening on http://127.0.0.1:${port}`);
 console.log(`Pairing code: ${code}`);
 console.log('Keep this window open. Paste the code into the Aftershock page once.');
 console.log('Only pair pages you opened from your aftershock.html file.');
 server.on('exhausted',()=>{console.error('Too many invalid pairing attempts. Restart the reader for a fresh code.');process.exit(1);});
 const stop=()=>server.close(()=>process.exit(0));
 process.once('SIGINT',stop);process.once('SIGTERM',stop);
}
