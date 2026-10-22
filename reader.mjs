#!/usr/bin/env node
// Aftershock reader — a local, zero-dependency companion for the single-file
// artifact. Browsers intentionally hide one site's response headers from
// another page (CORS); no HTML file can scan a live site on its own. The
// reader is the honest bridge: it runs the exact same bounded, passive
// scanner as the repository server, on loopback only, gated by a one-time
// pairing code printed at startup. Nothing is installed, logged, or sent
// anywhere: scans read public responses, then live only in memory.
import http from 'node:http';
import {randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {scanWebsite} from './backend/scan.mjs';
import {validateUrl} from './backend/safe-fetch.mjs';

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

// Test-only dependency injection mirrors server.mjs: the CLI passes the real
// scanner; tests pass a stub. The pairing code is required and hex-shaped.
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
