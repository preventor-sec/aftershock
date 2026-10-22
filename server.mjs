import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';
import {scanWebsite} from './backend/scan.mjs';
import {validateUrl} from './backend/safe-fetch.mjs';

const root=fileURLToPath(new URL('.',import.meta.url));
const assets=new Map([['/','index.html'],['/index.html','index.html'],['/styles.css','styles.css'],['/app.js','app.js'],['/data.js','data.js'],['/engine.js','engine.js']]);
const mime={html:'text/html; charset=utf-8',css:'text/css; charset=utf-8',js:'text/javascript; charset=utf-8'};
const WINDOW=600000,TTL=600000;
const securityHeaders={
 'Cache-Control':'no-store',
 'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
 'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=()'
};
const errorBody=(code,message)=>({error:{code,message}});
function send(res,status,body,extra={}){if(res.writableEnded||res.destroyed)return;res.writeHead(status,{...securityHeaders,'Content-Type':'application/json; charset=utf-8',...extra});res.end(JSON.stringify(body));}
function tokenMatches(actual,expected){if(typeof actual!=='string'||!/^[0-9a-f]{64}$/.test(actual))return false;const supplied=Buffer.from(actual),known=Buffer.from(expected);return supplied.length===known.length&&timingSafeEqual(supplied,known);}
async function readJson(req){
 if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))throw Object.assign(new Error('Send application/json.'),{status:415,code:'CONTENT_TYPE'});
 const declared=Number(req.headers['content-length']||0);if(!Number.isFinite(declared)||declared>2048)throw Object.assign(new Error('Request body is limited to 2 KiB.'),{status:413,code:'BODY_LIMIT'});
 const chunks=[];let size=0;
 for await(const chunk of req.iterator({destroyOnReturn:false})){size+=chunk.length;if(size>2048)throw Object.assign(new Error('Request body is limited to 2 KiB.'),{status:413,code:'BODY_LIMIT'});chunks.push(chunk);}
 try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Object.assign(new Error('Request body must be valid JSON.'),{status:400,code:'INVALID_JSON'});}
}

// Test-only dependency injection is not exposed through the HTTP API.
export function createApp({scanner=scanWebsite,publicOrigin='',now=Date.now,maxConcurrent=2}={}){
 let configured;
 if(publicOrigin){configured=new URL(publicOrigin);if(configured.protocol!=='https:'||configured.origin!==publicOrigin||configured.username||configured.password)throw new Error('PUBLIC_ORIGIN must be an HTTPS origin with no path or trailing slash.');}
 const jobs=new Map(),clients=new Map(),targets=new Map();let active=0,globalWindow={start:now(),count:0};
 const prune=()=>{const time=now();for(const [id,job]of jobs)if(time-job.created>TTL){job.controller.abort();jobs.delete(id);}for(const map of [clients,targets])for(const [key,value]of map)if(time-value.start>=WINDOW)map.delete(key);};
 function consume(map,key,limit){const time=now();let entry=map.get(key);if(!entry||time-entry.start>=WINDOW){entry={start:time,count:0};map.set(key,entry);}if(entry.count>=limit)return false;entry.count++;return true;}
 function snapshot(job){return {id:job.id,status:job.status,stage:job.stage,...(job.report?{report:job.report}:{}),...(job.error?{error:job.error}:{})};}
 const server=http.createServer({maxHeaderSize:8192},async(req,res)=>{
  try{
   const port=server.address()?.port;
   const origins=new Set([`http://localhost:${port}`,`http://127.0.0.1:${port}`,`http://[::1]:${port}`,...(configured?[configured.origin]:[])]);
   const hosts=new Set([...origins].map(value=>new URL(value).host));
   if(!hosts.has(req.headers.host))return send(res,403,errorBody('HOST_DENIED','This Host is not configured for Aftershock.'));
   if(req.headers.origin&&!origins.has(req.headers.origin))return send(res,403,errorBody('ORIGIN_DENIED','Cross-origin requests are not accepted.'));
   if(req.headers['sec-fetch-site']==='cross-site'&&req.url?.startsWith('/api/'))return send(res,403,errorBody('ORIGIN_DENIED','Cross-site API requests are not accepted.'));
   const url=new URL(req.url,'http://local');
   if(url.search)return send(res,400,errorBody('QUERY_DENIED','API and asset URLs do not accept query parameters.'));
   if(url.pathname==='/api/health'&&req.method==='GET')return send(res,200,{ok:true,version:'0.3.0',mode:'passive-public-url'});
   if(url.pathname==='/api/scans'&&req.method==='POST'){
    prune();const body=await readJson(req);
    if(!body||typeof body!=='object'||Array.isArray(body)||typeof body.url!=='string'||body.url.length>2048||Object.keys(body).some(key=>key!=='url'))return send(res,400,errorBody('INVALID_INPUT','Provide one public website URL.'));
    let target;try{target=validateUrl(body.url);}catch(error){return send(res,400,errorBody('INVALID_URL',error.message));}
    if(active>=maxConcurrent)return send(res,503,errorBody('BUSY','Both scan slots are in use. Try again shortly.'),{'Retry-After':'10'});
    if(jobs.size>=100||clients.size>=256&&!clients.has(req.socket.remoteAddress))return send(res,503,errorBody('BUSY','The scanner is at capacity. Try again shortly.'),{'Retry-After':'60'});
    if(now()-globalWindow.start>=WINDOW)globalWindow={start:now(),count:0};
    if(globalWindow.count>=50||!consume(clients,req.socket.remoteAddress,8)||!consume(targets,target.hostname,4))return send(res,429,errorBody('RATE_LIMIT','Scan limit reached. Try again in ten minutes.'),{'Retry-After':'600'});
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
    if(!tokenMatches(req.headers['x-scan-token'],job.token))return send(res,401,errorBody('TOKEN_REQUIRED','A valid scan token is required.'));
    if(req.method==='DELETE'){job.controller.abort(new Error('User cancelled'));jobs.delete(job.id);return send(res,200,{id:job.id,status:'cancelled'});}
    return send(res,200,snapshot(job));
   }
   if(url.pathname.startsWith('/api/'))return send(res,404,errorBody('NOT_FOUND','API route not found.'));
   if(['GET','HEAD'].includes(req.method)&&assets.has(url.pathname)){
    const asset=assets.get(url.pathname);const content=await readFile(resolve(root,asset));res.writeHead(200,{...securityHeaders,'Content-Type':mime[asset.split('.').pop()],'Content-Length':content.length});res.end(req.method==='HEAD'?undefined:content);return;
   }
   return send(res,404,errorBody('NOT_FOUND','Page not found.'));
  }catch(error){return send(res,error.status||400,errorBody(error.code||'BAD_REQUEST',error.status?error.message:'The request could not be read.'),error.code==='BODY_LIMIT'?{'Connection':'close'}:{});}
 });
 server.requestTimeout=10000;server.headersTimeout=10000;server.timeout=15000;server.keepAliveTimeout=5000;server.maxRequestsPerSocket=100;
 const cleanup=setInterval(prune,60000);cleanup.unref();
 server.on('close',()=>{clearInterval(cleanup);for(const job of jobs.values())job.controller.abort();jobs.clear();});
 return server;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const host=process.env.HOST||'127.0.0.1',port=Number(process.env.PORT||4175),publicOrigin=process.env.PUBLIC_ORIGIN||'';
 if(!Number.isInteger(port)||port<1||port>65535)throw new Error('PORT must be 1–65535.');
 if(!['127.0.0.1','::1','localhost'].includes(host)&&!publicOrigin)throw new Error('Set PUBLIC_ORIGIN before binding to a non-loopback interface.');
 const app=createApp({publicOrigin});app.listen(port,host,()=>console.log(`Aftershock ready at http://${host==='::1'?'[::1]':host}:${port}`));
 const stop=()=>{app.close();app.closeAllConnections();};process.once('SIGINT',stop);process.once('SIGTERM',stop);
}
