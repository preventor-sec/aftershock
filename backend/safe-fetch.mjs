import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import {isIP} from 'node:net';

export const LIMITS={requests:6,redirects:3,bytes:1048576,timeout:8000,duration:25000};
export function isPublicIP(address){
 const family=isIP(address); if(!family)return false;
 if(family===4){const [a,b,c]=address.split('.').map(Number);return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0||b===2||b===88&&c===99)||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19||b===51&&c===100)||a===203&&b===0&&c===113);}
 // Only globally routable unicast 2000::/3; exclude documentation, transition,
 // mapped IPv4, ORCHID and special-purpose blocks rather than decode gateways.
 const normalized=address.toLowerCase();
 if(!/^[23][0-9a-f]{0,3}:/.test(normalized))return false;
 const first=parseInt(normalized.split(':')[0],16), second=parseInt(normalized.split(':')[1]||'0',16);
 return first>=0x2000&&first<=0x3fff&&!(first===0x2001&&(second<=0x1ff||second===0xdb8)||first===0x2002||first===0x3fff);
}
export function validateUrl(input){
 const value=new URL(input);
 if(!['http:','https:'].includes(value.protocol))throw new Error('Only HTTP and HTTPS URLs are supported.');
 if(value.username||value.password)throw new Error('URLs with credentials are not supported.');
 if(value.port && value.port!==(value.protocol==='https:'?'443':'80'))throw new Error('Only standard web ports are supported.');
 const host=value.hostname.toLowerCase().replace(/\.$/,'');
 if(isIP(host.replace(/^\[|\]$/g,''))||!host.includes('.')||/(?:^|\.)(?:localhost|local|internal|test|invalid|onion|home|lan|arpa)$/.test(host))throw new Error('Enter a public DNS website hostname.');
 if(value.search)throw new Error('Remove query parameters before scanning; URLs may contain private tokens.');
 value.hash='';return value;
}
export async function resolvePublic(hostname,resolve=dns.lookup){
 const addresses=await resolve(hostname,{all:true,verbatim:true});
 if(!addresses.length||addresses.some(x=>!isPublicIP(x.address)))throw new Error('Destination DNS includes a private or reserved address.');
 return addresses[0];
}
export function requestPinned(url,address,{signal,timeout=LIMITS.timeout,maxBytes=LIMITS.bytes}={}){
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
export function createFetcher({resolve=dns.lookup,request=requestPinned,signal,budget={count:0},onRequest=()=>{}}={}){
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
