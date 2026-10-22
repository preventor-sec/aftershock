import {createHash} from 'node:crypto';
const mdn='https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/';
const finding=(id,title,category,status,priority,evidence,why,fix,source)=>({id,title,category,status,priority,confidence:status==='unknown'?'unknown':'observed',evidence,why,fix,...(source?{source}:{})});
export function checkHeaders(headers,url){
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
export function checkCookies(headers,url){
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
export function checkContent(body,url){
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
export function compareVersions(a,b){const x=a.split('.').map(Number),y=b.split('.').map(Number);for(let i=0;i<3;i++){if(x[i]!==y[i])return x[i]<y[i]?-1:1;}return 0;}
export function checkBanners(headers){
 const text=[headers.server,headers['x-powered-by']].filter(Boolean).join(' ');const out=[];
 for(const [runtime,pattern] of [['PHP',/\bPHP\/(\d+\.\d+\.\d+)/i],['NGINX',/\bnginx\/(\d+\.\d+\.\d+)/i],['Node.js',/\bnode(?:\.js)?\/(\d+\.\d+\.\d+)/i]]){
 const match=text.match(pattern);if(!match)continue;const version=match[1];const branch=runtime==='Node.js'?version.split('.')[0]:version.split('.').slice(0,2).join('.');const floor=floors[runtime][branch];const below=floor&&compareVersions(version,floor)<0;
 const f=finding('banner-'+runtime,below?`${runtime} banner is below an advisory patch floor`:`${runtime} version banner needs runtime verification`,'advisory',below?'action':'unknown',below?'medium':'info',[`Unverified response banner advertises ${runtime} ${version}.`,floor?`October 2026 advisory patch floor for branch: ${floor}.`:'This runtime branch is outside the bundled comparison rules.'],'Headers can be stale, spoofed, or maintained with vendor backports. This does not confirm a CVE or reveal all backend deployments.','Verify the actual running binary and vendor patch status across every production instance.',sources[runtime]);f.confidence='inferred';out.push(f);
 }return out;
}
export {finding};
