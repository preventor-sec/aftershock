// Patch app.js: add Aftershock reader support. Idempotent-ish; run once.
import {readFileSync,writeFileSync} from 'node:fs';
let src=readFileSync('app.js','utf8');
const fail=m=>{console.error('PATCH FAIL:',m);process.exit(1);};

// --- 1) api() -> reader-aware
const oldApi="async function api(path,options={}){let response;try{response=await fetch(path,options);}catch(e){if(e.name==='AbortError')throw e;throw new Error('The scan server is unavailable. Start this app with npm start, then open its local URL.');}let data;try{data=await response.json();}catch{throw new Error('The scan API did not return JSON. Run npm start and open the server URL.');}if(!response.ok)throw new Error(data.error?.message||data.message||`Scan request failed (${response.status}).`);return data;}";
if(!src.includes(oldApi))fail('api anchor');
const newApi=`const READER={base:null,code:null,checked:false,
 async discover(){if(this.checked)return this.base;this.checked=true;
  for(const port of [4176,4177,4178,4179,4180]){try{
   const probe=await fetch('http://127.0.0.1:'+port+'/api/health',{cache:'no-store'});
   const info=await probe.json();
   if(info&&info.ok&&info.mode==='reader'){this.base='http://127.0.0.1:'+port;break;}
  }catch(e){}}
  return this.base;},
 save(){try{sessionStorage.setItem('aftershock.reader',JSON.stringify({base:this.base,code:this.code}));}catch(e){}},
 load(){try{const saved=JSON.parse(sessionStorage.getItem('aftershock.reader')||'null');if(saved&&saved.base&&saved.code){this.base=saved.base;this.code=saved.code;this.checked=true;}}catch(e){}}};
READER.load();
async function api(path,options={}){let response;try{response=await fetch(path,options);}catch(e){if(e.name==='AbortError')throw e;
 const reader=await READER.discover();
 if(!reader)throw new Error('No scanner reachable. Choose one: run npm start in the repository, or start the Aftershock reader (node reader.mjs) and enter its pairing code. The example report works without it.');
 try{response=await fetch(reader+path,options);}catch(e2){if(e2.name==='AbortError')throw e2;throw new Error('The reader stopped responding. Check the reader window, then retry.');}
 }
 let data;try{data=await response.json();}catch{throw new Error('The scan API did not return JSON. Run npm start or the Aftershock reader, then retry.');}
 if(!response.ok){const code=data&&data.error&&data.error.code;
  if(code==='CODE_REQUIRED'||code==='CODE_EXHAUSTED'){READER.code=null;const err=new Error((data.error&&data.error.message)||'A pairing code is required.');err.name='CodeRequired';throw err;}
  throw new Error(data&&data.error&&data.error.message||data&&data.message||('Scan request failed ('+response.status+').'));}
 return data;}`;
src=src.replace(oldApi,newApi);

// --- 2) file:// guards -> reader-aware
const oldFile1="if(location.protocol==='file:'){$('target-error').textContent='Live scanning needs the local server. Run npm start in the project folder, then open the printed localhost URL.';";
if(!src.includes(oldFile1))fail('file guard 1');
// The scan() guard returns early on file://, blocking reader scans. Replace with reader-aware flow.
src=src.replace(oldFile1,"if(location.protocol==='file:'&&!READER.base){READER.discover().then(async reader=>{if(!reader){$('target-error').textContent='Live scans need the Aftershock reader running on this device. The example works without it.';return;}$('target-error').textContent='Reader detected. Enter your URL and scan.';});}");
const oldFile2="if(location.protocol==='file:')$('target-error').textContent='Live scanning needs the local server. Run npm start, then open the printed localhost URL. The example works here.';";
if(!src.includes(oldFile2))fail('file guard 2');
const newFile2="if(location.protocol==='file:')READER.discover().then(reader=>{$('target-error').textContent=reader?'Aftershock reader detected on this device. Enter a URL and scan; you will be asked for its one-time pairing code.':'This file works alone for the example report. For live scans, start the Aftershock reader (node reader.mjs) and pair it, or run the repository server with npm start.';});";
src=src.replace(oldFile2,newFile2);

// --- 3) POST /api/scans includes pairing code
const oldPost="const created=await api('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url}),signal});";
if(!src.includes(oldPost))fail('post anchor');
const newPost="const created=await api('/api/scans',{method:'POST',headers:{'Content-Type':'application/json',...(READER.code?{'X-Reader-Code':READER.code}:{})},body:JSON.stringify({url}),signal});";
src=src.replace(oldPost,newPost);

// --- 4) GET status also carries the pairing code (reader requires it on every request)
const oldGet="const state=await api(`/api/scans/${encodeURIComponent(job.id)}`,{headers:{'X-Scan-Token':job.token},signal});";
if(!src.includes(oldGet))fail('get anchor');
const newGet="const state=await api(`/api/scans/${encodeURIComponent(job.id)}`,{headers:{'X-Scan-Token':job.token,...(READER.code?{'X-Reader-Code':READER.code}:{})},signal});";
src=src.replace(oldGet,newGet);

// --- 5) catch -> pairing-code retry flow
const oldCatch="catch(e){if(generation===sequence&&e.name!=='AbortError')$('target-error').textContent=e.message;}";
if(!src.includes(oldCatch))fail('catch anchor');
const newCatch=`catch(e){
 if(generation!==sequence||e.name==='AbortError')return;
 if(e.name==='CodeRequired'){
  const code=await askReaderCode();
  if(code){READER.code=code;READER.save();return scan(url,recheck);}
  $('target-error').textContent='A pairing code is needed for live scans with the reader.';
 }else $('target-error').textContent=e.message;}`;
src=src.replace(oldCatch,newCatch);

// --- 6) askReaderCode() + reader download button handler, inserted before the file: guard
const anchor="if(location.protocol==='file:')READER.discover()";
if(!src.includes(anchor))fail('ask anchor');
const askFn=`async function askReaderCode(){
 return new Promise(resolve=>{
  openDialog('PAIR THE READER','Almost there. One honest code.','<p style="font-size:12px;color:#b5b5ad;line-height:1.8">The Aftershock reader printed a one-time pairing code when it started. Paste it below to let this page use the scanner on this device. The code stays in this browser session only.</p><p style="font:11px var(--mono);color:#dcdcd2;margin:20px 0 8px">PAIRING CODE FROM THE READER WINDOW</p><input id="reader-code-input" autocomplete="off" spellcheck="false" style="width:250px;background:#111;border:1px solid #333;border-radius:9px;padding:13px 15px;color:#e2e2de;font:14px var(--mono);letter-spacing:2px" placeholder="8-character hex code" maxlength="64"><div style="margin-top:24px;display:flex;gap:14px;align-items:center"><button class="pill small primary" id="reader-code-accept">Pair ↗</button><span style="font-size:10px;color:#8f8f83">The reader stops after 5 wrong attempts.</span></div><p style="font-size:10px;color:#7c7c74;margin-top:16px">Only pair a page you opened from your own aftershock.html file.</p>');
  const input=$('reader-code-input');input.focus();
  const done=()=>{const v=String(input.value||'').trim().toLowerCase();if(!/^[0-9a-f]{8,64}$/.test(v)){$('target-error').textContent='The pairing code is 8 to 64 hex characters.';return;}$('details-dialog').close();resolve(v);};
  input.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();done();}});
  $('reader-code-accept').addEventListener('click',done);
 });}
`;
src=src.replace(anchor,askFn+anchor);

writeFileSync('app.js',src);
console.log('PATCHED app.js —',src.length,'bytes');
