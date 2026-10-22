/* UI fixture tests: intercepted responses exercise the frontend, not the scanner. */
'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..');
const fixture=(status='action')=>({schemaVersion:'2.0',id:`fixture-${status}`,target:'https://example.com',finalUrl:'https://example.com',startedAt:'2026-10-22T08:00:00Z',completedAt:'2026-10-22T08:00:02Z',durationMs:2000,status:'complete',summary:{observations:1,actionItems:status==='action'?1:0,passed:status==='pass'?1:0,unknown:status==='unknown'?1:0},findings:[{id:'header-hsts',title:'Fixture HSTS check',category:'configuration',status,priority:'medium',confidence:status==='unknown'?'unknown':'observed',evidence:['Fixture response header only.'],why:'Fixture explanation.',fix:'Fixture fix.',source:'https://developer.mozilla.org/'}],coverage:[{id:'headers',label:'Headers',status:'checked',detail:'Fixture coverage.'}],requests:[{url:'https://example.com',status:200,bytes:100}],limitations:['Fixture only. No live target was scanned.']});
(async()=>{
 const browserServer=await chromium.launchServer({headless:true,timeout:20000,...(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{})});
 const browser=await chromium.connect(browserServer.wsEndpoint(),{timeout:10000});
 const context=await browser.newContext({viewport:{width:1440,height:1100}});
 const page=await context.newPage();let mode='complete',scanCount=0,cancelCount=0,postCount=0;const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('http://aftershock.test/**',async route=>{
  const req=route.request(),u=new URL(req.url());
  const json=(status,body)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
  if(u.pathname==='/api/scans'&&req.method()==='POST'){
   postCount++;assert.equal(req.postDataJSON().url,'https://example.com');if(mode==='error')return json(400,{error:{code:'INVALID_TARGET',message:'Fixture target rejected.'}});
   scanCount++;return json(201,{id:`fixture-${scanCount}`,token:'fixture-token',status:'queued'});
  }
  if(u.pathname.startsWith('/api/scans/')){
   assert.equal(req.headers()['x-scan-token'],'fixture-token');
   if(req.method()==='DELETE'){cancelCount++;return json(200,{status:'cancelled'});}
   if(mode==='running')return json(200,{id:'fixture-running',status:'running',stage:'Fixture response inspection…'});
   const report=fixture(mode==='unknown'?'unknown':['partial-pass','redirect-pass','http-error-pass','valid-pass'].includes(mode)?'pass':'action');
   report.completedAt=`2026-10-22T08:${String(scanCount).padStart(2,'0')}:02Z`;
   if(mode==='partial-pass')report.status='partial';
   if(mode==='redirect-pass'){report.finalUrl='https://example.com/challenge';report.requests[0].url=report.finalUrl;}
   if(mode==='http-error-pass')report.requests[0].status=503;
   return json(200,{id:`fixture-${scanCount}`,status:'complete',stage:'Complete',report});
  }
  const relative=u.pathname==='/'?'index.html':u.pathname.slice(1),filename=path.resolve(root,relative);
  if(!filename.startsWith(root+path.sep)&&filename!==path.join(root,'index.html'))return route.fulfill({status:404,body:'Not found'});
  if(!fs.existsSync(filename)||!fs.statSync(filename).isFile())return route.fulfill({status:404,body:'Not found'});
  return route.fulfill({status:200,contentType:filename.endsWith('.html')?'text/html':filename.endsWith('.css')?'text/css':'text/javascript',body:fs.readFileSync(filename)});
 });
 try{
  await page.goto('http://aftershock.test/');
  await page.locator('#sample-button').click();
  await page.locator('#workbench').waitFor({state:'visible'});
  assert.match(await page.locator('#evidence-badge').innerText(),/SAMPLE/);assert.equal(postCount,0,'Sample must not call scan API');
  await page.locator('#target').fill('example.com');await page.locator('#target-form').evaluate(f=>f.requestSubmit());
  await page.waitForFunction(()=>document.querySelector('#evidence-badge').textContent==='PUBLIC RESPONSE CHECK');
  assert.equal(postCount,1);assert.match(await page.locator('#findings-list').innerText(),/Fixture HSTS check/);
  await page.locator('#findings-list [data-finding]').click();assert.match(await page.locator('#dialog-body').innerText(),/Fixture response header only/);await page.locator('#dialog-close').click();
  mode='unknown';await page.locator('#verify-tab').click();await page.locator('#rescan-button').click();
  await page.waitForFunction(()=>document.querySelector('#compare-results').textContent.includes('Unresolved'));
  assert.match(await page.locator('#compare-results').innerText(),/0 observed improvements/);assert.equal(postCount,2);
  await page.locator('#export-button').click();const exported=JSON.parse(await page.locator('#export-json').inputValue());assert.equal(exported.comparison.changes[0].state,'unresolved');await page.locator('#dialog-close').click();
  for(const nextMode of ['partial-pass','redirect-pass','http-error-pass']){
   mode='complete';await page.locator('#target-form').evaluate(f=>f.requestSubmit());await page.waitForFunction(()=>!document.querySelector('#scan-button').disabled);
   mode=nextMode;await page.locator('#verify-tab').click();await page.locator('#rescan-button').click();await page.waitForFunction(()=>!document.querySelector('#scan-button').disabled);
   assert.match(await page.locator('#compare-results').innerText(),/0 observed improvements/);assert.match(await page.locator('#compare-results').innerText(),/Unresolved/);
  }
  mode='complete';await page.locator('#target-form').evaluate(f=>f.requestSubmit());await page.waitForFunction(()=>!document.querySelector('#scan-button').disabled);
  mode='valid-pass';await page.locator('#verify-tab').click();await page.locator('#rescan-button').click();await page.waitForFunction(()=>!document.querySelector('#scan-button').disabled);assert.match(await page.locator('#compare-results').innerText(),/1 observed improvement/);
  mode='running';await page.locator('#target-form').evaluate(f=>f.requestSubmit());await page.waitForFunction(()=>document.querySelector('#scan-stage').textContent.includes('Fixture response inspection'));
  await page.locator('#cancel-scan').click();await page.waitForFunction(()=>document.querySelector('#target-error').textContent==='Scan cancelled.');
  await new Promise(resolve=>setTimeout(resolve,100));assert.equal(cancelCount,1);assert.equal(await page.locator('#scan-state').isVisible(),false);
  mode='error';await page.locator('#target-form').evaluate(f=>f.requestSubmit());await page.waitForFunction(()=>document.querySelector('#target-error').textContent.includes('Fixture target rejected'));
  assert.equal(await page.locator('#scan-button').isEnabled(),true);
  await page.setViewportSize({width:390,height:844});await page.locator('#sample-button').click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Mobile page should not overflow');
  assert.deepEqual(errors,[]);console.log('PASS: UI fixture tests (sample, bare-domain API report, evidence, rescan unknown/partial/redirect/error and valid improvement, export, cancel, API error, mobile). No live scan tested.');
 }finally{
  // Only this test's owned BrowserServer can be terminated by this fallback.
  // context.close()/browser.close() occasionally hang on Windows after route tests.
  let timer;
  const graceful=Promise.resolve().then(()=>browser.close()).then(()=>browserServer.close());
  const closed=await Promise.race([graceful.then(()=>true,()=>false),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),5000);})]);
  clearTimeout(timer);
  if(!closed){console.warn('Owned test browser did not close within 5s; terminating its BrowserServer.');await browserServer.kill();}
 }
})().catch(error=>{console.error(error);process.exitCode=1;});
