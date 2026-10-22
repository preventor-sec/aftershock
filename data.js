'use strict';
window.AftershockData = (() => {
 const snapshot='2026-10-22';
 const advisories=[
  {id:'php-oct26',runtime:'PHP',title:'PHP request handling RCE',severity:'Critical',date:'2026-10-21',source:'https://www.php.net/archive/2026.php#2026-10-21-5',summary:'Two critical issues affect web-serving PHP installations. The running process matters, not just the installed package.',floors:{'8.2':'8.2.35','8.3':'8.3.36','8.4':'8.4.27','8.5':'8.5.12'}},
  {id:'node-oct26',runtime:'Node.js',title:'Node.js October security release',severity:'High',date:'2026-10-21',source:'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',summary:'Runtime fixes include Brotli memory safety and certificate validation issues. Scope varies by issue.',floors:{'22':'22.23.4','24':'24.22.1','26':'26.12.1'}},
  {id:'nginx-oct26',runtime:'NGINX',title:'NGINX protocol and memory-safety fixes',severity:'Medium',date:'2026-10-14',source:'https://nginx.org/en/security_advisories.html',summary:'Configuration-dependent issues include HTTP/3, TLS and AIO paths. A version match is a reason to investigate, not proof of exploitability.',floors:{'1.30':'1.30.6','1.31':'1.31.7'}},
  {id:'drupal-field-ui',runtime:'Drupal',title:'Drupal Field UI remote code execution',severity:'Critical',date:'2026-10-14',source:'https://www.drupal.org/sa-core-2026-014',summary:'Core alone is not directly exploitable; contributed or custom modules can expose a vulnerable path. Field UI configuration matters.',floors:{'10.6':'10.6.19','11.3':'11.3.19','11.4':'11.4.10'}},
  {id:'go-trust',runtime:'Go',title:'Go certificate trust update',severity:'Review',date:'2026-10-21',source:'https://pkg.go.dev/vuln/GO-2026-6809',summary:'crypto/x509 adds a denylist for intermediate certificates that are no longer trustworthy. Rebuild affected Go binaries.',floors:{'1.26':'1.26.10','1.27':'1.27.3'}},
  {id:'hermes-session',runtime:'Hermes Agent',title:'Hermes Agent session takeover',severity:'High',date:'2026-10-09',source:'https://www.tenable.com/security/research/tra-2026-65',summary:'Redirect-URI parser disagreement can expose an authorization code during login. The same release also addresses resource exhaustion.',floors:{'0.21':'0.21.6'}},
  {id:'langchain-mongo',runtime:'@langchain/mongodb',title:'MongoDB chat history injection',severity:'Review',date:'2026-10-05',source:'https://github.com/langchain-ai/langchainjs/security/advisories/GHSA-m6rx-h84q-8r95',summary:'Untrusted structured session IDs can become query conditions and expose other users’ chat history.',floors:{'1.3':'1.3.1'}}
 ];
 const item=(id,name,runtime,version,revision)=>({id,name,runtime,version,environment:'production',revision,collectedAt:'2026-10-22T08:00:00Z',source:'Illustrative deployment export',config:{}});
 const exampleBefore={schemaVersion:'1.0',target:'https://example.com',capturedAt:'2026-10-22T08:00:00Z',components:[item('api','Public API','PHP','8.3.35','release-142'),item('worker','Queue worker','PHP','8.3.35','release-142'),item('renderer','Web renderer','Node.js','24.22.0','release-142'),item('payments','Payments service','Go','1.27.2','release-142'),item('edge','Edge proxy','NGINX','1.30.5','edge-19')]};
 const exampleAfter=JSON.parse(JSON.stringify(exampleBefore));exampleAfter.capturedAt='2026-10-22T09:00:00Z';
 const updates={api:'8.3.36',renderer:'24.22.1',payments:'1.27.3',edge:'1.30.6'};
 for(const c of exampleAfter.components){c.collectedAt=exampleAfter.capturedAt;if(updates[c.id]){c.version=updates[c.id];c.revision=c.id==='edge'?'edge-20':'release-143';}}
 return {snapshot,advisories,exampleBefore,exampleAfter};
})();
