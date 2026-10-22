// Build the single-file aftershock.html artifact.
// Inlines styles.css, data.js, app.js; embeds aftershock-reader.mjs as base64
// with its SHA-256; wires the download button. One file in, whole tool out.
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const html=readFileSync('index.html','utf8');
const css=readFileSync('styles.css','utf8');
const data=readFileSync('data.js','utf8');
const app=readFileSync('app.js','utf8');
const reader=readFileSync('aftershock-reader.mjs','utf8');
for(const [name,src] of [['data.js',data],['app.js',app]]){
 if(src.includes('</script'))throw new Error(name+' contains </script — cannot inline');
}
const readerB64=Buffer.from(reader,'utf8').toString('base64');
const sha256=createHash('sha256').update(reader).digest('hex');

const downloadScript=`<script>
window.AFTERSHOCK_READER_B64="${readerB64}";
window.AFTERSHOCK_READER_SHA256="${sha256}";
(function(){
 var b=document.getElementById('download-reader');
 if(!b)return;
 b.addEventListener('click',function(){
  try{
   var bytes=Uint8Array.from(atob(window.AFTERSHOCK_READER_B64),function(c){return c.charCodeAt(0);});
   var blob=new Blob([bytes],{type:'text/javascript'});
   var url=URL.createObjectURL(blob);
   var a=document.createElement('a');a.href=url;a.download='aftershock-reader.mjs';
   document.body.appendChild(a);a.click();a.remove();
   setTimeout(function(){URL.revokeObjectURL(url);},2000);
   var err=document.getElementById('target-error');
   if(err)err.textContent='aftershock-reader.mjs saved. Run: node aftershock-reader.mjs — then enter its pairing code here and scan. SHA-256: '+window.AFTERSHOCK_READER_SHA256.slice(0,16)+'…';
  }catch(e){alert('Could not build the reader download: '+e.message);}
 });
})();
</script>`;

let out=html
 .replace('<link rel="stylesheet" href="styles.css">','<style>\n'+css+'\n</style>')
 .replace('<script src="data.js"></script>','<script>\n'+data+'\n</script>')
 .replace('<script src="app.js"></script>','<script>\n'+app+'\n</script>'+downloadScript);
writeFileSync('aftershock.html',out);
console.log('built aftershock.html:',out.length,'bytes; reader b64:',readerB64.length,'chars; sha256:',sha256);
