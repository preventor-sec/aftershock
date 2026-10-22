// Regenerate MANIFEST.json — SHA-256 integrity for every shipped file.
// Zero dependencies. Usage: node tools/build-manifest.mjs
// Walks the repo, skips .git/, node_modules/, previews/ (binary previews),
// and MANIFEST.json itself. Deterministic ordering (sorted paths).
import {readFileSync,writeFileSync,readdirSync,statSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {join,relative} from 'node:path';

const ROOT=process.cwd();
const SKIP=new Set(['.git','node_modules','MANIFEST.json']);
const pkg=JSON.parse(readFileSync(join(ROOT,'package.json'),'utf8'));

function walk(dir,out=[]){
 for(const entry of readdirSync(dir,{withFileTypes:true})){
  if(SKIP.has(entry.name))continue;
  const p=join(dir,entry.name);
  if(entry.isDirectory())walk(p,out);
  else if(entry.isFile())out.push(p);
 }
 return out;
}

const files=walk(ROOT).map(p=>relative(ROOT,p).replace(/\\/g,'/')).sort().map(path=>{
 const buf=readFileSync(join(ROOT,path));
 return {path,bytes:buf.length,sha256:createHash('sha256').update(buf).digest('hex')};
});

const manifest={product:'Aftershock',version:pkg.version,files};
writeFileSync(join(ROOT,'MANIFEST.json'),JSON.stringify(manifest,null,1)+'\n');
console.log(`MANIFEST.json regenerated: ${files.length} files, version ${pkg.version}`);
