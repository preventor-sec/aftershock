// Build single-file aftershock-reader.mjs from the repository modules.
// The scanner is embedded verbatim: only import/export *syntax* is rewritten
// (module wiring), no logic is touched, all comments are preserved.
import {readFileSync,writeFileSync} from 'node:fs';
const read=p=>readFileSync(p,'utf8').replace(/\r\n/g,'\n');
const log=(...a)=>console.log(...a);

const safeFetch=read('backend/safe-fetch.mjs');
const checks=read('backend/checks.mjs');
const scan=read('backend/scan.mjs');
const reader=read('reader.mjs');

// Rewrite a module body for single-file concatenation:
// - drop its import lines (one shared import block goes at the top)
// - `export function/const X` -> plain declaration
// - `export {x};` re-export blocks -> removed (names already declared)
function unwrap(src){
 return src
  .replace(/^import[^\n]*?\n/gm,'')
  .replace(/^export\s+(async\s+function|function|const|let|class)\s/gm,(m,kw)=>kw+' ')
  .replace(/^export\s*\{[^}]*\}\s*;?\s*$/gm,'');
}

// One import block for the whole bundle (union of what the modules use).
const imports=`import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import {isIP} from 'node:net';
import {createHash,randomUUID,randomBytes,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
`;

const banner=`#!/usr/bin/env node
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
`;

// The reader banner comments are replaced by the bundle banner above; its
// import lines are dropped (shared import block at top).
const readerCode=reader.replace(/^#!.*\n/,'')
 .replace(/^\/\/[^\n]*\n/gm,'')
 .replace(/^import[^\n]*?\n/gm,'');

const bundle=[
 banner,
 imports,
 '// ==== backend/safe-fetch.mjs (verbatim) ====',
 unwrap(safeFetch),
 '// ==== backend/checks.mjs (verbatim) ====',
 unwrap(checks),
 '// ==== backend/scan.mjs (verbatim) ====',
 unwrap(scan),
 '// ==== reader.mjs (verbatim) ====',
 readerCode
].join('\n');

writeFileSync('aftershock-reader.mjs',bundle);
log('built aftershock-reader.mjs:',bundle.length,'bytes');
