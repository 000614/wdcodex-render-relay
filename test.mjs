import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {createRelay} from './server.mjs';

const site='https://wdcodex-relay.example';
async function listen(server){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));return 'http://127.0.0.1:'+server.address().port;}
async function fixture(t,handler){
 const upstream=http.createServer(handler),upstreamOrigin=await listen(upstream);
 const relay=createRelay({upstreamOrigin,publicOrigin:site,allowInsecureLoopback:true});const url=await listen(relay);
 t.after(()=>{relay.dispose();upstream.closeAllConnections();upstream.close();});return {url,upstreamOrigin};
}
function request(url,path='/',headers={},body='',method=body?'POST':'GET'){
 return new Promise((resolve,reject)=>{const req=http.request(url+path,{method,headers:{host:new URL(site).host,...headers}},res=>{
  const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}));
 });req.on('error',reject);req.end(body);});
}
test('health is local, fixed target cannot be chosen by path or browser headers',async t=>{
 let hits=0;const {url}=await fixture(t,(req,res)=>{hits++;res.end('fixed');});
 assert.equal((await request(url,'/healthz')).status,200);assert.equal(hits,0);
 assert.equal((await request(url,'//evil.example/')).status,400);
 assert.equal((await request(url,'/',{host:'evil.example'})).status,403);
 assert.equal((await request(url,'/api/local/shutdown',{origin:site},'{}')).status,403);assert.equal(hits,0);
});
test('mutations require the relay origin; malicious or absent origin never reaches host',async t=>{
 let hits=0;const {url}=await fixture(t,(req,res)=>{hits++;res.end();});
 assert.equal((await request(url,'/api/login',{},'{}')).status,403);
 assert.equal((await request(url,'/api/login',{origin:'https://evil.example'},'{}')).status,403);assert.equal(hits,0);
});
test('valid same-origin requests rebase Origin, preserve CSRF and only host session cookie',async t=>{
 let got;const {url,upstreamOrigin}=await fixture(t,(req,res)=>{got=req.headers;res.end('ok');});
 const result=await request(url,'/api/threads',{origin:site,'x-csrf-token':'csrf-test',cookie:'other=private; codex_web=session-test','x-forwarded-proto':'http','x-forwarded-host':'evil.example',authorization:'Bearer never-forward'},'{}');
 assert.equal(result.status,200);assert.equal(got.origin,upstreamOrigin);assert.equal(got.host,new URL(upstreamOrigin).host);assert.equal(got['x-csrf-token'],'csrf-test');assert.equal(got.cookie,'codex_web=session-test');assert.equal(got.authorization,undefined);assert.equal(got['x-forwarded-host'],undefined);assert.equal(got['x-forwarded-proto'],undefined);assert.equal(got['ngrok-skip-browser-warning'],'1');
});
test('secure login and logout cookies remain host-only at relay',async t=>{
 const {url}=await fixture(t,(req,res)=>{res.setHeader('Set-Cookie',['codex_web=session; Domain=old.example; Path=/; HttpOnly; SameSite=Strict','unrelated=private']);res.end('{}');});
 const r=await request(url,'/api/login',{origin:site},'{}');assert.equal(r.headers['set-cookie'].length,1);assert.match(r.headers['set-cookie'][0],/Secure/);assert.doesNotMatch(r.headers['set-cookie'][0],/Domain=/i);assert.match(r.headers['set-cookie'][0],/HttpOnly/);
});
test('SSE first chunk arrives before response completion, and reconnect cursor is passed',async t=>{
 let finish,seenId;const {url}=await fixture(t,(req,res)=>{seenId=req.headers['last-event-id'];res.writeHead(200,{'Content-Type':'text/event-stream'});res.write('id: 8\ndata: first\n\n');finish=()=>res.end('id: 9\ndata: second\n\n');});
 const output=await new Promise((resolve,reject)=>{http.get(url+'/api/events',{headers:{host:new URL(site).host,'last-event-id':'7'}},res=>{let body='';res.on('data',c=>{body+=c;if(body.includes('first')&&!body.includes('second'))finish();});res.on('end',()=>resolve(body));}).on('error',reject);});
 assert.equal(seenId,'7');assert.match(output,/first/);assert.match(output,/second/);
});
test('binary downloads preserve bytes, name and length without proxy buffering',async t=>{
 const bytes=Buffer.alloc(200000);for(let i=0;i<bytes.length;i++)bytes[i]=i%251;
 const {url}=await fixture(t,(req,res)=>{res.writeHead(200,{'Content-Type':'application/zip','Content-Length':bytes.length,'Content-Disposition':"attachment; filename*=UTF-8''project.zip"});res.end(bytes);});
 const r=await request(url,'/api/archives/id/download');assert.equal(r.status,200);assert.equal(r.headers['content-length'],String(bytes.length));assert.match(r.headers['content-disposition'],/project.zip/);assert.equal(createHash('sha256').update(r.body).digest('hex'),createHash('sha256').update(bytes).digest('hex'));
});
test('large request bodies are rejected and upstream secrets are never redirected externally',async t=>{
 const {url}=await fixture(t,(req,res)=>{res.writeHead(302,{Location:'https://evil.example'});res.end();});
 assert.equal((await request(url,'/',{origin:site},'x'.repeat(262145))).status,413);
 assert.equal((await request(url)).status,502);
});
test('upstream same-site redirects rebase to relay and connection-specific headers are dropped',async t=>{
 let destination;const {url,upstreamOrigin}=await fixture(t,(req,res)=>{res.writeHead(302,{Location:destination,Connection:'x-secret','x-secret':'do-not-pass'});res.end();});destination=upstreamOrigin+'/next?q=1';
 const r=await request(url);assert.equal(r.headers.location,site+'/next?q=1');assert.equal(r.headers['x-secret'],undefined);assert.equal(r.headers['cache-control'],'no-store');
});
test('production validates HTTPS origins and rejects loops and embedded credentials',()=>{
 assert.throws(()=>createRelay({upstreamOrigin:'http://example.com',publicOrigin:site}),/HTTPS/);
 assert.throws(()=>createRelay({upstreamOrigin:site,publicOrigin:site}),/itself/);
 assert.throws(()=>createRelay({upstreamOrigin:'https://user:secret@example.com',publicOrigin:site}),/Origin/);
});
