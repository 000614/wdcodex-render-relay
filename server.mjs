import http from 'node:http';
import https from 'node:https';
import {Transform} from 'node:stream';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const HOP=new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade']);
const REQUEST_HEADERS=['accept','accept-encoding','accept-language','content-type','content-length','last-event-id','x-csrf-token','user-agent','range'];
function error(res,status,message){
  if(res.headersSent){res.destroy();return;}
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify({error:message}));
}
function origin(value,allowLocal){
  const u=new URL(value);
  if(u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error('Origin must contain only scheme and host');
  if(u.protocol!=='https:'&&!(allowLocal&&u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname)))throw Error('HTTPS is required');
  return u;
}
export function createRelay({upstreamOrigin,publicOrigin,allowInsecureLoopback=false,idleTimeout=75000,maxBodyBytes=262144}){
  const upstream=origin(upstreamOrigin,allowInsecureLoopback),site=origin(publicOrigin,allowInsecureLoopback);
  if(upstream.origin===site.origin)throw Error('Relay cannot point to itself');
  const transport=upstream.protocol==='https:'?https:http;
  const sockets=new Set();
  const server=http.createServer((req,res)=>{
    res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('X-Frame-Options','DENY');res.setHeader('X-Robots-Tag','noindex, nofollow');
    if(req.headers.host!==site.host)return error(res,403,'域名不匹配');
    if(!req.url.startsWith('/')||req.url.startsWith('//')||req.url.includes('\\'))return error(res,400,'无效路径');
    if(!['GET','HEAD','POST'].includes(req.method))return error(res,405,'不支持此方法');
    const target=new URL(req.url,site);
    if(target.origin!==site.origin)return error(res,400,'无效目标');
    if(target.pathname==='/healthz'){
      if(req.method!=='GET'&&req.method!=='HEAD')return error(res,405,'不支持此方法');
      res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(req.method==='HEAD'?'':JSON.stringify({ok:true,service:'wdcodex-relay'}));return;
    }
    // The host's shutdown/control endpoints are never exposed through this relay.
    if(target.pathname==='/api/local'||target.pathname.startsWith('/api/local/'))return error(res,403,'仅限主机本地操作');
    if(req.headers.origin&&req.headers.origin!==site.origin)return error(res,403,'来源不被允许');
    if(req.method==='POST'&&req.headers.origin!==site.origin)return error(res,403,'缺少同源验证');
    if(Number(req.headers['content-length']||0)>maxBodyBytes)return error(res,413,'请求过大');
    const headers={};for(const name of REQUEST_HEADERS)if(req.headers[name]!==undefined)headers[name]=req.headers[name];
    const cookies=(req.headers.cookie||'').split(';').map(s=>s.trim()).filter(s=>s.startsWith('codex_web='));
    if(cookies.length)headers.cookie=cookies.join('; ');
    // The HTTPS tunnel terminator supplies X-Forwarded-Proto itself. Supplying
    // another value here would let some tunnels append "https, https" and
    // break the host's strict HTTPS-origin validation.
    headers.host=upstream.host;headers['ngrok-skip-browser-warning']='1';
    // Browser-origin validation happens above. Rebase it for the fixed upstream's
    // existing same-origin check; never trust an arbitrary client-supplied target.
    if(req.headers.origin)headers.origin=upstream.origin;
    const out=transport.request(upstream.origin+target.pathname+target.search,{method:req.method,headers},incoming=>{
      const responseHeaders={};const forbidden=new Set([...HOP,...String(incoming.headers.connection||'').split(',').map(x=>x.trim().toLowerCase())]);
      for(const [name,value] of Object.entries(incoming.headers))if(value!==undefined&&!forbidden.has(name)&&name!=='set-cookie'&&name!=='location')responseHeaders[name]=value;
      if(incoming.headers.location){
        const destination=new URL(incoming.headers.location,upstream);
        if(destination.origin!==upstream.origin){incoming.destroy();error(res,502,'上游返回了非工作台跳转');return;}
        responseHeaders.location=site.origin+destination.pathname+destination.search+destination.hash;
      }
      const setCookies=(incoming.headers['set-cookie']||[]).filter(c=>c.startsWith('codex_web=')).map(c=>{
        let value=c.replace(/;\s*Domain=[^;]*/ig,'');if(!/;\s*Secure(?:;|$)/i.test(value))value+='; Secure';return value;
      });
      if(setCookies.length)responseHeaders['set-cookie']=setCookies;
      responseHeaders['cache-control']='no-store';responseHeaders['x-accel-buffering']='no';
      res.writeHead(incoming.statusCode||502,responseHeaders);res.flushHeaders();
      incoming.on('error',()=>res.destroy());incoming.pipe(res);
    });
    out.setTimeout(idleTimeout,()=>out.destroy(new Error('upstream idle timeout')));
    out.on('error',()=>error(res,502,'本机工作台暂不可达，请确认家中电脑和隧道已启动'));
    let size=0;const limiter=new Transform({transform(chunk,encoding,callback){size+=chunk.length;if(size>maxBodyBytes){callback(Object.assign(Error('body too large'),{status:413}));return;}callback(null,chunk);}});
    limiter.on('error',()=>{error(res,413,'请求过大');out.destroy();});req.on('error',()=>out.destroy());
    res.on('close',()=>out.destroy());req.pipe(limiter).pipe(out);
  });
  server.requestTimeout=30000;server.headersTimeout=10000;
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  server.on('upgrade',(req,socket)=>{socket.end('HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\n\r\n');});
  server.on('connect',(req,socket)=>socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n'));
  server.dispose=()=>{for(const s of sockets)s.destroy();server.close();};
  return server;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const publicOrigin=process.env.PUBLIC_ORIGIN||process.env.RENDER_EXTERNAL_URL;
  if(!process.env.UPSTREAM_ORIGIN||!publicOrigin)throw Error('Set UPSTREAM_ORIGIN and PUBLIC_ORIGIN (or RENDER_EXTERNAL_URL)');
  const server=createRelay({upstreamOrigin:process.env.UPSTREAM_ORIGIN,publicOrigin});
  const port=Number(process.env.PORT||10000);
  server.listen(port,'0.0.0.0',()=>console.log(`WDCodex relay listening on port ${port}`));
  const stop=()=>{server.dispose();};process.on('SIGTERM',stop);process.on('SIGINT',stop);
}
