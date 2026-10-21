'use strict';
/* RoLoP server - no dependencies. Run:  node server.js   then open http://localhost:3000
   - serves RoLoP.html
   - real accounts (email + password stored with scrypt, optional Google sign-in)
   - shared multiplayer room + chat, shared saved games
   Env: PORT, GOOGLE_CLIENT_ID, DATA_FILE, HTML_FILE */
const http=require('http'),https=require('https'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+process.env.PORT||3000,GCID=process.env.GOOGLE_CLIENT_ID||'';
const DATA_FILE=process.env.DATA_FILE||path.join(__dirname,'rolop-data.json'),HTML=process.env.HTML_FILE||path.join(__dirname,'RoLoP.html');
const MAXMSG=1.5*1024*1024,MAXDOC=250*1024;
let DATA={users:{},google:{},sessions:{},docs:{}};
try{DATA=Object.assign(DATA,JSON.parse(fs.readFileSync(DATA_FILE,'utf8')));}catch(e){}
let dirty=false;const save=()=>{dirty=true;};
function flush(){if(!dirty)return;dirty=false;try{fs.writeFileSync(DATA_FILE+'.tmp',JSON.stringify(DATA));fs.renameSync(DATA_FILE+'.tmp',DATA_FILE);}catch(e){console.error('save failed',e.message);}}
setInterval(flush,1000).unref();['SIGINT','SIGTERM'].forEach(s=>process.on(s,()=>{flush();process.exit(0);}));
const rid=n=>crypto.randomBytes(n).toString('hex');
const scrypt=(p,s)=>new Promise((res,rej)=>crypto.scrypt(p,s,32,(e,k)=>e?rej(e):res(k.toString('hex'))));
function gverify(cred){return new Promise((res,rej)=>{https.get('https://oauth2.googleapis.com/tokeninfo?id_token='+encodeURIComponent(cred),r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>{try{res(JSON.parse(b));}catch(e){rej(e);}});}).on('error',rej);});}
/* ---- who may touch which document ---- */
function canRead(uid,p){const a=p.split('/');if(a[0]==='data'&&a[1]==='users')return a[2]===uid;if(a[0]==='games')return true;return false;}
function canWrite(uid,p){const a=p.split('/');if(a[0]==='data'&&a[1]==='users')return a[2]===uid;if(a[0]==='games')return a.length===2&&a[1]===uid;return false;}
/* ---- http: serves the game page ---- */
const server=http.createServer((req,res)=>{
  const u=req.url.split('?')[0];
  if(u==='/'||u==='/index.html'||u==='/RoLoP.html'){fs.readFile(HTML,(e,b)=>{if(e){res.writeHead(404);return res.end('RoLoP.html not found next to server.js');}res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(b);});}
  else if(u==='/health'){res.writeHead(200);res.end('ok');}
  else{res.writeHead(404);res.end('Not found');}});
server.on('upgrade',(req,sock)=>{
  if(req.url.split('?')[0]!=='/ws'||!req.headers['sec-websocket-key']){sock.destroy();return;}
  const acc=crypto.createHash('sha1').update(req.headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+acc+'\r\n\r\n');
  new Client(sock);});
/* ---- websocket clients ---- */
const rooms=new Map();
class Client{
  constructor(s){this.s=s;this.buf=Buffer.alloc(0);this.id='c'+rid(5);this.uid=null;this.name='';this.room=null;this.pres=null;this.frag=[];this.tok=120;this.tl=Date.now();this.closed=false;
    s.on('data',d=>{this.buf=Buffer.concat([this.buf,d]);this.parse();});s.on('close',()=>this.close());s.on('error',()=>this.close());}
  frame(op,p){const n=p.length;let h;if(n<126)h=Buffer.from([0x80|op,n]);else if(n<65536){h=Buffer.alloc(4);h[0]=0x80|op;h[1]=126;h.writeUInt16BE(n,2);}else{h=Buffer.alloc(10);h[0]=0x80|op;h[1]=127;h.writeBigUInt64BE(BigInt(n),2);}
    try{this.s.write(Buffer.concat([h,p]));}catch(e){}}
  send(o){if(!this.closed)this.frame(1,Buffer.from(JSON.stringify(o)));}
  parse(){for(;;){const b=this.buf;if(b.length<2)return;const b0=b[0],b1=b[1],op=b0&15,masked=!!(b1&128);let len=b1&127,off=2;
      if(len===126){if(b.length<4)return;len=b.readUInt16BE(2);off=4;}else if(len===127){if(b.length<10)return;len=Number(b.readBigUInt64BE(2));off=10;}
      if(len>MAXMSG){this.s.destroy();return;}const need=off+(masked?4:0)+len;if(b.length<need)return;
      const payload=Buffer.from(b.slice(off+(masked?4:0),need));if(masked){const m=b.slice(off,off+4);for(let i=0;i<payload.length;i++)payload[i]^=m[i&3];}
      this.buf=b.slice(need);
      if(op===8){this.s.end();return;}if(op===9){this.frame(10,payload);continue;}if(op===10)continue;
      if(op===1||op===2){this.frag=[payload];}else if(op===0){this.frag.push(payload);}else continue;
      if(b0&128){const full=Buffer.concat(this.frag);this.frag=[];this.onText(full.toString('utf8'));}}}
  close(){if(this.closed)return;this.closed=true;this.leave();try{this.s.destroy();}catch(e){}}
  leave(){if(!this.room)return;const set=rooms.get(this.room);if(set){set.delete(this);set.forEach(c=>c.send({t:'bye',id:this.id}));if(!set.size)rooms.delete(this.room);}this.room=null;}
  async login(uid,name){const token=rid(24);DATA.sessions[token]={uid,name};save();this.uid=uid;this.name=name;return{ok:true,uid,token,name};}
  async onText(txt){
    const now=Date.now();this.tok=Math.min(120,this.tok+(now-this.tl)*.06);this.tl=now;if(this.tok<1)return;this.tok--;
    let m;try{m=JSON.parse(txt);}catch(e){return;}if(!m||typeof m.t!=='string')return;
    const reply=o=>{if(m.rid)this.send(Object.assign({rid:m.rid},o));};
    try{
      switch(m.t){
        case 'config':return reply({ok:true,googleClientId:GCID});
        case 'signup':{const em=String(m.email||'').trim().toLowerCase(),pw=String(m.pass||'');
          if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em))return reply({ok:false,err:'Enter a valid email address.'});if(pw.length<6)return reply({ok:false,err:'Password must be at least 6 characters.'});
          if(DATA.users[em])return reply({ok:false,err:'That email already has an account. Use Sign in.'});
          const salt=rid(8),hash=await scrypt(pw,salt),uid='u'+rid(8);if(DATA.users[em])return reply({ok:false,err:'That email already has an account. Use Sign in.'});
          DATA.users[em]={uid,salt,hash,email:em};return reply(await this.login(uid,em));}
        case 'login':{const em=String(m.email||'').trim().toLowerCase(),a=DATA.users[em];if(!a)return reply({ok:false,err:'No account with that email. Create one first.'});
          const h=await scrypt(String(m.pass||''),a.salt);if(!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(a.hash)))return reply({ok:false,err:'Wrong password.'});return reply(await this.login(a.uid,em));}
        case 'google':{if(!GCID)return reply({ok:false,err:'Google sign-in is not configured on the server (set GOOGLE_CLIENT_ID).'});
          const t=await gverify(String(m.credential||''));if(!t||t.aud!==GCID||!t.sub)return reply({ok:false,err:'Google sign-in could not be verified.'});
          let g=DATA.google[t.sub];if(!g){g=DATA.google[t.sub]={uid:'g'+rid(8),email:t.email||'',name:t.name||''};save();}return reply(await this.login(g.uid,g.email||g.name||'Google user'));}
        case 'resume':{const s=DATA.sessions[String(m.token||'')];if(!s)return reply({ok:false,err:'Session expired.'});this.uid=s.uid;this.name=s.name;return reply({ok:true,uid:s.uid,name:s.name});}
      }
      if(!this.uid)return reply({ok:false,err:'Not signed in.'});
      switch(m.t){
        case 'get':{const p=String(m.path||'');if(!canRead(this.uid,p))return reply({ok:false,err:'Not allowed.'});const d=DATA.docs[p];return reply({ok:true,exists:d!==undefined,data:d===undefined?null:d});}
        case 'set':{const p=String(m.path||'');if(!canWrite(this.uid,p))return reply({ok:false,err:'Not allowed.'});const j=JSON.stringify(m.data);if(j===undefined||j.length>MAXDOC)return reply({ok:false,err:'Document too large.'});DATA.docs[p]=JSON.parse(j);save();return reply({ok:true});}
        case 'del':{const p=String(m.path||'');if(!canWrite(this.uid,p))return reply({ok:false,err:'Not allowed.'});delete DATA.docs[p];save();return reply({ok:true});}
        case 'list':{const pre=String(m.prefix||'')+'/';const docs=[];for(const k of Object.keys(DATA.docs)){if(k.startsWith(pre)&&k.slice(pre.length).indexOf('/')<0&&canRead(this.uid,k))docs.push({path:k,data:DATA.docs[k]});}return reply({ok:true,docs});}
        case 'join':{const name=String(m.room||'main').toLowerCase().replace(/[^a-z0-9]/g,'').slice(0,20)||'main';this.leave();this.room=name;let set=rooms.get(name);if(!set)rooms.set(name,set=new Set());
          set.forEach(c=>{if(c.pres)this.send({t:'pres',id:c.id,d:c.pres});});set.add(this);reply({ok:true,id:this.id});return;}
        case 'pres':{if(!this.room||JSON.stringify(m.d||'').length>2048)return;this.pres=m.d;rooms.get(this.room).forEach(c=>{if(c!==this)c.send({t:'pres',id:this.id,d:m.d});});return;}
        case 'chat':{if(!this.room||JSON.stringify(m.d||'').length>600)return;rooms.get(this.room).forEach(c=>{if(c!==this)c.send({t:'chat',id:this.id,d:m.d});});return;}
      }
    }catch(e){reply({ok:false,err:'Server error.'});}
  }}
server.listen(PORT,()=>console.log('RoLoP server running on http://localhost:'+PORT+(GCID?' (Google sign-in on)':' (Google sign-in off: set GOOGLE_CLIENT_ID)')));
