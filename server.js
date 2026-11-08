'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { WebSocketServer, WebSocket } = require('ws');
const PORT = Number(process.env.PORT) || 3000;
const MAX_PLAYERS = 80;
const WORLD_W = 29400, WORLD_H = 20400;
const index = fs.readFileSync(path.join(__dirname, 'index.html'));

/* Optional PostgreSQL save storage. No database = no online persistence, but the game still works. */
const {scryptSync,timingSafeEqual,createHmac,randomBytes}=crypto;
let db=null;
if(process.env.DATABASE_URL){
 const {Pool}=require('pg');
 db=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='disable'?false:{rejectUnauthorized:false},max:3});
 db.query(`CREATE TABLE IF NOT EXISTS hwan_rpg_saves (
  nickname TEXT PRIMARY KEY, passhash TEXT NOT NULL, data JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
 .then(()=>console.log('☁️ PostgreSQL saves ready'))
 .catch(e=>console.error('☁️ PostgreSQL connection failed:',e.message));
}
const SESSION_SECRET=process.env.SESSION_SECRET||randomBytes(32).toString('hex');
function jsonOut(res,code,payload){if(res.headersSent)return;res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(payload))}
async function readJson(req){let size=0,chunks=[];for await (const b of req){size+=b.length;if(size>500000)throw Error('too_large');chunks.push(b)}return JSON.parse(Buffer.concat(chunks).toString('utf8'))}
function makeHash(secret){const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(secret,salt,64).toString('hex')}
function checkHash(secret,stored){try{const [salt,expected]=stored.split(':'),a=Buffer.from(expected,'hex'),b=scryptSync(secret,salt,a.length);return a.length===b.length&&timingSafeEqual(a,b)}catch{return false}}
function authCookie(req){const cookie=req.headers.cookie?.split(';').map(v=>v.trim()).find(v=>v.startsWith('hwan_session='))?.split('=')[1];if(!cookie)return null;const parts=decodeURIComponent(cookie).split('.');if(parts.length!==3)return null;const [name,expiry,sig]=parts;if(Number(expiry)<Date.now()||name.length>20)return null;const actual=createHmac('sha256',SESSION_SECRET).update(name+'.'+expiry).digest('hex');try{if(!timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(sig,'hex')))return null}catch{return null}return name}
function setAuthCookie(res,nick){const expiration=String(Date.now()+30*86400000),value=nick+'.'+expiration,sig=createHmac('sha256',SESSION_SECRET).update(value).digest('hex');res.setHeader('Set-Cookie','hwan_session='+encodeURIComponent(value+'.'+sig)+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000'+(process.env.NODE_ENV==='production'?'; Secure':''))}
async function handleCloudRequest(req,res){const u=new URL(req.url,'http://localhost');if(u.pathname==='/api/cloud/status'&&req.method==='GET'){return jsonOut(res,200,{enabled:!!db})}
 if(!db)return jsonOut(res,503,{message:'database_not_configured'});
 if(u.pathname==='/api/cloud/connect'&&req.method==='POST'){
  let input;try{input=await readJson(req)}catch{return jsonOut(res,400,{message:'invalid_json'})}
  const nick=typeof input.nick==='string'?input.nick.trim():'';
  const pass=typeof input.password==='string'?input.password:'';
  if(nick.length<2||nick.length>12||/[<>\\]/.test(nick)||pass.length<8||pass.length>128)return jsonOut(res,400,{message:'nickname_or_password_invalid'});
  let r=await db.query('SELECT passhash, data FROM hwan_rpg_saves WHERE nickname=$1',[nick]);
  if(!r.rowCount){if(input.create!==true)return jsonOut(res,404,{message:'not_registered'});
    const hash=makeHash(pass);await db.query('INSERT INTO hwan_rpg_saves(nickname,passhash) VALUES($1,$2) ON CONFLICT DO NOTHING',[nick,hash]);r=await db.query('SELECT passhash,data FROM hwan_rpg_saves WHERE nickname=$1',[nick]);}
  if(!checkHash(pass,r.rows[0].passhash))return jsonOut(res,401,{message:'wrong_password'});
  setAuthCookie(res,nick);return jsonOut(res,200,{ok:true,data:r.rows[0].data?.nick?r.rows[0].data:null});
 }
 if(u.pathname==='/api/cloud/save'&&req.method==='POST'){
  const nick=authCookie(req);if(!nick)return jsonOut(res,401,{message:'not_logged_in'});
  let input;try{input=await readJson(req)}catch{return jsonOut(res,400,{message:'invalid_json'})}
  const data=input?.data;
  if(!data||data.nick!==nick||!Number.isFinite(Number(data.lv))||!Number.isFinite(Number(data.gold))||typeof data.quests!=='object')return jsonOut(res,400,{message:'invalid_save'});
  await db.query('UPDATE hwan_rpg_saves SET data=$1::jsonb, updated_at=now() WHERE nickname=$2',[JSON.stringify(data),nick]);return jsonOut(res,200,{ok:true});
 }
 return jsonOut(res,404,{message:'not_found'});
}

const server = http.createServer((req,res)=>{
  if(req.url?.startsWith('/api/cloud/')){handleCloudRequest(req,res).catch(e=>{console.error('cloud request error',e.message);jsonOut(res,500,{message:'server_error'})});return}
  if(req.method !== 'GET'){res.writeHead(405);res.end();return;}
  const url = new URL(req.url,'http://localhost');
  if(url.pathname==='/' || url.pathname==='/index.html'){
    res.writeHead(200, {'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}); res.end(index);
  } else if(url.pathname==='/health'){
    res.writeHead(200, {'Content-Type':'application/json'});res.end(JSON.stringify({ok:true,players:players.size}));
  } else {res.writeHead(404);res.end('Not found')}
});
const wss = new WebSocketServer({server,path:'/ws',maxPayload:4096});
const players=new Map();
const safeNum=(v,lo,hi,d=lo)=>Number.isFinite(v)?Math.min(hi,Math.max(lo,v)):d;
const sanitizeName=s=>typeof s==='string'?s.replace(/[\x00-\x1f<>]/g,'').trim().slice(0,16):'';
function sanitizeState(obj){
  if(!obj||typeof obj!=='object'||Array.isArray(obj))return null;
  const app=obj.appearance && typeof obj.appearance==='object' ? obj.appearance : {};
  const colors={};
  for(const key of ['skin','hair','shirt','pants'])if(typeof app[key]==='string'&&/^#[0-9a-fA-F]{6}$/.test(app[key]))colors[key]=app[key];
  return {x:Math.round(safeNum(obj.x,0,WORLD_W,340)),y:Math.round(safeNum(obj.y,0,WORLD_H,355)),
    lv:Math.floor(safeNum(obj.lv,1,50,1)),job:Math.floor(safeNum(obj.job,-1,20,-1)),
    appearance:colors,hp:Math.round(safeNum(obj.hp,0,100000,100)),maxHp:Math.round(safeNum(obj.maxHp,1,100000,100)),running:!!obj.running};
}
function send(ws,payload){if(ws.readyState===WebSocket.OPEN){try{ws.send(JSON.stringify(payload))}catch{}}}
function broadcast(payload,exclude){for(const ws of players.keys())if(ws!==exclude)send(ws,payload)}
wss.on('connection',(ws)=>{
  if(players.size>=MAX_PLAYERS){send(ws,{type:'error',message:'서버 인원이 가득 찼어요'});ws.close(1013,'full');return}
  const id=crypto.randomUUID();
  const p={id,name:'',x:340,y:355,lv:1,job:-1,hp:100,maxHp:100,appearance:{},running:false};
  players.set(ws,p);
  send(ws,{type:'welcome',id,players:[...players.values()].filter(a=>a.id!==id&&a.name),count:players.size});
  broadcast({type:'count',count:players.size},ws);
  let chatWindow=0,chatCount=0,lastMoveAt=0;
  ws.on('message',buffer=>{
    let data;try{data=JSON.parse(buffer.toString('utf8'))}catch{return}
    if(!data||typeof data!=='object')return;
    if(data.type==='hello'){
      const name=sanitizeName(data.name);
      if(name.length<2){send(ws,{type:'error',message:'닉네임은 2글자 이상이어야 해요'});return}
      const wasNamed=!!p.name;p.name=name;
      const state=sanitizeState(data.state);if(state)Object.assign(p,state);
      broadcast({type:wasNamed?'state':'join',id,state:{...p},player:{...p},count:players.size},ws);
    } else if(data.type==='state'){
      if(!p.name)return;
      const now=Date.now();if(now-lastMoveAt<55)return;lastMoveAt=now;
      const state=sanitizeState(data.state);if(!state)return;
      // Coarse speed plausibility cap; respawn/teleport can jump after server reconnect.
      Object.assign(p,state);
      broadcast({type:'state',id,state},ws);
    } else if(data.type==='chat'){
      if(!p.name||typeof data.message!=='string')return;
      const now=Date.now();if(now-chatWindow>5000){chatWindow=now;chatCount=0}
      if(++chatCount>5)return;
      const message=data.message.replace(/[\x00-\x1f]/g,' ').trim().slice(0,120);
      if(message)broadcast({type:'chat',name:p.name,message});
    }
  });
  ws.on('close',()=>{players.delete(ws);broadcast({type:'leave',id,count:players.size})});
  ws.on('error',()=>{});
});
setInterval(()=>{for(const ws of players.keys()){
  if(ws.isAlive===false){ws.terminate();continue}
  ws.isAlive=false;ws.ping();
}},30000).unref();
wss.on('connection',ws=>{ws.isAlive=true;ws.on('pong',()=>{ws.isAlive=true})});
server.listen(PORT,'0.0.0.0',()=>console.log(`환 RPG 온라인 서버: http://localhost:${PORT}`));
