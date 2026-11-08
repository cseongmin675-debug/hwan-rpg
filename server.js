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
const server = http.createServer((req,res)=>{
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
    lv:Math.floor(safeNum(obj.lv,1,50,1)),job:Math.floor(safeNum(obj.job,-1,19,-1)),
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
