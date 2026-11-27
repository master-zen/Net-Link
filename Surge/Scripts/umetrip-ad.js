(() => {
'use strict';
const HOSTS=new Set(["activity.umetrip.com","appmsg.umetrip.com","bkclient.umetrip.com.cn","home.umetrip.com","opactivity.umetrip.com","sns.umetrip.com","umehome.umetrip.com","umerp.umetrip.com","umerp.umetrip.com.cn","umeflightstatus.umetrip.com","umestartup.umetrip.com","114.115.217.129"]);
const EMPTY=new Set(['1000019','1420002','1370286','1430064']);
const FILTER=new Set(['1000002','1100001','1000029','1370126']);
const HOME_NAMES=new Set(['机上闭门购虚拟卡片','机上内购-weex包更新虚拟卡片','无行程机票直销卡片8.4.7','中秋国庆活动','回归礼包_无行程首页底部条']);
const MINE_NAMES=new Set(['我的页面-会员卡片V3','我的页-腰部banner第四帧','礼金中心','票券权益','特价专区-个人中心','机票-31-推荐管']);
function route(url){
 const m=/^https?:\/\/([a-z0-9.-]+)\/gateway\/api\/umetrip\/native(?:\?[^#]*)?$/i.exec(String(url));
 return !!m&&HOSTS.has(m[1].toLowerCase());
}
function rpid(req){
 const values=Object.entries(req.headers||{}).filter(([k])=>k.toLowerCase()==='rpid').map(([,v])=>String(v).trim());
 const qs=[...String(req.url||'').matchAll(/[?&]rpid=([^&#]*)/ig)].map(x=>x[1]);
 const all=[...values,...qs];
 return all.length&&all.every(v=>/^\d{7}$/.test(v)&&v===all[0])?all[0]:'';
}
function varint(b,p){
 let n=0,m=1;
 for(let i=0;i<8&&p<b.length;i++){const v=b[p++];n+=(v&127)*m;if(!Number.isSafeInteger(n))throw Error('varint');if(!(v&128))return [n,p];m*=128;}
 throw Error('varint');
}
function enc(n){const a=[];while(n>=128){a.push(n%128+128);n=Math.floor(n/128);}a.push(n);return Uint8Array.from(a);}
function concat(parts){const out=new Uint8Array(parts.reduce((a,b)=>a+b.length,0));let p=0;for(const b of parts){out.set(b,p);p+=b.length;}return out;}
function wrap(n,b){return concat([enc(n*8+2),enc(b.length),b]);}
function parse(b){
 const a=[];let p=0;
 while(p<b.length){
  if(a.length>20000)throw Error('fields');
  const start=p;let tag;[tag,p]=varint(b,p);
  const n=Math.floor(tag/8),w=tag%8;if(n<1||n>536870911)throw Error('tag');
  let data=null,value=null;
  if(w===0){[value,p]=varint(b,p);}
  else if(w===1)p+=8;
  else if(w===5)p+=4;
  else if(w===2){let len;[len,p]=varint(b,p);if(len>b.length-p)throw Error('length');data=b.subarray(p,p+len);p+=len;}
  else throw Error('wire');
  if(p>b.length)throw Error('truncated');
  a.push({n,w,data,value,raw:b.subarray(start,p)});
 }
 return a;
}
function decode(b){
 if(typeof TextDecoder==='function')return new TextDecoder('utf-8',{fatal:true}).decode(b);
 return decodeURIComponent(Array.from(b,v=>'%'+v.toString(16).padStart(2,'0')).join(''));
}
function encode(s){if(typeof TextEncoder==='function')return new TextEncoder().encode(s);const x=encodeURIComponent(s),a=[];for(let i=0;i<x.length;i++){if(x[i]==='%'){a.push(parseInt(x.slice(i+1,i+3),16));i+=2;}else a.push(x.charCodeAt(i));}return Uint8Array.from(a);}
const txt=b=>{try{return decode(b);}catch(_){return '';}};
const isObj=x=>x&&typeof x==='object'&&!Array.isArray(x);
function explicitAd(o){
 if(!isObj(o))return false;
 return String(o.dataSource||'').toUpperCase()==='ADVERT'||/^advert_/i.test(String(o.serviceTrack||''))||Object.prototype.hasOwnProperty.call(o,'advertId')||[o.image,o.url,o.imageUrl,o.adBannerImg].some(x=>typeof x==='string'&&/\/fs\/advert\//i.test(x));
}
function jsonClean(o,id,depth=0){
 if(depth>16||!o||typeof o!=='object')return false;
 let changed=false;
 if(Array.isArray(o)){for(const x of o)if(jsonClean(x,id,depth+1))changed=true;return changed;}
 for(const k of ['groupList','cardList','subGroupList','advertDataList']){
  if(!Array.isArray(o[k]))continue;
  const a=o[k].filter(v=>!explicitAd(v));
  if(k==='advertDataList'&&a.length){o[k]=[];changed=true;}else if(a.length!==o[k].length){o[k]=a;changed=true;}
 }
 for(const v of Object.values(o))if(jsonClean(v,id,depth+1))changed=true;
 return changed;
}
function cardSection(f,id){
 if(f.n!==5||f.w!==2)return false;
 let fields;try{fields=parse(f.data);}catch(_){return false;}
 if(!fields.some(x=>(x.n===8||x.n===32)&&x.w===2))return false;
 if(fields.some(x=>x.n===37&&x.w===2&&txt(x.data)==='ADVERT'))return true;
 if(id!=='1000002'&&id!=='1100001')return false;
 const names=id==='1000002'?HOME_NAMES:MINE_NAMES;
 for(const c of fields.filter(x=>x.n===8&&x.w===2)){
  try{if(parse(c.data).some(x=>x.n===3&&x.w===2&&names.has(txt(x.data))))return true;}catch(_){}
 }
 return false;
}
function walk(b,id,depth,budget){
 if(depth>9||budget.left--<=0)return b;
 let fields;try{fields=parse(b);}catch(_){return b;}
 let changed=false;const parts=[];
 for(const f of fields){
  if(f.w!==2){parts.push(f.raw);continue;}
  if(cardSection(f,id)){changed=true;continue;}
  if((id==='1370126'||id==='1000029')&&f.n===8){
   const s=txt(f.data);
   if(id==='1370126'&&s.includes('付费会员')&&s.includes('更早历史行程待解锁')||id==='1000029'&&/瀑布流_(?:特价机票|酒店|租车卡片|权益)/.test(s)){changed=true;continue;}
  }
  let data=f.data;
  if((data[0]===123||data[0]===91)&&data.length>2){
   try{const o=JSON.parse(decode(data));if(jsonClean(o,id))data=encode(JSON.stringify(o));}catch(_){}
  }else if(data.length>=2)data=walk(data,id,depth+1,budget);
  if(data!==f.data){parts.push(wrap(f.n,data));changed=true;}else parts.push(f.raw);
 }
 return changed?concat(parts):b;
}
function transform(req,b){
 if(!route(req.url)||!(b instanceof Uint8Array)||b.length>2097152)return b;
 const id=rpid(req);if(!EMPTY.has(id)&&!FILTER.has(id))return b;
 try{
  const fields=parse(b),payload=fields.filter(f=>f.n===7&&f.w===2);
  if(payload.length!==1)return b;
  const old=payload[0];if(!old.data.length)return b;
  let next;
  if(EMPTY.has(id)){
   if(!parse(old.data).length)return b;
   next=Uint8Array.from([10,0,16,0,32,0]);
   if(old.data.length===next.length&&old.data.every((v,i)=>v===next[i]))return b;
  }else next=walk(old.data,id,0,{left:10000});
  if(next===old.data)return b;
  return concat(fields.map(f=>f===old?wrap(7,next):f.raw));
 }catch(_){return b;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,rpid,route,parse,wrap,concat,enc};
if(typeof $done==='function'){
 let out={};
 try{if(Number($response.status)===200){const b=transform($request,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}
 $done(out);
}
})();
