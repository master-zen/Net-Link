(() => {
'use strict';
const JSON_ROUTES=[["splash","^https?://(?:app\\.bilibili\\.com|app\\.biliapi\\.(?:net|com))/x/v2/splash/(?:list|show|brand/list|event/list2?)(?:\\?[^#]*)?$"],["feed","^https?://(?:app\\.bilibili\\.com|app\\.biliapi\\.(?:net|com))/x/v2/feed/index(?:/(?:relate/)?story)?(?:\\?[^#]*)?$"],["web-feed","^https?://(?:api\\.bilibili\\.com|api\\.biliapi\\.net)/x/web-interface/wbi/index/top/feed/rcmd(?:\\?[^#]*)?$"],["live","^https?://api\\.live\\.bilibili\\.com/xlive/(?:app-interface/v2/(?:index/feed|room/recList)|app-room/v1/index/getInfoByRoom)(?:\\?[^#]*)?$"]].map(([k,p])=>[k,new RegExp(p)]);
const PROTO_ROUTES=[["unite","^https://(?:grpc\\.biliapi\\.net|grpc\\.bilibili\\.com|app\\.bilibili\\.com|app\\.biliapi\\.(?:net|com))/bilibili\\.app\\.viewunite\\.v1\\.View/View$"],["view","^https://(?:grpc\\.biliapi\\.net|grpc\\.bilibili\\.com|app\\.bilibili\\.com|app\\.biliapi\\.(?:net|com))/bilibili\\.app\\.view\\.v1\\.View/View$"],["dynamic","^https://(?:grpc\\.biliapi\\.net|grpc\\.bilibili\\.com|app\\.bilibili\\.com|app\\.biliapi\\.(?:net|com))/bilibili\\.app\\.dynamic\\.v2\\.Dynamic/DynAll$"],["pause","^https://(?:grpc\\.biliapi\\.net|grpc\\.bilibili\\.com|app\\.bilibili\\.com|app\\.biliapi\\.(?:net|com))/bilibili\\.app\\.viewunite\\.v1\\.View/(?:PlayPause|ViewEndPage)$"]].map(([k,p])=>[k,new RegExp(p)]);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const yes=x=>x===true||x===1||x==='1';
const own=(o,k)=>obj(o)&&Object.prototype.hasOwnProperty.call(o,k);
function ad(o){
 if(!obj(o))return false;
 return yes(o.is_ad)||yes(o.isAd)||o.goto==='ad'||/^ad_/.test(String(o.card_goto||''))||/^cm_/.test(String(o.card_type||''))||o.card_type==='small_cover_v10'&&o.card_goto==='game'||['ad','ad_inline'].includes(o.type);
}
function liveAd(o){return ad(o)||obj(o)&&(yes(o.show_ad_icon)||ad(o.card_data?.small_card_v1)||yes(o.card_data?.small_card_v1?.show_ad_icon));}
function json(url,body){
 const route=JSON_ROUTES.find(([,p])=>p.test(url));
 if(!route||typeof body!=='string'||body.length>8388608)return body;
 try{
  const r=JSON.parse(body),d=r.data;if(!obj(r)||!obj(d)||r.code!==0&&r.code!=='0')return body;
  let changed=false;
  function clear(o,k){if(Array.isArray(o[k])&&o[k].length){o[k]=[];changed=true;}}
  function filter(o,k,fn){if(!obj(o)||!Array.isArray(o[k]))return;const a=o[k].filter(x=>!fn(x));if(a.length!==o[k].length){o[k]=a;changed=true;}}
  if(route[0]==='splash'){
   for(const k of ['list','show','event_list','keep_ids','preload'])clear(d,k);
  }else if(route[0]==='live'){
   filter(d,'card_list',liveAd);filter(d,'list',liveAd);
  }else{
   for(const k of ['items','item']){
    if(!Array.isArray(d[k]))continue;
    for(const v of d[k])if(obj(v)&&Array.isArray(v.banner_item))filter(v,'banner_item',ad);
    filter(d,k,v=>ad(v)||obj(v)&&['banner_v8','banner_ipad_v8'].includes(v.card_type)&&Array.isArray(v.banner_item)&&v.banner_item.length===0);
   }
  }
  return changed?JSON.stringify(r):body;
 }catch(_){return body;}
}
function vi(b,p){
 let n=0,m=1;
 for(let i=0;i<8&&p<b.length;i++){const v=b[p++];n+=(v&127)*m;if(!Number.isSafeInteger(n))throw Error('varint');if(!(v&128))return [n,p];m*=128;}
 throw Error('varint');
}
function enc(n){const a=[];while(n>=128){a.push(n%128+128);n=Math.floor(n/128);}a.push(n);return Uint8Array.from(a);}
function cat(a){const r=new Uint8Array(a.reduce((n,v)=>n+v.length,0));let p=0;for(const v of a){r.set(v,p);p+=v.length;}return r;}
function wrap(n,b){return cat([enc(n*8+2),enc(b.length),b]);}
function parse(b){
 let p=0;const a=[];
 while(p<b.length){
  if(a.length>=20000)throw Error('fields');
  const s=p;let tag;[tag,p]=vi(b,p);const n=Math.floor(tag/8),w=tag%8;
  if(n<1||n>536870911)throw Error('tag');
  let data,value;
  if(w===0){const start=p;let done=false;for(let j=0;j<10&&p<b.length;j++){if(!(b[p++]&128)){done=true;break;}}if(!done)throw Error('varint');try{[value]=vi(b,start);}catch(_){}}
  else if(w===1)p+=8;
  else if(w===5)p+=4;
  else if(w===2){let l;[l,p]=vi(b,p);if(l>b.length-p)throw Error('length');data=b.subarray(p,p+l);p+=l;}
  else throw Error('wire');
  if(p>b.length)throw Error('truncated');
  a.push({n,w,data,value,raw:b.subarray(s,p)});
 }
 return a;
}
function strip(b,fn){const f=parse(b);let changed=false;const a=[];for(const v of f){const out=fn(v);if(out===null){changed=true;continue;}if(out!==v.raw)changed=true;a.push(out);}return changed?cat(a):b;}
function dynamicAd(b){return parse(b).some(f=>f.n===1&&f.w===0&&f.value===15);}
function payload(id,b){
 if(id==='pause'){parse(b);return b.length?new Uint8Array(0):b;}
 if(id==='unite')return strip(b,f=>f.n===7&&f.w===2?null:f.raw);
 if(id==='view')return strip(b,f=>{
  if(f.w===2&&[30,31,41].includes(f.n))return null;
  return f.raw;
 });
 if(id==='dynamic')return strip(b,f=>{
  if(f.n!==1||f.w!==2)return f.raw;
  const n=strip(f.data,v=>v.n===1&&v.w===2&&dynamicAd(v.data)?null:v.raw);
  return n===f.data?f.raw:wrap(1,n);
 });
 return b;
}
function frame(b){const h=new Uint8Array(5);new DataView(h.buffer).setUint32(1,b.length,false);return cat([h,b]);}
function header(h,k){const a=Object.keys(h||{}).find(x=>x.toLowerCase()===k);return a===undefined?'':String(h[a]);}
function grpc(url,b,h={},ungzip){
 const route=PROTO_ROUTES.find(([,p])=>p.test(url));
 if(!route||!(b instanceof Uint8Array)||b.length<5||b.length>2097152)return b;
 const status=header(h,'grpc-status');if(status&&status!=='0')return b;
 const type=header(h,'content-type');if(type&&!/^application\/grpc(?:[+;]|$)/i.test(type))return b;
 try{
  let p=0,changed=false;const parts=[];
  while(p<b.length){
   if(b.length-p<5)throw Error('frame');
   const flag=b[p],n=new DataView(b.buffer,b.byteOffset+p+1,4).getUint32(0,false);
   if(n>b.length-p-5||flag!==0&&flag!==1)throw Error('frame');
   const original=b.subarray(p,p+5+n);let data=b.subarray(p+5,p+5+n);
   if(flag===1){
    if(header(h,'grpc-encoding').toLowerCase()!=='gzip'||typeof ungzip!=='function')return b;
    data=ungzip(data);if(!(data instanceof Uint8Array)||data.length>8388608)return b;
   }
   const out=payload(route[0],data);
   if(out!==data){parts.push(frame(out));changed=true;}else parts.push(original);
   p+=5+n;
  }
  return changed?cat(parts):b;
 }catch(_){return b;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={json,grpc,parse,wrap,frame,cat,enc};
if(typeof $done==='function'){
 let result={};
 try{
  const raw=$response.status??$response.statusCode;
  const m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));
  if(Number(m?m[1]:raw)===200){
   const b=$response.body;
   const u=String($request.url);
   const next=typeof b==='string'?json(u,b):grpc(u,b,$response.headers,typeof $utils!=='undefined'&&typeof $utils.ungzip==='function'?x=>$utils.ungzip(x):undefined);
   if(next!==b)result={body:next};
  }
 }catch(_){}
 $done(result);
}
})();
