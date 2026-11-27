(() => {
'use strict';
const ROUTES=[["trpc","^https?://(?:i|pre)\\.video\\.qq\\.com/(?:\\?[^#]*)?$"],["jce","^https?://iacc\\.qq\\.com/(?:\\?[^#]*)?$"]].map(([id,p])=>[id,new RegExp(p)]);
const MAX=4194304;
const types=new Set(['AdResponseInfo','AdFeedInfo','InnerAdPromotionEventList','InnerAdCommonPromotionEventActivityList']);
const cat=a=>{const b=new Uint8Array(a.reduce((n,x)=>n+x.length,0));let p=0;for(const x of a){b.set(x,p);p+=x.length;}return b;};
const u32=(b,p)=>new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(p,false);
const put=(b,p,n)=>new DataView(b.buffer,b.byteOffset,b.byteLength).setUint32(p,n,false);
const ascii=b=>{if(b.length>512)return '';let s='';for(const x of b){if(x<32||x>126)return '';s+=String.fromCharCode(x);}return s;};
function contains(b,s){const a=Array.from(s,x=>x.charCodeAt(0));outer:for(let i=0;i<=b.length-a.length;i++){if(b[i]!==a[0])continue;for(let j=1;j<a.length;j++)if(b[i+j]!==a[j])continue outer;return true;}return false;}
function read(b,p){let n=0,m=1;for(let i=0;i<8&&p<b.length;i++){const x=b[p++];n+=(x&127)*m;if(!Number.isSafeInteger(n))throw Error('varint');if(!(x&128))return [n,p];m*=128;}throw Error('varint');}
function enc(n){const a=[];while(n>=128){a.push(n%128+128);n=Math.floor(n/128);}a.push(n);return Uint8Array.from(a);}
function wrap(n,b){return cat([enc(n*8+2),enc(b.length),b]);}
function fields(b){let p=0;const a=[];while(p<b.length){if(a.length>=20000)throw Error('fields');const s=p;let t;[t,p]=read(b,p);const n=Math.floor(t/8),w=t%8;let data;if(n<1||n>536870911)throw Error('tag');if(w===0){let ok=false;for(let j=0;j<10&&p<b.length;j++)if(!(b[p++]&128)){ok=true;break;}if(!ok)throw Error('int');}else if(w===1)p+=8;else if(w===5)p+=4;else if(w===2){let l;[l,p]=read(b,p);if(l>b.length-p)throw Error('length');data=b.subarray(p,p+l);p+=l;}else throw Error('wire');if(p>b.length)throw Error('bounds');a.push({n,w,data,raw:b.subarray(s,p)});}return a;}
function adAny(a){if(a.length!==2||a[0].n!==1||a[0].w!==2||a[1].n!==2||a[1].w!==2)return false;const s=ascii(a[0].data);return /^type\.googleapis\.com\/[A-Za-z0-9_.]+$/.test(s)&&types.has(s.split(/[./]/).pop());}
function proto(b,depth,budget){if(depth>12||--budget.n<0)throw Error('budget');let a;try{a=fields(b);}catch(_){return b;}let changed=false;const out=[];for(const f of a){if(f.w!==2||!contains(f.data,'type.googleapis.com/')){out.push(f.raw);continue;}let child;try{child=fields(f.data);}catch(_){out.push(f.raw);continue;}if(adAny(child)){changed=true;continue;}const next=proto(f.data,depth+1,budget);if(next!==f.data){changed=true;out.push(wrap(f.n,next));}else out.push(f.raw);}return changed?cat(out):b;}
function gzip(b){let crc=0xffffffff;for(const x of b){crc^=x;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}crc=(crc^0xffffffff)>>>0;const n=Math.max(1,Math.ceil(b.length/65535)),o=new Uint8Array(18+5*n+b.length);o.set([31,139,8,0,0,0,0,0,0,255]);let p=10;for(let i=0;i<n;i++){const l=Math.min(65535,b.length-i*65535);o.set([i===n-1?1:0,l&255,l>>>8,(~l)&255,((~l)>>>8)&255],p);p+=5;o.set(b.subarray(i*65535,i*65535+l),p);p+=l;}const v=new DataView(o.buffer);v.setUint32(p,crc,true);v.setUint32(p+4,b.length,true);return o;}
function unpack(b,ungzip){if(typeof ungzip!=='function'||b.length<18)throw Error('gzip');const n=new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(b.length-4,true);if(n>MAX)throw Error('size');const v=ungzip(b);if(!(v instanceof Uint8Array)||v.length!==n)throw Error('gzip');return v;}
function trpc(b,ungzip){const gz=b[0]===31&&b[1]===139;const v=gz?unpack(b,ungzip):b;if(v.length<16||v[0]!==9||v[1]!==48||u32(v,4)!==v.length)return b;const p=16+v[8]*256+v[9];if(p>v.length)return b;const data=v.subarray(p);if(!contains(data,'type.googleapis.com/'))return b;const out=proto(data,0,{n:5000});if(out===data)return b;const r=cat([v.subarray(0,p),out]);put(r,4,r.length);return gz?gzip(r):r;}
function jhead(b,p,e){if(p>=e)throw Error('head');const v=b[p++];let tag=v>>>4;if(tag===15){if(p>=e)throw Error('tag');tag=b[p++];}return {tag,t:v&15,p};}
function jint(b,p,e){const h=jhead(b,p,e),v=new DataView(b.buffer,b.byteOffset,b.byteLength);p=h.p;if(h.tag!==0)throw Error('count tag');if(h.t===12)return [0,p];const n=[1,2,4][h.t];if(!n||p+n>e)throw Error('int');return [n===1?v.getInt8(p):n===2?v.getInt16(p):v.getInt32(p),p+n];}
function jfield(b,p,e,d=0){if(d>24)throw Error('depth');const s=p,h=jhead(b,p,e);p=h.p;const start=p;let count,ds;
if(h.t<=5)p+=[1,2,4,8,4,8][h.t];else if(h.t===6){if(p>=e)throw Error('str');p+=1+b[p];}else if(h.t===7){if(p+4>e)throw Error('str');p+=4+u32(b,p);}else if(h.t===8||h.t===9){[count,p]=jint(b,p,e);if(count<0||count>10000)throw Error('count');for(let i=0;i<count*(h.t===8?2:1);i++)p=jfield(b,p,e,d+1).end;}else if(h.t===10){while(true){const x=jfield(b,p,e,d+1);p=x.end;if(x.t===11)break;}}else if(h.t===11||h.t===12){}else if(h.t===13){const z=jhead(b,p,e);if(z.t!==0||z.tag!==0)throw Error('simple');[count,p]=jint(b,z.p,e);if(count<0)throw Error('count');ds=p;p+=count;}else throw Error('type');if(p>e||p<=s)throw Error('bounds');return {...h,s,start,end:p,count,ds};}
function jfields(b,s,e){const a=[];while(s<e){if(a.length>10000)throw Error('fields');const x=jfield(b,s,e);if(x.t===11)throw Error('end');a.push(x);s=x.end;}return a;}
const empty=t=>Uint8Array.of(t*16+9,12);
function simple(tag,b){const n=b.length;const count=n===0?Uint8Array.of(12):n<=127?Uint8Array.of(0,n):n<=32767?Uint8Array.of(1,n>>>8,n&255):Uint8Array.of(2,n>>>24,(n>>>16)&255,(n>>>8)&255,n&255);return cat([Uint8Array.of(tag*16+13,0),count,b]);}
function edit(b,s,e,a,fn){let change=false;const r=[];for(const x of a){const v=fn(x);if(v){r.push(v);change=true;}else r.push(b.subarray(x.s,x.end));}return change?cat(r):null;}
function jcePayload(b,cmd){const a=jfields(b,0,b.length);
 if(cmd===129278||cmd===130273)return edit(b,0,b.length,a,x=>x.tag===2&&x.t===9&&x.count>0&&contains(b.subarray(x.start,x.end),'livemsg')?empty(2):null);
 if(cmd===129279){if(!contains(b,'ad_splash')&&!contains(b,'SpaServerData'))return null;return edit(b,0,b.length,a,x=>[2,3,4].includes(x.tag)&&x.t===9&&x.count>0?empty(x.tag):null);}
 if(cmd===129196)return edit(b,0,b.length,a,x=>{if(x.tag!==1||x.t!==10||b[x.end-1]!==11)return null;const inner=jfields(b,x.start,x.end-1);const v=edit(b,x.start,x.end-1,inner,y=>{if(y.tag!==1||y.t!==13)return null;const raw=b.subarray(y.ds,y.end),fields=jfields(raw,0,raw.length);if(fields.length!==1||fields[0].tag!==0||fields[0].t!==9||!fields[0].count||!contains(raw,'livemsg'))return null;return simple(1,empty(0));});return v?cat([b.subarray(x.s,x.start),v,Uint8Array.of(11)]):null;});
 return null;
}
function jce(b,ungzip,splashOnly=false){if(b.length<100||b[0]!==19||u32(b,1)!==b.length||b[b.length-1]!==3)return b;const cmd=b[8]*65536+b[9]*256+b[10];if(![129278,130273,129196,129279].includes(cmd)||splashOnly&&cmd!==129279)return b;let p=-1;for(let i=60;i<Math.min(b.length-18,140);i++)if(b[i]===31&&b[i+1]===139&&b[i+2]===8){p=i;break;}if(p<0)return b;const v=unpack(b.subarray(p,b.length-1),ungzip);if(v.length<18||v[0]!==38||u32(v,1)!==v.length||u32(b,p-4)!==v.length||v[v.length-1]!==40)return b;const a=jfields(v,16,v.length-1),body=a.filter(x=>x.tag===1&&x.t===13);if(body.length!==1)return b;const x=body[0],next=jcePayload(v.subarray(x.ds,x.end),cmd);if(!next)return b;const ni=cat([v.subarray(0,x.s),simple(1,next),v.subarray(x.end)]);put(ni,1,ni.length);const head=b.slice(0,p);put(head,p-4,ni.length);const out=cat([head,gzip(ni),Uint8Array.of(3)]);put(out,1,out.length);return out;}
function transform(url,b,ungzip,splashOnly=false){try{const r=ROUTES.find(([,p])=>p.test(url));if(!r||!(b instanceof Uint8Array)||b.length>1048576)return b;return r[0]==='trpc'?(splashOnly?b:trpc(b,ungzip)):jce(b,ungzip,splashOnly);}catch(_){return b;}}
const splashMethods=new Set(["/trpc.business_splash.ad_ssp_splash.splashService/GetSplashPreload","/trpc.business_splash.ad_ssp_splash.splashService/GetSplashRealtimePoll"]);
function splashRequest(url,b,ungzip){
 try{
  if(!ROUTES[0][1].test(url)||!(b instanceof Uint8Array)||b.length>1048576)return b;
  const gz=b[0]===31&&b[1]===139,v=gz?unpack(b,ungzip):b;
  if(v.length<16||v[0]!==9||v[1]!==48||u32(v,4)!==v.length)return b;
  const p=16+v[8]*256+v[9];
  if(p>v.length||p===16)return b;
  const header=v.subarray(16,p),all=fields(header).filter(f=>f.n===7);
  if(all.length!==1||all[0].w!==2)return b;
  const field=all[0],method=ascii(field.data);
  if(!splashMethods.has(method))return b;
  const copy=v.slice(),start=field.data.byteOffset-v.byteOffset,offset=method.lastIndexOf('/')+1;
  copy[start+offset]=88;
  return gz?gzip(copy):copy;
 }catch(_){return b;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,splashRequest,gzip,wrap,cat,put,simple,jcePayload};
if(typeof $done==='function'){
 let out={};
 try{
  const un=typeof $utils!=='undefined'&&typeof $utils.ungzip==='function'?v=>$utils.ungzip(v):undefined;
  if(typeof $response==='undefined'){
   const b=$request.body,next=splashRequest($request.url,b,un);
   if(next!==b)out={body:next};
  }else{
   const raw=$response.status??$response.statusCode,m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));
   if(Number(m?m[1]:raw)===200){
    const b=$response.body,only=typeof $argument!=='undefined'&&$argument==='splash-only';
    if(only&&b instanceof Uint8Array&&b.length>=100&&b.length<=1048576&&b[0]===19&&u32(b,1)===b.length&&b[b.length-1]===3&&ROUTES[1][1].test($request.url)&&[129278,130273,129196].includes(b[8]*65536+b[9]*256+b[10])&&typeof $httpAPI==='function'){
     $httpAPI('GET','/v1/modules',null,state=>{
      let result={};
      try{if(Array.isArray(state?.enabled)&&state.enabled.includes('Tencent Video AD Blacklist')){const next=transform($request.url,b,un);if(next!==b)result={body:next};}}catch(_){}
      $done(result);
     });
     return;
    }
    const next=transform($request.url,b,un,only);if(next!==b)out={body:next};
   }
  }
 }catch(_){}
 $done(out);
}
})();
