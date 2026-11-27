(() => {
  'use strict';
  const MAX=4*1024*1024;
  const host='(?:spclient\\.wg|[a-z0-9-]+-spclient(?:\\.wg)?)\\.spotify\\.com';
  const route=new RegExp('^https://'+host+'(?::443)?/(bootstrap/v1/bootstrap|user-customization-service/v1/customize|nebula/v[0-9]+/configuration/attributes|remote-config-resolver/v[0-9]+/configuration|casita/v[0-9]+/home/default)/?(?:\\?[^#]*)?$','i');
  const attrs=new Map([['ads',false],['shuffle',false],['unrestricted',true],['on-demand',true],['pick-and-shuffle',false],['shuffle-eligible',true]]);
  const flags=new Set(['enable_ads','enable_audio_ads','enable_display_ads','enable_video_ads','enable_ads_on_podcast','enable_pick_and_shuffle_common_capping','enable_pick_and_shuffle_dynamic_cap']);
  function vi(n) {
    if(!Number.isSafeInteger(n)||n<0)throw Error('varint');
    const a=[]; do{const b=n%128;n=Math.floor(n/128);a.push(b+(n?128:0));}while(n);return Uint8Array.from(a);
  }
  function read(b,c,scalar=false) {
    let v=0,m=1;for(let i=0;i<10;i++){if(c.p>=b.length)throw Error('truncated');const x=b[c.p++];if(i===9&&x>1)throw Error('overflow');if(!scalar){v+=(x&127)*m;if(!Number.isSafeInteger(v))throw Error('overflow');}if(!(x&128))return v;m*=128;}throw Error('varint');
  }
  function join(a){const n=a.reduce((s,b)=>s+b.length,0);if(n>MAX)throw Error('size');const out=new Uint8Array(n);let p=0;for(const b of a){out.set(b,p);p+=b.length;}return out;}
  function parse(b){if(b.length>MAX)throw Error('size');let c={p:0},a=[];while(c.p<b.length){if(a.length>=50000)throw Error('fields');const start=c.p,t=read(b,c),n=Math.floor(t/8),w=t%8;if(!n||n>536870911)throw Error('tag');let p=c.p;if(w===0)read(b,c,true);else if(w===1)c.p+=8;else if(w===5)c.p+=4;else if(w===2){const len=read(b,c);p=c.p;c.p+=len;}else throw Error('wire');if(c.p>b.length)throw Error('truncated');a.push({n,w,d:b.subarray(p,c.p),raw:b.subarray(start,c.p)});}return a;}
  function field(n,d,w=2){return join(w===2?[vi(n*8+w),vi(d.length),d]:[vi(n*8+w),d]);}
  function str(b){if(!b||b.length>512)return '';return Array.from(b,x=>String.fromCharCode(x)).join('');}
  function enc(s){return Uint8Array.from(s,c=>c.charCodeAt(0));}
  function eq(a,b){return a.length===b.length&&a.every((x,i)=>x===b[i]);}
  function one(a,n,w=2){const f=a.filter(x=>x.n===n&&x.w===w);return f.length===1?f[0]:null;}
  function map(b,n,fn){let changed=false;const out=parse(b).map(f=>{if(f.n!==n||f.w!==2)return f.raw;const d=fn(f.d);if(eq(d,f.d))return f.raw;changed=true;return field(n,d);});return changed?join(out):b;}
  function at(b,path,fn){return path.length?map(b,path[0],d=>at(d,path.slice(1),fn)):fn(b);}
  function attributes(b){
    const a=parse(b);if(!a.length)return b;
    for(const f of a){if(f.n!==1||f.w!==2)continue;const k=parse(f.d),key=one(k,1),value=one(k,2);if(!key||!value)return b;parse(value.d);}
    return map(b,1,d=>{const k=parse(d),key=one(k,1),value=one(k,2),name=str(key?.d);if(!value||!attrs.has(name))return d;
      const parts=parse(value.d);if(!parts.some(f=>f.n===2&&f.w===0)||parts.some(f=>f.n===3||f.n===4))return d;
      return map(d,2,v=>join(parse(v).map(f=>f.n===2&&f.w===0?field(2,vi(attrs.get(name)?1:0),0):f.raw)));
    });
  }
  function config(b){
    return map(b,3,d=>{const a=parse(d),id=one(a,1),val=one(a,3);if(!id||!val||!flags.has(str(one(parse(id.d),2)?.d)))return d;
      if(a.some(f=>f.n===4||f.n===5))return d;
      return map(d,3,v=>{const a=parse(v);return a.some(f=>f.n===1&&f.w===0)?join(a.map(f=>f.n===1&&f.w===0?field(1,vi(0),0):f.raw)):v;});
    });
  }
  function looksConfig(b){try{const a=parse(b),v=a.filter(f=>f.n===3&&f.w===2);return v.length>0&&a.every(f=>f.n<=4)&&v.every(f=>{const id=one(parse(f.d),1);return id&&one(parse(id.d),1)&&one(parse(id.d),2);});}catch(_){return false;}}
  function remote(b){if(looksConfig(b))return config(b);const f=one(parse(b),1);return f&&looksConfig(f.d)?map(b,1,config):b;}
  function ucs(b){return map(map(b,1,d=>map(d,1,config)),3,attributes);}
  function home(b){return map(b,1,d=>{const a=parse(d);const out=a.filter(f=>{if(f.n!==1||f.w!==2)return true;const id=one(parse(f.d),1);if(!id)return true;const name=str(one(parse(id.d),1)?.d);return !(name.startsWith('spotify:section:')&&name.endsWith('|brand-ad'));});return out.length===a.length?d:join(out.map(f=>f.raw));});}
  function transform(b,path){
    if(path==='bootstrap/v1/bootstrap')return at(b,[2,1,1,1],ucs);
    if(path==='user-customization-service/v1/customize')return map(b,1,ucs);
    if(path.startsWith('nebula/'))return attributes(b);
    if(path.startsWith('remote-config-resolver/'))return remote(b);
    if(path.startsWith('casita/'))return home(b);
    return b;
  }
  function run(){let out={};try{const m=route.exec($request.url);const method=String($request.method||'').toUpperCase();if(m&&Number($response.status)===200&&(method==='POST'||method==='GET'&&/^(nebula|casita|remote-config-resolver)\//.test(m[1]))){const raw=$response.body;const b=raw instanceof ArrayBuffer?new Uint8Array(raw):ArrayBuffer.isView(raw)?new Uint8Array(raw.buffer,raw.byteOffset,raw.byteLength):null;if(b&&b.length&&b.length<=MAX){const d=transform(b,m[1]);if(!eq(b,d))out={body:d};}}}catch(_){}$done(out);}
  if(typeof module!=='undefined'&&module.exports)module.exports={vi,field,join,parse,enc,transform,route,run};
  if(typeof $done==='function')run();
})();
