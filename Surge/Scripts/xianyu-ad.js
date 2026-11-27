(() => {
'use strict';
const routes=[["home","^https?://(?:g-)?acs\\.m\\.goofish\\.com/gw/mtop\\.taobao\\.idlehome\\.home\\.nextfresh(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["local","^https?://(?:g-)?acs\\.m\\.goofish\\.com/gw/mtop\\.taobao\\.idle\\.local\\.home(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["search","^https?://(?:g-)?acs\\.m\\.goofish\\.com/gw/mtop\\.taobao\\.idlemtopsearch\\.search(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["community","^https?://(?:g-)?acs\\.m\\.goofish\\.com/gw/mtop\\.taobao\\.idlehome\\.home\\.community(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["newitem","^https?://(?:g-)?acs\\.m\\.goofish\\.com/gw/mtop\\.taobao\\.idlehome\\.home\\.newitem\\.page(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"]].map(([id,p])=>[id,new RegExp(p)]);
const yes=v=>v===true||v==='true';
const ad=v=>v?.data?.bizType==='AD'||v?.data?.clickParam?.args?.cardType==='mamaAD'||v?.template?.cardEnum==='ads';
const searchAd=v=>{const e=v?.data?.item?.main?.exContent;return yes(e?.isAliMaMaAD)||e?.dislikeFeedback?.clickParam?.args?.bizType==='ad'||ad(v);};
function transform(url,body){
 const r=routes.find(([,p])=>p.test(url));
 if(!r||typeof body!=='string'||body.length>8388608)return body;
 try{
  const x=JSON.parse(body);
  if(!x||typeof x!=='object'||Array.isArray(x)||Array.isArray(x.ret)&&x.ret.length&&!x.ret.some(s=>typeof s==='string'&&/^SUCCESS(?:::|$)/.test(s)))return body;
  const d=x.data;
  if(!d||typeof d!=='object')return body;
  const k=r[0]==='search'?'resultList':r[0]==='community'?'feedsList':'sections';
  if(!Array.isArray(d[k]))return body;
  const a=d[k].filter(v=>!(r[0]==='search'?searchAd(v):ad(v)));
  if(a.length===d[k].length)return body;
  const numbers=/"(?:\\[\s\S]|[^"\\])*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  for(const m of body.matchAll(numbers))if(m[0][0]!=='"'&&!Number.isSafeInteger(Number(m[0]))&&Math.abs(Number(m[0]))>=Number.MAX_SAFE_INTEGER)return body;
  d[k]=a;
  return JSON.stringify(x);
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform};
if(typeof $done==='function'){let out={};try{const raw=$response.status??$response.statusCode??200,m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));if(Number(m?m[1]:raw)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}$done(out);}
})();
