(() => {
'use strict';
const routes=[["home","^https?://conf\\.diditaxi\\.com\\.cn/homepage/v1/other/fast/?(?:\\?[^#]*)?$"],["activity","^https?://res\\.xiaojukeji\\.com/resapi/activity/mget/?(?:\\?[^#]*)?$"]];
function filterResponse(url,body,routes){
 if(typeof body!=='string'||body.length>2097152)return body;
 const r=routes.find(([,p])=>new RegExp(p).test(url));
 if(!r)return body;
 try{
  const x=JSON.parse(body),obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v),own=(o,k)=>obj(o)&&Object.prototype.hasOwnProperty.call(o,k);
  if(!obj(x)||!obj(x.data)||x.success===false)return body;
  for(const k of ['code','errno','errNo','error_code','status_code'])if(own(x,k)&&![0,'0',200,'200'].includes(x[k]))return body;
  let changed=false;
  function del(o,k){if(own(o,k)){delete o[k];changed=true;}}
  if(r[0]==='home'){del(x.data.order_cards,'marketing_card');del(x.data.order_cards,'super_banner_card');}
  if(r[0]==='activity')del(x.data,'mult_home_banner');
  if(!changed)return body;
  const numbers=/"(?:\\[\s\S]|[^"\\])*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  for(const m of body.matchAll(numbers))if(m[0][0]!=='"'&&!Number.isSafeInteger(Number(m[0]))&&Math.abs(Number(m[0]))>=Number.MAX_SAFE_INTEGER)return body;
  return JSON.stringify(x);
 }catch(_){return body;}
}
const transform=(url,body)=>filterResponse(url,body,routes);
if(typeof module!=='undefined'&&module.exports)module.exports={transform};
if(typeof $done==='function'){let out={};try{const raw=$response.status??$response.statusCode??200,m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));if(Number(m?m[1]:raw)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}$done(out);}
})();
