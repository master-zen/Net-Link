(() => {
'use strict';
const routes=[["splash0","^https?://guide-acs\\.m\\.taobao\\.com/gw/mtop\\.taobao\\.wireless\\.home\\.splash\\.awesome\\.get(?:\\?[^#]*)?$"],["splash1","^https?://guide-acs\\.m\\.taobao\\.com/gw/mtop\\.taobao\\.wireless\\.home\\.splash\\.awesome\\.get/[^?#]*(?:\\?[^#]*)?$"]].map(([,p])=>new RegExp(p));
function transform(url,body){
 if(!routes.some(p=>p.test(url))||typeof body!=='string'||body.length>1048576)return body;
 try{
  const root=JSON.parse(body);
  if(!root||typeof root!=='object'||Array.isArray(root)||Array.isArray(root.ret)&&root.ret.length&&!root.ret.some(s=>typeof s==='string'&&/^SUCCESS(?:::|$)/.test(s)))return body;
  let changed=false,budget=50000;
  function visit(n,depth){
   if(!n||typeof n!=='object')return;
   if(depth>48||--budget<0)throw Error('limit');
   for(const k of Object.keys(n)){
    const v=n[k];
    if(k==='taobao-splash'&&v&&typeof v==='object'){
     if(Array.isArray(v.data)&&v.data.length){v.data=[];changed=true;}
    }else visit(v,depth+1);
   }
  }
  visit(root,0);
  if(!changed)return body;
  if(/(?:^|[:[,])\s*-?\d{16,}(?=\s*[,}\]])/.test(body))return body;
  return JSON.stringify(root);
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform};
if(typeof $done==='function'){let out={};try{const raw=$response.status??$response.statusCode??200,m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));if(Number(m?m[1]:raw)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}$done(out);}
})();
