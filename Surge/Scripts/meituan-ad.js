(() => {
'use strict';
const routes=[["load","^https?://wmapi\\.meituan\\.com/api/v[0-9]+/loadInfo(?:\\?[^#]*)?$"],["load-slash","^https?://wmapi\\.meituan\\.com/api/v[0-9]+/loadInfo/(?:\\?[^#]*)?$"]].map(x=>new RegExp(x[1]));
function transform(url,body){
 if(!routes.some(p=>p.test(String(url)))||typeof body!=='string'||body.length>1048576)return body;
 try{
  const x=JSON.parse(body);
  const start=x?.data?.startpicture;
  if(!start||typeof start!=='object'||Array.isArray(start))return body;
  let changed=false;
  for(const k of ['ad','mk'])if(Array.isArray(start[k])&&start[k].length){start[k]=[];changed=true;}
  return changed?JSON.stringify(x):body;
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform};
if(typeof $done==='function'){
 let out={};
 try{
  const raw=$response.status??$response.statusCode??200;
  const m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));
  const code=Number(m?m[1]:raw);
  if(code>=200&&code<300){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}
 }catch(_){}
 $done(out);
}
})();
