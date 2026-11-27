(() => {
'use strict';
const routes=[["start0","^https?://api\\.m\\.jd\\.com/client\\.action\\?(?:[^#&]*&)*functionId=start(?:&[^#]*)?$"],["start1","^https://api\\.m\\.jd\\.com/api\\?(?:[^#&]*&)*functionId=start(?:&[^#]*)?$"],["welcomeHome","^https?://api\\.m\\.jd\\.com/client\\.action\\?(?:[^#&]*&)*functionId=welcomeHome(?:&[^#]*)?$"],["personinfoBusiness","^https?://api\\.m\\.jd\\.com/client\\.action\\?(?:[^#&]*&)*functionId=personinfoBusiness(?:&[^#]*)?$"],["deliverLayer","^https?://api\\.m\\.jd\\.com/client\\.action\\?(?:[^#&]*&)*functionId=deliverLayer(?:&[^#]*)?$"],["orderTrackBusiness","^https?://api\\.m\\.jd\\.com/client\\.action\\?(?:[^#&]*&)*functionId=orderTrackBusiness(?:&[^#]*)?$"],["getTabHomeInfo","^https?://api\\.m\\.jd\\.com/client\\.action\\?(?:[^#&]*&)*functionId=getTabHomeInfo(?:&[^#]*)?$"]].map(([k,p])=>[k,new RegExp(p)]);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const own=(o,k)=>obj(o)&&Object.prototype.hasOwnProperty.call(o,k);
function transform(url,body){
 const r=routes.find(([,p])=>p.test(url));
 if(!r||typeof body!=='string'||body.length>8388608)return body;
 if((url.match(/(?:\?|&)functionId=/g)||[]).length!==1)return body;
 try{
  const x=JSON.parse(body);
  if(!obj(x)||own(x,'code')&&![0,'0',200,'200'].includes(x.code))return body;
  let changed=false;
  function del(o,k){if(own(o,k)){delete o[k];changed=true;}}
  function zero(o,k){if(own(o,k)&&o[k]!==0){o[k]=0;changed=true;}}
  function filter(o,k,fn){if(!obj(o)||!Array.isArray(o[k]))return;const a=o[k].filter(v=>!fn(v));if(a.length!==o[k].length){o[k]=a;changed=true;}}
  const id=r[0];
  if(id.startsWith('start')){
   if(Array.isArray(x.images))for(const group of x.images)if(Array.isArray(group))for(const image of group)zero(image,'showTimes');
   zero(x,'showTimesDaily');
  }else if(id==='welcomeHome'){
   filter(x,'floorList',v=>['bottomXview','float','photoCeiling','tabBarAtmosphere'].includes(v?.type));
   del(x,'promotionTabs');
  }else if(id==='personinfoBusiness'){
   for(const o of [x,x.others]){
    filter(o,'floors',v=>['bigSaleFloor','newBigSaleFloor'].includes(v?.mId));
    if(Array.isArray(o?.floors))for(const v of o.floors)if(v?.mId==='basefloorinfo')del(v.data,'floatLayer');
   }
  }else if(id==='deliverLayer'||id==='orderTrackBusiness'){
   filter(x,'floors',v=>v?.mId==='jdDeliveryBanner');
  }else if(id==='getTabHomeInfo'){
   del(x.result,'iconInfo');
  }
  if(!changed)return body;
  if(/(?:^|[:[,])\s*-?\d{16,}(?=\s*[,}\]])/.test(body))return body;
  return JSON.stringify(x);
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform};
if(typeof $done==='function'){let out={};try{const raw=$response.status??$response.statusCode??200,m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));if(Number(m?m[1]:raw)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}$done(out);}
})();
