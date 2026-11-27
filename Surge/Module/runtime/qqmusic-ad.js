(() => {
'use strict';
const ROUTE=new RegExp("^https?://u\\.y\\.qq\\.com/cgi-bin/musicu\\.fcg(?:\\?[^#]*)?$");
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const own=(x,k)=>obj(x)&&Object.prototype.hasOwnProperty.call(x,k);
const yes=x=>x===true||x===1||x==='1'||x==='true';
const meaningful=x=>typeof x==='string'?x.trim()!==''&&x!=='0':typeof x==='number'?x>0:obj(x)?Object.keys(x).length>0:Array.isArray(x)?x.length>0:x===true;
function parseRequest(req){
 try{
  const q=/(?:\?|&)data=([^&#]*)/.exec(req.url);
  if(q){const v=JSON.parse(decodeURIComponent(q[1]));return obj(v)?v:null;}
  if(obj(req.body))return req.body;
  if(typeof req.body==='string'&&req.body.length<=1048576){const v=JSON.parse(req.body);return obj(v)?v:null;}
 }catch(_){}
 return null;
}
function isAdCard(c){
 if(!obj(c))return false;
 return yes(c.isAd)||yes(c.is_ad)||yes(c.sponsored)||['adid','ad_id','adId','adtype','ad_type'].some(k=>meaningful(c[k]))||[c.type,c.card_type,c.bizType].some(v=>typeof v==='string'&&/^(?:ad|advert|advertisement|sponsored)$/i.test(v));
}
function focusShape(d){
 if(!obj(d)||!obj(d.shelf)||!Array.isArray(d.shelf.v_card)&&!Array.isArray(d.shelf.v_niche))return false;
 return [d.shelf.title_template,d.shelf.title_content].some(v=>typeof v==='string'&&/^(?:首页焦点图|焦点图|焦点|focus)$/i.test(v.trim()));
}
function transform(req,body){
 if(!req||!ROUTE.test(String(req.url))||typeof body!=='string'||body.length>8388608)return body;
 try{
  const root=JSON.parse(body);
  if(!obj(root)||own(root,'code')&&root.code!==0&&root.code!=='0')return body;
  const meta=parseRequest(req);
  let changed=false,budget=30000;
  function scrub(node,depth){
   if(!node||typeof node!=='object'||depth>16||--budget<0)return;
   if(Array.isArray(node)){for(const v of node)scrub(v,depth+1);return;}
   for(const k of Object.keys(node)){
    if(/^(?:ad_config|ad_list|adlist|ad_info|adinfo|splash_ad|splashad)$/i.test(k)){
     const v=node[k];
     if(Array.isArray(v)&&v.length){node[k]=[];changed=true;}
     else if(obj(v)&&Object.keys(v).length){node[k]={};changed=true;}
     continue;
    }
    if(/^(?:v_card|v_niche)$/.test(k)&&Array.isArray(node[k])){
     const v=node[k].filter(c=>!isAdCard(c));
     if(v.length!==node[k].length){node[k]=v;changed=true;}
    }
    scrub(node[k],depth+1);
   }
  }
  for(const k of Object.keys(root)){
   if(!/^req(?:_\d+)?$/.test(k))continue;
   const v=root[k],m=meta&&meta[k];
   if(!obj(v)||!obj(v.data)||own(v,'code')&&v.code!==0&&v.code!=='0')continue;
   const hall=obj(m)&&m.module==='music.musicHall.MusicHallPlatform';
   const fallback=!meta&&focusShape(v.data);
   if(hall||fallback)scrub(v.data,0);
  }
  return changed?JSON.stringify(root):body;
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,isAdCard,parseRequest,ROUTE};
if(typeof $done==='function'){
 let out={};
 try{
  const raw=$response.status??$response.statusCode;
  const m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));
  if(Number(m?m[1]:raw)===200){const body=transform($request,$response.body);if(body!==$response.body)out={body};}
 }catch(_){}
 $done(out);
}
})();
