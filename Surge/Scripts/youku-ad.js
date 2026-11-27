(() => {
'use strict';
const ROUTES=[["startup","^https?://un-acs\\.youku\\.com/gw/mtop\\.youku\\.play\\.ups\\.appinfo\\.get(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["popup","^https?://push\\.m\\.youku\\.com/collect-api/get_push_interval_config_wx/?(?:\\?[^#]*)?$"],["detail","^https?://acs\\.youku\\.com/gw/mtop\\.youku\\.columbus\\.gateway\\.new\\.execute(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["feed","^https?://acs\\.youku\\.com/gw/mtop\\.youku\\.columbus\\.home\\.feed(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["channel","^https?://acs\\.youku\\.com/gw/mtop\\.youku\\.columbus\\.home\\.query(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["profile","^https?://acs\\.youku\\.com/gw/mtop\\.youku\\.columbus\\.uc\\.query(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["comments","^https?://acs\\.youku\\.com/gw/mtop\\.youku\\.columbus\\.ycp\\.query(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"],["search","^https?://acs\\.youku\\.com/gw/mtop\\.youku\\.soku\\.yksearch(?:/[0-9]+(?:\\.[0-9]+)*)?/?(?:\\?[^#]*)?$"]].map(([id,p])=>[id,new RegExp(p)]);
const TYPES=new Set(["PHONE_FEED_CARD_B_AD","PHONE_FEED_CARD_S_AD","PHONE_H_UC_AD","PHONE_YK_AD_BANNER","UC广告抽屉","橱窗广告","播放页广告组件"]);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const own=(o,k)=>obj(o)&&Object.prototype.hasOwnProperty.call(o,k);
const yes=v=>v===true||v===1||v==='1';
function ad(n){
 if(!obj(n))return false;
 return TYPES.has(n.typeName)||yes(n.isAd)||yes(n.is_ad)||yes(n.data?.isAd)||yes(n.data?.is_ad);
}
function transform(url,body){
 const match=ROUTES.find(([,p])=>p.test(String(url)));
 if(!match||typeof body!=='string'||body.length>8388608)return body;
 try{
  const root=JSON.parse(body);
  if(!obj(root)||Array.isArray(root.ret)&&root.ret.length&&!root.ret.some(s=>typeof s==='string'&&/^SUCCESS(?:::|$)/.test(s)))return body;
  let changed=false,budget=50000;
  function del(o,k){if(own(o,k)){delete o[k];changed=true;}}
  const id=match[0];
  if(id==='startup'){
   for(const k of ['ad','ykad'])del(root.data?.data,k);
  }else if(id==='popup'){
   for(const k of ['tipContent','tipContentNew'])del(root.data,k);
  }else{
   const start=id==='search'?root.data:root.data?.[id==='detail'?'2019030100':'2019061000']?.data;
   function clean(o,depth){
    if(!obj(o))return;
    if(depth>20||--budget<0)throw Error('limit');
    if(id==='channel')del(o.data,'crmSale');
    if(!Array.isArray(o.nodes))return;
    const a=o.nodes.filter(n=>{
     if(!obj(n))return true;
     if(ad(n))return false;
     if(id==='channel'&&[35505,272768].includes(Number(n.id)))return false;
     if(id==='profile'&&[32133,38466].includes(Number(n.id)))return false;
     if(id==='comments'&&Number(o.id)===23243&&Number(n.id)===-1000)return false;
     return true;
    });
    if(a.length!==o.nodes.length){o.nodes=a;changed=true;}
    for(const n of a)clean(n,depth+1);
   }
   clean(start,0);
  }
  return changed?JSON.stringify(root):body;
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,ad};
if(typeof $done==='function'){
 let out={};
 try{
  const raw=$response.status??$response.statusCode;
  const m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));
  if(Number(m?m[1]:raw)===200){
   const b=transform($request.url,$response.body);
   if(b!==$response.body)out={body:b};
  }
 }catch(_){}
 $done(out);
}
})();
