(() => {
'use strict';
const ROUTES = [["ad-loading","^https?://(?:adse(?:\\.wsa)?|adsehera)\\.ximalaya\\.com(?::(?:80|443))?/ting/loading(?:/ts-[0-9]+)?/?(?:\\?[^#]*)?$"],["ad-slots","^https?://(?:adse(?:\\.wsa)?|adsehera)\\.ximalaya\\.com(?::(?:80|443))?/adx/ad(?:/ts-[0-9]+)?/?(?:\\?[^#]*)?$"],["feed","^https?://(?:mobile|mobilehera|mobwsa)\\.ximalaya\\.com(?::(?:80|443))?/discovery-feed/v[0-9]+/mix(?:/[^?#]*)?(?:\\?[^#]*)?$"],["focus","^https?://(?:mobile|mobilehera|mobwsa)\\.ximalaya\\.com(?::(?:80|443))?/focus-mobile/focusPic(?:/[^?#]*)?(?:\\?[^#]*)?$"],["category","^https?://(?:mobile|mobilehera|mobwsa)\\.ximalaya\\.com(?::(?:80|443))?/discovery-category/v[0-9]+/category(?:/[^?#]*)?(?:\\?[^#]*)?$"],["portal","^https?://(?:mobile|mobilehera|mobwsa)\\.ximalaya\\.com(?::(?:80|443))?/football-portal/diff2/batch/?(?:\\?[^#]*)?$"],["player","^https?://(?:mobile|mobilehera|mobwsa)\\.ximalaya\\.com(?::(?:80|443))?/mobile-playpage/playpage/tabs/v[0-9]+(?:/[^?#]*)?(?:\\?[^#]*)?$"],["profile","^https?://(?:mobile|mobilehera|mobwsa)\\.ximalaya\\.com(?::(?:80|443))?/mobile-user/v[0-9]+/homePage(?:/[^?#]*)?(?:\\?[^#]*)?$"],["guide","^https?://(?:search|searchwsa)\\.ximalaya\\.com(?::(?:80|443))?/hub/guideWordV[0-9]+(?:/[^?#]*)?(?:\\?[^#]*)?$"]].map(([id,p])=>[id,new RegExp(p)]);
const SLOTS = new Set([1,28,44,293,316,318]);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const own=(o,k)=>obj(o)&&Object.prototype.hasOwnProperty.call(o,k);
const yes=x=>x===true||x===1||x==='1'||x==='true';
const nonempty=x=>obj(x)?Object.keys(x).length>0:Array.isArray(x)?x.length>0:typeof x==='string'?x.length>0:yes(x);
function ad(x){
 if(!obj(x))return false;
 return yes(x.isAd)||yes(x.is_ad)||yes(x.isSponsored)||yes(x.sponsored)||nonempty(x.adInfo)||x.moduleType==='mix_ad'||['IndexFeedAd/DoubleStream','IndexFeedAd/BigPicture'].includes(x.itemType)||['ad','advert','advertisement','sponsored','mix_ad'].includes(String(x.bizType||x.type||'').toLowerCase());
}
function transform(url,body){
 const route=ROUTES.find(([,p])=>p.test(String(url)));
 if(!route||typeof body!=='string'||body.length>8388608)return body;
 try{
  const x=JSON.parse(body);
  if(!obj(x)||(own(x,'ret')&&x.ret!==0&&x.ret!=='0'))return body;
  let changed=false;
  function filter(o,k,predicate=ad){
   if(!obj(o)||!Array.isArray(o[k]))return;
   const a=o[k].filter(v=>!predicate(v));
   if(a.length!==o[k].length){o[k]=a;changed=true;}
  }
  function clear(o,k,kind){
   if(!obj(o))return;
   const v=o[k];
   if(kind==='array'&&Array.isArray(v)&&v.length){o[k]=[];changed=true;}
   if(kind==='object'&&obj(v)&&Object.keys(v).length){o[k]={};changed=true;}
  }
  function remove(o,k){if(own(o,k)){delete o[k];changed=true;}}
  const feedAd=v=>ad(v)||(obj(v)&&ad(v.item));
  function cleanFeed(o){
   if(!obj(o))return;
   for(const k of ['body','heData','header']){
    filter(o,k,feedAd);
    if(!Array.isArray(o[k]))continue;
    for(const section of o[k]){
     if(!obj(section))continue;
     filter(section,'list',feedAd);
     if(obj(section.item)){
      filter(section.item,'list',feedAd);
      if(Array.isArray(section.item.list))for(const item of section.item.list)filter(item,'data');
      filter(section.item,'data');
     }
    }
   }
  }
  const id=route[0];
  if(id==='ad-loading'){
   if(x.ret!==0&&x.ret!=='0')return body;
   clear(x,'data','array');clear(x,'adTypes','array');clear(x,'bidSlotList','object');
  }else if(id==='ad-slots'){
   if(x.ret!==0&&x.ret!=='0')return body;
   if(Array.isArray(x.slotAds))for(const s of x.slotAds){
    if(obj(s)&&SLOTS.has(Number(s.positionId))){clear(s,'ads','array');clear(s,'bidSlotList','object');}
   }
  }else if(id==='feed'||id==='focus'){
   cleanFeed(x);cleanFeed(x.data);
  }else if(id==='category'){
   for(const o of [x,x.data])if(obj(o)&&obj(o.focusImages))filter(o.focusImages,'data');
  }else if(id==='portal'){
   if(obj(x.json))remove(x.json,'ad');
  }else if(id==='player'){
   const resource=x.data?.playpage?.resourceMap;
   if(obj(resource)){
    for(const k of ['defaultResource','playPageTip']){
     if(ad(resource[k])||k==='playPageTip'&&obj(resource[k])&&ad(resource[k].resource))remove(resource,k);
     else if(Array.isArray(resource[k]))filter(resource,k);
    }
    for(const k of ['ad','ads','advertisement','adResource'])remove(resource,k);
   }
  }else if(id==='profile'){
   if(obj(x.data)){
    if(obj(x.data.serviceModule))filter(x.data.serviceModule,'entrances');
    for(const k of ['banners','ads','promotions'])filter(x.data,k);
   }
  }else if(id==='guide'){
   for(const o of [x,x.data])if(obj(o))for(const k of ['guideWords','list','words','items','data'])filter(o,k);
  }
  return changed?JSON.stringify(x):body;
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,ad,ROUTES};
if(typeof $done==='function'){
 let out={};
 try{
  const raw=$response.status??$response.statusCode;
  const match=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));
  if(Number(match?match[1]:raw)===200){
   const b=transform($request.url,$response.body);
   if(b!==$response.body)out={body:b};
  }
 }catch(_){}
 $done(out);
}
})();
