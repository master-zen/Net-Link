(() => {
'use strict';
const ROUTES=[["drive","^https?://m5\\.amap\\.com/ws/perception/drive/(?:routeInfo|routePlan)(?:\\?[^#]*)?$"],["bus","^https?://m5\\.amap\\.com/ws/bus/plan/integrate(?:\\?[^#]*)?$"],["marketing","^https?://m5\\.amap\\.com/ws/shield/search_business/process/marketingOperationStructured(?:\\?[^#]*)?$"],["suggest","^https?://m5\\.amap\\.com/ws/shield/search_poi/sug(?:\\?[^#]*)?$"],["search","^https?://m5\\.amap\\.com/ws/shield/search_poi/(?:mps|search/sp)(?:\\?[^#]*)?$"],["detail","^https?://(?:info|m5)\\.amap\\.com/ws/shield/search/poi/detail(?:\\?[^#]*)?$"],["tips","^https?://m5\\.amap\\.com/ws/shield/search_poi/tips_operation_location(?:\\?[^#]*)?$"],["home","^https?://m5\\.amap\\.com/ws/faas/amap-navigation/(?:main-page|card-service-plan-home)(?:\\?[^#]*)?$"],["profile","^https?://m5\\.amap\\.com/ws/shield/dsp/profile/index/nodefaasv3(?:\\?[^#]*)?$"],["taxi","^https?://m5-zb\\.amap\\.com/ws/boss/car/order/content_info(?:\\?[^#]*)?$"],["taxipromo","^https?://m5-zb\\.amap\\.com/ws/promotion-web/resource(?:/home)?(?:\\?[^#]*)?$"],["hotel","^https?://m5\\.amap\\.com/ws/c3frontend/af-hotel/page/main(?:\\?[^#]*)?$"],["config","^https?://m0\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m1\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m2\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m3\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m4\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m5\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m6\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m7\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m8\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"],["config","^https?://m9\\.amap\\.com/ws/shield/frogserver/aocs/updatable/1/?(?:\\?[^#]*)?$"]].map(([k,p])=>[k,new RegExp(p)]);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const own=(o,k)=>obj(o)&&Object.prototype.hasOwnProperty.call(o,k);
const yes=x=>x===true||x===1||x==='1';
const ad=x=>obj(x)&&(yes(x.isAd)||yes(x.is_ad)||['ad','poi_ad','brandAdCard','advertisement'].includes(x.result_type)||['ad','poi_ad','brandAdCard','advertisement'].includes(x.item_type)||['ad','poi_ad'].includes(x.task_tag));
const navAd=x=>obj(x)&&typeof x.dynamic_id_s==='string'&&/^ads-\d+(?:$|[-_])/.test(x.dynamic_id_s);
const POI=new Set(['CouponBanner','adv_gift','common_coupon_bar','common_coupon_card','kaMarketingCampaign','new_operation_banner','operation_banner','poster_banner','yellowPageAdRecommendModule']);
const TIPS=new Set(['coupon_discount_float_bar','coupon_float_bar','discount_coupon','mood_coupon_banner','operation_brand','promotion_wrap_card']);
function transform(url,body){
 const r=ROUTES.find(([,p])=>p.test(url));
 if(!r||typeof body!=='string'||body.length>8388608)return body;
 try{
  const x=JSON.parse(body);
  if(!obj(x)||x.status===0||x.status==='0'||x.status==='error'||(own(x,'code')&&![0,'0',1,'1',200,'200','10000',10000].includes(x.code)))return body;
  let changed=false;const d=x.data;
  function del(o,k){if(own(o,k)){delete o[k];changed=true;}}
  function filter(o,k,p){if(!obj(o)||!Array.isArray(o[k]))return;const a=o[k].filter(v=>!p(v));if(a.length!==o[k].length){o[k]=a;changed=true;}}
  function clear(o,k){filter(o,k,()=>true);}
  function fields(o,keys){for(const k of keys)del(o,k);}
  function modules(o,keys){
   if(!obj(o)||!obj(o.modules))return;
   for(const k of keys)del(o.modules,k);
   const keep=v=>typeof v==='string'&&keys.has(v);
   if(obj(o.regions))for(const k of Object.keys(o.regions))filter(o.regions,k,keep);
   filter(o.meta,'half_hidden_modules',keep);
   const a=o.modules.anchor?.data;
   if(Array.isArray(a?.items)){
    for(const v of a.items)if(obj(v))filter(v,'anchor',keep);
    filter(a,'items',v=>obj(v)&&Array.isArray(v.anchor)&&v.anchor.length===0);
   }
  }
  function config(key,keys){
   const o=d?.[key];if(!obj(o)||typeof o.value!=='string')return;
   try{const v=JSON.parse(o.value);if(!obj(v))return;let c=false;for(const k of keys)if(own(v,k)){delete v[k];c=true;}if(c){o.value=JSON.stringify(v);changed=true;}}catch(_){}
  }
  switch(r[0]){
   case 'drive':filter(d?.tbt,'event',navAd);filter(d?.front_end,'download',navAd);break;
   case 'bus':filter(d?.banner_lists,'data',ad);break;
   case 'marketing':fields(d,['commonMaterial','tipsOperationLocation','resourcePlacement']);break;
   case 'suggest':{
    const p=v=>obj(v)&&ad(v.tip);
    filter(x,'tip_list',p);
    if(Array.isArray(x.city_list))for(const c of x.city_list)filter(c,'tip_list',p);
    break;
   }
   case 'search':{
    const lists=[d?.list_data,d?.modules?.list_data?.data,d?.modules?.not_parse_result?.data?.list_data];
    for(const l of lists)filter(l,'content',v=>ad(v)||obj(v)&&v.card?.card_id==='SearchCardBrand'&&v.item_type==='brandAdCard');
    break;
   }
   case 'detail':modules(d,POI);break;
   case 'tips':modules(d,TIPS);break;
   case 'home':
    for(const k of ['cardList','mapBizList','children'])filter(d,k,ad);
    break;
   case 'profile':filter(d,'cardList',ad);break;
   case 'config':
    for(const k of ['SplashScreenControl','splashscreen','splashview_config']){
     const o=d?.[k];if(obj(o)&&own(o,'value')&&(o.value!==''||o.status!==1||o.version!=='')){o.status=1;o.version='';o.value='';changed=true;}
    }
    config('amap_basemap_config',['splash','ai_splash']);
    config('engine_render',['can_show_advert','advert_note_num']);
    config('navi_cloud',['long_trip_service_coupon','long_trip_service_coupon_enter','long_trip_service_coupon_links','QQMusicVipText','ETCGuide','etc_banner']);
    config('taxi',['denghuo_ad','dache_toolbox_promo','dache_toolbox_marketing']);
    break;
   case 'taxi':clear(d?.lubanData?.skin,'dataList');break;
   case 'taxipromo':fields(d,['alpha','banner','bravo','charlie']);break;
   case 'hotel':
    modules(d,new Set(['CouponPortalCard','CouponWidget']));
    fields(d?.modules?.user_filter_card?.data,['banner','bannerList']);
    break;
  }
  return changed?JSON.stringify(x):body;
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,ad,navAd};
if(typeof $done==='function'){
 let out={};
 try{const raw=$response.status??$response.statusCode;const m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));if(Number(m?m[1]:raw)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}
 $done(out);
}
})();
