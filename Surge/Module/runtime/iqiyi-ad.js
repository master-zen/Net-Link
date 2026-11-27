(() => {
'use strict';
const ROUTES=[["mixer","^https?://(?:kjp|t7z)\\.cupid\\.iqiyi\\.com/mixer(?:\\?[^#]*)?$"],["home","^https?://(?:cards\\.iqiyi\\.com|access\\.if\\.iqiyi\\.com/3f1/cards\\.iqiyi\\.com|(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/3f1/cards\\.iqiyi\\.com)/views_home/3\\.0/qy_home(?:\\?[^#]*)?$"],["category","^https?://(?:cards\\.iqiyi\\.com|access\\.if\\.iqiyi\\.com/3f1/cards\\.iqiyi\\.com|(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/3f1/cards\\.iqiyi\\.com)/views_category/3\\.0/(?:category_home|categorylib_content|film_hybrid)(?:\\?[^#]*)?$"],["feed","^https?://(?:cards\\.iqiyi\\.com|access\\.if\\.iqiyi\\.com/3f1/cards\\.iqiyi\\.com|(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/3f1/cards\\.iqiyi\\.com)/waterfall(?:-plt)?/3\\.0/feed(?:\\?[^#]*)?$"],["player","^https?://cards\\.iqiyi\\.com/views_plt/3\\.0/player_tabs_v2(?:\\?[^#]*)?$"],["search","^https?://cards\\.iqiyi\\.com/views_search/3\\.0/(?:hot_query_)?search(?:\\?[^#]*)?$"],["comments","^https?://comment-card\\.iqiyi\\.com/views_comment/3\\.0/long_video_comments(?:\\?[^#]*)?$"],["config","^https?://iface2\\.iqiyi\\.com/fusion/3\\.0/common_switch(?:\\?[^#]*)?$"]].map(([id,p])=>[id,new RegExp(p)]);
const ALIASES=new Set(["ad_mobile_flow","ad_trueview","search_mid_text_ad","search_small_card_ad","hot_query_search_top_ad","play_ad_no_vip","play_vip_promotion","qy_home_vip_opr_banner"]);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const own=(x,k)=>obj(x)&&Object.prototype.hasOwnProperty.call(x,k);
const yes=x=>x===true||x===1||x==='1'||x==='true';
function ad(o){return obj(o)&&(ALIASES.has(o.alias_name)||yes(o.is_ad)||yes(o.isAd)||yes(o.isSponsored)||['ad','advert','advertisement'].includes(o.block_class)||['ad','advert','advertisement','sponsored'].includes(o.type));}
function transform(url,body){
 const route=ROUTES.find(([,p])=>p.test(String(url)));
 if(!route||typeof body!=='string'||body.length>4194304)return body;
 try{
  const r=JSON.parse(body);
  if(!obj(r))return body;
  let changed=false,budget=30000;
  const id=route[0];
  function del(o,k){if(own(o,k)){delete o[k];changed=true;}}
  function zero(o,k){if(own(o,k)&&[0,1,'0','1',true,false].includes(o[k])){const v=typeof o[k]==='string'?'0':typeof o[k]==='boolean'?false:0;if(o[k]!==v){o[k]=v;changed=true;}}}
  function walk(o,d=0){
   if(!obj(o)||d>12||--budget<0)return;
   for(const k of ['cards','blocks','items','l_blocks','r_blocks']){
    if(!Array.isArray(o[k]))continue;
    const a=o[k].filter(x=>!ad(x));if(a.length!==o[k].length){o[k]=a;changed=true;}
    for(const x of a)walk(x,d+1);
   }
   for(const k of ['top_banner','bottom_banner'])if(obj(o[k]))walk(o[k],d+1);
  }
  if(id==='mixer'){
   if(r.errorCode!==0&&r.errorCode!=='0')return body;
   for(const k of ['adSlots','splashLottieFile','splashUiConfig'])del(r,k);
  }else if(id==='config'){
   const c=r.content;if(!obj(c))return body;
   del(c.resource,'cast_device_ad');
   const s=c.switchs;
   if(obj(s)){
    zero(s.app_ad,'app_ad_enable');
    zero(s.ios_tech,'kPreadAdHintSwitch');
    zero(s.ios_tech,'ad_download');
    zero(s.m_qiyi_ios_tech,'KFocusAdVideoPlayTimesIn4G');
    const a=s.app_ad;if(own(a,'app_ad_duration')&&(typeof a.app_ad_duration==='number'||typeof a.app_ad_duration==='string'&&/^\d+$/.test(a.app_ad_duration))){const v=typeof a.app_ad_duration==='string'?'0':0;if(a.app_ad_duration!==v){a.app_ad_duration=v;changed=true;}}
   }
  }else{
   if(!Array.isArray(r.cards))return body;
   walk(r);
  }
  return changed?JSON.stringify(r):body;
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,ad};
if(typeof $done==='function'){let out={};try{const s=$response.status??$response.statusCode,m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(s));if(Number(m?m[1]:s)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}$done(out);}
})();
