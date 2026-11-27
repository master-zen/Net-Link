(() => {
'use strict';
const ROUTES=[["splash-cn","^https?://edith\\.xiaohongshu\\.com/api/sns/v[0-9]+/system_service/splash_config(?:\\?[^#]*)?$"],["splash-rnote","^https?://edith\\.rnote\\.com/api/sns/v[0-9]+/system_service/splash_config(?:\\?[^#]*)?$"],["startup-config","^https?://edith\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/system_service/config/?(?:\\?[^#]*)?$"],["splash-slash","^https?://edith\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/system_service/splash_config/(?:\\?[^#]*)?$"],["splash-legacy","^https?://edith\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/system_service/splash/?(?:\\?[^#]*)?$"],["home","^https?://(?:edith|rec)\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/homefeed/?(?:\\?[^#]*)?$"],["follow","^https?://(?:edith|rec)\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/(?:followfeed|user/followings/followfeed)/?(?:\\?[^#]*)?$"],["video","^https?://(?:edith|rec|www)\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/note/videofeed/?(?:\\?[^#]*)?$"],["search","^https?://(?:edith|so)\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/search/notes/?(?:\\?[^#]*)?$"],["search-promo","^https?://edith\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/search/(?:banner_list|hot_list|hint|trending)/?(?:\\?[^#]*)?$"],["widgets","^https?://edith\\.(?:xiaohongshu|rnote)\\.com/api/sns/v[0-9]+/note/widgets/?(?:\\?[^#]*)?$"]].map(([id,p])=>[id,new RegExp(p)]);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const own=(o,k)=>obj(o)&&Object.prototype.hasOwnProperty.call(o,k);
const yes=x=>x===true||x===1||x==='1';
const meaningful=x=>obj(x)?Object.keys(x).length>0:Array.isArray(x)?x.length>0:typeof x==='string'?x.trim()!==''&&x!=='0':typeof x==='number'?x>0:x===true;
const ad=x=>obj(x)&&(yes(x.is_ad)||yes(x.isAd)||yes(x.sponsored)||meaningful(x.ads_info)||meaningful(x.ad)||['ad','ads','advertisement','sponsored','ad_card','brand_ad'].includes(String(x.model_type||x.type||'').toLowerCase()));
function transform(url,body){
 const r=ROUTES.find(([,p])=>p.test(url));
 if(!r||typeof body!=='string'||body.length>8388608)return body;
 try{
  const x=JSON.parse(body);
  if(!obj(x)||x.success===false||own(x,'code')&&x.code!==0&&x.code!=='0')return body;
  let changed=false;const d=x.data;
  function del(o,k){if(own(o,k)){delete o[k];changed=true;}}
  function filter(o,k,p=ad){if(!obj(o)||!Array.isArray(o[k]))return;const a=o[k].filter(v=>!p(v));if(a.length!==o[k].length){o[k]=a;changed=true;}}
  function clean(o){if(!obj(o))return;for(const k of ['items','notes','note_list','list'])filter(o,k);}
  if(r[0].startsWith('splash-')){
   if(obj(d)){filter(d,'ads_groups',()=>true);del(d,'splash');del(d,'loading_img');}
  }else if(r[0]==='startup-config'){
   del(d,'splash');del(d,'loading_img');
  }else if(['home','follow','video','search'].includes(r[0])){
   filter(x,'data');clean(d);clean(x);
   if(Array.isArray(x.data))for(const item of x.data)clean(item);
   if(obj(d)&&Array.isArray(d.items))for(const item of d.items)clean(item);
  }else if(r[0]==='search-promo'){
   for(const k of ['items','hint_words','queries','banners','banner_list'])filter(d,k);
   if(ad(d?.hint_word))del(d,'hint_word');
  }else if(r[0]==='widgets'){
   del(d,'cooperate_binds');
   for(const k of ['widget_list','generic','widgets_nbb','widgets_ncb','widgets_ndb'])filter(d,k);
  }
  return changed?JSON.stringify(x):body;
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform,ad};
if(typeof $done==='function'){
 let out={};
 try{const raw=$response.status??$response.statusCode??200;const m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));if(Number(m?m[1]:raw)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}
 $done(out);
}
})();
