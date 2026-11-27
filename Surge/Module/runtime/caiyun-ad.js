(() => {
  'use strict';
  const ACT = /^https?:\/\/(?:api\.caiyunapp\.com|cdn-w\.caiyunapp\.com|wrapper\.cyapi\.cn)\/v[0-9]+\/activity\/?(?:\?[^#]*)?$/;
  const CFG = /^https?:\/\/starplucker\.cyapi\.cn\/v[0-9]+\/(?:config|config\/cypage\/[A-Za-z0-9_-]+\/conditions|operation\/(?:homefeatures|banners|feeds|features)|campaigns)\/?(?:\?[^#]*)?$/;
  const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
  const marker = /^(?:ad|ads|advert|advertisement|advertising|sponsored|promotion|commercial)(?:[_-][a-z0-9_-]+)?$/i;
  const critical = /(?:weather[_-]?alert|weather[_-]?warning|disaster|emergency|typhoon|(?:气象|暴雨|暴雪|台风|大风|高温|寒潮|雷电|地质|洪水|灾害|天气)?预警|避险|防灾|避灾)/i;
  const feature = /^(?:weather|forecast|radar|precipitation|rain|aqi|air_quality|temperature|wind|humidity|uv|sunrise|sunset|driveweather|driving_weather|aichat|weather_assistant)(?:$|[_-])/i;
  const weatherRoute = /^cy:\/\/(?:page_)?(?:driving_weather|weather|forecast|radar|precipitation|rain|aqi|air_quality|warning|alert|typhoon|aichat|weather_assistant)(?:$|[/?#_-])/i;
  const own = (o,k) => Object.prototype.hasOwnProperty.call(o,k);
  function safe(x) {
    if (!obj(x)) return false;
    return [x.type,x.name,x.card_type,x.banner_type,x.category,x.title,x.text,x.activity_name,x.url,x.link].some(v=>typeof v==='string'&&critical.test(v));
  }
  function normal(x) {
    return obj(x) && ([x.type,x.name,x.card_type,x.category].some(v=>typeof v==='string'&&feature.test(v)) || [x.url,x.link].some(v=>typeof v==='string'&&weatherRoute.test(v)));
  }
  function ad(x) {
    if (!obj(x) || safe(x)) return false;
    const labels = [x.type,x.name,x.card_type,x.banner_type,x.category,x.title];
    return x.is_ad===true || x.is_ad===1 || x.is_ad==='1' || x.is_sponsored===true || x.sponsored===true || labels.some(v=>typeof v==='string'&&marker.test(v));
  }
  function codeAd(x) {
    return obj(x) && !safe(x) && typeof x.name==='string' && /^(?:A[0-9]|C01)/i.test(x.name);
  }
  function transform(url,body) {
    if (typeof body!=='string' || body.length>33554432 || (!ACT.test(url)&&!CFG.test(url))) return body;
    try {
      const x=JSON.parse(body);
      if (!obj(x)) return body;
      let changed=false;
      const filter=(o,k,remove)=>{
        if (!obj(o)||!Array.isArray(o[k])) return;
        const a=o[k].filter(v=>!remove(v));
        if(a.length!==o[k].length){o[k]=a;changed=true;}
      };
      const stripPromotion=v=>obj(v)&&!safe(v)&&(ad(v)||!normal(v));
      if (ACT.test(url)) {
        const a03=/(?:\?|&)type_id=A03(?:&|$)/.test(url);
        if (!Array.isArray(x.activities)) return body;
        filter(x,'activities',a=>obj(a)&&!safe(a)&&ad(a)&&a.type!=='tabbar');
        if (!a03) {
          for (const a of x.activities) {
            if(!obj(a)||safe(a))continue;
            if(a.type==='activity_icon')filter(a,'items',stripPromotion);
            else filter(a,'items',ad);
          }
          filter(x,'activities',a=>obj(a)&&!safe(a)&&!normal(a)&&a.type!=='tabbar'&&a.type!=='activity_icon');
          if (x.activities.length===0) {x.activities=[{type:'activity_icon',items:[]}];changed=true;}
        }
      } else {
        const route=url.split('?')[0].replace(/\/$/,'').replace(/^https?:\/\/starplucker\.cyapi\.cn\/v[0-9]+\//,'');
        for(const o of [x,obj(x.data)?x.data:null]){
          if(!obj(o))continue;
          if(route==='config'){
            for(const k of ['pic_page_card_orders','map_page_card_orders'])filter(o,k,v=>ad(v)||codeAd(v));
            if(own(o,'search_suggestions')&&Array.isArray(o.search_suggestions)){
              const keep=o.search_suggestions.filter(safe);
              if(keep.length!==o.search_suggestions.length){o.search_suggestions=keep;changed=true;}
            }
            for(const k of ['popups','actions','banners','features','feeds','campaigns','items'])filter(o,k,ad);
          }else if(route.startsWith('config/cypage/')){
            for(const k of ['popups','actions'])filter(o,k,stripPromotion);
          }else if(route==='operation/homefeatures'){
            for(const k of ['data','features','items'])filter(o,k,stripPromotion);
          }else if(route==='operation/banners'||route==='campaigns'){
            for(const k of ['data','banners','campaigns','items'])filter(o,k,stripPromotion);
          }else if(route==='operation/features'){
            for(const k of ['data','features','items'])filter(o,k,v=>obj(v)&&!safe(v)&&(ad(v)||(!normal(v)&&typeof v.url==='string'&&/^https?:\/\//i.test(v.url))));
          }else if(route==='operation/feeds'){
            for(const k of ['data','feeds','items'])filter(o,k,v=>obj(v)&&!safe(v)&&(ad(v)||(!normal(v)&&typeof v.category_times_text==='string'&&!v.category_times_text.includes('人查看'))));
          }
        }
      }
      return changed?JSON.stringify(x):body;
    }catch(_){return body;}
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={transform,ACT,CFG,ad};
  if(typeof $done==='function'){
    let out={};
    try{if(Number($response.status)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}
    $done(out);
  }
})();
