(() => {
  'use strict';
  const route=/^https:\/\/(?:x|twitter)\.com\/i\/api\/graphql\/[A-Za-z0-9_-]+\/(HomeTimeline|HomeLatestTimeline|TweetDetail)(?:\?[^#]*)?$/;
  const limit=16*1024*1024;
  const record=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
  const paidId=x=>typeof x==='string'&&/^promoted(?:-tweet|-carousel|-ad)?(?:-|$)/i.test(x);
  const cursor=x=>typeof x==='string'&&/^cursor-/i.test(x);
  const paid=x=>record(x)&&record(x.promotedMetadata);
  function paidItem(x){
    if(!record(x)||cursor(x.entryId))return false;
    return paidId(x.entryId)||paid(x.itemContent)||paid(x.item?.itemContent);
  }
  function filter(entries){
    let changed=false;
    const kept=[];
    for(const e of entries){
      if(!record(e)||cursor(e.entryId)){kept.push(e);continue;}
      const c=e.content;
      if(paidId(e.entryId)||paid(c?.itemContent)||paid(c)){changed=true;continue;}
      if(record(c)&&Array.isArray(c.items)&&c.items.length){
        const items=c.items.filter(x=>!paidItem(x));
        if(items.length!==c.items.length){
          changed=true;
          if(items.length===0)continue;
          c.items=items;
        }
      }
      kept.push(e);
    }
    return {changed,kept};
  }
  function transform(data,operation){
    if(!record(data)||!record(data.data))return false;
    const ins=operation==='TweetDetail'?data.data.threaded_conversation_with_injections_v2?.instructions:
      ['HomeTimeline','HomeLatestTimeline'].includes(operation)?data.data.home?.home_timeline_urt?.instructions:null;
    if(!Array.isArray(ins))return false;
    let changed=false;
    for(const i of ins){
      if(!record(i))continue;
      if(Array.isArray(i.entries)&&(i.type==='TimelineAddEntries'||i.type===undefined)){
        const result=filter(i.entries);
        if(result.changed){i.entries=result.kept;changed=true;}
      }
      if(i.type==='TimelineAddToModule'&&Array.isArray(i.moduleItems)){
        const kept=i.moduleItems.filter(x=>!paidItem(x));
        if(kept.length!==i.moduleItems.length){i.moduleItems=kept;changed=true;}
      }
    }
    return changed;
  }
  function run(){
    let result={};
    try{
      const match=route.exec($request.url);
      const body=$response.body;
      if(match&&Number($response.status)===200&&typeof body==='string'&&body.length<=limit&&body.length){
        const data=JSON.parse(body);
        if(transform(data,match[1]))result={body:JSON.stringify(data)};
      }
    }catch(_){}
    $done(result);
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={route,transform,run};
  if(typeof $done==='function')run();
})();
