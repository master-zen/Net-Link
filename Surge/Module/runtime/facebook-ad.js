(() => {
  'use strict';
  const MAX=16777216;
  const URL=/^https:\/\/(?:www|web|m)\.facebook\.com\/api\/graphql\/?(?:\?[^#]*)?$/;
  const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
  const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
  const types=new Set(['AdsSideFeedUnit','MarketplaceFeedAdStory']);
  function sponsored(x){
    if(!obj(x))return false;
    if(types.has(x.__typename))return true;
    if(x.role==='SEARCH_ADS')return true;
    if(['th_dat_spo','sponsored_data'].some(k=>own(x,k)&&obj(x[k])&&Object.keys(x[k]).length>0))return true;
    const meta=x.comet_sections?.context_layout?.story?.comet_sections?.metadata;
    const items=Array.isArray(meta)?meta:obj(meta)?Object.values(meta):[];
    return items.some(v=>obj(v)&&v.__typename==='CometStorySponsoredLabelStrategy');
  }
  function adRow(x,key){
    if(!obj(x))return false;
    if(key==='edges'){
      if(!obj(x.node))return false;
      return sponsored(x.node)||x.category==='SPONSORED';
    }
    return sponsored(x)||((key==='nodes'||key==='upsell_stories')&&obj(x.node)&&sponsored(x.node));
  }
  function clean(root){
    let changed=false,count=0;
    function walk(x,depth){
      if(x===null||typeof x!=='object')return;
      if(depth>96||++count>300000)throw Error('limit');
      if(Array.isArray(x)){for(const v of x)walk(v,depth+1);return;}
      for(const k of Object.keys(x)){
        const v=x[k];
        if(Array.isArray(v)&&['edges','nodes','upsell_stories'].includes(k)){
          const filtered=v.filter(item=>!adRow(item,k));
          if(filtered.length!==v.length){x[k]=filtered;changed=true;}
          for(const item of filtered)walk(item,depth+1);
        }else walk(v,depth+1);
      }
    }
    walk(root,0);
    return changed;
  }
  function record(s){
    const match=/^(\s*(?:for\s*\(;;\);\s*)?)([\s\S]*?)(\s*)$/.exec(s);
    if(!match||!match[2])return {text:s,changed:false};
    const value=JSON.parse(match[2]);
    if(!clean(value))return {text:s,changed:false};
    return {text:match[1]+JSON.stringify(value)+match[3],changed:true};
  }
  function transform(body){
    if(typeof body!=='string'||!body.length||body.length>MAX)return body;
    try{return record(body).text;}catch(_){}
    try{
      const lines=body.split(/(\r?\n)/);
      if(lines.length>20001)return body;
      let changed=false;
      const out=lines.map((line,i)=>{
        if(i%2||!line.trim())return line;
        const x=record(line);changed=changed||x.changed;return x.text;
      });
      return changed?out.join(''):body;
    }catch(_){return body;}
  }
  function run(){
    let result={};
    try{
      if(URL.test($request.url)&&$request.method==='POST'&&Number($response.status)===200){
        const body=transform($response.body);
        if(body!==$response.body)result={body};
      }
    }catch(_){}
    $done(result);
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={transform,clean,sponsored,URL};
  if(typeof $done==='function')run();
})();
