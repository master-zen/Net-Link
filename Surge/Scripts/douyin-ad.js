(() => {
'use strict';
const route=new RegExp("^https?://(?:api3-core-c\\.amemv\\.com|api3-normal-c\\.amemv\\.com|api\\.amemv\\.com|aweme\\.snssdk\\.com)/aweme/v[12]/feed/?(?:\\?[^#]*)?$");
function transform(url,body){
 if(!route.test(String(url))||typeof body!=='string'||body.length>8388608)return body;
 try{
  const root=JSON.parse(body);
  if(!root||typeof root!=='object'||Array.isArray(root)||root.status_code!==undefined&&root.status_code!==0&&root.status_code!=='0')return body;
  const tokens=/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g;
  let t,depth=0,stack=[],list=null,duplicate=false,key=null,expectKey=false;
  while((t=tokens.exec(body))){
   const s=t[0],i=t.index;
   if(depth===1&&expectKey&&s[0]==='"'){key=JSON.parse(s);expectKey=false;continue;}
   if(s==='{'||s==='['){
    if(depth===1&&key==='aweme_list'){if(list)duplicate=true;else list={start:i,end:0,entries:[]};if(s!=='[')return body;}
    if(depth===2&&list&&!list.end)list.entries.push({start:i,end:0,marker:null,seen:false});
    stack.push(s);depth++;
    if(depth===1&&s==='{')expectKey=true;
   }else if(s==='}'||s===']'){
    if(depth===3&&list&&!list.end&&list.entries.length)list.entries[list.entries.length-1].end=tokens.lastIndex;
    if(depth===2&&list&&!list.end)list.end=i;
    stack.pop();depth--;
   }else if(s===','&&depth===1){expectKey=true;key=null;}
   else if(depth===2&&list&&!list.end&&s!==','&&s!==':')list.entries.push({start:i,end:tokens.lastIndex,marker:null,seen:false});
  }
  if(duplicate||!list||!list.end||!list.entries.length||!Array.isArray(root.aweme_list)||root.aweme_list.length!==list.entries.length)return body;
  function exactOne(s){
   const m=/^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(s);
   if(!m)return false;
   const digits=m[1]+(m[2]||''),trim=digits.replace(/0+$/,'');
   const exp=Number(m[3]||0);
   return trim.replace(/^0+/,'')==='1'&&Number.isSafeInteger(exp)&&exp-(m[2]||'').length+digits.length-trim.length===0;
  }
  function isAd(entry){
   if(body[entry.start]!=='{'||!entry.end)return false;
   const rx=/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g;
   rx.lastIndex=entry.start;
   let depth=0,k=false,marker=null,count=0,v;
   while((v=rx.exec(body))&&v.index<entry.end){
    const s=v[0];
    if(depth===1&&k&&s[0]==='"'){
     k=false;
     if(JSON.parse(s)==='is_ads'){
      count++;
      const colon=rx.exec(body),val=rx.exec(body);
      if(!colon||colon[0]!==':'||!val)return false;
      marker=val[0];
      if(marker==='{'||marker==='[')return false;
     }
     continue;
    }
    if(s==='{'||s==='['){depth++;if(depth===1)k=true;}
    else if(s==='}'||s===']')depth--;
    else if(s===','&&depth===1)k=true;
   }
   return count===1&&(marker==='true'||exactOne(marker||''));
  }
  const keep=list.entries.filter(e=>!isAd(e));
  if(keep.length===list.entries.length)return body;
  return body.slice(0,list.start+1)+keep.map(e=>body.slice(e.start,e.end)).join(',')+body.slice(list.end);
 }catch(_){return body;}
}
if(typeof module!=='undefined'&&module.exports)module.exports={transform};
if(typeof $done==='function'){let out={};try{const raw=$response.status??$response.statusCode??200,m=/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/.exec(String(raw));if(Number(m?m[1]:raw)===200){const b=transform($request.url,$response.body);if(b!==$response.body)out={body:b};}}catch(_){}$done(out);}
})();
