const profile=require("../data/sources/SuperAdBlock_platform_profiles.json").youtube;
const LIMIT=2097152;
const MAX_FIELDS=100000;

function readVarint(bytes,offset){
  let n=0n;
  for(let i=0;i<10;i++){
    if(offset>=bytes.length)throw Error("truncated-varint");
    const v=bytes[offset++];
    if(i===9&&v>1)throw Error("overflow-varint");
    n|=BigInt(v&127)<<BigInt(i*7);
    if(!(v&128))return [n,offset];
  }
  throw Error("invalid-varint");
}
function varint(n){
  n=BigInt(n);const out=[];
  while(n>=128n){out.push(Number(n&127n)|128);n>>=7n}
  out.push(Number(n));return Uint8Array.from(out);
}
function join(parts){
  const size=parts.reduce((n,p)=>n+p.length,0);
  if(size>LIMIT)throw Error("size");
  const out=new Uint8Array(size);let offset=0;
  for(const p of parts){out.set(p,offset);offset+=p.length}
  return out;
}
function fields(bytes,budget){
  const result=[];let i=0;
  while(i<bytes.length){
    if(--budget.left<0)throw Error("field-budget");
    const start=i;
    let tag,end;[tag,end]=readVarint(bytes,i);i=end;
    const num=Number(tag>>3n),wire=Number(tag&7n);
    if(num<1||num>536870911)throw Error("bad-tag");
    let payload=null;
    if(wire===0){[,i]=readVarint(bytes,i)}
    else if(wire===1){i+=8}
    else if(wire===5){i+=4}
    else if(wire===2){
      let len;[len,i]=readVarint(bytes,i);
      if(len>BigInt(bytes.length-i))throw Error("truncated-length");
      const e=i+Number(len);
      payload=bytes.subarray(i,e);i=e;
    }else throw Error("unsupported-wire");
    if(i>bytes.length)throw Error("truncated-field");
    result.push({num,wire,raw:bytes.subarray(start,i),tag:bytes.subarray(start,end),payload});
  }
  return result;
}
function marker(bytes,path,budget){
  for(const f of fields(bytes,budget)){
    if(f.num!==path[0]||f.wire!==2)continue;
    if(path.length===1){if(f.payload.length)return true}
    else if(marker(f.payload,path.slice(1),budget))return true;
  }
  return false;
}
function rewrite(bytes,path,budget){
  let changed=false;const out=[];
  for(const f of fields(bytes,budget)){
    if(!path.length&&f.num===profile.item_field&&f.wire===2&&marker(f.payload,profile.marker,budget)){
      changed=true;continue;
    }
    if(path.length&&f.num===path[0]&&f.wire===2){
      const next=rewrite(f.payload,path.slice(1),budget);
      if(next!==f.payload){out.push(f.tag,varint(next.length),next);changed=true;continue}
    }
    out.push(f.raw);
  }
  return changed?join(out):bytes;
}
function transform(bytes,endpoint){
  if(!(bytes instanceof Uint8Array)||bytes.length>LIMIT||typeof endpoint!=="string")return bytes;
  const match=/^\/youtubei\/v1\/(browse|next)$/.exec(endpoint);
  if(!match)return bytes;
  try{
    let out=bytes;const budget={left:MAX_FIELDS};
    for(const path of profile.roots[match[1]])out=rewrite(out,path,budget);
    return out;
  }catch{return bytes}
}
module.exports={transform,varint,join};
