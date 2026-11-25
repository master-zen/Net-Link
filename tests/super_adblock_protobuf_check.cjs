const assert=require("node:assert/strict");
const p=require("../data/sources/SuperAdBlock_platform_profiles.json").youtube;
const {transform,varint,join}=require("../scripts/super_adblock_protobuf.cjs");
const bytes=(...n)=>Uint8Array.from(n);
const field=(num,payload)=>join([varint(BigInt(num)*8n+2n),varint(payload.length),payload]);
const scalar=(num,n)=>join([varint(BigInt(num)*8n),varint(n)]);
const wrap=(path,body)=>path.reduceRight((v,n)=>field(n,v),body);
const same=(a,b)=>assert.deepEqual([...a],[...b]);
const normal=field(p.item_field,scalar(6,42));
const ad=field(p.item_field,wrap(p.marker,bytes(65)));
const unknown=scalar(120,999);
for(const [route,roots] of Object.entries(p.roots)){
  for(const root of roots){
    const input=join([unknown,wrap(root,join([normal,ad,unknown]))]);
    const expected=join([unknown,wrap(root,join([normal,unknown]))]);
    same(transform(input,"/youtubei/v1/"+route),expected);
    same(transform(expected,"/youtubei/v1/"+route),expected);
    same(transform(input,"/youtubei/v1/player"),input);
  }
}
const malformed=bytes(0x0a,0x7f,0x01);
same(transform(malformed,"/youtubei/v1/browse"),malformed);
const emptyMarker=field(p.item_field,wrap(p.marker,bytes()));
const untouched=wrap(p.roots.browse[0],join([normal,emptyMarker]));
same(transform(untouched,"/youtubei/v1/browse"),untouched);
const unknownWire=bytes(0x0b,0x0c);
same(transform(unknownWire,"/youtubei/v1/browse"),unknownWire);
const giant=new Uint8Array(2097153);
assert.equal(transform(giant,"/youtubei/v1/browse"),giant);
