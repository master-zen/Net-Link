const fs=require("node:fs");
const os=require("node:os");
const path=require("node:path");
const assert=require("node:assert/strict");
const cp=require("node:child_process");
const dir=fs.mkdtempSync(path.join(os.tmpdir(),"super-adblock-ast-"));
try{
  const scanner=path.resolve(__dirname,"../scripts/super_adblock_ast.cjs");
  const fixtures=[
    ["let a=JSON.parse($response.body); delete a.ads; $done({body:JSON.stringify(a)});",true],
    ["$httpClient.post('https://example.com',$response.body); $done({body:''});",false],
    ["let a=JSON.parse($response.body); a['constructor']; $done({body:JSON.stringify(a)});",false],
    ["let a=eval($response.body); $done({body:JSON.stringify(a)});",false],
    ["let a=JSON.parse($response.body); $done({body:JSON.stringify(a),headers:{}});",false],
    ["let a=JSON.parse($response.body); while(true){} $done({body:JSON.stringify(a)});",false],
    ["let a=JSON.parse($response.body); delete a.user; $done({body:JSON.stringify(a)});",false],
    ["let a=JSON.parse($response.body); a.ads=0; $done({body:JSON.stringify(a)});",false],
    ["let a=JSON.parse($response.body); delete a.data.adInfo; $done({body:JSON.stringify(a)});",true]
  ];
  for(let i=0;i<fixtures.length;i++){
    const file=path.join(dir,i+".js");
    fs.writeFileSync(file,fixtures[i][0]);
    assert.equal(JSON.parse(cp.execFileSync(process.execPath,[scanner,file],{encoding:"utf8"})).eligible,fixtures[i][1]);
  }
}finally{fs.rmSync(dir,{recursive:true,force:true})}
