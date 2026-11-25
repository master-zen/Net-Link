const fs=require("node:fs");
const acorn=require("acorn");
const nodes=new Set("Program VariableDeclaration VariableDeclarator Identifier Literal ExpressionStatement BlockStatement IfStatement ConditionalExpression ObjectExpression Property ArrayExpression MemberExpression CallExpression AssignmentExpression UnaryExpression BinaryExpression LogicalExpression EmptyStatement".split(" "));
const forbidden=new Set("__proto__ prototype constructor caller callee arguments eval Function globalThis window self process require module import fetch XMLHttpRequest WebSocket $httpClient $httpAPI $persistentStore $notification $network $surge $script $request $argument $environment $input $prefs $task".split(" "));
const globals=new Set(["$response","$done","JSON","Array","undefined"]);
const calls=new Set(["JSON.parse","JSON.stringify","Array.isArray","$done"]);
function name(n){
  if(n.type==="Identifier")return n.name;
  if(n.type!=="MemberExpression"||n.computed||n.optional)return null;
  const base=name(n.object);
  return base===null?null:base+"."+n.property.name;
}
function root(n){while(n.type==="MemberExpression")n=n.object;return n.type==="Identifier"?n.name:null}
function children(n,fn){for(const [k,v] of Object.entries(n)){if(Array.isArray(v))v.forEach(x=>{if(x?.type)fn(x,n,k)});else if(v?.type)fn(v,n,k)}}
const adKeys=new Set("ad ads adinfo adlist aditems adpayload advert adverts advertisement advertisements advertising admetadata adconfig splashad splashads splashadvertisement promotedads commentspageads adbanner adslots adslot adcontent".split(" "));
const parents=new Set("data result response payload body content page detail info".split(" "));
function adDeletionOnly(ast){
  const statements=ast.body;
  if(statements.length<3||statements.length>34)return false;
  const first=statements[0],last=statements.at(-1);
  if(first.type!=="VariableDeclaration"||first.declarations.length!==1)return false;
  const variable=first.declarations[0];
  if(variable.id.type!=="Identifier"||variable.init?.type!=="CallExpression"||name(variable.init.callee)!=="JSON.parse"||variable.init.arguments.length!==1||name(variable.init.arguments[0])!=="$response.body")return false;
  const id=variable.id.name;
  const done=last.expression;
  if(last.type!=="ExpressionStatement"||done?.type!=="CallExpression"||name(done.callee)!=="$done"||done.arguments.length!==1)return false;
  const properties=done.arguments[0].properties;
  if(properties?.length!==1)return false;
  const prop=properties[0],v=prop.value;
  if((prop.key.name??prop.key.value)!=="body"||v.type!=="CallExpression"||name(v.callee)!=="JSON.stringify"||v.arguments.length!==1||name(v.arguments[0])!==id)return false;
  for(const statement of statements.slice(1,-1)){
    const e=statement.expression;
    if(statement.type!=="ExpressionStatement"||e?.type!=="UnaryExpression"||e.operator!=="delete")return false;
    const path=name(e.argument)?.split(".");
    if(!path||path.shift()!==id||path.length<1||path.length>4||!adKeys.has(path.at(-1).toLowerCase())||path.slice(0,-1).some(k=>!parents.has(k.toLowerCase())))return false;
  }
  return true;
}
function audit(source){
  const ast=acorn.parse(source,{ecmaVersion:2024,sourceType:"script"});
  const locals=new Set();let count=0,done=0;
  function collect(n){if(n.type==="VariableDeclarator"){if(n.id.type!=="Identifier"||globals.has(n.id.name)||forbidden.has(n.id.name)||locals.has(n.id.name))throw Error("binding");locals.add(n.id.name)}children(n,collect)}
  collect(ast);
  function walk(n,p,k){
    if(++count>4000||!nodes.has(n.type))throw Error("unsupported-ast");
    if(n.type==="Identifier"){
      if(forbidden.has(n.name))throw Error("forbidden-identifier");
      const prop=(p?.type==="MemberExpression"&&k==="property")||(p?.type==="Property"&&k==="key"&&!p.computed);
      if(!prop&&!locals.has(n.name)&&!globals.has(n.name))throw Error("unknown-global");
      if(!prop&&globals.has(n.name)&&n.name!=="undefined"&&!(n.name==="$done"?p?.type==="CallExpression"&&k==="callee":p?.type==="MemberExpression"&&k==="object"))throw Error("global-reference");
    }
    if(n.type==="Literal"&&(n.regex||n.bigint||forbidden.has(n.value)))throw Error("literal");
    if(n.type==="Property"&&(n.computed||n.method||n.kind!=="init"||forbidden.has(n.key.value)))throw Error("property");
    if(n.type==="MemberExpression"){
      const v=name(n);if(!v||forbidden.has(n.property.name))throw Error("dynamic-property");
      if(root(n)==="$response"&&v!=="$response.body")throw Error("response-access");
      if(["JSON","Array"].includes(root(n))&&(!calls.has(v)||p?.type!=="CallExpression"||k!=="callee"))throw Error("global-member");
    }
    if(n.type==="CallExpression"){
      const v=name(n.callee);if(!calls.has(v)||n.optional)throw Error("call");
      if(v==="$done"){done++;if(n.arguments.length!==1||n.arguments[0].type!=="ObjectExpression"||n.arguments[0].properties.some(x=>(x.key?.name??x.key?.value)!=="body"))throw Error("done-shape")}
    }
    if(n.type==="AssignmentExpression"&&(n.operator!=="="||!locals.has(root(n.left))))throw Error("write-target");
    if(n.type==="UnaryExpression"&&n.operator==="delete"&&(!locals.has(root(n.argument))||n.argument.type!=="MemberExpression"))throw Error("delete-target");
    children(n,walk)
  }
  walk(ast,null,"");
  if(done!==1||ast.body.at(-1)?.expression?.callee?.name!=="$done")throw Error("completion");
  if(!adDeletionOnly(ast))throw Error("unproven-functional-transform");
  return {eligible:true,reason:"restricted-ad-field-deletion-profile"};
}
try{process.stdout.write(JSON.stringify(audit(fs.readFileSync(process.argv[2],"utf8"))))}catch(e){process.stdout.write(JSON.stringify({eligible:false,reason:e instanceof SyntaxError?"syntax-error":String(e.message).slice(0,80)}))}
