const fs=require("node:fs");
const acorn=require("acorn");
const adKeys=new Set("ad ads adinfo adlist aditems adpayload advert adverts advertisement advertisements advertising admetadata adconfig splashad splashads splashadvertisement promotedads commentspageads adbanner adslots adslot adcontent".split(" "));
const parents=new Set("data result response payload body content page detail info".split(" "));
const arrays=new Set("list items entries cards results contents feed feeds modules sections".split(" "));
const types=new Set("type _type __typename itemtype cardtype celltype adtype ad_type".split(" "));
const enums=new Set("ad ads advertisement advert pic_ad adpost admetadatacell promoted_ad sponsored_ad advertising".split(" "));
const bools=new Set("isad isadpost isadvertisement isadvertising issponsoredad".split(" "));
const capabilityGroups={
  network:new Set("$httpClient $httpAPI fetch XMLHttpRequest WebSocket $task".split(" ")),
  storage:new Set("$persistentStore $prefs localStorage sessionStorage indexedDB".split(" ")),
  dynamic_code:new Set("eval Function import require WebAssembly".split(" ")),
  process:new Set("process module globalThis window self".split(" ")),
  request_access:new Set("$request $argument $environment $input".split(" ")),
  side_effect:new Set("$notification $surge $script".split(" ")),
  entitlement:new Set("premium entitlement subscription subscriber productTier isPremium".toLowerCase().split(" "))
};
function member(n){
  if(n?.type==="Identifier")return [n.name];
  if(n?.type!=="MemberExpression"||n.computed||n.optional||n.property.type!=="Identifier")return null;
  const base=member(n.object);
  return base&&[...base,n.property.name];
}
function name(n){return member(n)?.join(".")}
function literal(n){return n?.type==="Literal"&&!n.regex&&!n.bigint?n.value:undefined}
function call(n,target,argc){return n?.type==="CallExpression"&&!n.optional&&name(n.callee)===target&&n.arguments.length===argc}
function same(a,b){return a&&b&&a.length===b.length&&a.every((v,i)=>v===b[i])}
function fieldPath(n,id,allowed){
  const path=member(n);
  if(!path||path.shift()!==id||path.length<1||path.length>4||!allowed.has(path.at(-1).toLowerCase())||path.slice(0,-1).some(x=>!parents.has(x.toLowerCase())))return null;
  return path;
}
function inspect(ast){
  const caps=new Set(),stack=[ast];let count=0,functions=0,loops=0,computed=0;
  while(stack.length){
    const n=stack.pop();
    if(++count>200000)return {capabilities:[...caps].sort(),nodes:count,truncated:true};
    if(n.type==="Identifier"){
      for(const [group,keys] of Object.entries(capabilityGroups)){
        if(keys.has(n.name)||group==="entitlement"&&keys.has(n.name.toLowerCase()))caps.add(group);
      }
    }
    if(n.type==="ImportExpression")caps.add("dynamic_code");
    if(n.type==="MemberExpression"&&n.computed)computed++;
    if(/Function/.test(n.type))functions++;
    if(/^(For|While|DoWhile)/.test(n.type))loops++;
    for(const v of Object.values(n)){
      if(Array.isArray(v)){for(const k of v){if(k?.type)stack.push(k)}}
      else if(v?.type)stack.push(v);
    }
  }
  return {capabilities:[...caps].sort(),nodes:count,functions,loops,computed,truncated:false};
}
function compile(ast){
  const statements=ast.body;
  if(statements.length<3||statements.length>18)return null;
  const first=statements[0],last=statements.at(-1);
  if(first.type!=="VariableDeclaration"||first.declarations.length!==1)return null;
  const v=first.declarations[0];
  if(v.id.type!=="Identifier"||!call(v.init,"JSON.parse",1)||name(v.init.arguments[0])!=="$response.body")return null;
  const id=v.id.name;
  if(["JSON","Array","$response","$done","undefined","eval","Function","__proto__","constructor","prototype"].includes(id))return null;
  if(last.type!=="ExpressionStatement"||!call(last.expression,"$done",1))return null;
  const obj=last.expression.arguments[0];
  if(obj.type!=="ObjectExpression"||obj.properties.length!==1)return null;
  const prop=obj.properties[0];
  if(prop.type!=="Property"||prop.computed||prop.method||prop.kind!=="init"||(prop.key.name??prop.key.value)!=="body"||!call(prop.value,"JSON.stringify",1)||name(prop.value.arguments[0])!==id)return null;
  const deletes=[],filters=[];
  for(const statement of statements.slice(1,-1)){
    let e=statement.expression;
    if(statement.type==="IfStatement"&&!statement.alternate){
      let guard=statement.test;
      let consequent=statement.consequent;
      if(consequent.type==="BlockStatement"&&consequent.body.length===1)consequent=consequent.body[0];
      if(consequent.type!=="ExpressionStatement")return null;
      e=consequent.expression;
      if(e?.type==="UnaryExpression"&&e.operator==="delete"){
        const target=fieldPath(e.argument,id,adKeys);
        if(!target||!same(member(guard),[id,...target]))return null;
        deletes.push(target);continue;
      }
      if(e?.type!=="AssignmentExpression"||!call(guard,"Array.isArray",1)||!same(member(guard.arguments[0]),member(e.left)))return null;
    }else if(statement.type!=="ExpressionStatement")return null;
    if(e?.type==="UnaryExpression"&&e.operator==="delete"){
      const path=fieldPath(e.argument,id,adKeys);
      if(!path)return null;
      deletes.push(path);continue;
    }
    if(e?.type!=="AssignmentExpression"||e.operator!=="="||e.right?.type!=="CallExpression"||e.right.optional||e.right.arguments.length!==1)return null;
    const path=fieldPath(e.left,id,arrays);
    const callee=member(e.right.callee);
    if(!path||!same(callee,[id,...path,"filter"]))return null;
    const fn=e.right.arguments[0];
    if(fn.type!=="ArrowFunctionExpression"||fn.async||fn.generator||fn.params.length!==1||fn.params[0].type!=="Identifier"||fn.body.type!=="BinaryExpression"||fn.body.operator!=="!==")return null;
    const field=member(fn.body.left),value=literal(fn.body.right);
    if(!field||field.length!==2||field[0]!==fn.params[0].name)return null;
    const key=field[1].toLowerCase();
    if(!(typeof value==="string"&&types.has(key)&&enums.has(value.toLowerCase())||value===true&&bools.has(key)||value===1&&key==="info_list_ad_style_type"))return null;
    filters.push({path,field:field[1],value});
  }
  return {deletes,filters};
}
function audit(source){
  const ast=acorn.parse(source,{ecmaVersion:2024,sourceType:"script"});
  const inspection=inspect(ast);
  const plan=inspection.truncated?null:compile(ast);
  return {eligible:!!plan,reason:plan?"restricted-ad-response-plan":"unproven-functional-transform",inspection,...(plan?{plan}:{})};
}
try{process.stdout.write(JSON.stringify(audit(fs.readFileSync(process.argv[2],"utf8"))))}catch(e){process.stdout.write(JSON.stringify({eligible:false,reason:e instanceof SyntaxError?"syntax-error":"scanner-error"}))}
