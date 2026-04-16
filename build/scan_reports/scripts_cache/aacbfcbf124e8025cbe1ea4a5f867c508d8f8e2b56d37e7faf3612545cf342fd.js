/*
脚本引用https://raw.githubusercontent.com/Keywos/rule/main/loon/tk.js
*/
let keyus={日本: "JP"},
lk = $persistentStore.read("JP"),loc = keyus[lk] || "KR",url = $request.url;
// if(loc == "inkey"){
//   inkeys = $persistentStore.read("手动输入地区代码[可选]");
//   loc = inkeys
// }
if (/(tnc|dm).+\.[^\/]+\.com\/\w+\/v\d\/\?/.test(url)) {
  url = url.replace(/\/\?/g,'');
  const response = {
    status: 302,
    headers: {Location: url},
  };
  $done({response});
} else if (/_region=CN&|&mcc_mnc=4/.test(url)) {
  url = url.replace(/_region=CN&/g,`_region=${loc}&`).replace(/&mcc_mnc=4/g,"&mcc_mnc=2");
  const response = {
    status: 307,
    headers: {Location: url},
  };
  $done({response});
} else {
  $done({})
}
