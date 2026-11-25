const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const script = fs.readFileSync("Surge/Module/runtime/app-startup-ad.js", "utf8");
function run(mode, payload, status = 200) {
    const body = typeof payload === "string" ? payload : JSON.stringify(payload);
    let output;
    vm.runInNewContext(script, {$argument: mode, $response: {body, status}, $done: result => { output = result; }});
    return output.body === undefined ? payload : JSON.parse(output.body);
}
assert.deepEqual(run("bili", {data:{list:[{id:1}],other:1},code:0}), {data:{list:[],other:1},code:0});
assert.deepEqual(run("vg", {data:{ad:{id:1},news:1}}), {data:{ad:null,news:1}});
assert.deepEqual(run("jd", {images:[[{showTimes:2,name:"x"},{name:"keep"}]],countdown:3,showTimesDaily:2}), {images:[[{showTimes:0,name:"x"},{name:"keep"}]],countdown:3,showTimesDaily:0});
assert.deepEqual(run("meituan", {data:{startpicture:{ad:[1],mk:[2],other:3},orders:[4]}}), {data:{startpicture:{ad:[],mk:[],other:3},orders:[4]}});
assert.deepEqual(run("xhs", {data:{splash:1,loading_img:2,ads_groups:[1],normal:4}}), {data:{ads_groups:[],normal:4}});
assert.deepEqual(run("family", {code:"200",data:{relayDisplayUrl:"x",other:1}}), {code:"200",data:{relayDisplayUrl:"",other:1}});
assert.deepEqual(run("dida", {startupPages:[1],order:1}), {startupPages:[],order:1});
assert.deepEqual(run("dmall", {data:{welcomePage:[{onlineTime:1,offlineTime:2,other:3}],business:1}}), {data:{welcomePage:[{onlineTime:4102444800000,offlineTime:4102444800000,other:3}],business:1}});
assert.deepEqual(run("bili", {data:{list:[1]}}, 500), {data:{list:[1]}});
assert.equal(run("bili", "not-json"), "not-json");
assert.deepEqual(run("unknown", {data:{ad:1}}), {data:{ad:1}});

assert.deepEqual(run("kuaidi", {adsplash:{id:1},tracking:{keep:true}}), {tracking:{keep:true}});
assert.deepEqual(run("taobao", {data:{items:[{"taobao-splash":{data:[1],other:2}},{data:[3]}]}}), {data:{items:[{"taobao-splash":{data:[],other:2}},{data:[3]}]}});
assert.deepEqual(run("faw", {data:[1],returnStatus:"SUCCEED",other:2}), {data:[],returnStatus:"SUCCEED",other:2});

assert.deepEqual(run("ireader", {Splash:{id:1},content:2}), {content:2});
assert.deepEqual(run("missevan", {info:{splash:1,splash_ready:2,tab_bar_live:3}}), {info:{tab_bar_live:3}});
assert.deepEqual(run("wuta", {regular:{splash:1,home_bottom_right_entry_v2:2},big_day:3}), {regular:{home_bottom_right_entry_v2:2},big_day:3});
assert.deepEqual(run("duitang", {data:{SPLASH_SWING_OPEN:1,STICKER_SEARCH_HOT_KEYWORDS:2}}), {data:{STICKER_SEARCH_HOT_KEYWORDS:2}});
assert.deepEqual(run("tuilan", {data:{splashConf:1,splashConfNew:2,servers:3}}), {data:{servers:3}});
assert.deepEqual(run("jump", {data:{adList:[1],launchAd:{showType:2,other:3},recommendation:4}}), {data:{adList:[],launchAd:{showType:0,other:3},recommendation:4}});
