function scrub(mode, value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const data = value.data;
    let changed = false;
    function clear(obj, key) {
        if (obj && Array.isArray(obj[key]) && obj[key].length) {
            obj[key] = [];
            changed = true;
        }
    }
    if (mode === "bili") {
        for (const key of ["list", "show", "event_list"]) clear(data, key);
    } else if (mode === "vg") {
        if (data && Object.prototype.hasOwnProperty.call(data, "ad") && data.ad !== null) {
            data.ad = null;
            changed = true;
        }
    } else if (mode === "jd") {
        if (Array.isArray(value.images)) for (const group of value.images) {
            if (!Array.isArray(group)) continue;
            for (const image of group) if (image && typeof image === "object" && Object.prototype.hasOwnProperty.call(image, "showTimes")) {
                if (image.showTimes !== 0) { image.showTimes = 0; changed = true; }
            }
        }
        if (Object.prototype.hasOwnProperty.call(value, "showTimesDaily") && value.showTimesDaily !== 0) {
            value.showTimesDaily = 0;
            changed = true;
        }
    } else if (mode === "dmall") {
        if (data && Array.isArray(data.welcomePage)) for (const page of data.welcomePage) {
            if (page && typeof page === "object" && "onlineTime" in page && "offlineTime" in page) {
                page.onlineTime = 4102444800000;
                page.offlineTime = 4102444800000;
                changed = true;
            }
        }
    } else if (mode === "family") {
        if (value.code === "200" && data && typeof data.relayDisplayUrl === "string" && data.relayDisplayUrl) {
            data.relayDisplayUrl = "";
            changed = true;
        }
    } else if (mode === "dida") {
        clear(value, "startupPages");
    } else if (mode === "xhs") {
        if (data && typeof data === "object") {
            clear(data, "ads_groups");
            for (const key of ["splash", "loading_img"]) {
                if (Object.prototype.hasOwnProperty.call(data, key)) { delete data[key]; changed = true; }
            }
        }
    } else if (mode === "ireader" || mode === "missevan" || mode === "wuta" || mode === "duitang" || mode === "tuilan") {
        const fields = {
            ireader: [[value, "Splash"]],
            missevan: [[value.info, "splash"], [value.info, "splash_ready"]],
            wuta: [[value.regular, "splash"]],
            duitang: [[data, "SPLASH_SWING_OPEN"]],
            tuilan: [[data, "splashConf"], [data, "splashConfNew"]]
        };
        for (const [target, key] of fields[mode]) {
            if (target && typeof target === "object" && Object.prototype.hasOwnProperty.call(target, key)) {
                delete target[key];
                changed = true;
            }
        }
    } else if (mode === "jump") {
        if (data && typeof data === "object") {
            clear(data, "adList");
            if (data.launchAd && typeof data.launchAd === "object" && "showType" in data.launchAd && data.launchAd.showType !== 0) {
                data.launchAd.showType = 0;
                changed = true;
            }
        }
    } else if (mode === "kuaidi") {
        if (Object.prototype.hasOwnProperty.call(value, "adsplash")) {
            delete value.adsplash;
            changed = true;
        }
    } else if (mode === "taobao") {
        function visit(node) {
            if (!node || typeof node !== "object") return;
            if (Array.isArray(node)) { for (const item of node) visit(item); return; }
            for (const key of Object.keys(node)) {
                const child = node[key];
                if (key === "taobao-splash" && child && typeof child === "object") {
                    clear(child, "data");
                } else { visit(child); }
            }
        }
        visit(value);
    } else if (mode === "faw") {
        clear(value, "data");
    } else if (mode === "tuhu") {
        if (data && data.pageId === "/launch") {
            clear(data, "moduleActionList");
            if (Object.prototype.hasOwnProperty.call(data, "dsl") && data.dsl !== null) {
                data.dsl = null;
                changed = true;
            }
        }
    } else if (mode === "fund") {
        clear(value, "datas");
    } else if (mode === "kfc") {
        const slots = ["bootStrapAd", "registBootStrapAd", "activeBootStrapAd", "app6_bootStrapAd", "app6_activeBootStrapAd", "newhomepage_AIbootStrapAd", "newhomepage_AIregistBootStrapAd", "newhomepage_AIactiveBootStrapAd"];
        for (const section of [value, data]) {
            if (!section || typeof section !== "object" || Array.isArray(section)) continue;
            for (const key of slots) {
                if (!Object.prototype.hasOwnProperty.call(section, key)) continue;
                if (Array.isArray(section[key])) clear(section, key);
                else { delete section[key]; changed = true; }
            }
        }
    } else if (mode === "netease-prefetch") {
        clear(value, "open_ads");
        clear(data, "open_ads");
    } else if (mode === "weibo-preload") {
        clear(value, "ads");
    } else if (mode === "yikaobang") {
        if (data && typeof data === "object" && Object.prototype.hasOwnProperty.call(data, "boot_page")) {
            delete data.boot_page;
            changed = true;
        }
    } else if (mode === "meituan") {
        const start = data && data.startpicture;
        clear(start, "ad");
        clear(start, "mk");
    }
    return changed;
}

try {
    const body = $response.body;
    const status = $response.status || $response.statusCode || 200;
    if (typeof body !== "string" || status < 200 || status >= 300) {
        $done({});
    } else {
        const value = JSON.parse(body);
        $done(scrub(String($argument || ""), value) ? {body: JSON.stringify(value)} : {});
    }
} catch (_) {
    $done({});
}
