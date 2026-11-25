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
