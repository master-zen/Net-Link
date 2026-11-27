(() => {
    'use strict';
    const ROUTE = /^https:\/\/(?:security\.wechat\.com|weixin110\.qq\.com)\/cgi-bin\/mmspamsupport-bin\/newredirectconfirmcgi\?[^#]+$/;
    function entities(s) {
        return s.replace(/&(?:amp|quot|apos|lt|gt|#39|#x27|#x26|#38);/gi, v => ({'&amp;':'&','&quot;':'"','&apos;':"'",'&lt;':'<','&gt;':'>','&#39;':"'",'&#x27;':"'",'&#x26;':'&','&#38;':'&'}[v.toLowerCase()] || v));
    }
    function destination(value) {
        if (typeof value !== 'string' || value.length > 8192) return null;
        let s = entities(value.trim());
        if (/%(?:3a|2f)/i.test(s.slice(0,24)) && !/^https?:\/\//i.test(s)) {
            try { s = decodeURIComponent(s); } catch (_) { return null; }
        }
        if (/[\u0000-\u0020\u007f\\]/.test(s) || /%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)/i.test(s) || !/^https?:\/\//i.test(s)) return null;
        try {
            const u = new URL(s);
            const h = u.hostname.toLowerCase();
            if (u.username || u.password || u.port || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h) || h.endsWith('.local') || h.endsWith('.localhost') || /(^|\.)(?:weixin110\.qq\.com|security\.wechat\.com)$/.test(h)) return null;
            return {url:u.href,host:h};
        } catch (_) { return null; }
    }
    function inspect(body) {
        if (typeof body !== 'string' || body.length > 1048576) return null;
        const m = /\bvar\s+cgiData\s*=\s*(\{[\s\S]*?\})\s*;\s*<\/script\s*>/i.exec(body);
        if (!m) return null;
        let data;
        try { data = JSON.parse(m[1]); } catch (_) { return null; }
        if (!data || !['gray','newgray','empty','block'].includes(data.type)) return null;
        const target = destination(data.url);
        return target ? {...target,type:data.type} : null;
    }
    function run() {
        try {
            if (ROUTE.test($request.url) && Number($response.status) === 200) {
                const x = inspect($response.body);
                if (x) {
                    const blocked = x.type === 'block';
                    const options = blocked ? {action:'clipboard',text:x.url} : {action:'open-url',url:x.url};
                    $notification.post('微信外部链接',x.host,blocked?'微信已拦截该链接。确认后复制原地址；请自行核验风险。':'请核对目标域名，点击通知在浏览器打开。',options);
                }
            }
        } catch (_) {}
        $done({});
    }
    if (typeof module !== 'undefined' && module.exports) module.exports = {inspect,destination,ROUTE};
    if (typeof $done === 'function') run();
})();
