from __future__ import annotations

import re

BLOCKED_URL_MARKERS = (
    "imasdk.googleapis.com/js/sdkloader/ima3.js",
    "/api/video/getadsdatalist",
    "hltv-tracking.js",
    "herebyad",
    "ad-provider.js",
    "help.fanza.cc/",
    "jquery/slim-3.2.min.js",
    "/assets/jquery/main100.js",
    "/assets/jquery/p2adult.js",
    "/_next/static/chunks/pages/home-",
    "/js/static/header/sda/ppsuma",
    "javlibrary.com/img/.*.gif",
    "javlibrary.com/cn/videoreviews.php",
    "www.pornhub.com$",
    "/api/v4/questions/",
    "/api/v4/answers/",
    "/api/articles/"
)
PRESERVED_AD_URL_MARKERS = (
    "js.wpadmngr.com/static/admanager.js",
    "https://a.realsrv.com/ad-provider.js",
    "https://a.magsrv.com/ad-provider.js"
)
BLOCKED_MITM_HOSTS = frozenset([
    "*.cloudfront.net",
    "*.cnn.com",
    "*.mit.edu",
    "*.bloomberg.com",
    "*.ted.com",
    "*.ycombinator.com",
    "*.cdn77.org",
    "www.federalreserve.gov",
    "www.nasa.gov",
    "www.stanford.edu",
    "m.imdb.com",
    "www.rottentomatoes.com",
    "stackoverflow.com",
    "www.reuters.com",
    "www.nytimes.com",
    "www.theguardian.com",
    "www.usatoday.com",
    "www.npr.org",
    "www.cbsnews.com",
    "www.cnn10.com",
    "www.wired.com",
    "www.theverge.com",
    "www.producthunt.com",
    "www.bbc.com",
    "www.bbc.co.uk",
    "www.ycombinator.com",
    "openai.com",
    "cdn.openai.com",
    "www.un.org",
    "webtv.un.org",
    "www.mit.edu",
    "www.reddit.com",
    "imasdk.googleapis.com",
    "blog.google",
    "techcrunch.com",
    "www.taipeitimes.com",
    "www.5dy*",
    "z-library.*"
])
USER_CSS_REPLACEMENTS = [
    [
        "        test: \"*, div,img {display: none !important}\",\n",
        ""
    ],
    [
        "        tvn: \"img[src*='gif'], iframe {display:none !important; pointer-events:none important;}\",\n",
        "        tvn: \"img[src*='gif'] {display:none !important; pointer-events:none important;}\",\n"
    ],
    [
        "        hanime1: \".comics-banner-ads,span.scaled-exoclick, iframe, #close-mobile-ad-btn, #bottom-ads, div[style*=\\\"width: 310px; height: 282px;\\\"] {display:none !important; pointer-events: none !important;}\",\n",
        "        hanime1: \".comics-banner-ads,span.scaled-exoclick, #close-mobile-ad-btn, #bottom-ads, div[style*=\\\"width: 310px; height: 282px;\\\"] {display:none !important; pointer-events: none !important;}\",\n"
    ],
    [
        "        diyibanzhu: \"img, #adsbox, .slide-ad {height:0px; display:none !important; pointer-events: none !important;}\",\n",
        "        diyibanzhu: \"#adsbox, .slide-ad {height:0px; display:none !important; pointer-events: none !important;}\",\n"
    ],
    [
        "        tz659: \"figure, img[src*='mt2.jpg'],img[src*='pf.gif'],[src*='.gif'], iframe {display:none !important}\",\n",
        "        tz659: \"img[src*='mt2.jpg'],img[src*='pf.gif'],[src*='.gif'] {display:none !important}\",\n"
    ],
    [
        "        javlibrary: \".menutext.whenmobile {top:90px;z-index:114;} a[href*='redirect'] {display:none!important} #toplogo {height:64px} .videothumblist .videos {min-width:auto;}.titlebox.whenmobile{width:250px} #topmenu.whenmobile {height:70px;} .searchbar.whenmobile{right:2px}  div.videothumblist.whenmobile {overflow:scroll!important;overflow-x:hidden!important;} div#rightcolumn.whenmobile {width:300px} #rightcolumn {right:90px} #leftmenu {width:90px; position:fixed;} div#content {width:auto !important} body.main { min-width: auto; width:auto !important} iframe,img[src*='gif'] , td.advsearch {display:none!important;pointer-events: none !important;}\",\n",
        "        javlibrary: \".menutext.whenmobile {top:90px;z-index:114;} a[href*='redirect'] {display:none!important} #toplogo {height:64px} .videothumblist .videos {min-width:auto;}.titlebox.whenmobile{width:250px} #topmenu.whenmobile {height:70px;} .searchbar.whenmobile{right:2px}  div.videothumblist.whenmobile {overflow:scroll!important;overflow-x:hidden!important;} div#rightcolumn.whenmobile {width:300px} #rightcolumn {right:90px} #leftmenu {width:90px; position:fixed;} div#content {width:auto !important} body.main { min-width: auto; width:auto !important} img[src*='gif'] , td.advsearch {display:none!important;pointer-events: none !important;}\",\n"
    ],
    [
        "        rouvideo: \"div[style*='pointer-events: none'],.flex.items-center.justify-center.my-2,ins > iframe,a.vast-blocker,.p-2.rounded.text-center,.text-xl.mb-1,[class*='hover:underline'],[style*='overflow: hidden'],[data-advadstrackid] {display:none !important; pointer-events: none !important;}\",\n",
        "        rouvideo: \"div[style*='pointer-events: none'],.flex.items-center.justify-center.my-2,ins > iframe,a.vast-blocker,.p-2.rounded.text-center,.text-xl.mb-1,[class*='hover:underline'],[data-advadstrackid] {display:none !important; pointer-events: none !important;}\",\n"
    ],
    [
        "        xchina: \"a[target='_blank']:not([href*='limbopro' i]):not([href*='.m3u8' i]):not(.echo *):not(:has(+ .echo)),a[href*='pre'],div.static-container-5,div.static-container-8,div.block-overlay,.push-slider,.push-top-container,.push-bottom {display:none !important; pointer-events: none !important;}\",\n",
        "        xchina: \"div.static-container-5, div.static-container-8 {display:none !important; pointer-events:none !important;}\",\n"
    ],
    [
        "        opgg: \".AdSense,  div[data-ad], tr.ad, #banner-container, section[class*='md:hidden'] {display:none !important; pointer-events: none !important;}\",\n",
        "        opgg: \".AdSense,  div[data-ad], tr.ad, #banner-container {display:none !important; pointer-events: none !important;}\",\n"
    ],
    [
        "        javday: \"p[style], p > a {display:none !important; pointer-events: none !important;} \",\n",
        "        javday: \"\",\n"
    ]
]

def unsafe_rewrite(line: str) -> bool:
    value = line.replace(r"\/", "/").replace(r"\.", ".").lower()
    if any(marker in value for marker in PRESERVED_AD_URL_MARKERS):
        return False
    if any(marker in value for marker in BLOCKED_URL_MARKERS):
        return True
    if "cloudfront.net/?" in value or "[-a-z]{6,}" in value:
        return True
    return "http" not in value and "https" not in value

def harden_module(source: str) -> str:
    section = ""
    rows = []
    for original in source.splitlines():
        line = original.strip()
        if re.fullmatch(r"\[[^\]]+\]", line):
            section = line
        if section == "[URL Rewrite]" and line and not line.startswith(("#", "[")):
            if unsafe_rewrite(original):
                continue
        if section == "[Header Rewrite]" and "header-replace Content-Security-Policy" in original:
            continue
        if section == "[MITM]" and original.startswith("hostname = %APPEND% "):
            entries = [part.strip() for part in original.split("%APPEND%", 1)[1].split(",")]
            hosts = list(dict.fromkeys(
                host for host in entries if host and host.lower() not in BLOCKED_MITM_HOSTS
            ))
            original = "hostname = %APPEND% " + ", ".join(hosts)
        rows.append(original)
    return "\n".join(rows).rstrip("\n") + "\n"

def harden_loader(source: str) -> str:
    first = "        let domainCSS_Injection = '';"
    last = "        // --- 动态 CSS 注入逻辑结束 ---"
    if source.count(first) != 1 or source.count(last) != 1:
        raise RuntimeError("Unexpected CSS injection structure")
    start, end = source.index(first), source.index(last)
    source = (
        source[:start]
        + "        const FINAL_TITLE_INJECTION = TITLE_INJECTION_BASE;\n"
        + "        const FINAL_BODY_INJECTION = BODY_INJECTION_BASE;\n"
        + source[end:]
    )
    old = "newBody = newBody.replace(TITLE_REGEX, FINAL_TITLE_INJECTION);"
    if source.count(old) != 2:
        raise RuntimeError("Unexpected HTML injection structure")
    source = source.replace(old, "newBody = newBody.replace(TITLE_REGEX, head => head + '\\n' + FINAL_TITLE_INJECTION);")
    old = "            newBody = newBody.replace(WINDOW_OPEN_REGEX, 'function block_open(');\n            modified = true;\n"
    if source.count(old) != 1:
        raise RuntimeError("Unexpected window.open rewrite structure")
    source = source.replace(old, "")
    first = "        // 6. 修改响应头"
    last = "    } catch (error)"
    if source.count(first) != 1 or source.count(last) != 1:
        raise RuntimeError("Unexpected response header change structure")
    start, end = source.index(first), source.index(last)
    source = source[:start] + "        $done({ body: newBody });\n\n" + source[end:]
    old = "const headers = $response.headers;"
    if source.count(old) != 1:
        raise RuntimeError("Unexpected response header read")
    source = source.replace(old, "const headers = $response.headers || {};")
    old = "const contentType = headers['Content-Type'] || headers['content-type'] || '';"
    if source.count(old) != 1:
        raise RuntimeError("Unexpected Content-Type guard")
    source = source.replace(old, "const contentType = String(headers['Content-Type'] || headers['content-type'] || '').toLowerCase();")
    source = source.replace('//const CSS_URL = "https://limbopro.com/CSS/Adblock4limbo.user.css";\n', "")
    return source

def harden_user(source: str) -> str:
    for old, new in USER_CSS_REPLACEMENTS:
        if source.count(old) != 1:
            raise RuntimeError("Upstream user CSS requires renewed review")
        source = source.replace(old, new)
    return source
