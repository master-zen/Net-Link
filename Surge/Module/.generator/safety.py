from __future__ import annotations
import re

PROTECTED_REWRITE_MARKERS = (
    "napi.ithome.com/",
    "learn.chaoxing.com/apis/service/appConfig",
    "api.dangdang.com/mapi",
    "mapi.dangdang.com/index.php?action=init",
    "r.inews.qq.com/",
    "helper.2bulu.com/",
    "apis.lifeweek.com.cn/api/baseConfig/",
    "ccsp-egmas.sf-express.com/cx-app-base/base/app/appVersion/",
    "tcmobileapi.17usoft.com/appindexnew/index/getappindexconfig",
    "gateway-api.dushu365.com/chief-orch/config/config/",
    "zconfig.alibabausercontent.com/zconfig",
    "fuss10.elemecdn.com/",
    "eastmoney.com/infoService/",
    "zhangyuyidong.cn/api/",
    "app.zhuanzhuan.com/zzx/transfer/getConfigInfo",
    "shopapi.io.mi.com/mtop/mf/resource/homePage/pageConfig",
    "api.coolapk.com/v6/",
    "api.m.jd.com/client.action?functionId=(hotWords|hotSearchTerms)",
    "api.m.jd.com/client.action?functionId=home_launchConfig",
    "notify.baicizhan.com/rpc/notify/get_latest_notify",
    "mangaapi.manhuaren.",
    "api.kmovie.gifshow.com/rest/n/kmovie/app/(resource|banner)",
    "rengine-platform.llsapp.com/auth/api/remoteResource/",
    "a.qiumibao.com/activities/config.php",
    "a.qiumibao.com/ios/config/",
    "meituan.net/movie/",
    "apps.api.ke.com/config/config/",
    "m.meitun.com/newapi/router/topic/hometptf/feedRecommend",
    "flyert",
    "api.smart.jd.com/c/service/getLoadingLinks",
    "dispatcher.camera360.com/api/v1/list",
    "home.mi.com/cgi-op/api/",
    "api.bevol.com/appmain/app/home/launch",
    "tipatipa.xyz/announcements",
    "iphone.ac.qq.com/",
    "api.xueqiu.com/snowpard/launch_strategy/",
    "api2.yaduo.com/",
    "zongheng.com/iosapi/system/startup",
    "mrobot.pconline.com.cn/s-900/onlineinfo/cms/launch",
    "new-app-api.ylyk.com/v1/user/myinfo/adviser",
    "api.shenyin.name/stay-fork/browse/featured",
)
DOUBAN_AD_REWRITES = frozenset({
    r"^https?://api.douban.com/v2/app_ads/splash",
    r"^https?://api.douban.com/b.*/common_ads\?.*",
})
PROTECTED_MITM_HOSTS = frozenset([
    "napi.ithome.com",
    "vt1.doubanio.com",
    "learn.chaoxing.com",
    "api.dangdang.com",
    "mapi.dangdang.com",
    "r.inews.qq.com",
    "helper.2bulu.com",
    "apis.lifeweek.com.cn",
    "ccsp-egmas.sf-express.com",
    "tcmobileapi.17usoft.com",
    "gateway-api.dushu365.com",
    "zconfig.alibabausercontent.com",
    "fuss10.elemecdn.com",
    "app.zhuanzhuan.com",
    "shopapi.io.mi.com",
    "api.coolapk.com",
    "notify.baicizhan.com",
    "rengine-platform.llsapp.com",
    "a.qiumibao.com",
    "apps.api.ke.com",
    "m.meitun.com",
    "*.flyert.*",
    "www.flyert.com",
    "api.smart.jd.com",
    "dispatcher.camera360.com",
    "home.mi.com",
    "api.bevol.com",
    "*.tipatipa.xyz",
    "iphone.ac.qq.com",
    "api.xueqiu.com",
    "api2.yaduo.com",
    "*.zongheng.com",
    "mrobot.pconline.com.cn",
    "new-app-api.ylyk.com",
    "api.shenyin.name",
])

CORE_OPERATION_PATTERN = re.compile(
    r"/(?:mobile/init|main/init|appConfig|launchConfig|remoteConfig|"
    r"getAppEntranceConfig|getConfigInfo|getIosNewConfig|detectionUpgrade|"
    r"queryTasks|searchHotCatList|getUserCenter|startInit|getappindexconfig)(?:[/?$]|$)",
    re.IGNORECASE,
)

def normalize_pattern(pattern: str) -> str:
    return pattern.replace(r"\/", "/").replace(r"\.", ".").replace(r"\:", ":")

def should_skip_rewrite(pattern: str) -> bool:
    value = normalize_pattern(pattern)
    if "api.douban.com/" in value:
        return value not in DOUBAN_AD_REWRITES
    if any(fragment in value for fragment in PROTECTED_REWRITE_MARKERS):
        return True
    if CORE_OPERATION_PATTERN.search(value):
        return True
    if value.endswith("/api/") and "ad" not in value.lower():
        return True
    if re.search(r"\.(?:mp4|m3u8|mov)(?:$|\\\?)", value, re.IGNORECASE):
        return not bool(re.search(r"/ad/|/ads/|advert|splash", value, re.IGNORECASE))
    return False

def is_protected_mitm_host(host: str) -> bool:
    return host.lower().strip() in PROTECTED_MITM_HOSTS
