/**
 * 起点读书去广告脚本
 * 用于Surge的http-response脚本
 *
 * 功能：
 * 1. 移除广告列表API的广告数据
 * 2. 清空闪屏广告配置
 * 3. 移除书架悬浮广告
 * 4. 清理Widget广告内容
 * 5. 移除签到页面广告
 * 6. 隐藏每日推荐（猜你喜欢）
 * 7. 清除书架顶部操作横幅广告
 * 8. 清除书架广告（/bookshelf/getad）
 * 9. 清除弹窗广告批量获取（/popup/batchget）
 * 10. 过滤"我"页面推广入口
 * 11. 清除客户端配置中的广告（活动弹窗、视频广告等）
 */

const url = $request.url;
let body = $response.body;

try {
    let obj = JSON.parse(body);

    // 1. 处理广告列表批量获取接口
    // /argus/api/v2/adv/getadvlistbatch
    if (url.includes('/adv/getadvlistbatch')) {
        if (obj.Data) {
            obj.Data = {};
        }
        console.log('已拦截广告列表批量接口');
    }

    // 2. 处理书架悬浮广告接口
    // /argus/api/v1/bookshelf/getHoverAdv
    else if (url.includes('/bookshelf/getHoverAdv')) {
        if (obj.Data) {
            // 清空广告数据
            obj.Data.AdvInfo = null;
            obj.Data.ShowAdv = false;
            if (obj.Data.AdvList) {
                obj.Data.AdvList = [];
            }
            // 清空ItemList（悬浮广告列表）
            if (obj.Data.ItemList) {
                obj.Data.ItemList = [];
            }
        }
        console.log('已清除书架悬浮广告');
    }

    // 3. 处理闪屏广告接口
    // /argus/api/v4/client/getsplashscreen
    else if (url.includes('/getsplashscreen')) {
        if (obj.Data) {
            obj.Data.AdList = [];
            obj.Data.SplashAdList = [];
            obj.Data.TipList = [];
            obj.Data.VideoAdList = [];
            // 清空List字段（主要的闪屏广告列表）
            if (obj.Data.List) {
                obj.Data.List = [];
            }
        }
        console.log('已清除闪屏广告配置');
    }

    // 4. 处理iOS广告接口
    // /argus/api/v1/client/iosad
    else if (url.includes('/client/iosad')) {
        obj.Data = {};
        obj.Result = 0;
        console.log('已拦截iOS广告请求');
    }

    // 5. 处理Widget内容接口（可能包含广告）
    // /argus/api/v1/widget/getContent
    else if (url.includes('/widget/getContent')) {
        if (obj.Data && obj.Data.WidgetInfo) {
            // 移除广告类型的Widget
            if (obj.Data.WidgetInfo.WidgetType === 'ad' ||
                obj.Data.WidgetInfo.WidgetType === 'advertisement') {
                obj.Data.WidgetInfo = null;
            }
            // 移除Widget列表中的广告
            if (obj.Data.WidgetList && Array.isArray(obj.Data.WidgetList)) {
                obj.Data.WidgetList = obj.Data.WidgetList.filter(item => {
                    return !(item.WidgetType === 'ad' ||
                           item.WidgetType === 'advertisement' ||
                           item.IsAd === true ||
                           item.isAd === true);
                });
            }
        }
        console.log('已过滤Widget广告内容');
    }

    // 6. 处理签到简要信息接口（可能包含广告）
    // /argus/api/v2/checkin/simpleinfo
    else if (url.includes('/checkin/simpleinfo')) {
        if (obj.Data) {
            // 移除广告相关字段
            if (obj.Data.AdInfo) {
                obj.Data.AdInfo = null;
            }
            if (obj.Data.AdvInfo) {
                obj.Data.AdvInfo = null;
            }
            if (obj.Data.BottomAdv) {
                obj.Data.BottomAdv = null;
            }
            if (obj.Data.FloatAdv) {
                obj.Data.FloatAdv = null;
            }
        }
        console.log('已清除签到页面广告');
    }

    // 7. 处理每日推荐接口（猜你喜欢）
    // /argus/api/v1/dailyrecommend/recommendBook
    else if (url.includes('/dailyrecommend/recommendBook')) {
        // 返回空数据，隐藏"猜你喜欢"推荐
        obj.Data = null;
        obj.Result = 0;
        console.log('已隐藏每日推荐（猜你喜欢）');
    }

    // 8. 处理书架顶部操作横幅（包含广告）
    // /argus/api/v1/bookshelf/getTopOperation
    else if (url.includes('/bookshelf/getTopOperation')) {
        if (obj.Data) {
            // 清空所有顶部操作项（通常包含广告）
            obj.Data.Items = [];
            // 清空主要信息（横幅广告）
            if (obj.Data.MainInfo) {
                obj.Data.MainInfo = null;
            }
        }
        console.log('已清除书架顶部操作横幅广告');
    }

    // 9. 处理每日推荐完整版接口（V2版本）
    // /argus/api/v2/dailyrecommend/getdailyrecommend
    else if (url.includes('/dailyrecommend/getdailyrecommend')) {
        if (obj.Data) {
            // 清空推荐书籍列表
            obj.Data.Items = [];
            // 清空背景信息
            if (obj.Data.BgInfo) {
                obj.Data.BgInfo = null;
            }
            // 清空AI推荐入口
            if (obj.Data.AiRecommendUrl) {
                obj.Data.AiRecommendUrl = "";
            }
        }
        console.log('已清除每日推荐完整版（V2）');
    }

    // 10. 处理书架高级阅读信息（包含推荐书籍）
    // /argus/api/v1/bookshelf/getHighLevelBookReadInfo
    else if (url.includes('/getHighLevelBookReadInfo')) {
        if (obj.Data) {
            // 清空沉浸推荐书籍列表（SinkBookInfos）
            if (obj.Data.SinkBookInfos) {
                obj.Data.SinkBookInfos = [];
            }
        }
        console.log('已清除书架沉浸推荐');
    }

    // 11. 处理书架广告接口
    // /argus/api/v1/bookshelf/getad
    else if (url.includes('/bookshelf/getad')) {
        if (obj.Data) {
            // 隐藏广告显示
            obj.Data.Show = 0;
            // 清空游戏中心URL
            if (obj.Data.GameUrl) {
                obj.Data.GameUrl = "";
            }
            // 清空其他可能的广告字段
            if (obj.Data.AdInfo) {
                obj.Data.AdInfo = null;
            }
            if (obj.Data.AdvInfo) {
                obj.Data.AdvInfo = null;
            }
        }
        console.log('已清除书架广告');
    }

    // 12. 处理弹窗广告批量获取接口
    // /argus/api/v1/popup/batchget
    else if (url.includes('/popup/batchget')) {
        if (obj.Data) {
            // 清空弹窗列表
            if (obj.Data.PopupList) {
                obj.Data.PopupList = [];
            }
            // 清空版本信息（防止更新弹窗）
            obj.Data.Version = 0;
        }
        console.log('已清除弹窗广告列表');
    }

    // 13. 处理"我"页面发现入口（过滤推广）
    // /argus/api/v1/user/getsimplediscover
    else if (url.includes('/user/getsimplediscover')) {
        if (obj.Data && obj.Data.Items) {
            // 过滤掉推广类型的入口
            const promotionKeywords = ['YOUXI', 'HUODONG', 'HONGBAO', 'SHANGCHENG', 'KAPAI', 'TOUZI'];
            const originalCount = obj.Data.Items.length;
            obj.Data.Items = obj.Data.Items.filter(item => {
                return !promotionKeywords.some(kw => item.KeyName.includes(kw));
            });
            const filteredCount = originalCount - obj.Data.Items.length;
            console.log(`已过滤"我"页面推广入口: ${filteredCount}个 (游戏、活动中心、红包广场、周边商城、卡牌广场、新书投资)`);
        }
    }

    // 14. 处理客户端配置接口（包含多种广告配置）
    // /argus/api/v1/client/getconf
    else if (url.includes('/client/getconf')) {
        if (obj.Data) {
            let cleanedItems = [];

            // 清除活动弹窗配置
            if (obj.Data.ActivityPopup && obj.Data.ActivityPopup.Data) {
                const popupCount = obj.Data.ActivityPopup.Data.length;
                obj.Data.ActivityPopup.Data = [];
                obj.Data.ActivityPopup.Version = 0;
                if (popupCount > 0) {
                    cleanedItems.push(`活动弹窗(${popupCount}个)`);
                }
            }

            // 清除活动图标
            if (obj.Data.ActivityIcon) {
                obj.Data.ActivityIcon = null;
                cleanedItems.push('活动图标');
            }

            // 清除视频广告位置配置
            if (obj.Data.AdVideoPositionConfig && obj.Data.AdVideoPositionConfig.length > 0) {
                const adCount = obj.Data.AdVideoPositionConfig.length;
                obj.Data.AdVideoPositionConfig = [];
                cleanedItems.push(`视频广告位(${adCount}个)`);
            }

            // 清除广点通广告配置（如果启用）
            if (obj.Data.GDT) {
                // 确保所有广告都是禁用状态
                if (obj.Data.GDT.Account) {
                    obj.Data.GDT.Account.Enable = 0;
                }
                if (obj.Data.GDT.Popup) {
                    obj.Data.GDT.Popup.Enable = 0;
                }
                cleanedItems.push('广点通配置');
            }

            // 清除阅读器弹窗配置（确保全部禁用）
            if (obj.Data.ReaderDialog) {
                if (obj.Data.ReaderDialog.BookDialog) {
                    obj.Data.ReaderDialog.BookDialog.Enabled = 0;
                }
                if (obj.Data.ReaderDialog.FirstDialog) {
                    obj.Data.ReaderDialog.FirstDialog.Enabled = 0;
                }
                if (obj.Data.ReaderDialog.SkateDialog) {
                    obj.Data.ReaderDialog.SkateDialog.Enabled = 0;
                }
                if (obj.Data.ReaderDialog.MultiChapters) {
                    obj.Data.ReaderDialog.MultiChapters.Enabled = 0;
                }
                if (obj.Data.ReaderDialog.DialogV2) {
                    obj.Data.ReaderDialog.DialogV2 = [];
                }
            }

            // 禁用剪贴板读取
            if (obj.Data.EnableClipboardReading !== undefined) {
                obj.Data.EnableClipboardReading = 0;
            }

            // 禁用章节提前引导
            if (obj.Data.EnableChapterAdvanceGuide !== undefined) {
                obj.Data.EnableChapterAdvanceGuide = 0;
            }

            // 禁用每日推荐灰度测试（书架顶部"每日导读"推荐卡片）
            if (obj.Data.DailyRecommendGray !== undefined) {
                obj.Data.DailyRecommendGray = 0;
                cleanedItems.push('每日推荐灰度测试');
            }

            // 禁用每日阅读推荐原因开关
            if (obj.Data.DailyReadRecReasonSwitch !== undefined) {
                obj.Data.DailyReadRecReasonSwitch = 0;
                cleanedItems.push('每日阅读推荐原因');
            }

            // 禁用书架推荐检查功能（占位符"每日导读"卡片）
            if (obj.Data.QueryBookShelfRecommendCheckNum !== undefined) {
                obj.Data.QueryBookShelfRecommendCheckNum = 0;
                cleanedItems.push('书架推荐检查');
            }

            if (cleanedItems.length > 0) {
                console.log(`已清除客户端配置广告: ${cleanedItems.join(', ')}`);
            } else {
                console.log('已处理客户端配置（无需清理）');
            }
        }
    }

    body = JSON.stringify(obj);

} catch (error) {
    console.log('处理响应时出错: ' + error);
    // 如果解析失败，返回原始响应
}

$done({ body });
