
/**
 * Nicegram广告列表清空脚本
 * 兼容 Surge 和 QuantumultX
 * 清空广告列表
 */

let body = $response.body;

if (body) {
    try {
        let obj = JSON.parse(body);
        
        if (obj.data) {
            let originalLength = Array.isArray(obj.data) ? obj.data.length : 0;
            obj.data = [];
            console.log("✅ Nicegram 广告列表清空成功 - 已移除 " + originalLength + " 条广告");
        }
        
        $done({ body: JSON.stringify(obj) });
    } catch (error) {
        console.log("❌ Nicegram 广告列表清空失败: " + error);
        $done({});
    }
} else {
    $done({});
}
