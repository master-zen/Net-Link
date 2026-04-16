/**
 * Nicegram ATT积分修改脚本
 * 兼容 Surge 和 QuantumultX
 * 修改ATT积分为888888888
 * 
 */

let body = $response.body;

if (body) {
    try {
        let obj = JSON.parse(body);
        
        if (obj.data) {
            obj.data.attPoints = 888888888;
            console.log("✅ Nicegram ATT积分修改成功 - 积分已设置为: " + obj.data.attPoints);
        }
        
        $done({ body: JSON.stringify(obj) });
    } catch (error) {
        console.log("❌ Nicegram ATT积分修改失败: " + error);
        $done({});
    }
} else {
    $done({});
}
