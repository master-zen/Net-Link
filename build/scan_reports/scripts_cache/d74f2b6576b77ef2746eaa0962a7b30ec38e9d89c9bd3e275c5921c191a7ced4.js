
/**
 * Nicegram用户信息解锁脚本
 * 兼容 Surge 和 QuantumultX
 * 解锁Plus订阅功能
 */

let body = $response.body;

if (body) {
    try {
        let obj = JSON.parse(body);
        
        if (obj.data && obj.data.user) {
            obj.data.user.subscriptionPlus = true;
            obj.data.user.store_subscription = true;
            obj.data.user.subscription = true;
            obj.data.user.lifetime_subscription = true;
            obj.data.user.gems_balance = 99999;
            
            console.log("✅ Nicegram 用户信息解锁成功 - 宝石余额: " + obj.data.user.gems_balance);
        }
        
        $done({ body: JSON.stringify(obj) });
    } catch (error) {
        console.log("❌ Nicegram 用户信息解锁失败: " + error);
        $done({});
    }
} else {
    $done({});
}
