// Net-Link Surge compatibility shim
// Source: https://raw.githubusercontent.com/irenemsIrenes/profiles/master/Quantumult/X/js/people-news.js
;(() => {
  const __net_link_compat__ = true;
  const __isSurgeLike = typeof $httpClient !== "undefined";
  if (!__isSurgeLike) return;

  if (typeof $task === "undefined") {
    globalThis.$task = {
      fetch(options) {
        return new Promise((resolve, reject) => {
          const request = typeof options === "string" ? { url: options } : { ...(options || {}) };
          const method = String(request.method || "GET").toUpperCase();
          const sender = method === "POST" ? $httpClient.post : $httpClient.get;
          sender(request, (error, response, data) => {
            if (error && !response) {
              reject({ error });
              return;
            }
            const result = response || {};
            result.body = data;
            resolve(result);
          });
        });
      },
    };
  }

  if (typeof $prefs === "undefined" && typeof $persistentStore !== "undefined") {
    globalThis.$prefs = {
      valueForKey(key) {
        return $persistentStore.read(key);
      },
      setValueForKey(value, key) {
        return $persistentStore.write(value, key);
      },
      removeValueForKey(key) {
        return $persistentStore.write("", key);
      },
    };
  }

  if (typeof $notify === "undefined" && typeof $notification !== "undefined") {
    globalThis.$notify = (title = "", subtitle = "", detail = "", url) => {
      const extra = url ? { url } : undefined;
      $notification.post(title, subtitle, detail, extra);
    };
  }

  if (typeof $request !== "undefined" && $request && $request.headers) {
    const lowered = Object.fromEntries(Object.entries($request.headers).map(([k, v]) => [String(k).toLowerCase(), v]));
    $request.headers = new Proxy(lowered, {
      get(target, prop, receiver) {
        return Reflect.get(target, String(prop).toLowerCase(), receiver);
      },
      set(target, prop, value, receiver) {
        return Reflect.set(target, String(prop).toLowerCase(), value, receiver);
      },
    });
  }

  if (typeof $response !== "undefined" && $response && $response.headers) {
    const lowered = Object.fromEntries(Object.entries($response.headers).map(([k, v]) => [String(k).toLowerCase(), v]));
    $response.headers = new Proxy(lowered, {
      get(target, prop, receiver) {
        return Reflect.get(target, String(prop).toLowerCase(), receiver);
      },
      set(target, prop, value, receiver) {
        return Reflect.set(target, String(prop).toLowerCase(), value, receiver);
      },
    });
  }
})();

/**
 * @supported 00D3992C8F27 8B87B7345981
 */


var obj = JSON.parse($response.body);
if (obj.data) {
let cnt = 0
  for (var i = obj.data.length - 1; i >= 0; i--) {
      let item = obj.data[i];
      if (item.view_type && item.view_type.startsWith('advert')) {
          obj.data.splice(i, 1);
          ++cnt;
      }
  }
  //$notify("people news", "ads", "remvoved " + cnt);
}
$done({ body: JSON.stringify(obj) });
