"use strict";

function parseArgument(input) {
  const result = {};
  for (const item of String(input || "").split("&")) {
    const index = item.indexOf("=");
    if (index < 0) continue;
    result[item.slice(0, index)] = decodeURIComponent(item.slice(index + 1));
  }
  return result;
}

let result = {};
try {
  const args = parseArgument(typeof $argument === "string" ? $argument : "");
  const body = typeof $response !== "undefined" && typeof $response.body === "string"
    ? $response.body
    : typeof $request !== "undefined" && typeof $request.body === "string"
      ? $request.body
      : null;
  if (body !== null && typeof args.find === "string" && typeof args.replace === "string") {
    const regex = new RegExp(args.find, "g");
    result = { body: body.replace(regex, args.replace) };
  }
} catch (error) {
  console.log("[Moyu Body Rewrite] " + String(error));
}
$done(result);
