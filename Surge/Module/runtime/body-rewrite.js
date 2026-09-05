"use strict";

function parseArgument(input) {
  const result = {};

  if (!input) {
    return result;
  }

  input.split("&").forEach((item) => {
    const index = item.indexOf("=");

    if (index === -1) {
      return;
    }

    const key = item.slice(0, index);
    const value = item.slice(index + 1);

    result[key] = decodeURIComponent(value);
  });

  return result;
}


try {
  const args = parseArgument($argument);

  if (
    typeof args.find !== "string" ||
    typeof args.replace !== "string"
  ) {
    $done({});
  } else {
    let body = "";

    if (
      typeof $response !== "undefined" &&
      typeof $response.body === "string"
    ) {
      body = $response.body;
    } else if (
      typeof $request !== "undefined" &&
      typeof $request.body === "string"
    ) {
      body = $request.body;
    } else {
      $done({});
    }

    const regex = new RegExp(
      args.find,
      "g"
    );

    const replaced = body.replace(
      regex,
      args.replace
    );

    $done({
      body: replaced
    });
  }

} catch (error) {
  console.log(
    "[Moyu Body Rewrite] " +
    String(error)
  );

  $done({});
}
