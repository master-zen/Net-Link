from __future__ import annotations

import os
import re
import time
from pathlib import Path
from urllib.request import Request, urlopen

from adblock_safety import harden_loader, harden_module, harden_user

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://raw.githubusercontent.com/limbopro/Adblock4limbo/main/"
SOURCES = {
    "module": "Surge/rewrite/Adblock4limbo.sgmodule",
    "loader": "Adguard/Adblock4limbo.js",
    "user": "Adguard/Adblock4limbo.user.js",
}


def download(path):
    error = None
    for attempt in range(3):
        if attempt:
            time.sleep(attempt * 2)
        try:
            request = Request(
                BASE + path,
                headers={"User-Agent": "Net-Link-Adblock4limbo/1.0", "Cache-Control": "no-cache"},
            )
            with urlopen(request, timeout=30) as response:
                data = response.read()
            head = data[:512].lower()
            if b"<!doctype html" in head or b"<html" in head:
                raise RuntimeError("Unexpected HTML response")
            return data.decode("utf-8-sig").replace("\r\n", "\n")
        except Exception as exc:
            error = exc
    raise RuntimeError(f"Upstream download failed: {path}") from error


def replace_exact(source, pattern, replacement, expected=1):
    changed, count = re.subn(
        pattern,
        lambda _: replacement,
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    if count != expected:
        raise RuntimeError(
            f"Upstream structure changed: {pattern!r}, expected {expected}, got {count}"
        )
    return changed


def transform_loader(source, js_url):
    tick = chr(96)
    token = "$" + "{JS_URL}"
    source = replace_exact(
        source,
        "^const privacyGate_style = " + tick + r".*?^const JS_URL = ",
        "const JS_URL = ",
    )
    source = replace_exact(
        source,
        r'^const JS_URL = "https://limbopro\.com/Adguard/Adblock4limbo\.user\.js";$',
        'const JS_URL = "' + js_url + '";',
    )
    source = replace_exact(
        source,
        r"^const (?:fc_JS_URL|fd_JS_URL|agent_JS_URL|autoAdDetector_JS_URL)[^\n]*(?:\n|$)",
        "",
        4,
    )
    title = (
        'const TITLE_INJECTION_BASE = ' + tick
        + '<script type="text/javascript" defer src="' + token + '"></script>\\n'
        + tick + ';'
    )
    body = (
        'const BODY_INJECTION_BASE = ' + tick
        + '<script type="text/javascript" defer src="' + token + '"></script>\\n</body>'
        + tick + ';'
    )
    source = replace_exact(
        source,
        "^const TITLE_INJECTION_BASE = " + tick + ".*?^" + tick + ";",
        title,
    )
    source = replace_exact(
        source,
        "^const BODY_INJECTION_BASE = " + tick + ".*?^" + tick + ";",
        body,
    )
    source = replace_exact(
        source,
        r"^[ \t]*newBody = newBody\.replace\(TITLE_REGEX,\s*privacyGate_style\)[^\n]*(?:\n|$)",
        "",
        2,
    )
    source = replace_exact(
        source,
        r"^[ \t]*newBody = newBody\.replace\(BODY_REGEX,\s*privacyGate_script\)[^\n]*(?:\n|$)",
        "",
        2,
    )
    for name in (
        "fc_JS_URL",
        "fd_JS_URL",
        "agent_JS_URL",
        "autoAdDetector_JS_URL",
        "privacyGate_style",
        "privacyGate_script",
        "elementBlocker.user.js",
    ):
        if name in source:
            raise RuntimeError(f"Unwanted dependency remains: {name}")
    if "function main()" not in source or "main();" not in source:
        raise RuntimeError("Missing main response processor")
    return harden_loader(source)


def transform_user(source):
    source = replace_exact(
        source,
        r"^[ \t]*daohang_build\(\);[ \t]*(?:\n|$)",
        "",
    )
    source = replace_exact(
        source,
        r"^function daohang_build\(\).*?(?=^// 按根据父元素是否包含子元素而删除父元素)",
        "",
    )
    source = replace_exact(
        source,
        r'^[ \t]*functionx:\s*"https://limbopro\.com/Adguard/Adblock4limbo\.function\.js",[^\n]*(?:\n|$)',
        "",
    )
    source = replace_exact(
        source,
        r"^/\* 监控用户尝试唤起导航页 \*/.*?(?=^window\.attemptFixScrolling =)",
        "",
    )
    source = source.replace('douban: "*{display:none!important}"', 'douban: ""')
    source = replace_exact(source, r"^\s*case 'douban':.*?(?=^\s*case 'zhihu':)", "", 1)
    source = source.replace("        'douban',\n", "")
    for phrase in ("floating-warning-box", "showFloatingWarning()", "function daohang_build()"):
        if phrase in source:
            raise RuntimeError(f"Navigation component remains: {phrase}")
    return harden_user(source)


def transform_module(source, loader_url):
    for section in ("[URL Rewrite]", "[Header Rewrite]", "[Script]", "[MITM]"):
        if section not in source:
            raise RuntimeError(f"Missing module section: {section}")
    old = "script-path=https://limbopro.com/Adguard/Adblock4limbo.js"
    new = "script-path=" + loader_url
    count = source.count(old)
    if count < 20:
        raise RuntimeError("Unexpected script rule count")
    source = source.replace(old, new)
    source = source.replace("script-update-interval=0", "script-update-interval=86400")
    source = replace_exact(source, r"^#!name=[^\n]*$", "#!name=Adblock4limbo Ads Only")
    source = replace_exact(
        source,
        r"^#!desc=[^\n]*$",
        "#!desc=Adblock4limbo 广告拦截专用版，移除悬浮导航及附加工具",
    )
    paths = re.findall(r"script-path=([^,\s]+)", source)
    if len(paths) != count or set(paths) != {loader_url}:
        raise RuntimeError("Unexpected external script reference")
    return harden_module(source)


def save_if_changed(path, data):
    data = data.rstrip("\n") + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == data:
        return
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(data, encoding="utf-8")
    temporary.replace(path)


def main():
    repository = os.environ.get("GITHUB_REPOSITORY", "master-zen/Net-Link")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise RuntimeError("Invalid GitHub repository")
    raw_url = (
        "https://raw.githubusercontent.com/" + repository
        + "/main/Surge/Module/runtime/Adblock4limbo.js"
    )
    cdn_url = (
        "https://cdn.jsdelivr.net/gh/" + repository
        + "@main/Surge/Module/runtime/Adblock4limbo.user.js"
    )
    originals = {key: download(path) for key, path in SOURCES.items()}
    if (
        len(originals["module"]) < 20000
        or len(originals["loader"]) < 5000
        or len(originals["user"]) < 100000
    ):
        raise RuntimeError("Upstream file size outside expected range")
    module = transform_module(originals["module"], raw_url)
    loader = transform_loader(originals["loader"], cdn_url)
    user = transform_user(originals["user"])
    if module.count(" - reject") > originals["module"].count(" - reject"):
        raise RuntimeError("Additional rewrite rules appeared")
    if harden_module(module) != module:
        raise RuntimeError("Adblock4limbo safety policy was not applied")
    if originals["module"].count("type=http-response") != module.count("type=http-response"):
        raise RuntimeError("Response script count changed")
    if "var adsMax" not in user or "FINAL_TITLE_INJECTION" not in loader:
        raise RuntimeError("Core ad filtering functionality missing")
    if "domainCSS_Injection =" in loader or "newHeaders" in loader:
        raise RuntimeError("Unsafe HTML response modification remains")
    runtime = ROOT / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    save_if_changed(runtime / "Adblock4limbo.js", loader)
    save_if_changed(runtime / "Adblock4limbo.user.js", user)
    save_if_changed(ROOT / "Adblock4limbo.sgmodule", module)


if __name__ == "__main__":
    main()
