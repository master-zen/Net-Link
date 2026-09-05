#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]

UPSTREAM_URL = "https://ddgksf2013.top/rewrite/StartUpAds.conf"

UPSTREAM_FILE = ROOT / "upstream" / "StartUpAds.conf"
META_FILE = ROOT / "upstream" / "metadata.json"
DIST_FILE = Path(
    os.environ.get(
        "OUTPUT_FILE",
        str(ROOT / "dist" / "StartUpAds.sgmodule"),
    )
).expanduser()

MIN_BYTES = 10000
MIN_RULES = 50


class BuildError(RuntimeError):
    pass


def get_runtime_base_url() -> str:
    value = os.getenv("RUNTIME_BASE_URL", "").strip().rstrip("/")
    if value:
        return value

    repo = os.getenv("GITHUB_REPOSITORY", "").strip()
    if repo:
        return f"https://raw.githubusercontent.com/{repo}/main"

    try:
        remote = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        remote = ""

    match = re.search(r"github\.com[:/](.+?/.+?)(?:\.git)?$", remote)
    if match:
        return f"https://raw.githubusercontent.com/{match.group(1)}/main"

    raise BuildError(
        "无法确定 GitHub 仓库地址。"
        "首次运行请设置 RUNTIME_BASE_URL。"
    )


def fetch_upstream() -> bytes:
    request = Request(
        UPSTREAM_URL,
        headers={
            "User-Agent": "Moyu-StartUpAds-Surge-Builder/1.0",
            "Accept": "text/plain,*/*",
        },
    )

    last_error = None

    for _ in range(3):
        try:
            with urlopen(request, timeout=20) as response:
                if response.status != 200:
                    raise BuildError(f"HTTP {response.status}")

                data = response.read()

            if len(data) < MIN_BYTES:
                raise BuildError(
                    f"上游文件过小，仅 {len(data)} bytes"
                )

            head = data[:1024].lower()

            if b"<html" in head or b"<!doctype html" in head:
                raise BuildError("上游返回 HTML，不是配置文件")

            return data

        except Exception as exc:
            last_error = exc

    raise BuildError(f"下载墨鱼上游失败：{last_error}")


def is_version_sentinel(pattern: str) -> bool:
    # 墨鱼使用类似：
    # ^https?:\/\/2026.08.29/c415/v2.0.648
    # 保存版本信息，这不是真实网络规则。
    return bool(
        re.match(
            r"^\^https\?:\\?/\\?/20\d{2}\.\d{2}\.\d{2}/",
            pattern,
        )
    )


def check_pattern(pattern: str, line_no: int) -> str:
    if not pattern:
        raise BuildError(f"第 {line_no} 行 URL Pattern 为空")

    if "\r" in pattern or "\n" in pattern:
        raise BuildError(f"第 {line_no} 行 URL Pattern 非法")

    if any(ch.isspace() for ch in pattern):
        raise BuildError(
            f"第 {line_no} 行 URL Pattern 含空白，停止自动转换："
            f"{pattern}"
        )

    return pattern


def script_pattern(pattern: str) -> str:
    # Surge Script 使用逗号分隔参数。
    # 正则自身如果有 {1,4} 之类逗号，需要加引号。
    if "," not in pattern:
        return pattern

    if '"' in pattern:
        raise BuildError(
            f"Script Pattern 同时含逗号和双引号，无法安全转换：{pattern}"
        )

    return f'"{pattern}"'


def make_body_argument(find: str, replacement: str) -> str:
    return (
        "find="
        + quote(find, safe="")
        + "&replace="
        + quote(replacement, safe="")
    )


def main() -> int:
    runtime_base = get_runtime_base_url()
    body_rewrite_script = runtime_base + "/runtime/body-rewrite.js"

    raw = fetch_upstream()

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BuildError(f"上游不是有效 UTF-8：{exc}")

    url_rewrite: list[str] = []
    map_local: list[str] = []
    body_rewrite: list[str] = []
    surge_rules: list[str] = []
    scripts: list[str] = []
    hosts: list[str] = []

    counts: dict[str, int] = {}
    active_rules = 0
    script_index = 0


    def bump(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1


    for line_no, original in enumerate(text.splitlines(), 1):
        line = original.strip()

        if not line:
            continue

        # QX / Surge 通用注释
        if line.startswith("#"):
            continue

        if line.startswith(";"):
            continue

        if line.startswith("//"):
            continue


        # MITM hostname
        if line.lower().startswith("hostname"):
            match = re.match(
                r"hostname\s*=\s*(.+)$",
                line,
                re.IGNORECASE,
            )

            if not match:
                raise BuildError(
                    f"第 {line_no} 行 hostname 无法解析：{original}"
                )

            for host in match.group(1).split(","):
                host = host.strip()

                if not host:
                    continue

                if "\r" in host or "\n" in host:
                    raise BuildError(
                        f"第 {line_no} 行 hostname 非法：{host}"
                    )

                if host not in hosts:
                    hosts.append(host)

            continue


        # --------------------------------------------------
        # Quantumult X 域名分流规则
        #
        # 例如：
        # host, ad.12306.cn, direct
        #
        # Surge：
        # DOMAIN,ad.12306.cn,DIRECT
        #
        # 只转换域名类窄范围规则。
        # 不把 GEOIP / IP-CIDR 等全局分流偷偷塞进开屏模块。
        # --------------------------------------------------

        filter_match = re.match(
            r"^(host|host-suffix|host-keyword|host-wildcard)"
            r"\s*,\s*([^,]+?)\s*,\s*([^,\s]+)\s*$",
            line,
            re.IGNORECASE,
        )

        if filter_match:
            qx_type = filter_match.group(1).lower()
            value = filter_match.group(2).strip()
            policy = filter_match.group(3).lower()

            type_map = {
                "host": "DOMAIN",
                "host-suffix": "DOMAIN-SUFFIX",
                "host-keyword": "DOMAIN-KEYWORD",
                "host-wildcard": "DOMAIN-WILDCARD",
            }

            policy_map = {
                "direct": "DIRECT",
                "reject": "REJECT",
            }

            if policy not in policy_map:
                raise BuildError(
                    f"第 {line_no} 行域名分流策略无法安全转换："
                    f"{original}"
                )

            if not value:
                raise BuildError(
                    f"第 {line_no} 行域名分流目标为空："
                    f"{original}"
                )

            surge_rules.append(
                f"{type_map[qx_type]},{value},{policy_map[policy]}"
            )

            active_rules += 1
            bump("filter-" + qx_type)
            continue


        # 对 IP / GEOIP / FINAL 等全局分流绝不自动塞入
        # 一个“去开屏”模块。
        if re.match(
            r"^(ip-cidr|ip6-cidr|geoip|final)\s*,",
            line,
            re.IGNORECASE,
        ):
            raise BuildError(
                f"第 {line_no} 行发现全局分流规则，"
                f"为避免污染 Surge 主路由，停止转换："
                f"{original}"
            )


        # 所有剩余有效 Rewrite 都必须有 " url "
        if " url " not in line:
            raise BuildError(
                f"\n发现未知配置，停止发布。\n"
                f"第 {line_no} 行：\n"
                f"{original}"
            )


        pattern, action = line.split(" url ", 1)

        pattern = check_pattern(pattern.strip(), line_no)
        action = action.strip()


        # 跳过墨鱼版本伪 URL
        if is_version_sentinel(pattern):
            bump("version")
            continue


        active_rules += 1


        # --------------------------------------------------
        # reject
        # --------------------------------------------------

        if action == "reject":
            url_rewrite.append(
                f"{pattern} _ reject"
            )
            bump("reject")
            continue


        # --------------------------------------------------
        # reject-200
        #
        # QX:
        # url reject-200
        #
        # Surge:
        # Map Local 空 body + HTTP 200
        # --------------------------------------------------

        if action == "reject-200":
            map_local.append(
                f'{pattern} '
                'data-type=text '
                'data="" '
                'status-code=200'
            )
            bump("reject-200")
            continue


        # --------------------------------------------------
        # reject-img
        # --------------------------------------------------

        if action == "reject-img":
            map_local.append(
                f"{pattern} "
                "data-type=tiny-gif "
                "status-code=200"
            )
            bump("reject-img")
            continue


        # --------------------------------------------------
        # reject-dict
        # --------------------------------------------------

        if action == "reject-dict":
            map_local.append(
                f'{pattern} '
                'data-type=text '
                'data="{}" '
                'header="Content-Type:application/json;charset=utf-8" '
                'status-code=200'
            )
            bump("reject-dict")
            continue


        # --------------------------------------------------
        # reject-array
        # --------------------------------------------------

        if action == "reject-array":
            map_local.append(
                f'{pattern} '
                'data-type=text '
                'data="[]" '
                'header="Content-Type:application/json;charset=utf-8" '
                'status-code=200'
            )
            bump("reject-array")
            continue


        # --------------------------------------------------
        # 302
        # --------------------------------------------------

        if action.startswith("302 "):
            target = action[4:].strip()

            if not target.startswith(("http://", "https://")):
                raise BuildError(
                    f"第 {line_no} 行 302 地址非法：{target}"
                )

            url_rewrite.append(
                f"{pattern} {target} 302"
            )

            bump("302")
            continue


        # --------------------------------------------------
        # 307
        # --------------------------------------------------

        if action.startswith("307 "):
            target = action[4:].strip()

            if not target.startswith(("http://", "https://")):
                raise BuildError(
                    f"第 {line_no} 行 307 地址非法：{target}"
                )

            url_rewrite.append(
                f"{pattern} {target} 307"
            )

            bump("307")
            continue


        # --------------------------------------------------
        # response-body
        #
        # 使用一个非常小的本仓库 JS。
        # 只对真正需要修改 body 的规则启用 requires-body。
        # --------------------------------------------------

        if action.startswith("response-body "):
            rest = action[len("response-body "):]

            separator = " response-body "

            if separator not in rest:
                raise BuildError(
                    f"第 {line_no} 行 response-body 无法解析："
                    f"{original}"
                )

            find, replacement = rest.split(separator, 1)

            script_index += 1

            argument = make_body_argument(
                find,
                replacement,
            )

            scripts.append(
                f"Moyu_{script_index:04d} = "
                f"type=http-response,"
                f"pattern={script_pattern(pattern)},"
                f"script-path={body_rewrite_script},"
                f"requires-body=true,"
                f"argument={argument}"
            )

            bump("response-body")
            continue


        # --------------------------------------------------
        # request-body
        # --------------------------------------------------

        if action.startswith("request-body "):
            rest = action[len("request-body "):]

            separator = " request-body "

            if separator not in rest:
                raise BuildError(
                    f"第 {line_no} 行 request-body 无法解析："
                    f"{original}"
                )

            find, replacement = rest.split(separator, 1)

            script_index += 1

            argument = make_body_argument(
                find,
                replacement,
            )

            scripts.append(
                f"Moyu_{script_index:04d} = "
                f"type=http-request,"
                f"pattern={script_pattern(pattern)},"
                f"script-path={body_rewrite_script},"
                f"requires-body=true,"
                f"argument={argument}"
            )

            bump("request-body")
            continue


        # --------------------------------------------------
        # echo-response
        #
        # Quantumult X:
        #
        # PATTERN url echo-response MIME echo-response RESOURCE
        #
        # 示例：
        #
        # ^https?://example.com/api url echo-response text/json echo-response https://example.com/data.json
        #
        # Surge 使用原生 Map Local：
        #
        # PATTERN data-type=file data="URL"
        #         header="Content-Type:MIME"
        #         status-code=200
        #
        # Surge 会下载并缓存远程资源，请求不会访问原始 API。
        # --------------------------------------------------

        if action.startswith("echo-response "):
            rest = action[len("echo-response "):]

            separator = " echo-response "

            if separator not in rest:
                raise BuildError(
                    f"第 {line_no} 行 echo-response 无法解析："
                    f"{original}"
                )

            response_meta, resource = rest.split(separator, 1)

            response_meta = response_meta.strip()
            resource = resource.strip()

            if not response_meta:
                raise BuildError(
                    f"第 {line_no} 行 echo-response Content-Type 为空："
                    f"{original}"
                )

            if not resource:
                raise BuildError(
                    f"第 {line_no} 行 echo-response Resource 为空："
                    f"{original}"
                )

            # 当前 StartUpAds 使用远程资源。
            # 自动仓库中不允许引用 Quantumult X 本地文件，
            # 因为 Surge 无法取得 QX 的本地 Data 文件。
            if not resource.startswith("https://"):
                raise BuildError(
                    f"第 {line_no} 行 echo-response 不是 HTTPS 远程资源，"
                    f"无法无损转换：{resource}"
                )

            # QX 允许：
            #
            # text/html\r\nHeader-A: value
            #
            # 第一个字段是 Content-Type，后面是额外响应头。
            meta_parts = response_meta.split(r"\r\n")

            content_type = meta_parts[0].strip()

            if not content_type:
                raise BuildError(
                    f"第 {line_no} 行 echo-response Content-Type 非法："
                    f"{original}"
                )

            surge_headers = [
                f"Content-Type:{content_type}"
            ]

            for extra_header in meta_parts[1:]:
                extra_header = extra_header.strip()

                if not extra_header:
                    continue

                if ":" not in extra_header:
                    raise BuildError(
                        f"第 {line_no} 行 echo-response Header 非法："
                        f"{extra_header}"
                    )

                surge_headers.append(extra_header)

            header_value = "|".join(surge_headers)

            if '"' in resource:
                raise BuildError(
                    f"第 {line_no} 行 echo-response URL 含非法双引号"
                )

            if '"' in header_value:
                raise BuildError(
                    f"第 {line_no} 行 echo-response Header 含非法双引号"
                )

            map_local.append(
                f'{pattern} '
                f'data-type=file '
                f'data="{resource}" '
                f'header="{header_value}" '
                f'status-code=200'
            )

            bump("echo-response")
            continue


        # --------------------------------------------------
        # jsonjq-response-body / jsonjq-request-body
        #
        # Quantumult X:
        # PATTERN url jsonjq-response-body '.data={}'
        #
        # Surge 5.14+:
        # [Body Rewrite]
        # http-response-jq PATTERN '.data={}'
        # --------------------------------------------------

        if action.startswith("jsonjq-response-body "):
            jq = action[len("jsonjq-response-body "):].strip()

            if not jq:
                raise BuildError(
                    f"第 {line_no} 行 jsonjq-response-body 表达式为空："
                    f"{original}"
                )

            if "\n" in jq or "\r" in jq:
                raise BuildError(
                    f"第 {line_no} 行 JQ 表达式含非法换行"
                )

            body_rewrite.append(
                f"http-response-jq {pattern} {jq}"
            )

            bump("jsonjq-response-body")
            continue


        if action.startswith("jsonjq-request-body "):
            jq = action[len("jsonjq-request-body "):].strip()

            if not jq:
                raise BuildError(
                    f"第 {line_no} 行 jsonjq-request-body 表达式为空："
                    f"{original}"
                )

            if "\n" in jq or "\r" in jq:
                raise BuildError(
                    f"第 {line_no} 行 JQ 表达式含非法换行"
                )

            body_rewrite.append(
                f"http-request-jq {pattern} {jq}"
            )

            bump("jsonjq-request-body")
            continue


        # --------------------------------------------------
        # QX Script → Surge Script
        # --------------------------------------------------

        script_types = {
            "script-response-body": (
                "http-response",
                True,
            ),

            "script-response-header": (
                "http-response",
                False,
            ),

            "script-request-body": (
                "http-request",
                True,
            ),

            "script-request-header": (
                "http-request",
                False,
            ),

            "script-analyze-echo-response": (
                "http-request",
                True,
            ),

            "script-echo-response": (
                "http-request",
                False,
            ),
        }


        handled = False


        for qx_type, (
            surge_type,
            requires_body,
        ) in script_types.items():

            prefix = qx_type + " "

            if not action.startswith(prefix):
                continue


            path = action[len(prefix):].strip()


            if not path.startswith("https://"):
                raise BuildError(
                    f"第 {line_no} 行脚本不是 HTTPS："
                    f"{path}"
                )


            if "," in path:
                raise BuildError(
                    f"第 {line_no} 行脚本 URL 含非法逗号："
                    f"{path}"
                )


            script_index += 1


            parameters = [
                f"type={surge_type}",
                f"pattern={script_pattern(pattern)}",
                f"script-path={path}",
            ]


            if requires_body:
                parameters.append(
                    "requires-body=true"
                )


            scripts.append(
                f"Moyu_{script_index:04d} = "
                + ",".join(parameters)
            )


            bump(qx_type)
            handled = True
            break


        if handled:
            continue


        # --------------------------------------------------
        # 未知 QX 新语法
        #
        # 绝不猜。
        # 绝不跳过。
        # 直接让 GitHub Action 失败。
        # --------------------------------------------------

        raise BuildError(
            f"\n发现新的 / 未支持的 Quantumult X 动作。\n"
            f"为了避免生成坏 Surge 模块，已停止发布。\n\n"
            f"第 {line_no} 行：\n"
            f"{original}\n"
        )


    if active_rules < MIN_RULES:
        raise BuildError(
            f"有效规则只有 {active_rules} 条，"
            f"低于安全阈值 {MIN_RULES}"
        )


    if not hosts:
        raise BuildError(
            "未读取到 hostname，停止发布"
        )


    output: list[str] = [
        "#!name=墨鱼去开屏 2.0 - Surge",
        "#!desc=自动同步并转换 ddgksf2013 StartUpAds.conf",
    ]


    if url_rewrite:
        output.extend(
            [
                "",
                "[URL Rewrite]",
                *url_rewrite,
            ]
        )


    if map_local:
        output.extend(
            [
                "",
                "[Map Local]",
                *map_local,
            ]
        )


    if body_rewrite:
        output.extend(
            [
                "",
                "[Body Rewrite]",
                *body_rewrite,
            ]
        )


    if surge_rules:
        output.extend(
            [
                "",
                "[Rule]",
                *surge_rules,
            ]
        )


    if scripts:
        output.extend(
            [
                "",
                "[Script]",
                *scripts,
            ]
        )


    output.extend(
        [
            "",
            "[MITM]",
            "hostname = %APPEND% "
            + ", ".join(hosts),
            "",
        ]
    )


    generated = "\n".join(output)


    # --------------------------------------------------
    # 防止第三方转换仓库出现过的问题再次发生
    # --------------------------------------------------

    forbidden = (
        " _ reject-200",
        " - reject-200",
        " _ reject-img",
        " - reject-img",
        " _ reject-dict",
        " - reject-dict",
        " _ reject-array",
        " - reject-array",
        "max-size=-1",
        "timeout=60",
    )


    for value in forbidden:
        if value in generated:
            raise BuildError(
                f"生成模块含禁止配置：{value}"
            )


    # 防止版本伪 URL 被重新加入模块
    if re.search(
        r"^\^https\?:\\?/\\?/20\d{2}\.\d{2}\.\d{2}/",
        generated,
        re.MULTILINE,
    ):
        raise BuildError(
            "版本信息被错误转换为 URL 规则"
        )


    # --------------------------------------------------
    # 原子写文件
    # --------------------------------------------------

    UPSTREAM_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    DIST_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    upstream_tmp = Path(
        str(UPSTREAM_FILE) + ".tmp"
    )

    dist_tmp = Path(
        str(DIST_FILE) + ".tmp"
    )

    meta_tmp = Path(
        str(META_FILE) + ".tmp"
    )


    upstream_tmp.write_bytes(raw)


    dist_tmp.write_text(
        generated,
        encoding="utf-8",
        newline="\n",
    )


    sha256 = hashlib.sha256(
        raw
    ).hexdigest()


    metadata = {
        "source": UPSTREAM_URL,

        "sha256": sha256,

        "fetched_at_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "active_rules":
            active_rules,

        "url_rewrite":
            len(url_rewrite),

        "map_local":
            len(map_local),

        "body_rewrite":
            len(body_rewrite),

        "rules":
            len(surge_rules),

        "scripts":
            len(scripts),

        "mitm_hosts":
            len(hosts),

        "counts":
            counts,

        "unsupported_rules":
            0,
    }


    meta_tmp.write_text(
        json.dumps(
            metadata,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


    os.replace(
        upstream_tmp,
        UPSTREAM_FILE,
    )

    os.replace(
        dist_tmp,
        DIST_FILE,
    )

    os.replace(
        meta_tmp,
        META_FILE,
    )


    print()
    print("========== BUILD OK ==========")
    print()
    print("上游：", UPSTREAM_URL)
    print("SHA256：", sha256)
    print("有效规则：", active_rules)
    print("URL Rewrite：", len(url_rewrite))
    print("Map Local：", len(map_local))
    print("Body Rewrite：", len(body_rewrite))
    print("Rule：", len(surge_rules))
    print("Script：", len(scripts))
    print("MITM Hosts：", len(hosts))
    print("Unsupported：0")
    print()
    print("生成：", DIST_FILE)
    print()


    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())

    except BuildError as exc:
        print()
        print("========== BUILD FAILED ==========")
        print()
        print(exc)
        print()
        raise SystemExit(1)
