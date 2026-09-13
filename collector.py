#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeProxyHub - Subscription Sync Collector
-------------------------------------------
把自己的 Free-v2ray-Configs 仓库作为唯一订阅数据源，
同步到 FreeProxyHub/data/，同时生成 proxies.json / stats.json / meta.json。

无需第三方 Python 依赖，Python 3.9+ 即可运行。

上游仓库：
https://github.com/xiaolaodi0719/Free-v2ray-Configs

主要输出：
data/
├── clash.yaml
├── subscribe.txt
├── subscribe_base64.txt
├── proxies.txt
├── proxies.json
├── stats.json
└── meta.json
"""

from __future__ import annotations

import base64
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# ============================================================
# 配置
# ============================================================

OWNER = "xiaolaodi0719"
SOURCE_REPO = "Free-v2ray-Configs"
SOURCE_BRANCH = "main"

# 你的 FreeProxyHub 仓库
TARGET_REPO = "FreeProxyHub"
TARGET_BRANCH = "main"

SOURCE_BASE = (
    f"https://raw.githubusercontent.com/"
    f"{OWNER}/{SOURCE_REPO}/{SOURCE_BRANCH}"
)

TARGET_RAW_BASE = (
    f"https://raw.githubusercontent.com/"
    f"{OWNER}/{TARGET_REPO}/{TARGET_BRANCH}"
)

OUTPUT_DIR = Path(__file__).resolve().parent / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "Mozilla/5.0 FreeProxyHub-Subscription-Sync/1.0"

TIMEOUT = 30
RETRIES = 3


# ============================================================
# 上游文件 → 本地文件
#
# name：meta.json 中使用的名称
# source：Free-v2ray-Configs 中的真实路径
# local：同步到 FreeProxyHub/data/ 中的文件名
# ============================================================

FILES = {
    "verified_clash": {
        "source": "verified/clash.yaml",
        "local": "clash.yaml",
    },
    "verified_uri": {
        "source": "verified/configs.txt",
        "local": "subscribe.txt",
    },
    "verified_base64": {
        "source": "verified/configs_base64.txt",
        "local": "subscribe_base64.txt",
    },
    "top100": {
        "source": "top100.txt",
        "local": "proxies.txt",
    },
}


# ============================================================
# 网络
# ============================================================

def fetch_text(url: str, timeout: int = TIMEOUT) -> str:
    """下载文本，失败自动重试。"""
    last_error = None

    for attempt in range(1, RETRIES + 1):
        try:
            print(f"  ↓ 下载 [{attempt}/{RETRIES}] {url}")

            request = Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/plain, text/*, */*",
                },
            )

            with urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                return response.read().decode(charset, errors="replace")

        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last_error = exc
            print(f"  ⚠ 下载失败: {exc}")

            if attempt < RETRIES:
                time.sleep(2)

    raise RuntimeError(f"无法下载文件: {url}\n最后错误: {last_error}")


# ============================================================
# 文件
# ============================================================

def write_text(path: Path, content: str) -> None:
    """安全写入文本。"""
    path.parent.mkdir(parents=True, exist_ok=True)

    temp = path.with_suffix(path.suffix + ".tmp")

    temp.write_text(content, encoding="utf-8", newline="\n")
    temp.replace(path)

    print(f"  ✅ 已写入 {path}")


def write_json(path: Path, data: object) -> None:
    """安全写入 JSON。"""
    content = json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
    )

    write_text(path, content + "\n")


# ============================================================
# URI 解析
# ============================================================

URI_SCHEMES = (
    "vmess",
    "vless",
    "trojan",
    "ss",
    "ssr",
    "hysteria2",
    "hy2",
    "tuic",
    "socks",
    "socks5",
)


def detect_protocol(line: str) -> str:
    """根据 URI 前缀判断协议。"""
    value = line.strip().lower()

    if "://" not in value:
        return "unknown"

    scheme = value.split("://", 1)[0]

    if scheme == "hy2":
        return "hysteria2"

    return scheme


def decode_vmess(line: str) -> dict:
    """解析 vmess:// Base64 JSON。"""
    payload = line[len("vmess://"):].strip()

    # Base64 URL-safe + 普通 Base64 都兼容
    payload += "=" * (-len(payload) % 4)

    try:
        raw = base64.urlsafe_b64decode(payload.encode("utf-8"))
        obj = json.loads(raw.decode("utf-8", errors="replace"))

        return {
            "protocol": "vmess",
            "server": obj.get("add", ""),
            "port": obj.get("port"),
            "name": obj.get("ps", ""),
            "network": obj.get("net", ""),
            "tls": obj.get("tls", ""),
        }
    except Exception:
        return {
            "protocol": "vmess",
            "server": "",
            "port": None,
            "name": "",
        }


def parse_uri(line: str) -> dict:
    """尽可能提取统一的节点信息。"""
    line = line.strip()

    if not line or line.startswith("#"):
        return {}

    protocol = detect_protocol(line)

    if protocol == "vmess":
        return decode_vmess(line)

    if protocol not in URI_SCHEMES:
        return {
            "protocol": protocol,
            "server": "",
            "port": None,
            "name": "",
        }

    # 去掉 scheme://
    rest = line.split("://", 1)[1]

    # 去掉备注
    if "#" in rest:
        endpoint, remark = rest.split("#", 1)
        remark = remark.strip()
    else:
        endpoint = rest
        remark = ""

    # 去掉 query
    if "?" in endpoint:
        endpoint = endpoint.split("?", 1)[0]

    # 去掉认证信息
    if "@" in endpoint:
        endpoint = endpoint.rsplit("@", 1)[1]

    server = ""
    port = None

    # [IPv6]:443
    ipv6_match = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", endpoint)

    if ipv6_match:
        server = ipv6_match.group(1)
        if ipv6_match.group(2):
            port = int(ipv6_match.group(2))

    else:
        # 普通 host:port
        if ":" in endpoint:
            host, possible_port = endpoint.rsplit(":", 1)
            server = host

            if possible_port.isdigit():
                port = int(possible_port)
        else:
            server = endpoint

    return {
        "protocol": protocol,
        "server": server,
        "port": port,
        "name": remark,
    }


def parse_subscription(text: str) -> list[dict]:
    """解析订阅文件，用于生成 proxies.json 和统计。"""
    result = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        item = parse_uri(line)

        if item:
            result.append(item)

    return result


# ============================================================
# 统计
# ============================================================

def generate_stats(nodes: list[dict]) -> dict:
    protocols: dict[str, int] = {}

    for node in nodes:
        protocol = node.get("protocol", "unknown")
        protocols[protocol] = protocols.get(protocol, 0) + 1

    protocols = dict(
        sorted(
            protocols.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )

    return {
        "total": len(nodes),
        "updated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "source": f"{OWNER}/{SOURCE_REPO}",
        "protocols": protocols,
    }


# ============================================================
# 主流程
# ============================================================

def main() -> int:
    print("=" * 70)
    print("  FreeProxyHub Subscription Sync")
    print("=" * 70)
    print(f"  Source : {SOURCE_BASE}")
    print(f"  Output : {OUTPUT_DIR}")
    print()

    downloaded: dict[str, dict] = {}

    # --------------------------------------------------------
    # 1. 同步上游文件
    # --------------------------------------------------------

    for name, info in FILES.items():
        source_path = info["source"]
        local_name = info["local"]

        source_url = f"{SOURCE_BASE}/{source_path}"
        local_path = OUTPUT_DIR / local_name

        print(f"[{name}]")
        content = fetch_text(source_url)

        if not content.strip():
            raise RuntimeError(
                f"上游文件为空，拒绝覆盖本地文件: {source_url}"
            )

        write_text(local_path, content)

        downloaded[name] = {
            "name": name,
            "source": source_path,
            "local": local_name,
            "source_url": source_url,
            "local_url": f"{TARGET_RAW_BASE}/data/{local_name}",
            "size": len(content.encode("utf-8")),
            "lines": len(content.splitlines()),
        }

        print()

    # --------------------------------------------------------
    # 2. 解析 verified/configs.txt
    # --------------------------------------------------------

    subscribe_path = OUTPUT_DIR / FILES["verified_uri"]["local"]
    subscribe_text = subscribe_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    nodes = parse_subscription(subscribe_text)

    # --------------------------------------------------------
    # 3. proxies.json
    # --------------------------------------------------------

    write_json(
        OUTPUT_DIR / "proxies.json",
        {
            "source": f"{OWNER}/{SOURCE_REPO}",
            "source_url": SOURCE_BASE,
            "updated_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "total": len(nodes),
            "nodes": nodes,
        },
    )

    # --------------------------------------------------------
    # 4. stats.json
    # --------------------------------------------------------

    stats = generate_stats(nodes)

    write_json(
        OUTPUT_DIR / "stats.json",
        stats,
    )

    # --------------------------------------------------------
    # 5. meta.json
    # --------------------------------------------------------

    meta_files = {}

    for name, info in downloaded.items():
        meta_files[name] = {
            "file": info["local"],
            "source": info["source"],
            "url": info["source_url"],
            "mirror_url": info["local_url"],
            "size": info["size"],
            "lines": info["lines"],
        }

    meta = {
        "version": "3.0",
        "source": {
            "owner": OWNER,
            "repository": SOURCE_REPO,
            "branch": SOURCE_BRANCH,
            "base_url": SOURCE_BASE,
        },
        "target": {
            "owner": OWNER,
            "repository": TARGET_REPO,
            "branch": TARGET_BRANCH,
            "base_url": TARGET_RAW_BASE,
        },
        "updated_at": stats["updated_at"],
        "total_proxies": len(nodes),
        "files": meta_files,
    }

    write_json(
        OUTPUT_DIR / "meta.json",
        meta,
    )

    # --------------------------------------------------------
    # 6. 输出汇总
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("  ✅ 同步完成")
    print("=" * 70)
    print(f"  节点总数: {len(nodes)}")

    if stats["protocols"]:
        print(
            "  协议统计: "
            + ", ".join(
                f"{name}={count}"
                for name, count in stats["protocols"].items()
            )
        )

    print()
    print("  永久订阅链接:")
    print(
        f"  Clash   : "
        f"{SOURCE_BASE}/verified/clash.yaml"
    )
    print(
        f"  URI     : "
        f"{SOURCE_BASE}/verified/configs.txt"
    )
    print(
        f"  Base64  : "
        f"{SOURCE_BASE}/verified/configs_base64.txt"
    )
    print(
        f"  Top100  : "
        f"{SOURCE_BASE}/top100.txt"
    )
    print()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n❌ 用户中断")
        raise SystemExit(130)
    except Exception as exc:
        print(f"\n❌ 运行失败: {exc}", file=sys.stderr)
        raise SystemExit(1)
