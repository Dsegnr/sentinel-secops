"""封堵清单：公益威胁情报 IP 清单本地化 + Windows 防火墙规则导出。

来源（均为公开免费清单）：
- FireHOL level1 netset（聚合多源、低误报）
- Spamhaus DROP（被劫持/垃圾广告网段）

设计：只下载与本地检索，不主动阻断；生成的防火墙脚本由用户审阅后自行执行。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime
from pathlib import Path

from .http import HttpClient

SOURCES: dict[str, dict] = {
    "firehol_level1": {
        "title": "FireHOL level1",
        "urls": [
            "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level1.netset",
            "https://iplists.firehol.org/files/firehol_level1.netset",
        ],
        "file": "firehol_level1.netset",
        "home": "https://iplists.firehol.org/",
    },
    "spamhaus_drop": {
        "title": "Spamhaus DROP",
        "urls": ["https://www.spamhaus.org/drop/drop.txt"],
        "file": "spamhaus_drop.txt",
        "home": "https://www.spamhaus.org/drop/",
    },
}


def should_refresh(age_hours: float | None, threshold_hours: float) -> bool:
    """是否该刷新：从未下载过 → True；超过阈值 → True。"""
    if age_hours is None:
        return True
    return age_hours >= threshold_hours


def parse_cidrs(text: str) -> list[str]:
    """从清单文本提取 CIDR（跳过注释/空行，坏行静默丢弃）。"""
    found: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        token = line.split()[0].split(";")[0].strip()
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        value = str(net)
        if value not in seen:
            seen.add(value)
            found.append(value)
    return found


class BlocklistStore:
    def __init__(self, data_dir: Path):
        self.dir = Path(data_dir) / "blocklists"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.dir / "meta.json"
        self.custom_path = self.dir / "custom.txt"
        self._cache: list[tuple[ipaddress._BaseNetwork, str]] | None = None
        self._cache_key: tuple | None = None

    # ---------- 自定义条目 ----------

    def custom_list(self) -> list[str]:
        if not self.custom_path.is_file():
            return []
        return [line.strip() for line in self.custom_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def add_custom(self, value: str) -> tuple[bool, str]:
        raw = (value or "").strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return False, f"不是合法 IP / CIDR：{raw}"
        entry = str(net)
        items = self.custom_list()
        if entry in items:
            return False, f"已存在：{entry}"
        items.append(entry)
        self.custom_path.write_text("\n".join(items) + "\n", encoding="utf-8")
        self._cache = None
        return True, f"已加入：{entry}"

    def remove_custom(self, value: str) -> bool:
        raw = (value or "").strip()
        try:
            entry = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            entry = raw
        items = self.custom_list()
        if entry not in items:
            return False
        items = [x for x in items if x != entry]
        self.custom_path.write_text(("\n".join(items) + "\n") if items else "", encoding="utf-8")
        self._cache = None
        return True

    # ---------- 元数据 ----------

    def meta(self) -> dict:
        if not self.meta_path.is_file():
            return {"sources": {}}
        try:
            return json.loads(self.meta_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {"sources": {}}

    def _save_meta(self, meta: dict) -> None:
        tmp = self.meta_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.meta_path)

    def stats(self) -> list[dict]:
        meta = self.meta().get("sources", {})
        rows = []
        for key, spec in SOURCES.items():
            info = meta.get(key, {})
            rows.append({
                "key": key,
                "title": spec["title"],
                "home": spec["home"],
                "file": str(self.dir / spec["file"]),
                "downloaded": (self.dir / spec["file"]).is_file(),
                "updated": info.get("updated", ""),
                "count": info.get("count", 0),
                "sha256": (info.get("sha256") or "")[:16],
                "error": info.get("error", ""),
            })
        custom = self.custom_list()
        rows.append({
            "key": "custom",
            "title": "自定义封堵",
            "home": "",
            "file": str(self.custom_path),
            "downloaded": bool(custom),
            "updated": (datetime.fromtimestamp(self.custom_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        if self.custom_path.is_file() else ""),
            "count": len(custom),
            "sha256": "",
            "error": "",
        })
        return rows

    # ---------- 下载 ----------

    def update(self, client: HttpClient, source: str | None = None) -> dict:
        results: dict[str, dict] = {}
        targets = [source] if source else list(SOURCES)
        meta = self.meta()
        meta.setdefault("sources", {})
        for key in targets:
            spec = SOURCES.get(key)
            if not spec:
                results[key] = {"ok": False, "error": "未知来源"}
                continue
            errors: list[str] = []
            got: str | None = None
            for url in spec["urls"]:
                try:
                    resp = client.get(url, timeout=60, retries=0)
                    if resp.status_code != 200 or len(resp.content) < 1000:
                        raise RuntimeError(f"HTTP {resp.status_code} / {len(resp.content)}B")
                    got = resp.text
                    break
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{url.split('/')[2]}: {str(exc)[:70]}")
            if got is None:
                meta["sources"][key] = {**meta["sources"].get(key, {}), "error": "；".join(errors)[:200]}
                results[key] = {"ok": False, "error": "；".join(errors)[:200]}
                continue
            cidrs = parse_cidrs(got)
            path = self.dir / spec["file"]
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text("\n".join(cidrs) + "\n", encoding="utf-8")
            tmp.replace(path)
            meta["sources"][key] = {
                "updated": datetime.now().isoformat(timespec="seconds"),
                "count": len(cidrs),
                "sha256": hashlib.sha256(("\n".join(cidrs)).encode()).hexdigest(),
                "error": "",
            }
            results[key] = {"ok": True, "count": len(cidrs)}
        self._save_meta(meta)
        self._cache = None
        return results

    # ---------- 检索 ----------

    def load_ranges(self) -> list[tuple[ipaddress._BaseNetwork, str]]:
        key = tuple(
            (key_, (self.dir / spec["file"]).stat().st_mtime if (self.dir / spec["file"]).is_file() else 0)
            for key_, spec in SOURCES.items()
        ) + (("custom", self.custom_path.stat().st_mtime if self.custom_path.is_file() else 0),)
        if self._cache is not None and self._cache_key == key:
            return self._cache
        ranges: list[tuple[ipaddress._BaseNetwork, str]] = []
        for key_, spec in SOURCES.items():
            path = self.dir / spec["file"]
            if not path.is_file():
                continue
            for cidr in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                cidr = cidr.strip()
                if not cidr:
                    continue
                try:
                    ranges.append((ipaddress.ip_network(cidr, strict=False), key_))
                except ValueError:
                    continue
        for cidr in self.custom_list():
            try:
                ranges.append((ipaddress.ip_network(cidr, strict=False), "custom"))
            except ValueError:
                continue
        self._cache = ranges
        self._cache_key = key
        return ranges

    def check_ip(self, target: str) -> list[dict]:
        try:
            ip = ipaddress.ip_address(target.strip())
        except ValueError:
            raise ValueError(f"不是合法 IP：{target}")
        hits = []
        for net, source in self.load_ranges():
            if ip.version != net.version:
                continue
            if ip in net:
                title = SOURCES[source]["title"] if source in SOURCES else "自定义封堵"
                hits.append({"source": title, "cidr": str(net)})
        return hits

    def age_hours(self) -> float | None:
        """本地清单的"最旧更新时间"距今多少小时；从未下载过返回 None。"""
        meta = self.meta().get("sources", {})
        stamps: list[str] = []
        for key, spec in SOURCES.items():
            updated = (meta.get(key) or {}).get("updated")
            if updated:
                stamps.append(str(updated))
            elif (self.dir / spec["file"]).is_file():
                stamps.append(
                    datetime.fromtimestamp((self.dir / spec["file"]).stat().st_mtime).isoformat(timespec="seconds")
                )
        if not stamps:
            return None
        oldest = min(stamps)
        try:
            when = datetime.fromisoformat(oldest)
        except ValueError:
            return None
        return max(0.0, (datetime.now() - when).total_seconds() / 3600)

    # ---------- 导出 ----------

    def export_firewall_script(self, chunk: int = 500) -> str:
        ranges = [str(net) for net, _ in self.load_ranges()]
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        lines = [
            "# Sentinel 封堵脚本（由工作台生成）",
            f"# 生成时间: {stamp} · 规则数: {len(ranges)} 条 IP/CIDR",
            "# 来源: FireHOL level1 + Spamhaus DROP（公益公开清单，存在误报可能）+ 自定义条目",
            "# 用法: 管理员 PowerShell 运行；卸载: Remove-NetFirewallRule -Group 'Sentinel-Blocklist'",
            "$ErrorActionPreference = 'Continue'",
            "$group = 'Sentinel-Blocklist'",
            "Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
            "$sets = @(",
        ]
        for i in range(0, len(ranges), chunk):
            part = ", ".join(f"'{r}'" for r in ranges[i:i + chunk])
            lines.append(f"  @({part}),")
        lines += [
            ")",
            "$i = 0",
            "foreach ($set in $sets) {",
            "  $i++",
            "  New-NetFirewallRule -DisplayName \"Sentinel-Blocklist-$i\" -Group $group -Direction Inbound -Action Block -RemoteAddress $set | Out-Null",
            "}",
            "Write-Host \"已应用 $i 组入站封堵规则（共 $($sets.Count) 组）\"",
        ]
        return "\n".join(lines) + "\n"

    def export_csv(self) -> str:
        lines = ["source,cidr"]
        for net, source in self.load_ranges():
            lines.append(f"{source},{net}")
        return "\n".join(lines) + "\n"
