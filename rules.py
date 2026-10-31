"""
rules.py —— 转发过滤规则

为什么需要它？
    内网里很多东西**不该**被穿透出去：数据库、远程桌面、SMB 共享、Redis……
    一旦端口暴露在公网上，等于把内网门锁拆了。
    与其靠"记得别填那个端口"，不如让程序自己拦住 —— 这就是本模块的作用。

两个概念（以前混在一起，现在分开了）

    · **每条规则的类型**（rule.action）
        deny  黑名单：命中就拒绝
        allow 白名单：命中就放行
      一条规则到底是拦还是放，由它自己说了算 —— 列表里可以黑白混排。

    · **默认策略**（ruleset.mode）—— 兜底动作
        blocklist：**未命中任何规则**时放行（等价"只拦黑名单"）
        allowlist：**未命中任何规则**时拒绝（等价"只放白名单"）

    判定顺序：**拒绝优先**
        先看有没有黑名单规则命中 → 有就拒绝（安全优先，宁可拦错不放错）；
        否则看有没有白名单规则命中 → 有就放行；
        都没有 → 按默认策略兜底。

    为什么选"拒绝优先"而不是"第一条命中说了算"？
        黑白混排时，"谁在前谁赢"会让人摸不着头脑（拖动一下顺序结果就变了）。
        "拒绝优先"是可预测的：想让某个端口通过，就别给它写黑名单规则。

匹配写法（host 与 port 各自独立匹配，两者都命中才算命中）
    host:  127.0.0.1    精确
           192.168.*    * 匹配任意字符（可出现在任意位置）
           *            任意
    port:  3389         单个端口
           8000-9000    闭区间
           *            任意端口

关于安全默认值
    程序**不会**替你偷偷加规则 —— 规则改了却不告诉你，比没规则更危险。
    但界面上提供"一键添加常见危险端口"，让你自己决定
    （加进去的一律是**黑名单**规则，也就是"拒绝" —— 别被白名单模式反过来）。

关于旧版数据
    早先的 rules.json 只有全局 mode、规则不带类型。载入时按当时的 mode
    把每条规则补上类型（blocklist→deny、allowlist→allow），
    因此**升级前后判定结果完全一致**，不会因为改版而放行或拒绝错了。
"""

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

# ---------------------------------------------------------------------------
# 规则类型
# ---------------------------------------------------------------------------
ACTION_DENY = "deny"       # 黑名单：命中即拒绝
ACTION_ALLOW = "allow"     # 白名单：命中即放行
ACTION_CHOICES = (ACTION_DENY, ACTION_ALLOW)

ACTION_LABEL = {ACTION_DENY: "黑名单", ACTION_ALLOW: "白名单"}
ACTION_DESC = {ACTION_DENY: "命中即拒绝", ACTION_ALLOW: "命中即放行"}


def normalize_action(value) -> str:
    """把用户/文件里给的值归一成合法 action（不认识的一律当黑名单）。"""
    v = str(value or "").strip().lower()
    if v in ("allow", "allowlist", "white", "whitelist", "permit", "pass"):
        return ACTION_ALLOW
    return ACTION_DENY


# ---------------------------------------------------------------------------
# 默认策略（兜底动作）
# ---------------------------------------------------------------------------
MODE_BLOCK = "blocklist"      # 未命中 → 放行
MODE_ALLOW = "allowlist"      # 未命中 → 拒绝
MODE_CHOICES = (MODE_BLOCK, MODE_ALLOW)

MODE_LABEL = {
    MODE_BLOCK: "默认放行（只拦黑名单）",
    MODE_ALLOW: "默认拒绝（只放白名单）",
}
MODE_SHORT = {MODE_BLOCK: "放行", MODE_ALLOW: "拒绝"}

# 值得提醒用户的高危端口（仅用于界面上的"快捷添加"，不会自动生效）
RISKY_PRESETS = [
    ("3389", "远程桌面 RDP"),
    ("445", "SMB 文件共享"),
    ("139", "NetBIOS 会话"),
    ("135", "RPC 端口映射"),
    ("5900", "VNC 远程桌面"),
    ("22", "SSH 远程登录"),
    ("23", "Telnet（明文）"),
    ("3306", "MySQL 数据库"),
    ("5432", "PostgreSQL 数据库"),
    ("1433", "SQL Server 数据库"),
    ("6379", "Redis（常无密码）"),
    ("27017", "MongoDB 数据库"),
    ("9200", "Elasticsearch"),
    ("11211", "Memcached"),
    ("2375", "Docker 未加密 API"),
]


def _wildcard_to_regex(pattern: str) -> "re.Pattern":
    """把带 * 的通配串编译成正则；同时容忍用户写成中文全角星号。"""
    pattern = (pattern or "").strip().replace("＊", "*").replace("？", "?")
    parts = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE)


def _normalize_host(host: str) -> str:
    """把主机名统一成便于比较的形式。

    · 去空白、转小写
    · "localhost" 视同 127.0.0.1（否则写规则的人会踩坑：
      客户端填 localhost，规则里写 127.0.0.1，就匹配不上了）
    """
    host = (host or "").strip().lower()
    if host in ("localhost", "localhost.localdomain"):
        return "127.0.0.1"
    return host


def _is_private(host: str) -> bool:
    """判断是不是内网/回环地址（仅用于界面提示，不参与匹配）。"""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


@dataclass
class Rule:
    """一条转发过滤规则。"""

    host: str = "*"          # 目标主机（内网侧，如 127.0.0.1）
    port: str = "*"          # 目标端口（如 3389 / 8000-9000 / *）
    note: str = ""           # 备注，给人看
    enabled: bool = True
    action: str = ACTION_DENY   # 本条规则的类型：deny=黑名单 / allow=白名单

    # ---------------- 类型 ----------------
    @property
    def is_allow(self) -> bool:
        return self.action == ACTION_ALLOW

    @property
    def is_deny(self) -> bool:
        return not self.is_allow

    def action_label(self) -> str:
        return ACTION_LABEL.get(self.action, ACTION_DENY)

    def action_desc(self) -> str:
        return ACTION_DESC.get(self.action, ACTION_DESC[ACTION_DENY])

    # ---------------- 匹配 ----------------
    def matches(self, host: str, port: int) -> bool:
        """这条规则是否命中给定的 目标主机:端口。"""
        if not self.enabled:
            return False
        h = _normalize_host(host)
        # host 匹配
        if self.host.strip() not in ("*", ""):
            if not _wildcard_to_regex(self.host).match(h):
                return False
        # port 匹配
        p = str(self.port or "*").strip().replace("－", "-")
        if p in ("*", ""):
            return True
        if "-" in p:
            try:
                lo, hi = (int(x) for x in p.split("-", 1))
            except ValueError:
                return False
            return lo <= int(port) <= hi
        if "," in p:
            try:
                return int(port) in {int(x) for x in p.split(",") if x.strip()}
            except ValueError:
                return False
        try:
            return int(port) == int(p)
        except ValueError:
            return False

    def describe(self) -> str:
        target = "%s:%s" % (self.host or "*", self.port or "*")
        tail = ("— " + self.note) if self.note else ""
        return ("%s  %s" % (target, tail)).strip()


@dataclass
class RuleSet:
    """一组规则 + 默认策略，可存盘。"""

    mode: str = MODE_BLOCK           # blocklist | allowlist —— 未命中时怎么办
    rules: list = field(default_factory=list)
    enabled: bool = True             # 总开关（关掉则一切放行，便于临时排障）

    # ---------------- 默认策略 ----------------
    @property
    def default_deny(self) -> bool:
        """未命中任何规则时，是否拒绝。"""
        return self.mode == MODE_ALLOW

    def policy_label(self) -> str:
        return MODE_LABEL.get(self.mode, MODE_LABEL[MODE_BLOCK])

    def counts(self):
        """返回 (启用中的黑名单条数, 启用中的白名单条数)。"""
        deny = sum(1 for r in self.rules if r.enabled and r.is_deny)
        allow = sum(1 for r in self.rules if r.enabled and r.is_allow)
        return deny, allow

    # ---------------- 判定 ----------------
    def check(self, host: str, port: int):
        """返回 (是否放行, 原因说明)。

        判定顺序：**拒绝优先**
            1) 任何一条启用的黑名单规则命中 → 拒绝
            2) 否则任何一条白名单规则命中 → 放行
            3) 都没有 → 按默认策略兜底

        原因说明会写进日志，方便事后追查"为什么这个端口没转出去"。
        """
        if not self.enabled:
            return True, "规则总开关已关闭，全部放行"

        deny_hit = None
        allow_hit = None
        for r in self.rules:
            if not r.matches(host, port):
                continue
            if r.is_allow:
                if allow_hit is None:
                    allow_hit = r
            else:
                if deny_hit is None:
                    deny_hit = r

        # 1) 黑名单优先 —— 安全工具宁可拦错，不可放错
        if deny_hit is not None:
            return False, "命中黑名单：%s" % deny_hit.describe()
        # 2) 白名单命中
        if allow_hit is not None:
            return True, "命中白名单：%s" % allow_hit.describe()
        # 3) 兜底
        if self.default_deny:
            return False, "未命中任何规则，按默认策略拒绝（%s:%s）" % (host, port)
        return True, "未命中任何规则，按默认策略放行"

    # ---------------- 存取 ----------------
    @classmethod
    def load(cls, path: str) -> "RuleSet":
        """从 JSON 读取；文件不存在或损坏时返回空规则集（不抛异常）。

        兼容旧版（version 1）：那时规则不带 action，类型由全局 mode 决定。
        这里按当时的 mode 把每条规则补上类型，保证升级前后判定结果一致。
        """
        if not path or not os.path.exists(path):
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return cls()
        mode = data.get("mode", MODE_BLOCK)
        if mode not in MODE_CHOICES:
            mode = MODE_BLOCK
        # 旧数据没有 action 字段：当时的全局 mode 就是它的类型
        legacy_action = ACTION_ALLOW if mode == MODE_ALLOW else ACTION_DENY
        rules = []
        for item in data.get("rules", []):
            if not isinstance(item, dict):
                continue
            raw_action = item.get("action")
            action = legacy_action if raw_action in (None, "") else normalize_action(raw_action)
            rules.append(Rule(
                host=str(item.get("host", "*")),
                port=str(item.get("port", "*")),
                note=str(item.get("note", "")),
                enabled=bool(item.get("enabled", True)),
                action=action,
            ))
        return cls(mode=mode, rules=rules, enabled=bool(data.get("enabled", True)))

    def save(self, path: str) -> None:
        """写盘。用"先写临时文件再替换"，避免写一半断电留下坏文件。"""
        data = {
            "version": 2,          # v2：每条规则自带 action
            "enabled": self.enabled,
            "mode": self.mode,
            "rules": [asdict(r) for r in self.rules],
        }
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    # ---------------- 便捷方法 ----------------
    def add(self, host: str, port: str, note: str = "",
            action: str = ACTION_DENY) -> Rule:
        """新增一条规则。action 默认黑名单（"加规则"的本意多半是"拦掉"。"""
        r = Rule(host=host or "*", port=str(port or "*"), note=note,
                 action=normalize_action(action))
        self.rules.append(r)
        return r

    def remove(self, index: int) -> bool:
        if 0 <= index < len(self.rules):
            del self.rules[index]
            return True
        return False

    def set_action(self, index: int, action: str) -> bool:
        """把第 index 条规则改成 allow / deny。"""
        if 0 <= index < len(self.rules):
            self.rules[index].action = normalize_action(action)
            return True
        return False

    def set_enabled(self, index: int, enabled: bool) -> bool:
        if 0 <= index < len(self.rules):
            self.rules[index].enabled = bool(enabled)
            return True
        return False

    # ---------------- 文案 ----------------
    def mode_label(self) -> str:
        return self.policy_label()

    def stats_line(self) -> str:
        if not self.enabled:
            return "规则已关闭"
        deny, allow = self.counts()
        return "共 %d 条（黑名单 %d / 白名单 %d）· %s" % (
            len(self.rules), deny, allow, self.policy_label())


def preset_rules(ports: Iterable[str] = ()) -> list:
    """按端口列表生成"禁止转发"的规则（供界面快捷添加）。

    **一律是黑名单（拒绝）** —— 快捷添加的本意就是"这些端口别放出去"，
    不能因为当前是白名单模式就反过来变成放行（那是旧版的一个坑）。
    """
    notes = dict(RISKY_PRESETS)
    return [Rule(host="*", port=str(p), note=notes.get(str(p), "高危端口"),
                 action=ACTION_DENY)
            for p in ports]
