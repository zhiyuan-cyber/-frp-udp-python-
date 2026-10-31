"""test_rules.py —— 验证「每条规则自带类型」这套新模型

背景（这是本测试存在的理由）：
    旧版把"黑名单/白名单"做成**全局模式**，规则自己不带类型。
    后果有两个：
      1) 列表里所有规则类型都一样，看不出哪条在拦、哪条在放；
      2) **白名单模式下点"常见高危端口"，加进去的规则变成"放行高危端口"**
         —— 与点它的本意完全相反（这是个真坑）。
    改成"每条规则自带 action（deny/allow）+ 默认策略兜底"后：
      · 列表能黑白混排，逐条可改；
      · 快捷添加固定为黑名单，不会再反过来。

覆盖：
    1. 规则类型（action）的默认值与显式指定
    2. 判定顺序：拒绝优先
    3. 默认策略兜底（未命中时放行 / 拒绝）
    4. 快捷添加一律黑名单
    5. 存盘 / 载入往返保真
    6. 旧版数据（version 1）迁移后判定结果不变
    7. set_action / set_enabled 生效
    8. 用户报的那个场景（白名单 + 高危端口 + 新增规则）复现与修复
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import rules as rules_mod
from rules import ACTION_ALLOW, ACTION_DENY, MODE_ALLOW, MODE_BLOCK, RuleSet

FAILS = []


def check(cond, desc):
    print("  [%s] %s" % ("OK" if cond else "FAIL", desc))
    if not cond:
        FAILS.append(desc)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="frp_rules_")
    path = os.path.join(tmp, "rules.json")

    # ------------------------------------------------------------------
    print("--- 1. 规则类型 ---")
    rs = RuleSet()
    r1 = rs.add("*", "3389", "远程桌面")
    check(r1.action == ACTION_DENY, "不指定时默认是黑名单")
    check(r1.is_deny and not r1.is_allow, "is_deny / is_allow 判断正确")
    check(r1.action_label() == "黑名单", "类型标签 = %s" % r1.action_label())

    r2 = rs.add("*", "8080", "我的网站", action=ACTION_ALLOW)
    check(r2.action == ACTION_ALLOW, "add 可以显式指定白名单")

    r3 = rs.add("*", "9000", "", action="whitelist")
    check(r3.action == ACTION_ALLOW, "别名 whitelist 归一成 allow")
    r4 = rs.add("*", "9001", "", action="随便乱写")
    check(r4.action == ACTION_DENY, "不认识的值一律当黑名单（保守）")

    # ------------------------------------------------------------------
    print("\n--- 2. 判定：拒绝优先 ---")
    rs2 = RuleSet()
    rs2.add("*", "3389", "RDP", action=ACTION_DENY)
    ok, why = rs2.check("127.0.0.1", 3389)
    check(not ok and "命中黑名单" in why, "黑名单命中 → 拒绝（%s）" % why)

    rs3 = RuleSet()
    rs3.add("*", "8080", "网站", action=ACTION_ALLOW)
    ok, why = rs3.check("127.0.0.1", 8080)
    check(ok and "命中白名单" in why, "白名单命中 → 放行（%s）" % why)

    # 黑白同时命中 → 拒绝优先
    rs4 = RuleSet()
    rs4.add("*", "3389", "拦掉", action=ACTION_DENY)
    rs4.add("*", "3389", "又想放", action=ACTION_ALLOW)
    ok, why = rs4.check("127.0.0.1", 3389)
    check(not ok, "黑白都命中 → 拒绝优先（安全优先）")
    check("命中黑名单" in why, "原因说明指向黑名单（%s）" % why)

    # 顺序反过来，结论必须一样（可预测）
    rs5 = RuleSet()
    rs5.add("*", "3389", "又想放", action=ACTION_ALLOW)
    rs5.add("*", "3389", "拦掉", action=ACTION_DENY)
    ok2, _ = rs5.check("127.0.0.1", 3389)
    check(ok == ok2, "调换列表顺序不改变结论（不是「谁在前谁赢」）")

    # ------------------------------------------------------------------
    print("\n--- 3. 默认策略兜底 ---")
    rs6 = RuleSet(mode=MODE_BLOCK)
    rs6.add("*", "3389", "", action=ACTION_DENY)
    ok, why = rs6.check("127.0.0.1", 9999)
    check(ok and "默认策略放行" in why, "默认放行：没命中 → 放行（%s）" % why)

    rs7 = RuleSet(mode=MODE_ALLOW)
    rs7.add("*", "8080", "", action=ACTION_ALLOW)
    ok, why = rs7.check("127.0.0.1", 9999)
    check(not ok and "默认策略拒绝" in why, "默认拒绝：没命中 → 拒绝（%s）" % why)
    ok, _ = rs7.check("127.0.0.1", 8080)
    check(ok, "默认拒绝下，白名单规则命中仍放行")

    # 总开关关掉 → 一切放行
    rs7.enabled = False
    ok, why = rs7.check("127.0.0.1", 9999)
    check(ok and "总开关" in why, "总开关关闭 → 全部放行")

    # ------------------------------------------------------------------
    print("\n--- 4. 快捷添加一律黑名单 ---")
    presets = rules_mod.preset_rules(["3389", "445"])
    check(len(presets) == 2, "生成 2 条")
    check(all(p.action == ACTION_DENY for p in presets),
          "全部是黑名单（旧版会跟着全局模式跑，白名单模式下等于放行高危端口）")

    # 复现用户报的场景：默认拒绝（白名单模式）+ 白名单规则 + 高危端口
    rs8 = RuleSet(mode=MODE_ALLOW)
    rs8.add("*", "8080", "我的网站", action=ACTION_ALLOW)      # 新增一条规则（白名单）
    for p in rules_mod.preset_rules(["3389", "445"]):          # 点常见高危端口
        rs8.rules.append(p)
    ok, why = rs8.check("127.0.0.1", 8080)
    check(ok, "白名单里的 8080 仍然放行（%s）" % why)
    ok, why = rs8.check("127.0.0.1", 3389)
    check(not ok and "命中黑名单" in why, "高危端口 3389 被拒绝（%s）" % why)
    ok, why = rs8.check("127.0.0.1", 9999)
    check(not ok, "没写进列表的 9999 按默认策略拒绝")
    deny, allow = rs8.counts()
    check((deny, allow) == (2, 1), "统计：黑名单 %d / 白名单 %d（期望 2/1）" % (deny, allow))

    # ------------------------------------------------------------------
    print("\n--- 5. 存盘 / 载入往返 ---")
    rs8.save(path)
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    check(raw.get("version") == 2, "落盘版本号 = %s（期望 2）" % raw.get("version"))
    check(raw["rules"][0].get("action") == ACTION_ALLOW, "第 1 条的 action 已落盘")
    check("action" in raw["rules"][1], "每条规则都写了自己的 action")

    back = RuleSet.load(path)
    check([r.action for r in back.rules] == [r.action for r in rs8.rules],
          "载入后 action 逐条保真")
    check(back.mode == rs8.mode, "默认策略保真")
    # 判定结果一致
    same = all(back.check("127.0.0.1", p)[0] == rs8.check("127.0.0.1", p)[0]
               for p in (8080, 3389, 445, 9999))
    check(same, "往返后判定结果完全一致")

    # ------------------------------------------------------------------
    print("\n--- 6. 旧版数据迁移（version 1）---")
    # 旧版黑名单：规则无 action，mode=blocklist
    legacy_block = {
        "version": 1, "enabled": True, "mode": "blocklist",
        "rules": [{"host": "*", "port": "3389", "note": "RDP", "enabled": True}],
    }
    p1 = os.path.join(tmp, "legacy_block.json")
    with open(p1, "w", encoding="utf-8") as f:
        json.dump(legacy_block, f, ensure_ascii=False)
    lb = RuleSet.load(p1)
    check(lb.rules[0].action == ACTION_DENY, "旧 blocklist 数据 → 规则补成黑名单")
    check(lb.check("127.0.0.1", 3389)[0] is False, "旧 blocklist：3389 仍然被拒绝")
    check(lb.check("127.0.0.1", 8080)[0] is True, "旧 blocklist：其它仍然放行")

    # 旧版白名单：规则无 action，mode=allowlist
    legacy_allow = {
        "version": 1, "enabled": True, "mode": "allowlist",
        "rules": [{"host": "*", "port": "8080", "note": "网站", "enabled": True}],
    }
    p2 = os.path.join(tmp, "legacy_allow.json")
    with open(p2, "w", encoding="utf-8") as f:
        json.dump(legacy_allow, f, ensure_ascii=False)
    la = RuleSet.load(p2)
    check(la.rules[0].action == ACTION_ALLOW, "旧 allowlist 数据 → 规则补成白名单")
    check(la.check("127.0.0.1", 8080)[0] is True, "旧 allowlist：8080 仍然放行")
    check(la.check("127.0.0.1", 9999)[0] is False, "旧 allowlist：其它仍然拒绝")

    # 坏文件不影响启动
    p3 = os.path.join(tmp, "broken.json")
    with open(p3, "w", encoding="utf-8") as f:
        f.write("{ 这不是 JSON")
    check(len(RuleSet.load(p3).rules) == 0, "损坏文件 → 空规则集（不抛异常）")
    check(len(RuleSet.load(os.path.join(tmp, "不存在.json")).rules) == 0,
          "文件不存在 → 空规则集")

    # ------------------------------------------------------------------
    print("\n--- 7. 改类型 / 改启用 ---")
    rs9 = RuleSet()
    rs9.add("*", "3389", "RDP")                       # 黑名单
    check(rs9.check("127.0.0.1", 3389)[0] is False, "初始：拒绝")
    check(rs9.set_action(0, ACTION_ALLOW), "set_action 返回成功")
    check(rs9.check("127.0.0.1", 3389)[0] is True, "改成白名单后 → 放行（立即生效）")
    check(rs9.set_action(0, ACTION_DENY), "再改回黑名单")
    check(rs9.check("127.0.0.1", 3389)[0] is False, "改回后 → 又拒绝")
    check(rs9.set_action(99, ACTION_ALLOW) is False, "越界序号返回 False（不崩）")

    check(rs9.set_enabled(0, False), "停用某条规则")
    check(rs9.check("127.0.0.1", 3389)[0] is True, "停用后该规则不再参与判定")
    rs9.set_enabled(0, True)
    check(rs9.check("127.0.0.1", 3389)[0] is False, "重新启用后恢复判定")

    # ------------------------------------------------------------------
    print("\n--- 8. 统计与文案 ---")
    rs10 = RuleSet(mode=MODE_ALLOW)
    rs10.add("*", "3389", "", action=ACTION_DENY)
    rs10.add("*", "8080", "", action=ACTION_ALLOW)
    rs10.add("*", "9000", "", action=ACTION_ALLOW)
    deny, allow = rs10.counts()
    check((deny, allow) == (1, 2), "counts() = %d/%d（期望 1/2）" % (deny, allow))
    line = rs10.stats_line()
    check("黑名单 1" in line and "白名单 2" in line, "stats_line 分开统计：%s" % line)
    check("默认拒绝" in line, "stats_line 带上默认策略")
    rs10.enabled = False
    check(rs10.stats_line() == "规则已关闭", "关闭时文案 = %s" % rs10.stats_line())

    # ------------------------------------------------------------------
    print("\n%s（%d 项失败）" % ("全部通过" if not FAILS else "存在失败", len(FAILS)))
    if FAILS:
        print("\n失败项：")
        for f in FAILS:
            print("  -", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
