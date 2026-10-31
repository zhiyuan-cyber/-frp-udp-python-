"""test_rules_gui.py —— 真跑界面，验证「规则列表下拉」的完整链路

为什么单独写一个 GUI 测试：
    这次改的是**每条规则的类型下拉**，光测 rules.py 不够 ——
    必须确认"界面上点一下下拉 → 内存改 → 落盘改 → 判定跟着改"整条链路通。
    所以这里真的把 App() 起起来（用临时数据目录，不碰真实规则文件），
    找到列表里的下拉控件，用 menu.invoke() 模拟用户选择，再逐层核对。

不截图、不依赖显示器交互，纯逻辑验证；跑完自动关窗。
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# 手机接口会让测试变慢且没必要，关掉
os.environ["FRP_NO_MOBILE_API"] = "1"

import json

FAILS = []


def check(cond, desc):
    print("  [%s] %s" % ("OK" if cond else "FAIL", desc))
    if not cond:
        FAILS.append(desc)


def find_widgets(root, cls, out=None):
    """深度遍历，收集指定类型的控件。"""
    if out is None:
        out = []
    for w in root.winfo_children():
        if isinstance(w, cls):
            out.append(w)
        find_widgets(w, cls, out)
    return out


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="frp_rules_gui_")
    print("临时数据目录：%s" % tmp)

    import gui
    import ui_kit as uk
    import rules as rules_mod

    # 把数据落到临时目录，绝不碰真实的 rules.json
    gui.DATA_DIR = tmp
    gui.RULES_FILE = os.path.join(tmp, "rules.json")
    gui.GEO_CACHE_FILE = os.path.join(tmp, "geo-cache.json")

    # 预置一组规则：一条黑名单 + 一条白名单，好观察混排
    rs = rules_mod.RuleSet(mode=rules_mod.MODE_ALLOW)
    rs.add("*", "3389", "远程桌面 RDP", action=rules_mod.ACTION_DENY)
    rs.add("*", "8080", "我的网站", action=rules_mod.ACTION_ALLOW)
    rs.save(gui.RULES_FILE)

    app = gui.App()
    app.update()

    # ------------------------------------------------------------------
    print("\n--- 1. 规则页渲染 ---")
    app.show_page("rules")
    app.update()
    check(app.rules is not None, "规则对象已载入")
    check(len(app.rules.rules) == 2, "载入 2 条规则")
    check(app._current_page == "rules", "已切到规则页")
    check(hasattr(app, "mode_select"), "默认策略下拉已创建")
    check(hasattr(app, "nr_action_select"), "新增规则的类型下拉已创建")
    check(hasattr(app, "try_result"), "试算结果标签已创建")

    # ------------------------------------------------------------------
    print("\n--- 2. 列表里每行一个类型下拉 ---")
    selects = find_widgets(app.rules_box, uk.Select)
    check(len(selects) == 2, "规则列表里有 2 个类型下拉（实际 %d）" % len(selects))
    if len(selects) >= 2:
        check(selects[0].get() == rules_mod.ACTION_DENY,
              "第 1 行的下拉显示黑名单（%s）" % selects[0].get())
        check(selects[1].get() == rules_mod.ACTION_ALLOW,
              "第 2 行的下拉显示白名单（%s）" % selects[1].get())
        # 下拉菜单里有且只有两个选项
        labels = [selects[0].menu.entrycget(i, "label")
                  for i in range(selects[0].menu.index("end") + 1)]
        check(labels == ["黑名单", "白名单"], "下拉选项 = %s" % labels)

    # 默认策略下拉也要能反映当前值
    check(app.mode_select.get() == rules_mod.MODE_ALLOW,
          "默认策略下拉显示「默认拒绝」（当前 mode=%s）" % app.mode_select.get())

    # ------------------------------------------------------------------
    print("\n--- 3. 下拉切换真的生效（核心）---")
    # 第 1 行本来是黑名单（拦 3389），改成白名单 —— 应当变成放行
    check(app.rules.check("127.0.0.1", 3389)[0] is False, "改之前：3389 被拒绝")
    selects[0].menu.invoke(1)          # 菜单第 2 项 = 白名单
    app.update()

    check(app.rules.rules[0].action == rules_mod.ACTION_ALLOW,
          "内存里第 1 条已变成白名单（%s）" % app.rules.rules[0].action)
    check(app.rules.check("127.0.0.1", 3389)[0] is True,
          "判定立即生效：3389 变成放行")

    with open(gui.RULES_FILE, encoding="utf-8") as f:
        saved = json.load(f)
    check(saved["rules"][0]["action"] == "allow", "落盘文件里第 1 条已是白名单")
    check(saved["version"] == 2, "落盘版本号 = %s" % saved["version"])

    # 再改回去
    app.show_page("rules")
    app.update()
    selects = find_widgets(app.rules_box, uk.Select)
    selects[0].menu.invoke(0)          # 第 1 项 = 黑名单
    app.update()
    check(app.rules.rules[0].action == rules_mod.ACTION_DENY, "再改回黑名单")
    check(app.rules.check("127.0.0.1", 3389)[0] is False, "3389 又变回拒绝")

    # ------------------------------------------------------------------
    print("\n--- 4. 用户报的那个场景：白名单模式 + 高危端口 + 新增规则 ---")
    # 当前是「默认拒绝 + 3389 黑名单 + 8080 白名单」
    app._add_rule_quick("445", "SMB 文件共享")
    app.update()
    check(len(app.rules.rules) == 3, "快捷添加后 3 条")
    check(app.rules.rules[2].action == rules_mod.ACTION_DENY,
          "快捷添加的是黑名单（不会因为默认拒绝就变成放行）")
    check(app.rules.check("127.0.0.1", 445)[0] is False, "445 被拒绝")
    check(app.rules.check("127.0.0.1", 8080)[0] is True, "8080 仍然放行")
    check(app.rules.check("127.0.0.1", 9999)[0] is False, "9999 按默认策略拒绝")

    selects = find_widgets(app.rules_box, uk.Select)
    check(len(selects) == 3, "列表里现在 3 个下拉（实际 %d）" % len(selects))

    # ------------------------------------------------------------------
    print("\n--- 5. 新增规则时可选类型 ---")
    app.nr_host.set("*")
    app.nr_port.set("9000")
    app.nr_note.set("测试端口")
    app.nr_action_select.menu.invoke(1)        # 选白名单
    check(app.nr_action.get() == rules_mod.ACTION_ALLOW, "新增区下拉已选白名单")
    app._add_rule()
    app.update()
    check(len(app.rules.rules) == 4, "新增后 4 条")
    check(app.rules.rules[3].action == rules_mod.ACTION_ALLOW,
          "新规则是白名单（%s）" % app.rules.rules[3].action)
    check(app.rules.check("127.0.0.1", 9000)[0] is True, "9000 放行")

    # ------------------------------------------------------------------
    print("\n--- 6. 试算框 ---")
    app.try_host.set("127.0.0.1")
    app.try_port.set("3389")
    app._try_rule()
    txt = app.try_result.cget("text")
    check("拒绝转发" in txt, "试算 3389 → %s" % txt)
    app.try_port.set("8080")
    app._try_rule()
    txt = app.try_result.cget("text")
    check("允许转发" in txt, "试算 8080 → %s" % txt)
    app.try_port.set("abc")
    app._try_rule()
    txt = app.try_result.cget("text")
    check("数字" in txt, "非法端口给提示 → %s" % txt)

    # ------------------------------------------------------------------
    print("\n--- 7. 默认策略切换 ---")
    app.mode_select.menu.invoke(0)      # 第 1 项 = 默认放行
    app.update()
    check(app.rules.mode == rules_mod.MODE_BLOCK, "模式切到 blocklist（默认放行）")
    check(app.rules.check("127.0.0.1", 9999)[0] is True, "9999 现在放行了（默认放行）")
    with open(gui.RULES_FILE, encoding="utf-8") as f:
        check(json.load(f)["mode"] == "blocklist", "默认策略已落盘")

    # ------------------------------------------------------------------
    print("\n--- 8. 总开关 / 停用 / 删除 ---")
    app._on_rules_toggle(False)
    app.update()
    check(app.rules.enabled is False, "总开关已关闭")
    check(app.rules.check("127.0.0.1", 3389)[0] is True, "关闭后一切放行")
    app._on_rules_toggle(True)
    app.update()
    check(app.rules.enabled is True, "总开关已恢复")

    app._toggle_rule(0, False)
    app.update()
    check(app.rules.rules[0].enabled is False, "第 1 条已停用")
    check(app.rules.check("127.0.0.1", 3389)[0] is True, "停用后 3389 不再被拦")
    app._toggle_rule(0, True)

    before = len(app.rules.rules)
    app._del_rule(before - 1)
    app.update()
    check(len(app.rules.rules) == before - 1, "删除一条：%d → %d" % (before, len(app.rules.rules)))

    # ------------------------------------------------------------------
    print("\n--- 9. 反复重绘不残留（下拉重建）---")
    for _ in range(3):
        app._render_rules()
        app.update()
    selects = find_widgets(app.rules_box, uk.Select)
    check(len(selects) == len(app.rules.rules),
          "重绘 3 次后下拉数量仍等于规则数（%d vs %d）"
          % (len(selects), len(app.rules.rules)))

    # ------------------------------------------------------------------
    print("\n--- 10. 与已建立的连接无关（只影响新隧道）---")
    check(app.rules.check("127.0.0.1", 8080)[0] is True, "既有放行规则仍在")

    app._really_quit = True
    try:
        app.destroy()
    except Exception:       # noqa: BLE001
        pass

    print("\n%s（%d 项失败）" % ("全部通过" if not FAILS else "存在失败", len(FAILS)))
    if FAILS:
        print("\n失败项：")
        for f in FAILS:
            print("  -", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
