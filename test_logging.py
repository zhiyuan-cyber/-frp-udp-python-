"""test_logging.py —— 验证日志管线：子 logger → 界面队列 + 7 天文件

回归要点（就是这次用户反馈的 bug）：
    frps / frpc / tray / frp.* 这些 logger 都是 propagate=False 的，
    只往 root 挂 handler 收不到它们 —— 必须逐个挂（protocol.install_logging）。
"""
import logging
import os
import queue
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import protocol


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="frp_logtest_")
    print("临时日志目录：%s" % tmp)

    # ---- 完全复刻 gui.py 的真实管线，确保测的是线上路径 ----
    import gui
    gui.LOG_DIR = tmp                      # 把日志目录指到临时目录
    gui.DATA_DIR = os.path.dirname(tmp)

    q: "queue.Queue" = queue.Queue()
    gui.install_gui_logging(q)             # 界面队列 handler
    fh = gui._file_handler_for_today()     # 7 天轮转文件 handler
    protocol.install_logging([fh], level=logging.DEBUG)
    fh.setLevel(logging.DEBUG)

    # 模拟各模块输出
    logging.getLogger("frps").info("服务端：控制端口监听 0.0.0.0:8800")
    logging.getLogger("frpc").warning("客户端：转发被过滤规则拒绝 192.168.1.5:3389")
    logging.getLogger("tray").info("托盘图标已添加到通知区域")
    logging.getLogger("frp.protocol").debug("协议层：心跳超时")
    logging.getLogger("frp.cert").error("证书读取失败：模拟错误")
    logging.getLogger("gui").info("界面自身的日志也要进文件")

    # 额外：同名 logger 重复 install 不应重复输出
    protocol.install_logging([fh], level=logging.DEBUG)
    logging.getLogger("frps").info("重复安装后仍应只有一行")

    fh.flush()

    drained = []
    while not q.empty():
        drained.append(q.get_nowait())

    print("\n--- 队列收到 %d 条 ---" % len(drained))
    for lv, text in drained:
        print("  %-7s %s" % (lv, text))

    path = os.path.join(tmp, "app.log")
    with open(path, encoding="utf-8") as f:
        file_lines = [ln.rstrip("\n") for ln in f if ln.strip()]
    print("\n--- 文件收到 %d 行 ---" % len(file_lines))
    for ln in file_lines:
        print("  " + ln)

    # ---------------- 断言 ----------------
    fails = []

    def check(cond, desc):
        print("  [%s] %s" % ("OK" if cond else "FAIL", desc))
        if not cond:
            fails.append(desc)

    print("\n--- 校验 ---")
    names_in_file = " ".join(file_lines)
    for mod in ("frps", "frpc", "tray", "frp.protocol", "frp.cert", "gui"):
        check("] %s:" % mod in names_in_file or "%s:" % mod in names_in_file,
              "文件里有 %s 的日志" % mod)

    qnames = " ".join("%s %s" % (lv, t) for lv, t in drained)
    for mod in ("frps", "frpc", "tray", "frp.protocol", "frp.cert"):
        check(mod in qnames, "界面队列里有 %s 的日志" % mod)

    # 上面一共发了 7 条不同的日志（重复 install 那次不应产生第 8 条）
    expect = 7
    check(len(file_lines) == expect,
          "文件共 %d 行（无重复），实际 %d" % (expect, len(file_lines)))
    check(len(drained) == expect,
          "队列共 %d 条（无重复），实际 %d" % (expect, len(drained)))
    check(sum(1 for _ in drained if "重复安装" in _[1]) == 1,
          "重复 install 后同一条日志只出现一次")
    check(any(lv == "ERROR" for lv, _ in drained), "ERROR 级别能透出来")
    check(any(lv == "DEBUG" for lv, _ in drained), "DEBUG 级别能透出来")

    # 7 天保留策略
    check(fh.backupCount == 7, "文件 handler 保留 7 份（backupCount=7）")
    check(fh.suffix == "%Y-%m-%d", "轮转后缀是日期格式（按天切）")
    check(fh.when == "MIDNIGHT", "每天 0 点轮转一次（when=midnight）")

    # 层级结构：handler 只能挂在 root 上，中间父节点不许挂（否则重复）
    check(len(logging.getLogger("frp").handlers) == 0,
          "父 logger 'frp' 上不挂 handler（避免子 logger 日志重复）")
    check(all(logging.getLogger(n).propagate for n in protocol.PROJECT_LOGGERS),
          "所有项目 logger 的 propagate 都是 True（能冒泡到 root）")

    # 界面读取历史日志（直接构造最小实例，验证 _read_recent_logs / 级别识别）
    print("\n--- 界面历史读取 ---")
    lines = gui._read_recent_logs_impl(tmp, max_lines=100)
    check(len(lines) == expect, "历史读取拿到 %d 行，实际 %d" % (expect, len(lines)))
    check(any("frp.cert" in ln for ln in lines), "历史里含 frp.cert 的记录")
    check(gui.level_of_line("2026-10-14 10:00:00 [WARNING] frps: x") == "WARNING",
          "能从日志行认出 WARNING 级别")
    check(gui.level_of_line("2026-10-14 10:00:00 [CRITICAL] x: y") == "WARNING",
          "CRITICAL 归并到 WARNING（界面只分四色）")

    print("\n%s（%d 项失败）" % ("全部通过" if not fails else "存在失败", len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
