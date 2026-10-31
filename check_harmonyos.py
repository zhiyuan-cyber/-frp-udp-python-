"""check_harmonyos.py —— 鸿蒙工程静态校验

本机没装 DevEco Studio / hvigor，无法真正编译，所以这里做"能做的全部检查"：
  1. 所有 JSON / JSON5 能解析
  2. 工程结构完整（每个必需文件都在）
  3. ArkTS 的 import 路径都能找到对应文件与导出符号
  4. module.json5 里引用的资源（$string: / $media: / $profile: / $color:）都存在
  5. pages 配置与实际页面文件一致
  6. ArkTS 大括号/圆括号配平（粗查语法）
  7. 与电脑端 API 的字段名一致性（对照 mobile_api.py 的输出）
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "harmonyos")

FAILS = []


def check(cond, desc):
    print("  [%s] %s" % ("OK" if cond else "FAIL", desc))
    if not cond:
        FAILS.append(desc)


def load_json5(path):
    """JSON5 是 JSON 超集；本工程用的写法只要去掉注释和尾逗号就能 json.loads。"""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    # 去掉 // 行注释（本工程没有块注释）
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    text = re.sub(r",(\s*[}\]])", r"\1", text)     # 去尾逗号
    return json.loads(text)


def main() -> int:
    print("===== 1. 工程结构 =====")
    required = [
        "build-profile.json5", "hvigorfile.ts", "oh-package.json5",
        "hvigor/hvigor-config.json5",
        "AppScope/app.json5",
        "AppScope/resources/base/element/string.json",
        "AppScope/resources/base/media/app_icon.png",
        "entry/hvigorfile.ts", "entry/oh-package.json5",
        "entry/hvigor/hvigor-config.json5",
        "entry/src/main/module.json5",
        "entry/src/main/ets/entryability/EntryAbility.ets",
        "entry/src/main/ets/pages/Index.ets",
        "entry/src/main/ets/model/Models.ets",
        "entry/src/main/ets/model/ApiClient.ets",
        "entry/src/main/ets/common/Fmt.ets",
        "entry/src/main/ets/common/Prefs.ets",
        "entry/src/main/ets/components/Widgets.ets",
        "entry/src/main/resources/base/element/string.json",
        "entry/src/main/resources/base/element/color.json",
        "entry/src/main/resources/base/profile/main_pages.json",
        "entry/src/main/resources/base/media/app_icon.png",
        "entry/src/main/resources/zh_CN/element/string.json",
        "entry/src/main/resources/en_US/element/string.json",
        "README.md",
    ]
    for rel in required:
        p = os.path.join(ROOT, rel)
        check(os.path.exists(p), "存在 %s" % rel)

    print("\n===== 2. JSON / JSON5 解析 =====")
    j5 = ["build-profile.json5", "oh-package.json5", "entry/oh-package.json5",
          "AppScope/app.json5", "entry/src/main/module.json5",
          "hvigor/hvigor-config.json5", "entry/hvigor/hvigor-config.json5"]
    parsed = {}
    for rel in j5:
        p = os.path.join(ROOT, rel)
        try:
            parsed[rel] = load_json5(p)
            check(True, "解析 %s" % rel)
        except Exception as exc:
            check(False, "解析 %s —— %s" % (rel, exc))
    for rel in ["AppScope/resources/base/element/string.json",
                "entry/src/main/resources/base/element/string.json",
                "entry/src/main/resources/base/element/color.json",
                "entry/src/main/resources/base/profile/main_pages.json",
                "entry/src/main/resources/zh_CN/element/string.json",
                "entry/src/main/resources/en_US/element/string.json"]:
        p = os.path.join(ROOT, rel)
        try:
            parsed[rel] = json.load(open(p, encoding="utf-8"))
            check(True, "解析 %s" % rel)
        except Exception as exc:
            check(False, "解析 %s —— %s" % (rel, exc))

    print("\n===== 3. bundleName / 版本一致性 =====")
    app = parsed.get("AppScope/app.json5", {}).get("app", {})
    check(app.get("bundleName") == "cn.jsdczd.frphelper",
          "bundleName = %s" % app.get("bundleName"))
    check(app.get("versionName") == "1.0.0", "versionName = %s" % app.get("versionName"))
    check(isinstance(app.get("versionCode"), int), "versionCode 是整数")
    check(app.get("minAPIVersion", 0) >= 12, "minAPIVersion = %s" % app.get("minAPIVersion"))

    print("\n===== 4. 资源引用完整性 =====")
    # 汇总所有已声明的资源
    strings = set()
    for rel in ("entry/src/main/resources/base/element/string.json",
                "AppScope/resources/base/element/string.json"):
        for item in parsed.get(rel, {}).get("string", []):
            strings.add(item["name"])
    colors = {c["name"] for c in
              parsed.get("entry/src/main/resources/base/element/color.json", {}).get("color", [])}
    media_dir = os.path.join(ROOT, "entry/src/main/resources/base/media")
    medias = {os.path.splitext(f)[0] for f in os.listdir(media_dir)} if os.path.isdir(media_dir) else set()
    profiles = {os.path.splitext(f)[0] for f in
                os.listdir(os.path.join(ROOT, "entry/src/main/resources/base/profile"))}

    # 扫描 module.json5 与 app.json5 里的 $type:name 引用
    for rel in ("entry/src/main/module.json5", "AppScope/app.json5"):
        text = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        for kind, name in re.findall(r"\$(string|media|profile|color):([A-Za-z0-9_]+)", text):
            pool = {"string": strings, "media": medias,
                    "profile": profiles, "color": colors}[kind]
            check(name in pool, "%s 引用 $%s:%s 存在" % (rel, kind, name))

    print("\n===== 5. ArkTS import 路径与导出符号 =====")
    ets_root = os.path.join(ROOT, "entry/src/main/ets")
    ets_files = []
    for d, _, fs in os.walk(ets_root):
        for f in fs:
            if f.endswith(".ets"):
                ets_files.append(os.path.join(d, f))

    # 建"文件 -> 导出名集合"的索引
    exports = {}
    for p in ets_files:
        text = open(p, encoding="utf-8").read()
        names = set()
        names |= set(re.findall(r"export\s+(?:interface|class|struct|enum)\s+(\w+)", text))
        names |= set(re.findall(r"export\s+(?:async\s+)?function\s+(\w+)", text))
        names |= set(re.findall(r"export\s+(?:const|let|var)\s+(\w+)", text))
        # @Builder export function / 无 export 的 Builder
        names |= set(re.findall(r"export\s+function\s+(\w+)", text))
        exports[os.path.normpath(p)] = names

    import_count = 0
    for p in ets_files:
        text = open(p, encoding="utf-8").read()
        for names_part, path_part in re.findall(
                r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]", text):
            if not path_part.startswith("."):
                continue        # @ohos.* 等系统模块，本机无 SDK，跳过
            import_count += 1
            target = os.path.normpath(
                os.path.join(os.path.dirname(p), path_part + ".ets"))
            rel_self = os.path.relpath(p, ROOT)
            if not os.path.exists(target):
                check(False, "%s: 找不到 %s" % (rel_self, path_part))
                continue
            avail = exports.get(target, set())
            wanted = {n.strip() for n in names_part.split(",") if n.strip()}
            # 类型导入（如 interface）也应能对上
            missing = {w for w in wanted if w not in avail}
            check(not missing, "%s: from %s 导出齐全%s" % (
                rel_self, path_part, "" if not missing else "（缺 %s）" % sorted(missing)))
    print("  （共检查 %d 条相对导入）" % import_count)

    print("\n===== 6. 页面配置一致性 =====")
    pages_cfg = parsed.get("entry/src/main/resources/base/profile/main_pages.json", {})
    srcs = pages_cfg.get("src", [])
    check("pages/Index" in srcs, "main_pages.json 声明了 pages/Index")
    check(os.path.exists(os.path.join(ets_root, "pages/Index.ets")),
          "pages/Index.ets 实际存在")
    idx = open(os.path.join(ets_root, "pages/Index.ets"), encoding="utf-8").read()
    check("@Entry" in idx and "@Component" in idx, "Index.ets 带有 @Entry @Component")

    print("\n===== 7. ArkTS 括号配平（粗查语法）=====")
    for p in ets_files:
        text = open(p, encoding="utf-8").read()
        rel = os.path.relpath(p, ROOT)
        # 去掉字符串与注释，避免误判
        s = re.sub(r"//[^\n]*", "", text)
        s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
        s = re.sub(r"'(\\.|[^'\\])*'", "''", s)
        s = re.sub(r'"(\\.|[^"\\])*"', '""', s)
        s = re.sub(r"`(\\.|[^`\\])*`", "``", s)
        ok = (s.count("{") == s.count("}") and s.count("(") == s.count(")")
              and s.count("[") == s.count("]"))
        check(ok, "%s 括号配平" % rel)

    print("\n===== 8. 与电脑端接口字段一致性 =====")
    api = open(os.path.join(HERE, "mobile_api.py"), encoding="utf-8").read()
    models = open(os.path.join(ets_root, "model/Models.ets"), encoding="utf-8").read()
    client = open(os.path.join(ets_root, "model/ApiClient.ets"), encoding="utf-8").read()

    # 电脑端 state() 返回的键（驼峰）
    # 注意：不能按固定缩进匹配（缩进会随代码层级变化）。先截出 state() 的函数体，
    # 再在函数体内取 "键": 形式的字面量键。
    state_fn = re.search(r"def state\(self\)[^\n]*\n(.*?)\n(?=\s{4}def |\Z)",
                         api, flags=re.S)
    state_body = state_fn.group(1) if state_fn else ""
    # 只取 return { ... } 里的键，避免把 stats.get("xxx") 的取值当成输出键
    ret_obj = re.search(r"return\s*\{(.*?)\n\s*\}", state_body, flags=re.S)
    state_keys = set(re.findall(r'"(\w+)":', ret_obj.group(1))) if ret_obj else set()
    # 鸿蒙端 StatsSnapshot 的字段
    snap_block = re.search(r"interface StatsSnapshot \{(.*?)\}", models, re.S)
    snap_keys = set(re.findall(r"(\w+)\s*[?:]", snap_block.group(1))) if snap_block else set()
    missed = snap_keys - state_keys
    check(not missed, "StatsSnapshot 字段与电脑端 state() 对齐%s" % (
        "" if not missed else "（电脑端未提供 %s）" % sorted(missed)))

    # 路由一致性
    api_routes = set(re.findall(r'path == "(/api/[\w/-]+)"', api))
    client_routes = set(re.findall(r"'(/api/[\w/-]+)'", client))
    client_routes |= set(re.findall(r"this\.(?:get|post)<[^>]*>\('(/api/[\w/-]+)", client))
    unrouted = client_routes - api_routes
    check(not unrouted, "鸿蒙端调用的接口电脑端都有%s" % (
        "" if not unrouted else "（缺 %s）" % sorted(unrouted)))
    print("  电脑端路由：", sorted(api_routes))
    print("  鸿蒙端调用：", sorted(client_routes))

    print("\n===== 9. 权限声明 =====")
    mod = open(os.path.join(ROOT, "entry/src/main/module.json5"), encoding="utf-8").read()
    check("ohos.permission.INTERNET" in mod, "声明了 INTERNET 权限")
    check("deviceTypes" in mod and "phone" in mod, "支持 phone 设备")

    print("\n===== 10. 应用图标 =====")
    icon = os.path.join(ROOT, "entry/src/main/resources/base/media/app_icon.png")
    size = os.path.getsize(icon) if os.path.exists(icon) else 0
    check(size > 1000, "app_icon.png 大小 %d 字节（非空占位）" % size)

    print("\n%s（%d 项失败）" % ("全部通过" if not FAILS else "存在失败", len(FAILS)))
    if FAILS:
        print("\n失败项：")
        for f in FAILS:
            print("  -", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
