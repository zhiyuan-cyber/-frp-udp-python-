/**
 * Models.ets —— 与电脑端 API 对应的数据模型
 *
 * 电脑端（Python）负责真正的穿透逻辑，手机端只是"控制台"：
 *   手机  ──HTTP/JSON──▶  电脑上的 内网穿透助手（--mobile-api 端口）
 *
 * 这样做是因为鸿蒙不支持 Python 运行时：
 *   无法把 frps.py / frpc.py 搬到手机上跑，
 *   所以手机 App 的定位是"远程查看 + 控制"，而非"自己当服务端"。
 */

/** 运行统计快照（对应 protocol.Stats.snapshot） */
export interface StatsSnapshot {
  role: string;           // server / client / idle
  running: boolean;
  uptime: number;         // 已运行秒数
  clients: number;        // 在线客户端数
  tunnels: number;        // 隧道数
  connections: number;    // 当前活跃连接
  connectionsPeak: number;// 连接峰值
  bytesUp: number;        // 累计上行字节
  bytesDown: number;      // 累计下行字节
  speedUp: number;        // 上行速度 B/s
  speedDown: number;      // 下行速度 B/s
  rejected: number;       // 被拒连接数
  authFailed: number;     // 鉴权失败数
}

/** 一条转发连接 */
export interface ConnItem {
  name: string;
  peer: string;
  target: string;
  bytesUp: number;
  bytesDown: number;
  duration: number;
  since: string;
}

/** 服务器信息 */
export interface ServerInfo {
  publicIp: string;
  geo: string;
  isp: string;
  latencyMs: number;
  localPorts: string[];
}

/** 一条过滤规则 */
export interface RuleItem {
  index: number;
  host: string;
  ports: string;
  action: string;        // allow（白名单：命中即放行）/ deny（黑名单：命中即拒绝）
  note: string;
  enabled: boolean;
}

/**
 * 规则集整体状态
 *
 * mode 是「默认策略」——**未命中任何规则**时怎么办，不是整张表的类型：
 *   blacklist → 默认放行（只拦 action=deny 的规则）
 *   whitelist → 默认拒绝（只放 action=allow 的规则）
 * 每条规则是拦还是放，看它自己的 action；黑白可以混排。
 */
export interface RulesPayload {
  mode: string;          // blacklist（默认放行）/ whitelist（默认拒绝）
  enabled: boolean;
  rules: RuleItem[];
}

/** 一条日志 */
export interface LogLine {
  time: string;
  level: string;         // DEBUG / INFO / WARNING / ERROR
  module: string;
  message: string;
}

/** 统一响应外壳 */
export interface ApiResult<T> {
  ok: boolean;
  data?: T;
  error?: string;
}
