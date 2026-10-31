/**
 * Fmt.ets —— 格式化与主题工具
 *
 * 全部是纯函数，方便单元测试，也避免各页面重复实现。
 */

/** 字节 → 人类可读（与电脑端 gui.py 的 format_bytes 保持一致的口径） */
export function fmtBytes(n: number): string {
  if (!n || n <= 0) {
    return '0 B';
  }
  const units: string[] = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${Math.round(v)} B` : `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

/** 速度 */
export function fmtSpeed(bps: number): string {
  return fmtBytes(bps) + '/s';
}

/** 秒 → 1天2小时3分 / 2小时3分4秒 */
export function fmtDuration(sec: number): string {
  if (!sec || sec <= 0) {
    return '0 秒';
  }
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (d > 0) {
    return `${d} 天 ${h} 小时`;
  }
  if (h > 0) {
    return `${h} 小时 ${m} 分`;
  }
  if (m > 0) {
    return `${m} 分 ${s} 秒`;
  }
  return `${s} 秒`;
}

/** 级别 → 颜色（遵循与电脑端一致的配色，红=错、黄=警、灰=调试） */
export function levelColor(level: string): string {
  switch (level) {
    case 'ERROR':
      return '#FF7B72';
    case 'WARNING':
      return '#E3B341';
    case 'DEBUG':
      return '#7D8799';
    default:
      return '#D7DDE8';
  }
}

/** 状态 → 颜色 */
export function runningColor(running: boolean): string {
  return running ? '#3FBF7F' : '#6B7785';
}

/** 级别列表（供筛选下拉使用） */
export const LOG_LEVELS: string[] = ['ALL', 'DEBUG', 'INFO', 'WARNING', 'ERROR'];
