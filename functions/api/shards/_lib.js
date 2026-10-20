/**
 * 分片存储池 —— 共享库（下划线目录不生成路由，仅被同目录函数 import）
 *
 * 设计：
 *  - 单个 Pages 项目最多绑定 10 个 D1。本项目内通过 SHARD_D1S 环境变量声明已绑定的库名池，
 *    按 key 哈希挑库，实现项目内分片分流；横向扩到更多库时，新增项目/节点并在调度层替换
 *    resolveNode() 即可，业务代码不变。
 *  - D1 单行 BLOB 上限 1MB，分片固定 900KB 留余量。
 *  - 文件主索引、标签反向索引放 KV（SHARD_KV，未绑定回退 AUTH_KV）。
 */

// 单片大小：900 KiB，低于 D1 单行 1MB 硬顶
export const CHUNK_SIZE = 900 * 1024;

export const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
};

// 允许的前端来源（CSRF/来源白名单）
export const ALLOWED_ORIGINS = [
  "https://songyuheng800.github.io",
  "https://utau-catbox-test.pages.dev",
  "https://utau-4oo.pages.dev",
];

export function originAllowed(request) {
  const origin = request.headers.get("Origin") || "";
  if (origin) return ALLOWED_ORIGINS.includes(origin);
  const ref = request.headers.get("Referer") || "";
  if (!ref) return false;
  try { return ALLOWED_ORIGINS.includes(new URL(ref).origin); } catch (e) { return false; }
}

export function cors(allowCredentials = false) {
  return {
    "Access-Control-Allow-Origin": allowCredentials ? "https://songyuheng800.github.io" : "*",
    "Access-Control-Allow-Credentials": String(allowCredentials),
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
    ...SECURITY_HEADERS,
  };
}

export function json(obj, status = 200, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors(), "Content-Type": "application/json; charset=utf-8", ...(extra || {}) },
  });
}

/* ---------- 哈希（FNV-1a 32bit，稳定分布，用于选库/选节点） ---------- */
export function fnv1a(str) {
  let h = 2166136261;
  const s = String(str);
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/* ---------- D1 池 ---------- */
// 返回 { names, pool }；pool 是真正可用的 D1 绑定实例数组
export function d1Pool(env) {
  const names = String(env.SHARD_D1S || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const pool = names.map((n) => env[n]).filter((db) => db && typeof db.prepare === "function");
  return { names, pool };
}

// 按 key 哈希挑一个本项目内的 D1 实例；池为空抛错由调用方转 500
export function pickDb(env, key) {
  const { pool } = d1Pool(env);
  if (!pool.length) throw new Error("NO_D1_POOL");
  return pool[fnv1a(key) % pool.length];
}

/* ---------- KV（分片索引） ---------- */
export function shardKv(env) {
  return env.SHARD_KV || env.AUTH_KV || null;
}

/* ---------- base64 <-> bytes（Workers 全局 atob/btoa） ---------- */
export function b64ToBytes(b64) {
  const bin = atob(String(b64).replace(/\s/g, ""));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export function bytesToB64(u8) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
  }
  return btoa(bin);
}

/* ---------- 标签规范化 ---------- */
export function normTag(t) {
  return String(t || "").trim().toLowerCase().replace(/\s+/g, "-").replace(/[^\w\-一-龥]/g, "").slice(0, 40);
}

/* ---------- 索引 key 约定 ---------- */
export const idxKey = (fileId) => `shard:file:${fileId}`;
export const pendingKey = (fileId) => `shard:pending:${fileId}`;
export const tagKey = (tag) => `shard:tag:${tag}`;

/* ---------- 校验 fileId 合法性（防注入/路径穿越到 key） ---------- */
export function validFileId(id) {
  return typeof id === "string" && /^[A-Za-z0-9_\-]{8,64}$/.test(id);
}
