/**
 * 服务器配置 API（开发平台 · 服务器配置页）
 *   GET  /api/server-config  - 读取当前配置（公开只读），并下发一次性配置 nonce
 *   POST /api/server-config  - 保存配置（需管理员令牌 + 一次性 nonce + 来源白名单，防 CSRF/未授权写入）
 *
 * 安全加固：
 *  - POST 必须携带管理员令牌 admin_token（与环境变量 ADMIN_CONFIG_TOKEN 一致；未配置时拒绝写入）
 *  - 一次性 nonce：GET 签发、POST 校验即销毁，防重放
 *  - Origin / Referer 白名单，拦截跨站伪造
 *  - 字段白名单 + URL 格式校验；安全开关（CORS/敏感词/强制HTTPS/封禁名单）禁止经此接口改写
 *  - 统一安全响应头
 */

const CONFIG_KEY = "server_config";
const NONCE_KEY = "cfg_nonce:current";
const NONCE_TTL = 5 * 60;

const DEFAULT_CONFIG = {
  env: "prod",
  api_open_url: "https://utau-4oo.pages.dev",
  api_auth_url: "https://utau-catbox-test.pages.dev/api",
  frontend_domain: "songyuheng800.github.io/utau",
  oauth_authorize: "https://songyuheng800.github.io/utau/openplatform/authorize.html",
  oauth_token: "https://utau-4oo.pages.dev/oauth/token",
  default_redirect: "https://songyuheng800.github.io/utau/login/",
  cors_enabled: true,
  sensitive_check_enabled: true,
  https_force: true,
  banned_accounts: ["豆包老傻子", "妈没"],
};

// 允许写入的字段白名单（安全开关不在其中，禁止经此接口关闭）
const WRITABLE_FIELDS = ["env", "api_open_url", "api_auth_url", "frontend_domain", "default_redirect"];
const ENV_VALUES = ["prod", "dev", "staging"];

const ALLOWED_ORIGINS = [
  "https://songyuheng800.github.io",
  "https://utau-catbox-test.pages.dev",
  "https://utau-4oo.pages.dev",
];

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
};

function originAllowed(request) {
  const origin = request.headers.get("Origin") || "";
  if (origin) return ALLOWED_ORIGINS.includes(origin);
  const ref = request.headers.get("Referer") || "";
  if (!ref) return false;
  try { return ALLOWED_ORIGINS.includes(new URL(ref).origin); } catch (e) { return false; }
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch (e) { return false; }
}

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors() });
  }

  // GET - 读取配置（公开只读），并签发一次性 nonce
  if (request.method === "GET") {
    if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);
    const raw = await kv.get(CONFIG_KEY).catch(() => null);
    const config = raw ? JSON.parse(raw) : DEFAULT_CONFIG;

    const nonce = randomHex(24);
    try { await kv.put(NONCE_KEY, nonce, { expirationTtl: NONCE_TTL }); } catch (e) { /* 忽略 */ }

    return json({ ok: true, config, nonce });
  }

  // POST - 保存配置
  if (request.method === "POST") {
    return handleSave(request, env, kv);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

async function handleSave(request, env, kv) {
  if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);

  // CSRF：跨站伪造的保存请求会被 Origin/Referer 白名单拦截
  if (!originAllowed(request)) {
    return json({ ok: false, msg: "非法来源，拒绝保存" }, 403);
  }

  const body = await request.json().catch(() => null);
  if (!body) return json({ ok: false, msg: "请求体必须是 JSON" }, 400);

  // 1) 管理员令牌鉴权（未在环境变量配置 ADMIN_CONFIG_TOKEN 时，默认拒绝写入）
  const adminToken = String(body.admin_token || "");
  const expected = env.ADMIN_CONFIG_TOKEN || "";
  if (!expected) {
    return json({ ok: false, msg: "服务端未配置 ADMIN_CONFIG_TOKEN，配置写入已禁用" }, 503);
  }
  if (adminToken !== expected) {
    return json({ ok: false, msg: "管理员令牌无效，拒绝保存" }, 403);
  }

  // 2) 一次性 nonce 校验（TOCTOU 缓解：先读取并立即销毁，再比对值，压缩并发复用窗口）
  const nonce = String(body.nonce || "");
  const savedNonce = await kv.get(NONCE_KEY).catch(() => null);
  await kv.delete(NONCE_KEY).catch(() => {});
  if (!nonce || savedNonce !== nonce) {
    return json({ ok: false, msg: "配置凭证失效，请重新加载页面后再保存" }, 403);
  }

  // 3) 字段白名单 + 格式校验
  const raw = await kv.get(CONFIG_KEY).catch(() => null);
  const current = raw ? JSON.parse(raw) : DEFAULT_CONFIG;
  const merged = { ...current };

  for (const field of WRITABLE_FIELDS) {
    if (!(field in body)) continue;
    const val = String(body[field] || "").trim();
    if (field === "env") {
      if (!ENV_VALUES.includes(val)) return json({ ok: false, msg: "环境取值非法（prod/dev/staging）" }, 400);
      merged[field] = val;
    } else if (field === "frontend_domain") {
      // 域名/路径片段，非完整 URL：只允许安全字符，长度上限
      if (val.length > 200 || !/^[\w.\-/:\[\]]+$/.test(val)) {
        return json({ ok: false, msg: "前端域名格式非法" }, 400);
      }
      merged[field] = val;
    } else {
      if (!safeUrl(val)) return json({ ok: false, msg: field + " 必须是合法的 http/https 地址" }, 400);
      merged[field] = val;
    }
  }

  await kv.put(CONFIG_KEY, JSON.stringify(merged));
  return json({ ok: true, msg: "配置已保存", config: merged });
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
    ...SECURITY_HEADERS,
  };
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors(), "Content-Type": "application/json; charset=utf-8" },
  });
}
