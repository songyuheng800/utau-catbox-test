/**
 * 账号密码登录（自建账号体系）
 * POST /api/auth/login  {username, password}
 * PBKDF2 校验密码，签发会话
 *
 * 安全加固：
 *  - Origin / Referer 白名单校验，拦截跨站伪造（CSRF）
 *  - 按 IP 的登录失败限流（5 分钟窗口，超出拒绝），缓解暴力破解
 *  - 统一安全响应头（防点击劫持 / MIME 嗅探 / 降级 / 信息泄露）
 *  - 用户名/密码长度与类型预检，避免异常输入进入哈希计算
 */
const SESSION_TTL = 7 * 24 * 3600;
const RATE_WINDOW = 5 * 60;      // 限流窗口 5 分钟
const RATE_MAX_FAIL = 8;         // 窗口内最大失败次数

// 封禁账号黑名单（用户名小写）
const BANNED = ["豆包老傻子", "妈没"];

// 允许发起写操作的前端来源（Origin 白名单）
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

// 写操作 CSRF 校验：Origin 命中白名单，缺失时回退 Referer 同源校验
function originAllowed(request) {
  const origin = request.headers.get("Origin") || "";
  if (origin) return ALLOWED_ORIGINS.includes(origin);
  const ref = request.headers.get("Referer") || "";
  if (!ref) return false;
  try { return ALLOWED_ORIGINS.includes(new URL(ref).origin); } catch (e) { return false; }
}

function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0].trim() ||
    "unknown"
  );
}

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors() });
  }
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);
  if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);

  // CSRF：跨站伪造的登录请求会被 Origin/Referer 白名单拦截
  if (!originAllowed(request)) {
    return json({ ok: false, msg: "非法来源，拒绝登录" }, 403);
  }

  const body = await request.json().catch(() => null);
  if (!body) return json({ ok: false, msg: "请求体必须是 JSON" }, 400);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  // 输入预检：长度/类型限制，避免异常输入进入后续处理
  if (!username || !password) return json({ ok: false, msg: "请填写用户名和密码" }, 400);
  if (username.length > 32 || password.length > 128) {
    return json({ ok: false, msg: "输入长度超出限制" }, 400);
  }

  // 失败限流：按 IP 计数
  const ip = clientIp(request);
  const failKey = "login_fail:" + ip;
  let fails = 0;
  try {
    const raw = await kv.get(failKey);
    fails = raw ? parseInt(raw, 10) || 0 : 0;
  } catch (e) { /* 限流读取失败不阻断主流程 */ }
  if (fails >= RATE_MAX_FAIL) {
    return json({ ok: false, msg: "尝试次数过多，请 5 分钟后再试" }, 429);
  }

  const key = "pwd_user:" + username.toLowerCase();
  const raw = await kv.get(key).catch(() => null);

  // 用户不存在 / 密码错误走同一分支，统一响应，避免用户名枚举
  let authorized = false;
  let user = null;
  if (raw) {
    try {
      user = JSON.parse(raw);
      const hash = await pbkdf2(password, user.salt);
      authorized = hash === user.hash;
    } catch (e) { authorized = false; }
  }

  if (!authorized) {
    // 记录失败次数，5 分钟窗口
    try {
      await kv.put(failKey, String(fails + 1), { expirationTtl: RATE_WINDOW });
    } catch (e) { /* 忽略写入失败 */ }
    return json({ ok: false, msg: "用户名或密码错误" }, 401);
  }

  // 封禁检查
  if (BANNED.includes(user.name.toLowerCase())) {
    return json({ ok: false, msg: "此账号已被封禁" }, 403);
  }

  // 登录成功：清零失败计数
  try { await kv.delete(failKey); } catch (e) { /* 忽略 */ }

  const token = randomHex(32);
  const session = { provider: "password", username: user.name, name: user.name, created_at: Date.now() };
  await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });

  return json({ ok: true, msg: "登录成功", user: session }, 200, {
    // 前端(github.io)与后端(pages.dev)跨域，需 SameSite=None 才能在 credentials fetch 中携带；CSRF 由 Origin 白名单防护
    "Set-Cookie": `utau_session=${token}; Path=/; Max-Age=${SESSION_TTL}; Secure; HttpOnly; SameSite=None`,
  });
}

async function pbkdf2(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "https://songyuheng800.github.io",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
    ...SECURITY_HEADERS,
  };
}

function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors(), "Content-Type": "application/json; charset=utf-8", ...(extra || {}) },
  });
}
