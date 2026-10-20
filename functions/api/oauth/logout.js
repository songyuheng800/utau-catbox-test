/**
 * 退出登录
 *   POST /api/oauth/logout  （推荐，前端 fetch 调用，防 GET-CSRF 强制登出）
 *   GET  /api/oauth/logout  （兼容旧链接，但必须通过 Origin/Referer 校验）
 * 删除 KV 会话 + 清 cookie，302 回登录页
 */
const FRONT_ORIGIN = "https://songyuheng800.github.io";

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
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
};

function originAllowed(request) {
  const origin = request.headers.get("Origin") || "";
  if (origin) return ALLOWED_ORIGINS.includes(origin);
  const ref = request.headers.get("Referer") || "";
  if (!ref) return false;
  try { return ALLOWED_ORIGINS.includes(new URL(ref).origin); } catch (e) { return false; }
}

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  // 写操作（含登出）一律校验来源，拦截跨站触发
  if (!originAllowed(request)) {
    return new Response(null, {
      status: 403,
      headers: { ...SECURITY_HEADERS, "Content-Type": "application/json" },
    });
  }

  const cookie = parseCookie(request.headers.get("Cookie") || "");
  const token = cookie.utau_session;
  if (token && kv) {
    try { await kv.delete("session:" + token); } catch (e) {}
  }

  const clear = "utau_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=None";
  return new Response(null, {
    status: 302,
    headers: {
      ...SECURITY_HEADERS,
      Location: `${FRONT_ORIGIN}/utau/login/?logout=1`,
      "Set-Cookie": clear,
    },
  });
}

function parseCookie(str) {
  const out = {};
  for (const part of str.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
