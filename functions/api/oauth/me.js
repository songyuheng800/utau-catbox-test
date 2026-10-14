/**
 * 查询当前登录态
 * GET /api/oauth/me
 * 读 cookie utau_session → KV 查会话 → 返回用户信息（跨域 CORS，支持 credentials）
 */
const ALLOWED = ["https://songyuheng800.github.io", "https://utau-4oo.pages.dev"];

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  const origin = request.headers.get("Origin") || "";
  const allowOrigin = ALLOWED.includes(origin) ? origin : ALLOWED[0];
  const cors = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== "GET") {
    return json({ ok: false, msg: "方法错误" }, 405, cors);
  }

  if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500, cors);

  const cookie = parseCookie(request.headers.get("Cookie") || "");
  const token = cookie.utau_session;
  if (!token) return json({ ok: false, logged_in: false }, 200, cors);

  try {
    const raw = await kv.get("session:" + token);
    if (!raw) {
      return json({ ok: false, logged_in: false }, 200, cors);
    }
    const s = JSON.parse(raw);
    return json({ ok: true, logged_in: true, user: s }, 200, cors);
  } catch (e) {
    return json({ ok: false, msg: "会话读取异常" }, 500, cors);
  }
}

function parseCookie(str) {
  const out = {};
  for (const part of str.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });
}
