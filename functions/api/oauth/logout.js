/**
 * 退出登录
 * GET /api/oauth/logout
 * 删除 KV 会话 + 清 cookie → 302 回登录页
 */
const FRONT_ORIGIN = "https://songyuheng800.github.io";

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  const cookie = parseCookie(request.headers.get("Cookie") || "");
  const token = cookie.utau_session;
  if (token && kv) {
    try { await kv.delete("session:" + token); } catch (e) {}
  }

  const clear = "utau_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=None";
  return new Response(null, {
    status: 302,
    headers: { Location: `${FRONT_ORIGIN}/utau/login/?logout=1`, "Set-Cookie": clear },
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
