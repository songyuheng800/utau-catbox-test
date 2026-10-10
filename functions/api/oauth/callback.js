/**
 * GitHub OAuth 回调
 * GET /api/oauth/callback?code=...&state=...
 * 1. 校验 state（KV 一次性）
 * 2. 用 code 换 access_token
 * 3. 拉取 GitHub 用户信息
 * 4. 签发会话 cookie（存 KV，7 天），302 跳回登录页
 */
const FRONT_ORIGIN = "https://songyuheng800.github.io";
const SESSION_TTL = 7 * 24 * 3600;

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;
  const CLIENT_ID = env.GH_OAUTH_CLIENT_ID;
  const CLIENT_SECRET = env.GH_OAUTH_CLIENT_SECRET;
  const REDIRECT_URI = "https://utau-catbox-test.pages.dev/api/oauth/callback";

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const fail = (why) => Response.redirect(`${FRONT_ORIGIN}/utau/login/?err=${encodeURIComponent(why)}`, 302);

  if (!code || !state) return fail("缺少 code 或 state");
  if (!kv || !CLIENT_ID || !CLIENT_SECRET) return fail("服务未配置");

  try {
    const saved = await kv.get("oauth_state:" + state);
    if (saved === null) return fail("state 校验失败");
    await kv.delete("oauth_state:" + state);
  } catch (e) {
    return fail("state 校验异常");
  }

  let tokenResp;
  try {
    tokenResp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "utau-login" },
      body: JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code, redirect_uri: REDIRECT_URI }),
    });
  } catch (e) {
    return fail("换取 token 失败：" + e.message);
  }
  const tokenData = await tokenResp.json();
  if (!tokenData.access_token) {
    return fail("GitHub 拒绝授权：" + (tokenData.error_description || tokenData.error || "未知错误"));
  }

  let userResp;
  try {
    userResp = await fetch("https://api.github.com/user", {
      headers: { Authorization: "Bearer " + tokenData.access_token, "User-Agent": "utau-login", "Accept": "application/vnd.github+json" },
    });
  } catch (e) {
    return fail("获取用户信息失败：" + e.message);
  }
  if (userResp.status !== 200) return fail("GitHub 用户接口异常 " + userResp.status);
  const user = await userResp.json();

  const session = {
    gh_login: user.login,
    gh_id: user.id,
    name: user.name || user.login,
    avatar: user.avatar_url || "",
    created_at: Date.now(),
  };

  const token = randomHex(32);
  try {
    await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });
  } catch (e) {
    return fail("会话写入失败");
  }

  const cookie = `utau_session=${token}; Path=/; Max-Age=${SESSION_TTL}; Secure; HttpOnly; SameSite=None`;
  return new Response(null, {
    status: 302,
    headers: { Location: `${FRONT_ORIGIN}/utau/login/?ok=1`, "Set-Cookie": cookie },
  });
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}
