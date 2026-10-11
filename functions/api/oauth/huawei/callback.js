/**
 * 华为账号 OAuth 回调（OIDC）
 * GET /api/oauth/huawei/callback?code=...&state=...
 */
const FRONT_ORIGIN = "https://songyuheng800.github.io";
const SESSION_TTL = 7 * 24 * 3600;

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;
  const CLIENT_ID = env.HUAWEI_OAUTH_CLIENT_ID;
  const CLIENT_SECRET = env.HUAWEI_OAUTH_CLIENT_SECRET;
  const REDIRECT_URI = "https://utau-catbox-test.pages.dev/api/oauth/huawei/callback";

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
    tokenResp = await fetch("https://oauth-login.cloud.huawei.com/oauth2/v3/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      }),
    });
  } catch (e) {
    return fail("换取 token 失败：" + e.message);
  }
  const tokenData = await tokenResp.json();
  if (!tokenData.access_token) {
    return fail("华为拒绝授权：" + (tokenData.error_description || tokenData.error || "未知错误"));
  }

  let userResp;
  try {
    userResp = await fetch("https://oauth-login.cloud.huawei.com/oauth2/v3/userinfo", {
      headers: { Authorization: "Bearer " + tokenData.access_token, "Accept": "application/json" },
    });
  } catch (e) {
    return fail("获取用户信息失败：" + e.message);
  }
  if (userResp.status !== 200) return fail("华为用户接口异常 " + userResp.status);
  const u = await userResp.json();

  const session = {
    provider: "huawei",
    huawei_id: String(u.sub || u.userID || u.userId || ""),
    name: u.name || u.displayName || "",
    email: u.email || "",
    avatar: u.avatar || "",
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
