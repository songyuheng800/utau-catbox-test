/**
 * Microsoft 账号 OAuth 回调
 * GET /api/oauth/microsoft/callback?code=...&state=...
 * 用 id_token（JWT）解析用户信息：name / email / sub
 */
const FRONT_ORIGIN = "https://songyuheng800.github.io";
const SESSION_TTL = 7 * 24 * 3600;

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;
  const CLIENT_ID = env.MS_OAUTH_CLIENT_ID;
  const CLIENT_SECRET = env.MS_OAUTH_CLIENT_SECRET;
  const REDIRECT_URI = "https://utau-catbox-test.pages.dev/api/oauth/microsoft/callback";

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
    tokenResp = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        scope: "openid email profile",
      }),
    });
  } catch (e) {
    return fail("换取 token 失败：" + e.message);
  }
  const tokenData = await tokenResp.json();
  if (!tokenData.id_token) {
    return fail("Microsoft 拒绝授权：" + (tokenData.error_description || tokenData.error || "未知错误"));
  }

  const claims = decodeJwt(tokenData.id_token);
  if (!claims || !claims.sub) return fail("id_token 解析失败");

  const session = {
    provider: "microsoft",
    ms_id: String(claims.sub || ""),
    name: claims.name || "",
    email: claims.email || claims.preferred_username || "",
    avatar: "",
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
    headers: {
        Location: `${FRONT_ORIGIN}/utau/login/?ok=1`,
        "Set-Cookie": cookie,
        "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      },
  });
}

function decodeJwt(jwt) {
  try {
    const part = jwt.split(".")[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    return null;
  }
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}
