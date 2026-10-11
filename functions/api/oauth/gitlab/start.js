/**
 * 发起 GitLab OAuth 授权
 * GET /api/oauth/gitlab/start
 */
export async function onRequest(context) {
  const { env } = context;
  const kv = env.AUTH_KV;
  const CLIENT_ID = env.GITLAB_OAUTH_CLIENT_ID;
  const REDIRECT_URI = "https://utau-catbox-test.pages.dev/api/oauth/gitlab/callback";

  if (!kv || !CLIENT_ID) {
    return new Response("服务未配置（缺 GITLAB_OAUTH_CLIENT_ID 或 KV）", { status: 500 });
  }

  const state = randomHex(32);
  try {
    await kv.put("oauth_state:" + state, "1", { expirationTtl: 300 });
  } catch (e) {}

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "read_user",
    state,
  });
  return Response.redirect("https://gitlab.com/oauth/authorize?" + params.toString(), 302);
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}
