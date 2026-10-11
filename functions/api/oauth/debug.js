/**
 * 临时调试端点：检查运行时环境变量是否存在（不输出值）
 * GET /api/oauth/debug
 */
export async function onRequest(context) {
  const { env } = context;
  const keys = [
    "AUTH_KV",
    "GH_OAUTH_CLIENT_ID", "GH_OAUTH_CLIENT_SECRET",
    "GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET",
    "DISCORD_OAUTH_CLIENT_ID", "DISCORD_OAUTH_CLIENT_SECRET",
    "GITEE_OAUTH_CLIENT_ID", "GITEE_OAUTH_CLIENT_SECRET",
    "MS_OAUTH_CLIENT_ID", "MS_OAUTH_CLIENT_SECRET",
    "TWITCH_OAUTH_CLIENT_ID", "TWITCH_OAUTH_CLIENT_SECRET",
    "GITLAB_OAUTH_CLIENT_ID", "GITLAB_OAUTH_CLIENT_SECRET",
  ];
  const out = {};
  for (const k of keys) {
    out[k] = env[k] ? "present" : "MISSING";
  }
  return new Response(JSON.stringify(out, null, 2), {
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
