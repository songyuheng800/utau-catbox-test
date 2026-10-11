/**
 * 查询已启用的登录方式
 * GET /api/oauth/providers
 * github / password 永远启用；google / discord / gitlab 取决于是否配置了 Client ID
 */
export async function onRequest(context) {
  const { env } = context;
  const providers = ["github", "password"];
  if (env.GOOGLE_OAUTH_CLIENT_ID) providers.push("google");
  if (env.DISCORD_OAUTH_CLIENT_ID) providers.push("discord");
  if (env.GITLAB_OAUTH_CLIENT_ID) providers.push("gitlab");

  const cors = {
    "Access-Control-Allow-Origin": "https://songyuheng800.github.io",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Vary": "Origin",
  };
  if (context.request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }
  return new Response(JSON.stringify({ ok: true, providers }), {
    headers: { ...cors, "Content-Type": "application/json; charset=utf-8" },
  });
}
