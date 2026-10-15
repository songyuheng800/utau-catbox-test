/**
 * 服务器配置 API
 * GET /api/server-config  - 读取当前配置
 * POST /api/server-config - 保存配置（需要管理员）
 */

const CONFIG_KEY = "server_config";
const DEFAULT_CONFIG = {
  env: "prod",
  api_open_url: "https://utau-4oo.pages.dev",
  api_auth_url: "https://utau-catbox-test.pages.dev/api",
  frontend_domain: "songyuheng800.github.io/utau",
  oauth_authorize: "https://songyuheng800.github.io/utau/openplatform/authorize.html",
  oauth_token: "https://utau-4oo.pages.dev/oauth/token",
  default_redirect: "https://songyuheng800.github.io/utau/login/",
  cors_enabled: true,
  sensitive_check_enabled: true,
  https_force: true,
  banned_accounts: ["豆包老傻子", "妈没"],
};

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors() });
  }

  // GET - 读取配置
  if (request.method === "GET") {
    if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);
    const raw = await kv.get(CONFIG_KEY).catch(() => null);
    const config = raw ? JSON.parse(raw) : DEFAULT_CONFIG;
    return json({ ok: true, config });
  }

  // POST - 保存配置
  if (request.method === "POST") {
    if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);
    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, msg: "请求体必须是 JSON" }, 400);

    // 合并保存
    const raw = await kv.get(CONFIG_KEY).catch(() => null);
    const current = raw ? JSON.parse(raw) : DEFAULT_CONFIG;
    const merged = { ...current, ...body };

    await kv.put(CONFIG_KEY, JSON.stringify(merged));
    return json({ ok: true, msg: "配置已保存", config: merged });
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors(), "Content-Type": "application/json; charset=utf-8" },
  });
}
