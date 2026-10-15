/**
 * 账号密码登录（自建账号体系）
 * POST /api/auth/login  {username, password}
 * PBKDF2 校验密码，签发会话
 */
const SESSION_TTL = 7 * 24 * 3600;

// 封禁账号黑名单（用户名小写）
const BANNED = ["豆包老傻子", "妈没"];

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors() });
  }
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);
  if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);

  const body = await request.json().catch(() => null);
  if (!body) return json({ ok: false, msg: "请求体必须是 JSON" }, 400);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!username || !password) return json({ ok: false, msg: "请填写用户名和密码" }, 400);

  const key = "pwd_user:" + username.toLowerCase();
  const raw = await kv.get(key).catch(() => null);
  if (!raw) return json({ ok: false, msg: "用户名或密码错误" }, 401);

  const user = JSON.parse(raw);
  const hash = await pbkdf2(password, user.salt);
  if (hash !== user.hash) return json({ ok: false, msg: "用户名或密码错误" }, 401);

  // 封禁检查
  if (BANNED.includes(user.name.toLowerCase())) {
    return json({ ok: false, msg: "此账号已被封禁" }, 403);
  }

  const token = randomHex(32);
  const session = { provider: "password", username: user.name, name: user.name, created_at: Date.now() };
  await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });

  return json({ ok: true, msg: "登录成功", user: session }, 200, {
    "Set-Cookie": `utau_session=${token}; Path=/; Max-Age=${SESSION_TTL}; Secure; HttpOnly; SameSite=None`,
  });
}

async function pbkdf2(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "https://songyuheng800.github.io",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors(), "Content-Type": "application/json; charset=utf-8", ...(extra || {}) },
  });
}
