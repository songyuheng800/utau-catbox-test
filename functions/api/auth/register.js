/**
 * 账号密码注册（自建账号体系）
 * POST /api/auth/register  {username, password}
 * 密码 PBKDF2 加盐哈希存 KV；注册成功直接签发会话
 */
const SESSION_TTL = 7 * 24 * 3600;

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

  if (username.length < 2 || username.length > 20) {
    return json({ ok: false, msg: "用户名需 2-20 个字符" }, 400);
  }
  if (!/^[\w\u4e00-\u9fa5]+$/.test(username)) {
    return json({ ok: false, msg: "用户名仅限字母、数字、下划线、中文" }, 400);
  }
  if (password.length < 6 || password.length > 64) {
    return json({ ok: false, msg: "密码需 6-64 位" }, 400);
  }

  // 敏感词检测
  const BLOCKED = ["傻子", "傻逼", "sb", "草泥马", "他妈", "你妈", "操你", "狗日", "王八蛋", "脑残", "智障", "去死", "fuck", "shit", "bitch", "asshole", "豆包", "doubao", "字节", "bytedance"];
  const lower = username.toLowerCase();
  for (const w of BLOCKED) {
    if (lower.includes(w)) {
      return json({ ok: false, msg: "用户名包含不文明词汇，请换一个" }, 400);
    }
  }

  const key = "pwd_user:" + username.toLowerCase();
  const exist = await kv.get(key).catch(() => null);
  if (exist) return json({ ok: false, msg: "该用户名已被注册" }, 409);

  const salt = randomHex(16);
  const hash = await pbkdf2(password, salt);

  const user = { salt, hash, name: username, provider: "password", created_at: Date.now() };
  await kv.put(key, JSON.stringify(user));

  // 注册即登录：签发会话
  const token = randomHex(32);
  const session = { provider: "password", username, name: username, created_at: Date.now() };
  await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });

  return json({ ok: true, msg: "注册成功", user: session }, 200, {
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
