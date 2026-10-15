/**
 * 账号密码注册（自建账号体系）
 * POST /api/auth/register  {username, password}
 * 密码 PBKDF2 加盐哈希存 KV；注册成功直接签发会话
 */
const SESSION_TTL = 7 * 24 * 3600;

// 封禁账号黑名单（防止重新注册）
const BANNED = ["豆包老傻子"];

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

  // 敏感词检测 v3：大词库 + 正则模式
  const lower = username.toLowerCase();
  const BLOCKED = ["傻逼","傻子","sb","草泥马","操你妈","他妈","你妈","操你","草你","狗日",
    "王八蛋","脑残","智障","去死","废物","垃圾","贱","婊子","贱人","骚货",
    "妈逼","妈了","妈没","妈死","妈蛋","妈卖批","草泥","日你","干你",
    "尼玛","泥马","煞笔","沙比","鸡巴","鸡吧","几把","jiba","jb","屌","鸡鸡",
    "fuck","shit","bitch","asshole","cunt","damn","bastard",
    "滚","去死","弄死","杀了你"];
  for (const w of BLOCKED) {
    if (lower.includes(w)) {
      return json({ ok: false, msg: "用户名包含不文明词汇，请换一个" }, 400);
    }
  }
  // 正则模式检测
  const PATTERNS = [
    /妈[没死蛋逼了卖操了个批的]/,
    /[操草日干靠][你他她妈娘姐妹哥弟爸]/,
    /傻[子逼b13x屄了]/,
    /[草操][泥你][马妈]/,
    /鸡[巴吧逼吧叭]/,
    /狗[日娘东西]/,
    /s\s*b/i, /cnm/i, /tmd/i,
  ];
  for (const re of PATTERNS) {
    if (re.test(username)) {
      return json({ ok: false, msg: "用户名包含不文明词汇，请换一个" }, 400);
    }
  }

  // 封禁用户名检测
  if (BANNED.includes(lower)) {
    return json({ ok: false, msg: "该用户名已被封禁" }, 403);
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
