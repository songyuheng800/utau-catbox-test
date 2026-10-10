/**
 * UTAU 测试站文件上传接口（Gofile 版）
 * POST /api/upload   multipart: fileToUpload=文件
 * GET  /api/upload   返回已上传文件列表（存 KV）
 * DELETE /api/upload?id=xxx  移除本站记录
 *
 * 流程：浏览器 → 本站函数（100MB 上限）→ Gofile 匿名上传 → 拿分享链接 → 记录 KV
 */
const ALLOWED_EXT = ["ust", "ustx", "vsq", "vsqx", "vpr", "pp2", "pp3", "zip", "rar"];
const MAX_SIZE = 100 * 1024 * 1024; // 100MB（Cloudflare 免费版请求体上限）
const LIST_KEY = "gofile_test:list";
const GO_SERVERS = "https://api.gofile.io/servers";

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;

  if (request.method === "GET") return handleList(kv);
  if (request.method === "DELETE") return handleDelete(request, kv);
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);

  let form;
  try {
    form = await request.formData();
  } catch (e) {
    return json({ ok: false, msg: "请求必须是 multipart/form-data" }, 400);
  }

  const file = form.get("fileToUpload");
  if (!file) return json({ ok: false, msg: "缺少文件字段 fileToUpload" }, 400);
  const rawName = String(file.name || "");
  const ext = rawName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return json({ ok: false, msg: "不允许的文件类型：" + (ext || "(无扩展名)") }, 400);
  }
  if (file.size > MAX_SIZE) {
    return json({ ok: false, msg: "文件过大，上限 100 MB（受中转限制）" }, 413);
  }

  // ---------- Gofile 上传 ----------
  // 1. 获取可用服务器
  let srv;
  try {
    const sr = await fetch(GO_SERVERS, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" },
    });
    const sd = await sr.json();
    if (sd.status !== "ok" || !(sd.data && sd.data.servers && sd.data.servers.length)) {
      return json({ ok: false, msg: "Gofile 服务器获取失败" }, 502);
    }
    srv = sd.data.servers[0].name;
  } catch (e) {
    return json({ ok: false, msg: "连接 Gofile 失败：" + e.message }, 502);
  }

  // 2. 上传文件
  let upResp;
  try {
    const fd = new FormData();
    fd.append("file", new Blob([await file.arrayBuffer()], { type: file.type || "application/octet-stream" }), rawName);
    upResp = await fetch(`https://${srv}.gofile.io/contents/uploadfile`, {
      method: "POST",
      body: fd,
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" },
    });
  } catch (e) {
    return json({ ok: false, msg: "上传到 Gofile 失败：" + e.message }, 502);
  }

  let upData;
  try {
    upData = await upResp.json();
  } catch (e) {
    return json({ ok: false, msg: "Gofile 响应解析失败（HTTP " + upResp.status + "）" }, 502);
  }
  if (upData.status !== "ok" || !(upData.data && upData.data.downloadPage)) {
    return json({ ok: false, msg: "Gofile 上传失败：" + JSON.stringify(upData).slice(0, 200) }, 502);
  }

  const fileId = upData.data.fileId || "";
  const downloadPage = upData.data.downloadPage;

  // 3. 记录到 KV（新的在前）
  const record = {
    id: fileId,
    name: rawName,
    size: file.size,
    url: downloadPage,
    time: Date.now(),
  };

  if (kv) {
    try {
      const old = await kv.get(LIST_KEY, "json");
      const list = Array.isArray(old) ? old : [];
      list.unshift(record);
      await kv.put(LIST_KEY, JSON.stringify(list.slice(0, 200)));
    } catch (e) {
      // KV 写入失败不阻塞上传成功
    }
  }

  return json({ ok: true, file: record, msg: "上传成功" }, 200);
}

async function handleList(kv) {
  if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);
  try {
    const list = (await kv.get(LIST_KEY, "json")) || [];
    return json({ ok: true, files: list }, 200);
  } catch (e) {
    return json({ ok: false, msg: "列表读取失败：" + e.message }, 500);
  }
}

async function handleDelete(request, kv) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ ok: false, msg: "缺少 id" }, 400);
  if (!kv) return json({ ok: false, msg: "KV 未绑定" }, 500);
  try {
    const list = (await kv.get(LIST_KEY, "json")) || [];
    const next = list.filter((f) => String(f.id) !== String(id));
    await kv.put(LIST_KEY, JSON.stringify(next));
    return json({ ok: true, msg: "已移除记录（Gofile 匿名文件无法真删）" }, 200);
  } catch (e) {
    return json({ ok: false, msg: "删除失败：" + e.message }, 500);
  }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
