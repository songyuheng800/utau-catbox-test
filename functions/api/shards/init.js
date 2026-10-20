/**
 * POST /api/shards/init
 * 登记一个待上传文件的元信息，生成 fileId，写 pending 索引。
 * 之后前端逐片调 /api/shards/chunk，最后调 /api/shards/finalize 转正。
 *
 * body: { name, mime, totalSize, sha256, chunkCount, tags:[], uploader }
 */
import { json, originAllowed, shardKv, pendingKey, normTag, CHUNK_SIZE } from "./_lib.js";

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: json({}).headers });
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);
  if (!originAllowed(request)) return json({ ok: false, msg: "非法来源" }, 403);

  const kv = shardKv(env);
  if (!kv) return json({ ok: false, msg: "分片 KV 未绑定" }, 500);

  const body = await request.json().catch(() => null);
  if (!body) return json({ ok: false, msg: "请求体必须是 JSON" }, 400);

  const name = String(body.name || "").trim().slice(0, 200);
  const mime = String(body.mime || "application/octet-stream").slice(0, 80);
  const totalSize = Number(body.totalSize) || 0;
  const sha256 = String(body.sha256 || "").trim();
  const chunkCount = Number(body.chunkCount) || 0;
  const uploader = String(body.uploader || "anonymous").slice(0, 64);

  if (!name) return json({ ok: false, msg: "缺少文件名" }, 400);
  if (totalSize <= 0 || totalSize > 2 * 1024 * 1024 * 1024) {
    return json({ ok: false, msg: "文件大小非法（上限 2GB）" }, 400);
  }
  if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > 4096) {
    return json({ ok: false, msg: "分片数非法（1-4096）" }, 400);
  }
  if (sha256 && !/^[a-f0-9]{64}$/i.test(sha256)) {
    return json({ ok: false, msg: "sha256 格式非法" }, 400);
  }

  const tags = Array.isArray(body.tags) ? body.tags.map(normTag).filter(Boolean).slice(0, 12) : [];

  // fileId：UUID 去横线，合法字符
  const fileId = crypto.randomUUID().replace(/-/g, "");

  const pending = {
    status: "pending",
    fileId,
    name,
    mime,
    totalSize,
    sha256,
    chunkCount,
    tags,
    uploader,
    createdAt: Date.now(),
  };
  // pending 5 分钟有效，超时未 finalize 由垃圾回收清理
  await kv.put(pendingKey(fileId), JSON.stringify(pending), { expirationTtl: 300 });

  return json({ ok: true, fileId, chunkSize: CHUNK_SIZE, chunkCount });
}
