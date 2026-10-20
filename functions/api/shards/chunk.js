/**
 * POST /api/shards/chunk
 * 接收单个分片（multipart/form-data 二进制直传，不经 base64），
 * 按 chunk_id 哈希选 D1 库，以 BLOB 落库（INSERT OR REPLACE，幂等可重试）。
 *
 * formData 字段：
 *   file    分片二进制（Blob）
 *   fileId  初始化返回的文件 ID
 *   index   分片序号
 *   hash    可选，单片 sha256（对账用）
 */
import {
  json, originAllowed, shardKv, pickDb, pendingKey, validFileId, CHUNK_SIZE,
} from "./_lib.js";

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: json({}).headers });
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);
  if (!originAllowed(request)) return json({ ok: false, msg: "非法来源" }, 403);

  const kv = shardKv(env);

  // multipart 二进制直传
  let form;
  try {
    form = await request.formData();
  } catch (e) {
    return json({ ok: false, msg: "请求体必须是 multipart/form-data" }, 400);
  }

  const fileId = String(form.get("fileId") || "");
  const index = Number(form.get("index"));
  if (!validFileId(fileId)) return json({ ok: false, msg: "fileId 非法" }, 400);
  if (!Number.isInteger(index) || index < 0 || index > 4095) {
    return json({ ok: false, msg: "分片序号非法" }, 400);
  }

  // 必须有对应 pending 登记，防止凭空写分片
  const pendingRaw = kv ? await kv.get(pendingKey(fileId)) : null;
  if (!pendingRaw) return json({ ok: false, msg: "上传会话不存在或已过期，请重新 init" }, 404);
  let pending;
  try { pending = JSON.parse(pendingRaw); } catch (e) { return json({ ok: false, msg: "会话数据损坏" }, 500); }
  if (index >= pending.chunkCount) return json({ ok: false, msg: "分片序号超出范围" }, 400);

  // 取分片二进制
  const part = form.get("file");
  if (!part || typeof part.arrayBuffer !== "function") {
    return json({ ok: false, msg: "缺少分片文件字段 file" }, 400);
  }
  const bytes = new Uint8Array(await part.arrayBuffer());
  if (bytes.length === 0) return json({ ok: false, msg: "分片为空" }, 400);
  if (bytes.length > CHUNK_SIZE) return json({ ok: false, msg: "单片超过 900KB" }, 413);

  const hash = String(form.get("hash") || "").trim();
  if (hash && !/^[a-f0-9]{64}$/i.test(hash)) return json({ ok: false, msg: "分片 hash 格式非法" }, 400);

  const chunkId = `${fileId}#${index}`;
  let db;
  try { db = pickDb(env, chunkId); } catch (e) { return json({ ok: false, msg: "D1 分片池未配置（SHARD_D1S）" }, 500); }

  try {
    await db.prepare(
      "INSERT OR REPLACE INTO chunks (chunk_id, data, hash, size) VALUES (?, ?, ?, ?)"
    ).bind(chunkId, bytes, hash, bytes.length).run();
  } catch (e) {
    return json({ ok: false, msg: "分片写入失败：" + (e.message || "D1 error") }, 502);
  }

  return json({ ok: true, stored: chunkId, size: bytes.length });
}
