/**
 * POST /api/shards/chunk
 * 接收单个分片，按 chunk_id 哈希选 D1 库，以 BLOB 落库（INSERT OR REPLACE，幂等可重试）。
 *
 * body: { fileId, index, data(base64), hash(可选, 单片sha256) }
 */
import {
  json, originAllowed, shardKv, pickDb, b64ToBytes, pendingKey, validFileId, CHUNK_SIZE,
} from "./_lib.js";

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: json({}).headers });
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);
  if (!originAllowed(request)) return json({ ok: false, msg: "非法来源" }, 403);

  const kv = shardKv(env);
  const body = await request.json().catch(() => null);
  if (!body) return json({ ok: false, msg: "请求体必须是 JSON" }, 400);

  const fileId = String(body.fileId || "");
  const index = Number(body.index);
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

  // 解码并限长
  let bytes;
  try { bytes = b64ToBytes(body.data || ""); } catch (e) { return json({ ok: false, msg: "分片 data 不是合法 base64" }, 400); }
  if (bytes.length === 0) return json({ ok: false, msg: "分片为空" }, 400);
  if (bytes.length > CHUNK_SIZE) return json({ ok: false, msg: "单片超过 900KB" }, 413);

  const hash = String(body.hash || "").trim();
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
