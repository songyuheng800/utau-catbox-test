/**
 * POST /api/shards/finalize
 * 对账：逐片回 D1 校验存在性与 hash；齐全则把 pending 转正为正式文件索引，
 * 写标签反向索引，删除 pending。缺失分片直接报错（孤立分片由垃圾回收清理）。
 *
 * body: { fileId }
 */
import {
  json, originAllowed, shardKv, pickDb, pendingKey, idxKey, tagKey, validFileId, normTag,
} from "./_lib.js";

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: json({}).headers });
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);
  if (!originAllowed(request)) return json({ ok: false, msg: "非法来源" }, 403);

  const kv = shardKv(env);
  if (!kv) return json({ ok: false, msg: "分片 KV 未绑定" }, 500);

  const body = await request.json().catch(() => null);
  const fileId = String(body?.fileId || "");
  if (!validFileId(fileId)) return json({ ok: false, msg: "fileId 非法" }, 400);

  const pendingRaw = await kv.get(pendingKey(fileId));
  if (!pendingRaw) return json({ ok: false, msg: "上传会话不存在或已过期" }, 404);
  let pending;
  try { pending = JSON.parse(pendingRaw); } catch (e) { return json({ ok: false, msg: "会话数据损坏" }, 500); }

  // 逐片对账
  const chunks = [];
  const missing = [];
  for (let i = 0; i < pending.chunkCount; i++) {
    const chunkId = `${fileId}#${i}`;
    let db;
    try { db = pickDb(env, chunkId); } catch (e) { return json({ ok: false, msg: "D1 分片池未配置（SHARD_D1S）" }, 500); }
    const row = await db.prepare("SELECT hash, size FROM chunks WHERE chunk_id = ?").bind(chunkId).first();
    if (!row) { missing.push(i); continue; }
    if (pending.expectedHashes && pending.expectedHashes[i] && row.hash !== pending.expectedHashes[i]) {
      return json({ ok: false, msg: `分片 ${i} 校验不一致` }, 400);
    }
    chunks.push({ index: i, chunk_id: chunkId, size: row.size, hash: row.hash });
  }
  if (missing.length) {
    return json({ ok: false, msg: "分片不完整，缺少序号：" + missing.join(","), missing }, 409);
  }

  const finalized = {
    fileId,
    name: pending.name,
    mime: pending.mime,
    totalSize: pending.totalSize,
    sha256: pending.sha256,
    chunks,
    tags: pending.tags || [],
    uploader: pending.uploader,
    createdAt: pending.createdAt,
    finalizedAt: Date.now(),
  };

  // 转正索引（长期保存，不设短 TTL）
  await kv.put(idxKey(fileId), JSON.stringify(finalized));

  // 标签反向索引：去重追加 fileId
  for (const tag of finalized.tags.map(normTag).filter(Boolean)) {
    const raw = await kv.get(tagKey(tag));
    let list = [];
    try { list = raw ? JSON.parse(raw) : []; } catch (e) { list = []; }
    if (!list.includes(fileId)) {
      list.push(fileId);
      await kv.put(tagKey(tag), JSON.stringify(list));
    }
  }

  await kv.delete(pendingKey(fileId));
  return json({ ok: true, fileId, chunks: chunks.length, name: finalized.name });
}
