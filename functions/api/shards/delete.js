/**
 * DELETE /api/shards/file?fileId=xxx  （也支持 body {fileId}）
 * 清理：删除各 D1 分片、正式索引、标签反向索引中的条目、残留 pending。
 */
import {
  json, originAllowed, shardKv, pickDb, idxKey, pendingKey, tagKey, validFileId, normTag,
} from "./_lib.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: json({}).headers });
  if (request.method !== "DELETE" && request.method !== "POST") {
    return json({ ok: false, msg: "方法错误" }, 405);
  }
  if (!originAllowed(request)) return json({ ok: false, msg: "非法来源" }, 403);

  const kv = shardKv(env);
  if (!kv) return json({ ok: false, msg: "分片 KV 未绑定" }, 500);

  let fileId = new URL(request.url).searchParams.get("fileId") || "";
  if (!fileId && request.method === "POST") {
    const b = await request.json().catch(() => null);
    fileId = String(b?.fileId || "");
  }
  if (!validFileId(fileId)) return json({ ok: false, msg: "fileId 非法" }, 400);

  const raw = await kv.get(idxKey(fileId));
  if (!raw) {
    // 索引已不在，仅清残留 pending
    await kv.delete(pendingKey(fileId));
    return json({ ok: true, msg: "文件不存在，已清理残留" });
  }
  let meta;
  try { meta = JSON.parse(raw); } catch (e) { return json({ ok: false, msg: "索引损坏" }, 500); }

  // 1) 删除各 D1 分片
  let deleted = 0;
  for (const c of meta.chunks || []) {
    try {
      const db = pickDb(env, c.chunk_id);
      await db.prepare("DELETE FROM chunks WHERE chunk_id = ?").bind(c.chunk_id).run();
      deleted++;
    } catch (e) { /* 单片失败不阻断其余清理 */ }
  }

  // 2) 从标签反向索引移除
  for (const tag of (meta.tags || []).map(normTag).filter(Boolean)) {
    const tRaw = await kv.get(tagKey(tag));
    if (!tRaw) continue;
    let list = [];
    try { list = JSON.parse(tRaw); } catch (e) { list = []; }
    list = list.filter((x) => x !== fileId);
    if (list.length) await kv.put(tagKey(tag), JSON.stringify(list));
    else await kv.delete(tagKey(tag));
  }

  // 3) 删正式索引与残留 pending
  await kv.delete(idxKey(fileId));
  await kv.delete(pendingKey(fileId));

  return json({ ok: true, msg: "已删除", chunksDeleted: deleted });
}
