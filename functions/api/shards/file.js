/**
 * GET /api/shards/file?fileId=xxx
 * 读正式索引，按分片顺序从各 D1 取 BLOB，用 ReadableStream 逐片拼接下发，
 * 不全量载入内存（避免大文件 OOM）。
 */
import { json, cors, shardKv, pickDb, idxKey, validFileId } from "./_lib.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "GET") return json({ ok: false, msg: "方法错误" }, 405);

  const kv = shardKv(env);
  if (!kv) return json({ ok: false, msg: "分片 KV 未绑定" }, 500);

  const url = new URL(request.url);
  const fileId = url.searchParams.get("fileId") || "";
  if (!validFileId(fileId)) return json({ ok: false, msg: "fileId 非法" }, 400);

  const raw = await kv.get(idxKey(fileId));
  if (!raw) return json({ ok: false, msg: "文件不存在或已删除" }, 404);
  let meta;
  try { meta = JSON.parse(raw); } catch (e) { return json({ ok: false, msg: "索引损坏" }, 500); }

  const stream = new ReadableStream({
    async start(controller) {
      try {
        for (const c of meta.chunks || []) {
          const db = pickDb(env, c.chunk_id);
          const row = await db.prepare("SELECT data FROM chunks WHERE chunk_id = ?")
            .bind(c.chunk_id).first();
          if (!row || !row.data) throw new Error("分片缺失：" + c.chunk_id);
          controller.enqueue(new Uint8Array(row.data));
        }
        controller.close();
      } catch (e) {
        controller.error(e);
      }
    },
  });

  const safeName = encodeURIComponent(meta.name || fileId);
  return new Response(stream, {
    status: 200,
    headers: {
      ...cors(),
      "Content-Type": meta.mime || "application/octet-stream",
      "Content-Length": String(meta.totalSize || 0),
      "Content-Disposition": `attachment; filename*=UTF-8''${safeName}`,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "private, no-store",
    },
  });
}
