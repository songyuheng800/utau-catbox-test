/**
 * GET /api/shards/list?tag=xxx[&uploader=yyy]
 * KV 不支持全量扫描，列表以标签反向索引为入口；返回元信息（不含文件内容）。
 */
import { json, shardKv, idxKey, tagKey, normTag } from "./_lib.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "GET") return json({ ok: false, msg: "方法错误" }, 405);

  const kv = shardKv(env);
  if (!kv) return json({ ok: false, msg: "分片 KV 未绑定" }, 500);

  const url = new URL(request.url);
  const tag = normTag(url.searchParams.get("tag") || "");
  const uploader = String(url.searchParams.get("uploader") || "").trim();
  if (!tag) return json({ ok: false, msg: "请提供 tag 参数（KV 不支持全量枚举）" }, 400);

  const tRaw = await kv.get(tagKey(tag));
  let fileIds = [];
  try { fileIds = tRaw ? JSON.parse(tRaw) : []; } catch (e) { fileIds = []; }

  const items = [];
  for (const fid of fileIds) {
    const raw = await kv.get(idxKey(fid));
    if (!raw) continue;
    let m;
    try { m = JSON.parse(raw); } catch (e) { continue; }
    if (uploader && m.uploader !== uploader) continue;
    items.push({
      fileId: m.fileId,
      name: m.name,
      mime: m.mime,
      totalSize: m.totalSize,
      sha256: m.sha256,
      tags: m.tags || [],
      uploader: m.uploader,
      createdAt: m.createdAt,
    });
  }

  return json({ ok: true, tag, count: items.length, files: items });
}
