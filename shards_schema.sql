-- ============================================================
-- 分片存储 D1 建表语句：【每一个绑定的 D1 库都执行一次】本文件
-- 所有库表结构完全相同；chunk_id = `${fileId}#${index}`，全局唯一。
-- 单库 BLOB 单行上限 1MB，分片固定 900KB（见 _lib.js CHUNK_SIZE）。
-- ============================================================

CREATE TABLE IF NOT EXISTS chunks (
  chunk_id   TEXT PRIMARY KEY,          -- `${fileId}#${index}`
  data       BLOB NOT NULL,             -- 分片二进制
  hash       TEXT,                      -- 单片 sha256（可选，对账用）
  size       INTEGER NOT NULL,          -- 分片字节数
  created_at INTEGER DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_chunks_hash ON chunks(hash);

-- 可选：垃圾回收时按时间找孤立分片
CREATE INDEX IF NOT EXISTS idx_chunks_created ON chunks(created_at);
