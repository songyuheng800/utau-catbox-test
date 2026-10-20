# 分片存储（多 D1 池 + KV 索引）部署说明

大文件按 900KB 切片存入多个 D1 的 BLOB，KV 存文件主索引与标签反向索引，下载时后端按序流式组装。代码已按"哈希选库"写成可横向扩展的池结构。

## 一、端点（前缀 `/api/shards`）

| 方法 | 路径 | 作用 |
|---|---|---|
| POST | `/init` | 登记元信息，返回 `fileId`，写 5 分钟 pending |
| POST | `/chunk` | 单片 base64 落 D1（幂等，可重试） |
| POST | `/finalize` | 逐片对账，齐全后转正索引 + 写标签 |
| GET | `/file?fileId=` | 流式组装下载（不全量进内存） |
| POST/DELETE | `/delete?fileId=` | 删分片 + 索引 + 标签条目（body 也可传 `{fileId}`） |
| GET | `/list?tag=xx` | 按标签查元信息（KV 不能全量枚举） |

前端测试页：`utau-front/shards/index.html`。

## 二、Cloudflare 后台配置（已完成，账号 2593657999@qq.com）

> 说明：**D1/KV 没有独立"访问 Token"**，它们是在你账户里建库后绑定到 Pages 项目的环境变量，代码用 `env.绑定名` 访问，不存在可下发的密钥。

### 已完成的绑定（Pages 项目 utau-catbox-test → Settings → Bindings）

| 绑定类型 | 变量名 | 实际资源 |
|---|---|---|
| KV namespace | `AUTH_KV` | `UTAU_AUTH`（分片索引回退用它，未单独建 SHARD_KV） |
| D1 database | `DB0` | `shard-db-00` |
| D1 database | `DB1` | `shard-db-01` |
| D1 database | `DB2` | `shard-db-02` |
| D1 database | `DB3` | `shard-db-03` |
| D1 database | `DB4` | `shard-db-04` |
| D1 database | `DB5` | `shard-db-05` |
| D1 database | `DB6` | `shard-db-06` |
| D1 database | `DB7` | `shard-db-07` |
| D1 database | `DB8` | `shard-db-08` |
| D1 database | `DB9` | `shard-db-09` |

- 10 个库均已执行 `shards_schema.sql`，`chunks` 表结构核对通过。
- 环境变量 `SHARD_D1S = DB0,DB1,DB2,DB3,DB4,DB5,DB6,DB7,DB8,DB9` 已保存。
- 代码按 `chunk_id` 的 FNV-1a 哈希从这个池里选库；池里列几个就用几个，同项目加库只需往这个字符串追加绑定名（单项目硬上限 10 个）。

> 备注：本项目无 `wrangler.toml`，由 Pages git 自动部署 + dashboard 绑定为准；不要在控制台引入 wrangler 管理以免覆盖上述绑定。

## 三、横向扩到更多库（200 的现实路径）

- **单 Pages 项目硬上限 10 个 D1 绑定**，一个项目放不下 200 个。
- 扩法：每 10 个库建一个"分片节点项目"（node-00 绑 DB0–DB9，node-01 绑 DB10–DB19…），由调度层按 `fileId` 哈希把请求转发到对应节点。当前 `_lib.js` 的 `pickDb()` 是项目内选库，跨项目的 `resolveNode()` 留作替换点，业务端点不用改。
- 200 个 D1 意味着 20 个项目；且免费额度（每库 100k 读/天、10k 写/天）会被均摊，需评估是否付费。

## 四、存储与限制

- 单片 900KB，D1 单行 BLOB ≤1MB；单文件上限前端设 2GB（受 Functions 超时/内存约束，实际建议 ≤100–200MB）。
- 跨 D1 无全局事务：上传中途失败会留孤立分片，需定时垃圾回收（扫 pending 超时、对账删除无主 chunk）。
- 一次性凭证/会话仍留在 KV，D1 只放文件分片与业务索引。

## 五、安全

- 写操作（init/chunk/finalize/delete）已做 Origin/Referer 白名单、安全响应头；下载为 GET 直链。
- `fileId` 字符白名单校验，防 key 注入；文件名只用于响应头，不进 SQL 拼接（全部 bind 参数）。
