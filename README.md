# NodeLoc 邀请码自动发放

Cloudflare Workers + TypeScript + D1/KV 的申请系统。申请文字至少 100 个 Unicode 字符，经过 OpenAI 兼容接口审核后，通过 NodeLoc 的 Discourse `POST /invites` 创建一个单次使用、24 小时有效的邀请码。

## 部署

1. `npm install`
2. 创建 D1：`npx wrangler d1 create nodeloc-invite-auto`，将返回的 ID 填入 `wrangler.jsonc`。
3. 创建 KV：`npx wrangler kv namespace create RATE_LIMIT`，将 ID 填入配置。
4. 初始化数据库：`npx wrangler d1 execute nodeloc-invite-auto --remote --file=schema.sql`
5. 逐项设置秘密：`NODELOC_COOKIE`、`NODELOC_CSRF_TOKEN`、`AI_API_URL`、`AI_API_KEY`、`AI_MODEL`、`HASH_SALT`。命令：`npx wrangler secret put NAME`。
6. 推荐在 Cloudflare Turnstile 创建小组件，设置 `TURNSTILE_SECRET`，并将 site key 填入 `wrangler.jsonc` 的 `vars.TURNSTILE_SITE_KEY`。未配置时仍有 IP、设备指纹和 D1 限制，但无法有效阻挡自动化脚本。
7. `npm run deploy`

Cookie 更新只需重新执行 `npx wrangler secret put NODELOC_COOKIE`；CSRF Token 失效时同样更新 `NODELOC_CSRF_TOKEN`。

## 限制设计

- IP 和浏览器指纹均独立限制：任一命中当天锁或永久成功锁都会拒绝。
- 在 AI 审核前先写入当天锁，所以失败、拒绝与上游错误都算一次。
- D1 是最终一致性与审计来源；KV 用于快速拦截。数据只保存加盐 SHA-256 哈希，不保存原始 IP/指纹。
- 成功后写入两项永久锁；邀请码不会保存在日志或页面以外的明文数据库字段。
