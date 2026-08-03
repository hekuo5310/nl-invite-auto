# NodeLoc 邀请码自动发放

Cloudflare Workers + TypeScript + D1/KV 的申请系统。Worker 每天北京时间 08:00 通过 NodeLoc 创建 3 张单次使用、有效至 9999-12-31 的邀请码，存入 D1 邀请码池；申请文字经 OpenAI 兼容接口审核后，按邀请码最早入池的顺序发放。

## 部署

1. `npm install`
2. 创建 D1：`npx wrangler d1 create nodeloc-invite-auto`，将返回的 ID 填入 `wrangler.jsonc`。
3. 创建 KV：`npx wrangler kv namespace create RATE_LIMIT`，将 ID 填入配置。
4. 初始化数据库：`npx wrangler d1 execute nodeloc-invite-auto --remote --file=schema.sql`
5. 按下文“配置 Secrets”逐项设置秘密。
6. 推荐在 Cloudflare Turnstile 创建小组件，设置 `TURNSTILE_SECRET`，并将 site key 填入 `wrangler.jsonc` 的 `vars.TURNSTILE_SITE_KEY`。未配置时仍有 IP、设备指纹和 D1 限制，但无法有效阻挡自动化脚本。
7. `npm run deploy`

> 请在本地被忽略的 `wrangler.jsonc` 中加入 `"triggers": { "crons": ["0 0 * * *"] }`。Cloudflare Cron 使用 UTC，因此 `0 0 * * *` 即每天北京时间 08:00。

如果 Cron 未执行，可由管理员使用 `POST /internal/backfill-daily-invite` 手动补发。该接口必须设置 `ADMIN_TOKEN` Secret，并在 `Authorization: Bearer <ADMIN_TOKEN>` 中传入；它不会返回邀请码链接。

Cookie 更新只需重新执行 `npx wrangler secret put NODELOC_COOKIE`；CSRF Token 失效时同样更新 `NODELOC_CSRF_TOKEN`。

## 配置 Secrets

所有敏感配置均通过 `wrangler secret put` 写入 Cloudflare，不要写进 `wrangler.jsonc`、`.dev.vars` 或 Git。每条命令会等待输入值；粘贴后回车保存。

```powershell
npx wrangler secret put NODELOC_COOKIE
npx wrangler secret put NODELOC_CSRF_TOKEN
npx wrangler secret put AI_API_URL
npx wrangler secret put AI_API_KEY
npx wrangler secret put AI_MODEL
npx wrangler secret put HASH_SALT
```

### NodeLoc 登录信息

- `NODELOC_COOKIE`：浏览器开发者工具中请求的整个 `Cookie` 请求头，例如 `_t=...; _forum_session=...`。不要只填写其中一个 Cookie。
- `NODELOC_CSRF_TOKEN`：同一已登录请求中的 `X-CSRF-Token` 请求头。Cookie 与 Token 应来自同一个登录会话。
- Cookie 会过期或可被手动注销；更新后重新执行对应的 `wrangler secret put` 即可，不需要重新部署。
- 不要在 Git、截图、公开聊天或 issue 中发送 Cookie / CSRF Token；已经泄露时请退出 NodeLoc 后重新登录以使旧会话失效。

### AI 审核接口

接口必须兼容 OpenAI Chat Completions。`AI_API_URL` 填**完整请求 URL**，系统会直接向它发送 `POST`，不会自动追加路径：

```text
https://api.openai.com/v1/chat/completions
# 或兼容服务：
https://your-ai-provider.example/v1/chat/completions
```

`AI_API_KEY` 是该服务的密钥，`AI_MODEL` 是模型名称。接口响应须遵循 Chat Completions 格式，并在 `choices[0].message.content` 返回 AI 决策。

### HASH_SALT

`HASH_SALT` 是高熵、长期不变的私密随机值。它会与 IP / 浏览器指纹一起做 SHA-256 哈希，数据库只保存哈希而不保存原文。可用 PowerShell 生成：

```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
```

生成后用 `npx wrangler secret put HASH_SALT` 保存。**部署后不要更换它**：更换会让历史哈希无法匹配，导致原有的永久领取限制失效。

### Turnstile（强烈建议）

浏览器指纹可被伪造，若要严格防自动化申请，应启用 Cloudflare Turnstile：

1. 在 Cloudflare 创建一个 Turnstile Widget，并绑定 Worker 的域名。
2. 将 secret key 设为 `TURNSTILE_SECRET`：`npx wrangler secret put TURNSTILE_SECRET`。
3. 将 site key 填入 `wrangler.jsonc` 的 `vars.TURNSTILE_SITE_KEY`，再重新部署。

当设置 `TURNSTILE_SECRET` 后，后端会拒绝没有通过 Turnstile 的申请。site key 是公开配置；secret key 必须保密。

## 限制设计

- IP 和浏览器指纹均独立限制：任一命中当天锁或永久成功锁都会拒绝。
- 在 AI 审核前先写入当天锁以阻止并发申请；AI 审核拒绝算一次。AI 服务异常或 NodeLoc 创建邀请码失败时会释放当天锁，允许稍后重试。
- D1 是最终一致性与审计来源；KV 用于快速拦截。数据只保存加盐 SHA-256 哈希，不保存原始 IP/指纹。
- 成功后写入两项永久锁；邀请码不会保存在日志或页面以外的明文数据库字段。
- 每天预创建 3 张单次邀请码；邀请码池按最早入池优先（FIFO）发放，并以原子条件更新避免并发重复发放。
