### 通过 Cloudflare Workers 的 TOTP 验证器应用

一个跑在 Cloudflare Workers 上的双因素验证码（TOTP）应用，数据存在 R2，支持自动备份 / 恢复 / 扫码录入。

仓库里有两个可选的入口，**二选一部署**：

| 版本 | 入口文件 | 配置文件 | 特点 |
| --- | --- | --- | --- |
| 个人版 | `workers.js` | `wrangler.jsonc` | 单账号。首次打开网页引导设置用户名 + 主密码 |
| 多人版 | `Multiplayer.js` | `wrangler.multiplayer.jsonc` | 支持开放注册、多用户数据隔离、安全问题找回密码 |

两个版本都只依赖 **一个 R2 绑定，变量名固定为 `DB`**。

---

## 部署方式一：Dashboard 连接 GitHub（推荐，R2 自动创建 + 自动绑定）

这是本仓库默认支持的部署方式，**不需要提前在控制台手工建 R2 存储桶**，也不需要手工配置绑定。

### 原理

Cloudflare 的 Automatic Provisioning 规则：**绑定里不写资源标识，部署时就会自动创建资源并自动绑定。**

本仓库的配置里，R2 绑定写的是：

```jsonc
"r2_buckets": [{ "binding": "DB" }]   // ⚠️ 故意不写 bucket_name
```

因为没写 `bucket_name`，`wrangler deploy` 执行时会：

1. 自动创建一个 R2 存储桶，命名以 `wrangler.jsonc` 里的 `name` 作为前缀；
2. 自动把该桶绑定到 Worker 的环境变量 `DB` 上，与代码里的 `env.DB` 对应。

一旦你手动补上 `"bucket_name": "xxx"`，自动供给就会失效，变成「必须提前手工建桶」。

### 操作步骤

**第 0 步（必做，最常见的部署失败原因）**

> ⚠️ 首次使用 R2 的账号，必须先开通 R2：
> 进入 Cloudflare Dashboard → **R2** 页面，点一次同意条款 / 开通。
> 没开通的话，自动创建 bucket 会直接失败。

**第 1 步：把代码推到 GitHub**

```bash
git init
git add .
git commit -m "init"
git remote add origin <你的仓库地址>
git push -u origin main
```

**第 2 步：在 Dashboard 创建 Worker 并连接仓库**

进入 **Workers & Pages → Create Application → Connect to Git**，选择上面的仓库，然后按下表填写：

| 配置项 | 个人版 | 多人版 |
| --- | --- | --- |
| Project name | `auth-store-personal` | `auth-store-multiplayer` |
| Build command | `npm install` | `npm install` |
| Deploy command | `npx wrangler deploy` | `npx wrangler deploy -c wrangler.multiplayer.jsonc` |

> **Project name 必须与对应配置文件里的 `name` 完全一致**，自动创建出来的资源才会按预期命名。
> 两个版本的 `name` 不同，所以自动创建的是**两套独立的 R2**，数据天然隔离，可以同时部署互不影响。

**第 3 步：点 Deploy**

构建日志里会出现自动创建 R2 的提示。部署完成后，进入 Worker 详情页 → **Settings → Bindings**，能看到名为 `DB` 的 R2 Bucket 绑定已经自动就绪。

**第 4 步：配置人机验证（可选）**

进入 Worker → **Settings → Variables and Secrets**：

| 变量名 | 类型 | 说明 |
| --- | --- | --- |
| `TURNSTILE_SITE_KEY` | Text | Turnstile 站点密钥（公开值） |
| `TURNSTILE_SECRET_KEY` | **Secret** | Turnstile 密钥，必须加密存储 |

配置后**重新部署一次**（改环境变量不会自动生效到已部署版本）。

> 两个都不配置 = 自动回退到无验证码模式（旧版逻辑），不会报错。
> 但注意：**只配了 Site Key 没配 Secret Key 会直接 500**（代码里的 Fail-Secure 检查），
> 所以这两个变量要么都配、要么都不配。

**第 5 步：打开页面**

访问 `https://<worker-name>.<你的子域>.workers.dev`。

- 个人版：首次打开会引导你设置用户名和主密码；
- 多人版：进入 `/register` 注册账号，之后可用安全问题在 `/forgot-password` 找回密码。

---

## 部署方式二：本地 wrangler CLI

```bash
npm install

# 个人版
npm run dev        # 本地开发（本地 R2 持久化在 .wrangler/，不碰线上）
npm run deploy     # 部署到线上

# 多人版
npm run dev:multiplayer
npm run deploy:multiplayer
```

本地开发的环境变量：复制 `.dev.vars.example` 为 `.dev.vars`（已被 git 忽略）并填入值。

线上密钥：

```bash
npx wrangler secret put TURNSTILE_SECRET_KEY
```

> **两种方式混用的重要提醒**：
> 通过 Dashboard 部署时，自动创建的 R2 资源 ID **不会写回仓库**，只能在 Dashboard 里查看。
> 如果你之后改用本地 `wrangler deploy`，务必先从 Dashboard → Settings → Bindings 复制
> 实际的 bucket 名称填进配置文件，否则 wrangler 会把它当成「没有绑定」**再创建一套新桶**，
> 你会以为「线上的数据丢了」（其实还在旧桶里）。

---

## 功能预览

**自动备份（最多保留 20 份）**

- 保存新备份：每次增删账户前，先把当前数据写入 `backups/` 目录；
- 获取列表：列出 `backups/` 下的所有文件；
- 检查数量：文件总数超过 20 个时自动清理；
- 批量删除：算出最旧的若干个文件并一次性删除。

**灾难恢复**

- 从本地上传：选择电脑里的 JSON 文件导入；
- 从云端回滚：直接从 R2 的备份列表中选择历史版本覆盖。

**扫码录入**

- 在「添加账户」弹窗中点击 **📷 扫描二维码**；
- 请求摄像头权限并在弹窗内显示取景框；
- 识别到二维码后自动解析 `otpauth://` 链接，填入服务商与密钥并关闭摄像头。

---

## 目录结构

```
.
├── workers.js                  # 个人版入口
├── Multiplayer.js              # 多人版入口
├── wrangler.jsonc              # 个人版配置（R2 自动创建 + 自动绑定）
├── wrangler.multiplayer.jsonc  # 多人版配置
├── package.json
├── .dev.vars.example           # 本地环境变量模板
└── .gitignore
```
