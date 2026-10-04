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

**第 4 步：打开页面**

访问 `https://<worker-name>.<你的子域>.workers.dev`。

- 个人版：首次打开会引导你设置用户名和主密码；
- 多人版：进入 `/register` 注册账号，之后可用安全问题在 `/forgot-password` 找回密码。

**第 5 步：在应用内配置人机验证（可选）**

不需要再回 Cloudflare 控制台。登录后点右上角 **⚙️ → 安全设置 / 系统设置 → 🛡️ 人机验证 (Turnstile)**，直接填两个密钥保存即可。

详见下面「人机验证密钥在应用内设置」一节。

---

## 人机验证密钥在应用内设置

### 为什么

传统做法要在 Cloudflare 控制台配 `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` 两个环境变量，改一次就要回一次控制台。现在密钥直接存在 R2 里，在应用内设置页维护。

### 配置优先级

```
应用内设置（R2 的 sys/settings.json）
        ↓ 为空时回退
环境变量（TURNSTILE_SITE_KEY / TURNSTILE_SECRET_KEY）
        ↓ 也为空
自动关闭 —— 登录/注册页不显示验证码，不报错
```

环境变量作为回退保留，所以你想切回控制台配置也不会失效；想彻底不用环境变量，两个都不配即可。

**启用规则：两个密钥都填了才算启用。** 代码里没有单独的 `enabled` 开关字段 —— 少一个状态就少一类 bug，不会出现「开关是开的但密钥是空的」这种矛盾态。

### 权限

| 版本 | 谁能改 |
| --- | --- |
| 个人版 | 就是你自己（单账号，登录后可改） |
| 多人版 | **只有管理员**。第一个注册的用户自动成为管理员；若库里已有用户但没有管理员记录（例如从旧版本升级上来），会自动把 `created_at` 最早的那个用户补录为管理员 |

多人版的非管理员账号看不到这个设置入口，直接调接口会返回 403。

### 安全约定

- **Secret Key 永不回显**。读取接口只返回掩码（如 `0xSECR••••••••tKEY`）和一个 `secretSet: true/false`，前端把它当输入框的 placeholder 提示。
- **留空 = 不修改，显式清空 = 清空**。Secret 输入框留空并保存，表示保持原值不变；要清空得点「清空密钥」并二次确认。
- **成对校验**。只填了 Site Key 没填 Secret（或反之）会直接返回 400 拒绝，避免出现「以为配好了、实际验证码永远过不去」。
- 保存后提示的是「**下次打开登录页生效**」，因为密钥是服务端渲染进登录页的，当前页面不会即时变化。

> ⚠️ **必须知道的取舍**：Cloudflare 的**环境变量 Secret 是加密存储**的，而 **R2 里存的值不是**。
> 放进 R2 换来了「部署后完全不用碰控制台」，代价是失去静态加密 —— 能读到你这个 R2 桶的人就能看到明文 Secret。
> 对自用项目通常可以接受；如果你更看重静态加密，把两个环境变量配上、并在应用内清空密钥即可切回原方案。

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

## 常见问题

### 「从云端回滚」显示「加载失败」

已修复。原来有两类原因都会表现成同一句无信息量的「加载失败」：

1. **接口请求被返回了 HTML**。个人版的路由守卫对**所有路径**都返回登录页 HTML（HTTP 200），
   包括 `/backups/list` 这种接口。前端 `await res.json()` 解析 HTML 会抛 `SyntaxError`，
   被 `catch` 吞掉后只剩一句「加载失败」。
2. **服务端抛异常时返回 Cloudflare 的 500 错误页**（同样是 HTML），前端一样解析不了。

现在的行为：

- 服务端：`/backups/list`、`/settings/turnstile` 这类接口路径未登录时返回 **401 JSON**；
  `/backup` 下载链接未登录时 **302 到登录页**；接口内部异常时返回
  `{"error":"list_failed","message":"..."}` 的 500 JSON，而不是 HTML 错误页。
- 前端：先看 HTTP 状态码再解析，分别给出
  **「登录已过期，请重新登录」/「没有权限查看备份列表」/「服务端错误：<具体原因>」/「服务端返回了非 JSON 内容 (HTTP xxx)」**，
  并提供**重试**按钮。列表为空时会明确显示「暂无历史备份」。

同时把备份列表渲染从「拼 HTML 字符串」改成了 DOM 构建：既免去多层引号转义，
也顺带消除了备份文件名带来的 XSS 面。时间格式化也做了容错 ——
文件名不符合 `日期_时间_auto.json` 命名时退回显示原始文件名，不会让一个异常文件把整个列表搞崩。

> 如果你已经部署过旧版本，**升级后请强制刷新一次**（或在浏览器设置里清除该站点的缓存）。
> 本次已把 `PWA_VERSION` 从 `v1.1.2` 升到 `v1.1.3`，新的 Service Worker 激活时会删除旧缓存。

**仍然失败时怎么排查**：打开浏览器开发者工具 → Network → 找 `backups/list` 请求，
看它的 **HTTP 状态码**和 **Response** 内容，就能直接定位到上面哪一类。

---

## 功能预览

**自动备份（最多保留 20 份）**

- 保存新备份：每次增删账户前，先把当前数据写入 `backups/` 目录；
- 获取列表：列出 `backups/` 下的所有文件（按时间倒序，最新的在最前）；
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
