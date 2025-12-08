### 通过 Cloudflare Workers 谷歌验证应用

## 1. 准备工作
在部署代码之前，你需要先在 Cloudflare 后台完成以下操作：

创建 R2 存储桶：

进入 Cloudflare Dashboard -> R2。

创建一个新的存储桶（Bucket），例如命名为 auth-store。

创建 Worker：

进入 Workers & Pages -> Create Application -> Create Worker。

命名你的 Worker。

绑定 R2 到 Worker：

进入你刚才创建的 Worker -> Settings -> Variables -> R2 Bucket Bindings。

点击 "Add binding"。

Variable name: 输入 DB (代码中将使用这个名字)。

R2 Bucket: 选择你刚才创建的 auth-store。

点击 "Deploy" 保存设置。

## 2. 完整代码 (worker.js)
将以下代码复制并粘贴到你的 Worker 编辑器中。

## 首次打开网页提示设置账号密码

### ✨ 功能预览

自动备份R2空间
保存新备份：先将当前数据写入 backups/ 目录。
获取列表：列出 backups/ 下的所有文件。
检查数量：如果文件总数超过 20 个。
批量删除：自动计算出最旧的那几个文件，并一次性删除。
从本地上传：选择电脑里的 JSON 文件。
从云端回滚：直接从 R2 的自动备份列表中选择一个历史版本进行覆盖

新增按钮：在“添加账户”弹窗中增加了 “📷 扫描二维码” 按钮。

调用相机：点击后会请求摄像头权限，并在弹窗内显示取景框。

自动识别：识别到二维码后，会自动解析 otpauth:// 链接，自动填入 服务商 和 密钥，并关闭摄像头。
