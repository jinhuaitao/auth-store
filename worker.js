// --- 配置区 ---
const CONFIG_FILE = 'auth_data.json';
const SESSION_COOKIE_NAME = 'web_auth_session';
const MAX_BACKUPS = 20; 

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 获取配置
    const configObj = await env.DB.get(CONFIG_FILE);
    let config = configObj ? await configObj.json() : null;

    // 1. 初始化
    if (!config) {
      if (path === '/setup' && request.method === 'POST') return await handleSetup(request, env);
      return new Response(renderSetupPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // 2. 鉴权
    const cookie = request.headers.get('Cookie');
    const isLoggedIn = cookie && cookie.includes(`${SESSION_COOKIE_NAME}=${config.sessionToken}`);

    if (path === '/login' && request.method === 'POST') return await handleLogin(request, env, config);
    if (path === '/logout') return logoutResponse();

    if (!isLoggedIn) {
      return new Response(renderLoginPage(false, null), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // --- 登录后功能 ---
    if (path === '/') return await handleDashboard(env, config);
    if (path === '/add' && request.method === 'POST') return await handleAddAccount(request, env, config);
    if (path === '/delete' && request.method === 'POST') return await handleDeleteAccount(request, env, config);
    
    // 备份与恢复
    if (path === '/backup') return await handleDownloadBackup(request, env);
    if (path === '/backups/list') return await handleListBackups(env);
    if (path === '/restore' && request.method === 'POST') return await handleRestore(request, env);

    return new Response('Not Found', { status: 404 });
  }
};

// --- 安全核心工具 ---
async function hashPassword(password, salt = null) {
    const encoder = new TextEncoder();
    if (!salt) {
        const saltBytes = new Uint8Array(16);
        crypto.getRandomValues(saltBytes);
        salt = [...saltBytes].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    const data = encoder.encode(password + salt);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return `${salt}$${hashArray.map(b => b.toString(16).padStart(2, '0')).join('')}`;
}

async function verifyPassword(input, stored) {
    if (!stored.includes('$')) return input === stored ? 'LEGACY_MATCH' : false;
    const [salt, hash] = stored.split('$');
    const newHash = await hashPassword(input, salt);
    return newHash.split('$')[1] === hash;
}

async function saveDataWithBackup(env, data) {
    const jsonString = JSON.stringify(data);
    await env.DB.put(CONFIG_FILE, jsonString);
    const timestamp = getBjTimeFilename(); 
    const backupKey = `backups/${timestamp}_auto.json`;
    await env.DB.put(backupKey, jsonString);

    try {
        const list = await env.DB.list({ prefix: 'backups/' });
        const backups = list.objects;
        if (backups.length > MAX_BACKUPS) {
            const deleteCount = backups.length - MAX_BACKUPS;
            const keysToDelete = backups.slice(0, deleteCount).map(obj => obj.key);
            if (keysToDelete.length > 0) await env.DB.delete(keysToDelete);
        }
    } catch (e) { console.error("Backup cleanup failed", e); }
}

function getBjTimeFilename() {
    const now = new Date();
    const bjTime = new Date(now.getTime() + 28800000);
    const iso = bjTime.toISOString(); 
    return iso.replace(/\..+/, '').replace('T', '_').replace(/:/g, '-');
}

// --- 业务逻辑 ---

function logoutResponse() {
    return new Response('Logged out', {
        status: 302,
        headers: { 'Location': '/', 'Set-Cookie': `${SESSION_COOKIE_NAME}=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict; Secure` }
    });
}

function jsonResponse(data) {
    return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
}

async function handleSetup(request, env) {
  const formData = await request.formData();
  const username = formData.get('username');
  const password = formData.get('password'); 
  if (!username || !password) return new Response('Incomplete data', { status: 400 });

  const hashedPassword = await hashPassword(password);
  const newConfig = { username, password: hashedPassword, sessionToken: crypto.randomUUID(), accounts: [], security: { failedAttempts: 0, lockoutUntil: 0 } };
  await saveDataWithBackup(env, newConfig);
  return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleLogin(request, env, config) {
  await new Promise(r => setTimeout(r, 2000)); 
  const now = Date.now();
  if (config.security && config.security.lockoutUntil > now) {
      const waitMin = Math.ceil((config.security.lockoutUntil - now) / 60000);
      return new Response(renderLoginPage(true, `已锁定，请 ${waitMin} 分钟后再试`), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  const formData = await request.formData();
  const inputUser = formData.get('username');
  const inputPass = formData.get('password');

  if (inputUser !== config.username || (await verifyPassword(inputPass, config.password)) === false) {
      if (!config.security) config.security = { failedAttempts: 0, lockoutUntil: 0 };
      config.security.failedAttempts += 1;
      if (config.security.failedAttempts >= 5) config.security.lockoutUntil = Date.now() + 15 * 60 * 1000;
      await saveDataWithBackup(env, config);
      return new Response(renderLoginPage(true, '用户名或密码错误'), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if ((await verifyPassword(inputPass, config.password)) === 'LEGACY_MATCH') config.password = await hashPassword(inputPass);
  if (config.security) { config.security.failedAttempts = 0; config.security.lockoutUntil = 0; }
  
  config.sessionToken = crypto.randomUUID();
  await saveDataWithBackup(env, config);

  return new Response(null, {
    status: 302,
    headers: { 'Location': '/', 'Set-Cookie': `${SESSION_COOKIE_NAME}=${config.sessionToken}; HttpOnly; Path=/; SameSite=Strict; Secure; Max-Age=86400` }
  });
}

async function handleDashboard(env, config) {
  return new Response(renderDashboard(config.username, config.accounts), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

async function handleAddAccount(request, env, config) {
    const formData = await request.formData();
    let issuer = formData.get('issuer') || 'Unknown';
    let secret = formData.get('secret') || '';
    secret = secret.replace(/\s+/g, '').toUpperCase().replace(/=+$/, ''); 
    const newAccount = { id: crypto.randomUUID(), issuer, secret, addedAt: Date.now() };
    if (!config.accounts) config.accounts = [];
    config.accounts.push(newAccount);
    await saveDataWithBackup(env, config);
    return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleDeleteAccount(request, env, config) {
    const formData = await request.formData();
    const id = formData.get('id');
    if (config.accounts) {
        config.accounts = config.accounts.filter(acc => acc.id !== id);
        await saveDataWithBackup(env, config);
    }
    return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleDownloadBackup(request, env) {
    const url = new URL(request.url);
    const targetFile = url.searchParams.get('file') || CONFIG_FILE;
    if (targetFile !== CONFIG_FILE && !targetFile.startsWith('backups/')) return new Response("Invalid path", { status: 403 });
    const object = await env.DB.get(targetFile);
    if (!object) return new Response("File not found", { status: 404 });
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    const downloadName = targetFile.replace('backups/', '').replace('/', '_');
    headers.set('Content-Disposition', `attachment; filename="${downloadName}"`);
    return new Response(object.body, { headers });
}

async function handleListBackups(env) {
    const list = await env.DB.list({ prefix: 'backups/' });
    const files = list.objects.reverse().map(obj => ({ key: obj.key, size: obj.size, uploaded: obj.uploaded }));
    return jsonResponse(files);
}

async function handleRestore(request, env) {
    const formData = await request.formData();
    const file = formData.get('backup_file');
    const r2Key = formData.get('r2_key');

    let json;
    try {
        if (file && file instanceof File && file.size > 0) {
            json = JSON.parse(await file.text());
        } else if (r2Key) {
            const obj = await env.DB.get(r2Key);
            if (!obj) throw new Error("Backup not found");
            json = await obj.json();
        } else {
            throw new Error("Invalid request");
        }

        if (!json.username || !json.accounts) throw new Error("Format Error");
        await saveDataWithBackup(env, json);
        return logoutResponse();
    } catch (e) {
        return new Response('Restore failed: ' + e.message, { status: 500 });
    }
}

// --- 前端 UI ---

const commonHead = `
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
<style>
  :root {
    --bg: #f3f4f6; --card-bg: #ffffff; --text-main: #111827; --text-sub: #6b7280;
    --primary: #2563eb; --primary-hover: #1d4ed8; --danger: #ef4444; --danger-bg: #fee2e2; --border: #e5e7eb;
    --input-bg: #ffffff; --shadow: 0 4px 6px -1px rgba(0,0,0,0.1); --code-color: #2563eb;
    --bar-bg: #e5e7eb; --modal-overlay: rgba(0,0,0,0.5); --list-hover: #f9fafb;
    --icon-btn-hover: #e5e7eb;
  }
  [data-theme="dark"] {
    --bg: #111827; --card-bg: #1f2937; --text-main: #f9fafb; --text-sub: #9ca3af;
    --primary: #3b82f6; --primary-hover: #60a5fa; --danger: #f87171; --danger-bg: #450a0a; --border: #374151;
    --input-bg: #111827; --shadow: 0 4px 6px -1px rgba(0,0,0,0.3); --code-color: #60a5fa;
    --bar-bg: #374151; --modal-overlay: rgba(0,0,0,0.7); --list-hover: #374151;
    --icon-btn-hover: #374151;
  }
  body { font-family: -apple-system, sans-serif; background-color: var(--bg); color: var(--text-main); margin: 0; padding: 20px 15px; display: flex; justify-content: center; transition: background-color 0.3s, color 0.3s; min-height: 100vh; box-sizing: border-box;}
  .container { width: 100%; max-width: 440px; }
  
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; gap: 10px; }
  .user-badge { font-size: 0.95rem; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 50%; display: flex; align-items: center; gap: 5px; color: var(--text-main); }
  .header-actions { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
  .btn-icon { background: none; border: none; cursor: pointer; font-size: 1.2rem; padding: 8px; border-radius: 8px; color: var(--text-main); transition: background 0.2s; display: flex; align-items: center; justify-content: center; }
  .btn-icon:hover { background: var(--icon-btn-hover); }

  .card { background: var(--card-bg); border-radius: 16px; box-shadow: var(--shadow); padding: 20px; margin-bottom: 15px; border: 1px solid var(--border); transition: background-color 0.3s, border-color 0.3s; }
  .auth-item { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid var(--border); }
  .auth-item:last-child { border-bottom: none; }
  .auth-info { flex: 1; overflow: hidden; } 
  .auth-issuer { font-size: 0.85rem; color: var(--text-sub); font-weight: 500; margin-bottom: 4px; text-transform: uppercase; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .auth-code { font-family: monospace; font-size: 2rem; font-weight: 700; letter-spacing: 3px; color: var(--code-color); cursor: pointer; line-height: 1; display: inline-block; }
  .auth-timer { height: 4px; background: var(--bar-bg); border-radius: 2px; margin-top: 8px; overflow: hidden; max-width: 60px;}
  .auth-timer-bar { height: 100%; background: var(--primary); width: 100%; transition: width 1s linear; }
  .delete-btn { background: none; border: none; color: var(--text-sub); font-size: 1.2rem; cursor: pointer; padding: 10px; opacity: 0.6; margin-left: 5px; transition: color 0.2s, opacity 0.2s; }
  .delete-btn:hover { color: var(--danger); opacity: 1; }

  h1, h2 { margin: 0 0 1rem 0; text-align: center; } h3 { margin: 0 0 10px 0; font-size: 1rem;}
  input { width: 100%; padding: 12px; background: var(--input-bg); border: 1px solid var(--border); border-radius: 10px; color: var(--text-main); box-sizing: border-box; margin-bottom: 12px; font-size: 1rem; outline: none; }
  input:focus { border-color: var(--primary); }
  .btn { width: 100%; padding: 12px; background: var(--primary); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; font-size: 1rem; transition: background 0.2s;}
  .btn:hover { background: var(--primary-hover); }
  .btn-danger { background: var(--danger); color: white; }
  .btn-danger:hover { opacity: 0.9; }
  .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-main); cursor: pointer; border-radius: 8px; text-decoration: none; display: inline-block; text-align: center;}
  .btn-outline:hover { background: var(--list-hover); }
  .btn-sm { padding: 8px 12px; font-size: 0.9rem; width: auto; }
  .btn-block { width: 100%; display: block; box-sizing: border-box;}

  .backup-list { max-height: 300px; overflow-y: auto; margin-top: 10px; -webkit-overflow-scrolling: touch; }
  .backup-item { display: flex; justify-content: space-between; align-items: center; padding: 12px; border-bottom: 1px solid var(--border); text-decoration: none; color: var(--text-main); transition: background 0.2s; border-radius: 8px;}
  .backup-item:hover { background: var(--list-hover); }
  
  .restore-action-btn { background: var(--primary); color: white; border: none; padding: 4px 10px; border-radius: 4px; font-size: 0.8rem; cursor: pointer; margin-left: 10px; }
  
  .toast { position: fixed; top: 20px; left: 50%; transform: translateX(-50%) translateY(-20px); background: #10b981; color: white; padding: 10px 20px; border-radius: 50px; opacity: 0; pointer-events: none; transition: all 0.3s; z-index: 100; font-weight: 500; white-space: nowrap; box-shadow: 0 5px 15px rgba(0,0,0,0.2);}
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  .fab { position: fixed; bottom: 30px; right: 30px; width: 56px; height: 56px; background: var(--primary); border-radius: 50%; display: flex; justify-content: center; align-items: center; color: white; font-size: 30px; box-shadow: 0 4px 15px rgba(37, 99, 235, 0.4); cursor: pointer; border: none; z-index: 90; -webkit-tap-highlight-color: transparent;}
  .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: var(--modal-overlay); align-items: center; justify-content: center; padding: 20px; box-sizing: border-box; z-index: 99; backdrop-filter: blur(3px); opacity: 0; transition: opacity 0.2s;}
  .modal.open { display: flex; opacity: 1;}
  .icon-box-danger { width: 50px; height: 50px; border-radius: 50%; background: var(--danger-bg); color: var(--danger); display: flex; align-items: center; justify-content: center; font-size: 24px; margin: 0 auto 15px auto; }
  
  /* 扫描取景框样式 */
  #scannerContainer { position: relative; overflow: hidden; border-radius: 10px; margin-bottom: 15px; background: #000; display: none; }
  #qr-canvas { width: 100%; display: block; }
  .scan-overlay { position: absolute; top:0; left:0; right:0; bottom:0; border: 2px solid rgba(255,255,255,0.5); box-sizing: border-box; }
  
  .text-center { text-align: center; } .text-sub { color: var(--text-sub); font-size: 0.9rem; } .mt-4 { margin-top: 1rem; } .flex-gap { display: flex; gap: 10px; } .hidden { display: none; }
  .settings-section { margin-bottom: 20px; }
  .settings-title { font-size: 0.9rem; font-weight: 600; color: var(--text-sub); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
  .settings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
</style>
<script>
  function initTheme() {
    const saved = localStorage.getItem('theme');
    const system = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', saved || system);
    updateThemeIcon(saved || system);
  }
  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeIcon(next);
  }
  function updateThemeIcon(theme) { const icon = document.getElementById('theme-icon'); if(icon) icon.innerText = theme === 'dark' ? '🌙' : '☀️'; }
  function showToast(msg) { const t = document.getElementById('toast'); t.innerText = msg; t.className = 'toast show'; setTimeout(() => t.className = 'toast', 2000); }
  initTheme();
</script>
`;

function renderSetupPage() {
  return `<!DOCTYPE html><html><head><title>初始化</title>${commonHead}</head><body>
    <div class="container"><div class="card">
      <h1>☁️ 初始化验证器</h1>
      <p class="text-center text-sub">配置主账号以开启自动云备份</p>
      <form action="/setup" method="POST" class="mt-4">
        <input type="text" name="username" required placeholder="用户名">
        <input type="password" name="password" required placeholder="设置主密码">
        <button type="submit" class="btn">完成配置</button>
      </form>
    </div></div></body></html>`;
}

function renderLoginPage(isError, msg) {
  return `<!DOCTYPE html><html><head><title>登录</title>${commonHead}</head><body>
    <div class="container"><div class="card">
      <h1>🔐 登录</h1>
      ${isError ? `<p style="color:var(--danger);text-align:center;">${msg || '密码或用户名错误'}</p>` : ''}
      <form action="/login" method="POST" class="mt-4">
        <input type="text" name="username" required placeholder="用户名">
        <input type="password" name="password" required placeholder="密码">
        <button type="submit" class="btn">登录</button>
      </form>
      <p class="text-center text-sub" style="font-size:0.8rem; margin-top:20px; opacity:0.7;">安全提示：多次失败将锁定账户</p>
    </div></div></body></html>`;
}

function renderDashboard(username, accounts) {
  const accountsJson = JSON.stringify(accounts || []);
  return `<!DOCTYPE html><html><head><title>Authenticator</title>${commonHead}</head><body>
    <div id="toast" class="toast"></div>
    <div class="container">
      <div class="header">
        <div class="user-badge"><span>👤 ${username}</span></div>
        <div class="header-actions">
            <button onclick="toggleTheme()" id="theme-icon" class="btn-icon">☀️</button>
            <button onclick="openSettings()" class="btn-icon">⚙️</button>
            <a href="/logout" class="btn-icon" style="text-decoration:none;">🚪</a>
        </div>
      </div>
      
      <div id="settingsModal" class="modal">
         <div class="card" style="width:100%; max-width:340px; margin:0;">
             <h2>⚙️ 数据管理</h2>
             
             <div class="settings-section">
                <div class="settings-title">数据备份</div>
                <div class="settings-grid">
                    <a href="/backup" class="btn btn-outline btn-block">⬇️ 下载当前</a>
                    <button onclick="openBackupModal()" class="btn btn-outline btn-block">🕒 备份历史</button>
                </div>
             </div>

             <div class="settings-section" style="margin-bottom:0">
                <div class="settings-title">灾难恢复</div>
                <button onclick="openRestoreModal()" class="btn btn-outline btn-block">↺ 进入恢复中心</button>
             </div>

             <div class="mt-4">
                <button onclick="closeSettings()" class="btn btn-block">完成</button>
             </div>
         </div>
      </div>

      <div class="card" style="min-height: 300px; padding-bottom: 80px;">
        ${accounts.length === 0 ? `
            <div class="text-center" style="padding: 60px 0; opacity: 0.6;">
                <div style="font-size: 3rem; margin-bottom: 10px;">📭</div>
                <div class="text-sub">暂无账户<br>操作将自动触发备份</div>
            </div>
        ` : ''}
        <div id="list"></div>
      </div>
    </div>

    <button class="fab" onclick="openAddModal()">+</button>

    <div id="addModal" class="modal">
      <div class="card" style="width:100%; max-width:340px; margin:0;">
        <h2>添加账户</h2>
        
        <div id="scannerContainer">
            <canvas id="qr-canvas"></canvas>
            <button onclick="stopScan()" class="btn-sm btn-danger" style="position:absolute; bottom:10px; left:50%; transform:translateX(-50%); z-index:10;">停止扫描</button>
        </div>
        <button type="button" onclick="startScan()" id="scanBtn" class="btn btn-outline btn-block" style="margin-bottom:15px;">📷 扫描二维码</button>

        <form action="/add" method="POST">
          <label class="text-sub">服务商 / 备注</label>
          <input type="text" id="inpIssuer" name="issuer" placeholder="例如: Google" required>
          <label class="text-sub">密钥 (Key)</label>
          <input type="text" id="inpSecret" name="secret" placeholder="粘贴 Base32 密钥" required autocomplete="off">
          <div class="flex-gap mt-4">
            <button type="button" class="btn btn-outline" onclick="closeAddModal()">取消</button>
            <button type="submit" class="btn">保存</button>
          </div>
        </form>
      </div>
    </div>

    <div id="deleteModal" class="modal">
      <div class="card" style="width:100%; max-width:320px; margin:0; text-align:center;">
        <div class="icon-box-danger">🗑️</div>
        <h2 style="font-size:1.2rem; margin-bottom: 0.5rem;">确定删除?</h2>
        <p id="deleteMsg" class="text-sub" style="margin-bottom: 20px;">删除操作无法撤销，数据将永久丢失。</p>
        <form action="/delete" method="POST">
            <input type="hidden" id="deleteId" name="id" value="">
            <div class="flex-gap">
                <button type="button" class="btn btn-outline" onclick="closeDeleteModal()">取消</button>
                <button type="submit" class="btn btn-danger">确认删除</button>
            </div>
        </form>
      </div>
    </div>

    <div id="backupModal" class="modal">
      <div class="card" style="width:100%; max-width:340px; margin:0; max-height:80vh; display:flex; flex-direction:column;">
        <h2>备份历史</h2>
        <p class="text-sub text-center" style="margin-bottom:15px;">点击列表下载对应文件</p>
        <div id="backupListContainer" class="backup-list">
            <div class="text-center text-sub" style="padding:20px;">加载中...</div>
        </div>
        <div class="mt-4">
            <button type="button" class="btn btn-outline btn-block" onclick="backToSettings()">返回</button>
        </div>
      </div>
    </div>

    <div id="restoreModal" class="modal">
      <div class="card" style="width:100%; max-width:340px; margin:0; max-height:80vh; display:flex; flex-direction:column;">
        <h2>恢复数据</h2>
        
        <div style="margin-bottom: 20px;">
             <p class="text-sub text-center" style="margin-bottom:10px;">方法一：从本地上传</p>
             <button onclick="document.getElementById('restoreInput').click()" class="btn btn-block">📂 选择 JSON 文件</button>
             <form id="restoreForm" action="/restore" method="POST" enctype="multipart/form-data">
                <input type="file" id="restoreInput" name="backup_file" accept=".json" style="display:none" onchange="if(confirm('本地文件将覆盖现有数据，确定吗？')) document.getElementById('restoreForm').submit()">
             </form>
        </div>
        
        <div style="border-top: 1px solid var(--border); padding-top: 15px; flex: 1; overflow: hidden; display: flex; flex-direction: column;">
            <p class="text-sub text-center" style="margin-bottom:10px;">方法二：从云端回滚</p>
            <div id="restoreListContainer" class="backup-list">
                <div class="text-center text-sub" style="padding:20px;">加载中...</div>
            </div>
        </div>

        <div class="mt-4">
            <button type="button" class="btn btn-outline btn-block" onclick="backToSettings()">返回</button>
        </div>
      </div>
    </div>

    <script>
      const accounts = ${accountsJson};
      
      // 设置中心逻辑
      function openSettings() { document.getElementById('settingsModal').classList.add('open'); }
      function closeSettings() { document.getElementById('settingsModal').classList.remove('open'); }
      
      function backToSettings() {
          document.getElementById('backupModal').classList.remove('open');
          document.getElementById('restoreModal').classList.remove('open');
          openSettings();
      }

      function openAddModal() { document.getElementById('addModal').classList.add('open'); }
      function closeAddModal() { stopScan(); document.getElementById('addModal').classList.remove('open'); }
      function closeBackupModal() { document.getElementById('backupModal').classList.remove('open'); }
      function closeRestoreModal() { document.getElementById('restoreModal').classList.remove('open'); }

      function openDeleteModal(id, issuer) {
         document.getElementById('deleteId').value = id;
         document.getElementById('deleteMsg').innerText = \`确定要删除 \${issuer} 吗？\`;
         document.getElementById('deleteModal').classList.add('open');
      }
      function closeDeleteModal() { document.getElementById('deleteModal').classList.remove('open'); }

      async function openBackupModal() {
          const modal = document.getElementById('backupModal');
          const container = document.getElementById('backupListContainer');
          closeSettings();
          modal.classList.add('open');
          await loadBackupList(container, 'download');
      }

      async function openRestoreModal() {
          const modal = document.getElementById('restoreModal');
          const container = document.getElementById('restoreListContainer');
          closeSettings();
          modal.classList.add('open');
          await loadBackupList(container, 'restore');
      }

      async function loadBackupList(container, mode) {
          try {
              const res = await fetch('/backups/list');
              const files = await res.json();
              let html = '';
              
              if(files.length === 0) { 
                  html = '<div class="text-center text-sub" style="padding:20px;">暂无历史备份</div>'; 
              } else {
                  files.forEach(f => {
                      const rawTime = f.key.replace('backups/', '').replace('_auto.json', '');
                      const dateStr = rawTime.replace('_', ' ').replace(/-/g, ':').replace(/:/,'-').replace(/:/,'-'); 
                      const parts = rawTime.split('_');
                      const datePart = parts[0];
                      const timePart = parts[1].replace(/-/g, ':');
                      const displayStr = \`\${datePart} \${timePart}\`;
                      
                      if (mode === 'download') {
                          html += \`<a href="/backup?file=\${f.key}" class="backup-item"><div class="backup-date">\${displayStr}</div><div class="backup-size">下载</div></a>\`;
                      } else {
                          html += \`
                            <div class="backup-item">
                                <div class="backup-date">\${displayStr}</div>
                                <form action="/restore" method="POST" style="margin:0" onsubmit="return confirm('确定回滚到 \${displayStr} 吗？')">
                                    <input type="hidden" name="r2_key" value="\${f.key}">
                                    <button type="submit" class="restore-action-btn">恢复</button>
                                </form>
                            </div>\`;
                      }
                  });
              }
              container.innerHTML = html;
          } catch(e) { container.innerHTML = '<div class="text-center text-sub" style="color:var(--danger)">加载失败</div>'; }
      }

      // --- 扫码逻辑 ---
      let videoStream = null;
      let scanning = false;

      function startScan() {
          const container = document.getElementById('scannerContainer');
          const canvas = document.getElementById('qr-canvas');
          const ctx = canvas.getContext('2d', { willReadFrequently: true });
          const scanBtn = document.getElementById('scanBtn');
          
          scanBtn.style.display = 'none';
          container.style.display = 'block';
          
          navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } })
            .then(stream => {
                videoStream = stream;
                scanning = true;
                const video = document.createElement('video');
                video.srcObject = stream;
                video.setAttribute('playsinline', true);
                video.play();
                requestAnimationFrame(tick);

                function tick() {
                    if (!scanning) return;
                    if (video.readyState === video.HAVE_ENOUGH_DATA) {
                        canvas.height = video.videoHeight;
                        canvas.width = video.videoWidth;
                        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                        const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });
                        
                        if (code) {
                            parseOTPAuth(code.data);
                            stopScan();
                            showToast("识别成功！");
                        }
                    }
                    requestAnimationFrame(tick);
                }
            })
            .catch(err => {
                alert("无法访问摄像头，请确保已授权。");
                stopScan();
            });
      }

      function stopScan() {
          scanning = false;
          if (videoStream) {
              videoStream.getTracks().forEach(track => track.stop());
              videoStream = null;
          }
          document.getElementById('scannerContainer').style.display = 'none';
          document.getElementById('scanBtn').style.display = 'block';
      }

      function parseOTPAuth(url) {
          try {
              const u = new URL(url);
              if (u.protocol !== 'otpauth:') return alert('无效的 OTP 二维码');
              
              const params = u.searchParams;
              const secret = params.get('secret');
              let issuer = params.get('issuer');
              
              if (!issuer) {
                  // 尝试从路径中获取: otpauth://totp/Google:alice@gmail.com
                  const path = decodeURIComponent(u.pathname.replace('//', ''));
                  const parts = path.split(':');
                  if (parts.length > 0) issuer = parts[0].replace('totp/', '');
              }

              if (secret) document.getElementById('inpSecret').value = secret;
              if (issuer) document.getElementById('inpIssuer').value = issuer;
          } catch (e) { alert('解析失败'); }
      }

      function copyCode(code) {
        if(code === 'ERROR' || code === '...') return;
        if(navigator.vibrate) navigator.vibrate(50);
        navigator.clipboard.writeText(code).then(() => showToast('已复制 ' + code));
      }

      function base32ToBuf(str) {
          const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
          let bits = 0, value = 0, output = [];
          str = str.replace(/\\s+/g, '').toUpperCase().replace(/=+$/, '');
          for (let i = 0; i < str.length; i++) {
              const idx = alphabet.indexOf(str[i]);
              if (idx === -1) continue;
              value = (value << 5) | idx;
              bits += 5;
              if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
          }
          return new Uint8Array(output);
      }

      async function generateToken(secret) {
          try {
              if (!window.crypto || !window.crypto.subtle) return 'HTTPS!';
              const keyData = base32ToBuf(secret);
              if (keyData.length === 0) return 'EMPTY';
              const epoch = Math.floor(Date.now() / 1000);
              const counter = Math.floor(epoch / 30);
              const data = new ArrayBuffer(8);
              new DataView(data).setBigUint64(0, BigInt(counter), false);
              const key = await window.crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
              const signature = await window.crypto.subtle.sign('HMAC', key, data);
              const hmac = new Uint8Array(signature);
              const offset = hmac[hmac.length - 1] & 0x0f;
              const codeVal = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
              return (codeVal % 1000000).toString().padStart(6, '0');
          } catch(e) { return 'ERROR'; }
      }

      async function updateCodes() {
          const list = document.getElementById('list');
          const epoch = Math.floor(Date.now() / 1000);
          const seconds = epoch % 30;
          const percent = ((30 - seconds) / 30) * 100;
          
          if (list.innerHTML === '' && accounts.length > 0) {
              list.innerHTML = accounts.map(acc => \`
                  <div class="auth-item">
                      <div class="auth-info">
                          <div class="auth-issuer">\${acc.issuer}</div>
                          <div class="auth-code" id="code-\${acc.id}" onclick="copyCode(this.innerText)">...</div>
                          <div class="auth-timer"><div class="auth-timer-bar" id="bar-\${acc.id}"></div></div>
                      </div>
                      <button onclick="openDeleteModal('\${acc.id}', '\${acc.issuer}')" class="delete-btn" title="删除">🗑️</button>
                  </div>
              \`).join('');
          }

          for (let acc of accounts) {
              const codeEl = document.getElementById(\`code-\${acc.id}\`);
              const barEl = document.getElementById(\`bar-\${acc.id}\`);
              if(codeEl && barEl) {
                  if (seconds === 0 || codeEl.innerText === '...' || codeEl.innerText === 'ERROR') {
                      codeEl.innerText = await generateToken(acc.secret);
                      codeEl.style.opacity = '0.5'; setTimeout(()=>codeEl.style.opacity = '1', 200);
                  }
                  barEl.style.width = \`\${percent}%\`;
                  if (percent < 15) {
                      barEl.style.background = 'var(--danger)';
                      codeEl.style.color = 'var(--danger)';
                  } else {
                      barEl.style.background = 'var(--primary)';
                      codeEl.style.color = 'var(--code-color)';
                  }
              }
          }
      }
      setInterval(updateCodes, 1000);
      updateCodes();
    </script>
  </body></html>`;
}
