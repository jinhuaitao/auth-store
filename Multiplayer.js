// --- 配置区 ---
const SESSION_COOKIE_NAME = 'web_auth_session';
const MAX_BACKUPS = 20; 

// --- PWA 配置 ---
const PWA_VERSION = 'v1.1.2'; // 版本升级，配合登录页清理逻辑确保更新

// --- 多用户存储前缀 ---
const PREFIX_USER = 'usr/'; // 用户档案 (密码、密保等)
const PREFIX_DATA = 'dat/'; // 2FA 数据
const PREFIX_SESS = 'sess/'; // 会话

// --- 安全工具函数 (后端用) ---
function escapeHtml(unsafe) {
    if (!unsafe) return "";
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 检查 R2 绑定
    if (!env.DB || typeof env.DB.put !== 'function') {
        return new Response('Configuration Error: Please bind an R2 Bucket to "DB".', { status: 500 });
    }

    // --- PWA 静态资源路由 ---
    if (path === '/manifest.json') return handleManifest();
    if (path === '/sw.js') return handleServiceWorker();
    if (path === '/app-icon.svg') return handleAppIcon();

    const siteKey = env.TURNSTILE_SITE_KEY || null;

    // --- 公开路由 (登录、注册、找回密码) ---
    if (path === '/login') {
        if (request.method === 'POST') return await handleLogin(request, env);
        return new Response(renderLoginPage(false, null, siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    if (path === '/register') {
        if (request.method === 'POST') return await handleRegister(request, env);
        return new Response(renderRegisterPage(false, null, siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    if (path === '/forgot-password') {
        if (request.method === 'POST') return await handleForgotPassword(request, env);
        const step = url.searchParams.get('step') || '1';
        const username = url.searchParams.get('u') || '';
        return await renderForgotPage(env, step, username, null, siteKey);
    }
    if (path === '/logout') return await handleLogout(request, env);

    // --- 鉴权拦截 ---
    const user = await getCurrentUser(request, env);
    if (!user) {
        if (path === '/') return new Response(renderLoginPage(false, null, siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        return new Response(null, { status: 302, headers: { 'Location': '/login' } });
    }

    // --- 登录后功能 ---
    if (path === '/') return await handleDashboard(env, user);
    if (path === '/add' && request.method === 'POST') return await handleAddAccount(request, env, user);
    if (path === '/delete' && request.method === 'POST') return await handleDeleteAccount(request, env, user);
    
    // 备份与恢复
    if (path === '/backup') return await handleDownloadBackup(request, env, user);
    if (path === '/backups/list') return await handleListBackups(env, user);
    if (path === '/restore' && request.method === 'POST') return await handleRestore(request, env, user);

    return new Response('Not Found', { status: 404 });
  }
};

// --- R2 多用户存储封装 ---

async function r2Get(env, key) {
    const obj = await env.DB.get(key);
    if (!obj) return null;
    return await obj.json();
}

async function r2Put(env, key, value) {
    await env.DB.put(key, JSON.stringify(value), {
        httpMetadata: { contentType: 'application/json' }
    });
}

async function r2Delete(env, key) {
    await env.DB.delete(key);
}

// Session 管理
async function setSession(env, token, username) {
    const data = { u: username, exp: Date.now() + 2592000 * 1000 }; // 30天
    await r2Put(env, PREFIX_SESS + token, data);
}

async function getSessionUser(env, token) {
    const data = await r2Get(env, PREFIX_SESS + token);
    if (!data) return null;
    if (Date.now() > data.exp) {
        await r2Delete(env, PREFIX_SESS + token);
        return null;
    }
    return data.u;
}

// --- PWA 处理函数 ---

function handleManifest() {
    const manifest = {
        name: "Cloud Authenticator",
        short_name: "Auth",
        start_url: "/",
        display: "standalone",
        background_color: "#f3f4f6",
        theme_color: "#2563eb",
        description: "Secure Cloudflare Worker Authenticator",
        icons: [
            { src: "/app-icon.svg", sizes: "192x192", type: "image/svg+xml", purpose: "any maskable" },
            { src: "/app-icon.svg", sizes: "512x512", type: "image/svg+xml", purpose: "any maskable" }
        ]
    };
    return new Response(JSON.stringify(manifest), { headers: { 'Content-Type': 'application/manifest+json' } });
}

function handleAppIcon() {
    const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" style="background:#2563eb;border-radius:20%">
      <rect width="512" height="512" fill="#2563eb"/>
      <path d="M256 48C150 48 64 134 64 240c0 88 57 163 136 186v-56c-49-20-80-69-80-125 0-75 61-136 136-136s136 61 136 136c0 56-31 105-80 125v56c79-23 136-98 136-186C448 134 362 48 256 48z" fill="#fff"/>
      <path d="M256 208c-35.3 0-64 28.7-64 64 0 21.6 10.9 40.4 27.2 52L200 384h112l-19.2-60c16.3-11.6 27.2-30.4 27.2-52 0-35.3-28.7-64-64-64z" fill="#fff"/>
    </svg>`.trim();
    return new Response(svg, { headers: { 'Content-Type': 'image/svg+xml' } });
}

function handleServiceWorker() {
    const js = `
    const CACHE_NAME = 'auth-cache-${PWA_VERSION}';
    // [安全修复] 只缓存静态资源，绝对不缓存HTML页面（包含敏感数据）
    const URLS_TO_CACHE = [
        '/app-icon.svg',
        'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js'
    ];

    self.addEventListener('install', event => {
        event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(URLS_TO_CACHE)));
        self.skipWaiting();
    });

    self.addEventListener('activate', event => {
        event.waitUntil(
            caches.keys().then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== CACHE_NAME) return caches.delete(cacheName);
                    })
                );
            })
        );
        self.clients.claim();
    });

    self.addEventListener('fetch', event => {
        if (event.request.method !== 'GET') return;
        
        const url = new URL(event.request.url);
        
        // [安全修复] 明确排除根路径和任何非静态资源
        if (url.pathname === '/' || url.pathname.startsWith('/api') || url.pathname === '/login' || url.pathname === '/register') {
             return; 
        }

        event.respondWith(
            caches.match(event.request)
                .then(response => {
                    if (response) return response;
                    return fetch(event.request).then(response => {
                         // 只缓存特定的静态资源类型
                         if (!response || response.status !== 200 || response.type !== 'basic') return response;
                         // 二次检查：确保不缓存 HTML
                         const contentType = response.headers.get('content-type');
                         if (contentType && contentType.includes('text/html')) return response;
                         
                         const responseToCache = response.clone();
                         caches.open(CACHE_NAME).then(cache => cache.put(event.request, responseToCache));
                         return response;
                    });
                })
        );
    });
    `;
    return new Response(js, { headers: { 'Content-Type': 'application/javascript' } });
}

// --- 安全核心工具 ---
async function hashPassword(password, salt = null) {
    const encoder = new TextEncoder();
    if (!salt) {
        const saltBytes = new Uint8Array(16);
        crypto.getRandomValues(saltBytes);
        salt = [...saltBytes].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    const data = encoder.encode(password + salt);
    // 维持 SHA-256 兼容性
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return `${salt}$${hashArray.map(b => b.toString(16).padStart(2, '0')).join('')}`;
}

async function verifyPassword(input, stored) {
    if (!stored) return false;
    if (!stored.includes('$')) return input === stored ? 'LEGACY_MATCH' : false;
    const [salt, hash] = stored.split('$');
    const newHash = await hashPassword(input, salt);
    return newHash.split('$')[1] === hash;
}

// --- Turnstile 验证工具 ---
async function verifyTurnstileToken(secret, token, ip) {
    if (!secret) return true;
    if (!token) return false;
    const formData = new FormData();
    formData.append('secret', secret);
    formData.append('response', token);
    formData.append('remoteip', ip);

    try {
        const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            body: formData,
            method: 'POST',
        });
        const outcome = await result.json();
        return outcome.success;
    } catch (e) { return false; }
}

async function getCurrentUser(request, env) {
    const cookie = request.headers.get('Cookie');
    if (!cookie) return null;
    const match = cookie.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
    if (!match) return null;
    const token = match[1];
    return await getSessionUser(env, token);
}

// --- 业务逻辑 (多用户数据操作) ---

function jsonResponse(data) {
    return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
}

async function getUserData(env, username) {
    const data = await r2Get(env, PREFIX_DATA + username);
    return data || { accounts: [] };
}

async function saveUserDataWithBackup(env, username, data, needBackup = true) {
    await r2Put(env, PREFIX_DATA + username, data);

    if (needBackup) {
        const timestamp = getBjTimeFilename(); 
        const backupKey = `backups/${username}/${timestamp}_auto.json`;
        await r2Put(env, backupKey, data);

        try {
            const list = await env.DB.list({ prefix: `backups/${username}/` });
            const backups = list.objects.sort((a, b) => a.key.localeCompare(b.key));
            if (backups.length > MAX_BACKUPS) {
                const deleteCount = backups.length - MAX_BACKUPS;
                const keysToDelete = backups.slice(0, deleteCount).map(obj => obj.key);
                if (keysToDelete.length > 0) await env.DB.delete(keysToDelete);
            }
        } catch (e) { console.error("Backup cleanup failed", e); }
    }
}

function getBjTimeFilename() {
    const now = new Date();
    const bjTime = new Date(now.getTime() + 28800000);
    const iso = bjTime.toISOString(); 
    return iso.replace(/\..+/, '').replace('T', '_').replace(/:/g, '-');
}

// --- 路由功能处理 ---

async function handleRegister(request, env) {
    const formData = await request.formData();
    const username = formData.get('username').trim().toLowerCase();
    const password = formData.get('password');
    const question = formData.get('question');
    const answer = formData.get('answer');
    const turnstileToken = formData.get('cf-turnstile-response');

    if (!username || !password || !question || !answer) return new Response('信息不完整', { status: 400 });

    if (!(await verifyTurnstileToken(env.TURNSTILE_SECRET_KEY, turnstileToken, request.headers.get('CF-Connecting-IP')))) {
        return new Response(renderRegisterPage(true, '人机验证失败', env.TURNSTILE_SITE_KEY), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
    }

    const existing = await env.DB.get(PREFIX_USER + username);
    if (existing) {
        return new Response(renderRegisterPage(true, '该用户名/邮箱已被注册', env.TURNSTILE_SITE_KEY), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
    }

    const userProfile = {
        username,
        password: await hashPassword(password),
        security: { question: question, answer: await hashPassword(answer), failedAttempts: 0, lockoutUntil: 0 },
        created_at: Date.now()
    };

    await r2Put(env, PREFIX_USER + username, userProfile);
    await r2Put(env, PREFIX_DATA + username, { accounts: [] });

    return new Response(null, { status: 302, headers: { 'Location': '/login?registered=1' } });
}

async function handleLogin(request, env) {
  const siteKey = env.TURNSTILE_SITE_KEY;
  const secretKey = env.TURNSTILE_SECRET_KEY;
  
  // [安全修复] Fail-Secure 配置检查
  if (siteKey && !secretKey) {
      return new Response('Server Configuration Error: Missing Turnstile Secret Key', { status: 500 });
  }

  await new Promise(r => setTimeout(r, 2000)); // 基础防爆破延时

  const formData = await request.formData();
  const inputUser = formData.get('username').trim().toLowerCase();
  const inputPass = formData.get('password');
  const turnstileToken = formData.get('cf-turnstile-response');

  const userProfile = await r2Get(env, PREFIX_USER + inputUser);
  
  if (userProfile && userProfile.security && userProfile.security.lockoutUntil > Date.now()) {
      const waitMin = Math.ceil((userProfile.security.lockoutUntil - Date.now()) / 60000);
      return new Response(renderLoginPage(true, `已锁定，请 ${waitMin} 分钟后再试`, siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  // --- Turnstile 验证 ---
  if (siteKey) {
      if (!turnstileToken) return new Response(renderLoginPage(true, '请完成人机验证', siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
      const ip = request.headers.get('CF-Connecting-IP');
      const isVerified = await verifyTurnstileToken(secretKey, turnstileToken, ip);
      if (!isVerified) return new Response(renderLoginPage(true, '人机验证失败，请重试', siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if (!userProfile) {
      return new Response(renderLoginPage(true, '用户名或密码错误', siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  const passMatchResult = await verifyPassword(inputPass, userProfile.password);

  if (passMatchResult === false) {
      if (!userProfile.security) userProfile.security = { failedAttempts: 0, lockoutUntil: 0 };
      userProfile.security.failedAttempts += 1;
      if (userProfile.security.failedAttempts >= 5) userProfile.security.lockoutUntil = Date.now() + 15 * 60 * 1000;
      await r2Put(env, PREFIX_USER + inputUser, userProfile);
      
      return new Response(renderLoginPage(true, '用户名或密码错误', siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if (passMatchResult === 'LEGACY_MATCH') userProfile.password = await hashPassword(inputPass);
  if (userProfile.security) { userProfile.security.failedAttempts = 0; userProfile.security.lockoutUntil = 0; }
  await r2Put(env, PREFIX_USER + inputUser, userProfile);
  
  const newToken = crypto.randomUUID();
  await setSession(env, newToken, inputUser);

  return new Response(null, {
    status: 302,
    headers: { 'Location': '/', 'Set-Cookie': `${SESSION_COOKIE_NAME}=${newToken}; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=2592000` } // 30天
  });
}

async function handleForgotPassword(request, env) {
    const formData = await request.formData();
    const step = formData.get('step');
    const username = (formData.get('username') || '').trim().toLowerCase();
    const siteKey = env.TURNSTILE_SITE_KEY;
    const turnstileToken = formData.get('cf-turnstile-response');

    if (step === '1') {
        const userProfile = await r2Get(env, PREFIX_USER + username);
        if (!userProfile) return new Response(await renderForgotPage(env, '1', '', '用户不存在', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
        if (!userProfile.security || !userProfile.security.question) return new Response(await renderForgotPage(env, '1', '', '该账号未设置安全问题', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
        
        return await renderForgotPage(env, '2', username, null, siteKey, userProfile.security.question);
    } 
    
    if (step === '2') {
        if (!(await verifyTurnstileToken(env.TURNSTILE_SECRET_KEY, turnstileToken, request.headers.get('CF-Connecting-IP')))) return new Response('人机验证失败', {status: 400});

        const answer = formData.get('answer');
        const newPassword = formData.get('new_password');
        
        const userProfile = await r2Get(env, PREFIX_USER + username);
        if (!userProfile) return new Response('Error', {status: 400});
        
        if (!(await verifyPassword(answer, userProfile.security.answer))) {
             return await renderForgotPage(env, '2', username, '密保答案错误', siteKey, userProfile.security.question);
        }

        userProfile.password = await hashPassword(newPassword);
        userProfile.security.failedAttempts = 0;
        userProfile.security.lockoutUntil = 0;
        await r2Put(env, PREFIX_USER + username, userProfile);

        return new Response(null, { status: 302, headers: { 'Location': '/login?reset=1' } });
    }
}

async function handleLogout(request, env) {
    const cookie = request.headers.get('Cookie');
    if (cookie) {
        const match = cookie.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
        if (match) await r2Delete(env, PREFIX_SESS + match[1]);
    }
    return new Response('Logged out', {
        status: 302,
        headers: { 'Location': '/login', 'Set-Cookie': `${SESSION_COOKIE_NAME}=; Max-Age=0; HttpOnly; Path=/; SameSite=Lax; Secure` }
    });
}

async function handleDashboard(env, username) {
  const data = await getUserData(env, username);
  return new Response(renderDashboard(username, data.accounts), { 
      headers: { 
          'Content-Type': 'text/html;charset=UTF-8',
          // [安全增强] 添加基础安全头
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff'
      } 
  });
}

async function handleAddAccount(request, env, username) {
    const formData = await request.formData();
    let issuer = formData.get('issuer') || 'Unknown';
    let secret = formData.get('secret') || '';
    
    // [安全修复] 输入长度限制
    if (issuer.length > 64) issuer = issuer.substring(0, 64);
    if (secret.length > 256) return new Response('Secret too long', { status: 400 });
    
    secret = secret.replace(/\s+/g, '').toUpperCase().replace(/=+$/, ''); 
    const newAccount = { id: crypto.randomUUID(), issuer, secret, addedAt: Date.now() };
    
    const data = await getUserData(env, username);
    if (!data.accounts) data.accounts = [];
    data.accounts.push(newAccount);
    
    // 添加账户：自动备份 (默认 true)
    await saveUserDataWithBackup(env, username, data);
    
    return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleDeleteAccount(request, env, username) {
    const formData = await request.formData();
    const id = formData.get('id');
    const data = await getUserData(env, username);
    
    if (data.accounts) {
        data.accounts = data.accounts.filter(acc => acc.id !== id);
        // 删除账户：自动备份 (默认 true)
        await saveUserDataWithBackup(env, username, data);
    }
    return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleDownloadBackup(request, env, username) {
    const url = new URL(request.url);
    const targetFile = url.searchParams.get('file');
    
    let dbKey, downloadName;
    if (targetFile) {
        if (!targetFile.startsWith(`backups/${username}/`)) return new Response("Access Denied", { status: 403 });
        dbKey = targetFile;
        downloadName = targetFile.replace(`backups/${username}/`, '').replace('/', '_');
    } else {
        dbKey = PREFIX_DATA + username;
        downloadName = `auth_backup_${username}_${getBjTimeFilename()}.json`;
    }

    const object = await env.DB.get(dbKey);
    if (!object) return new Response("File not found", { status: 404 });
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('Content-Disposition', `attachment; filename="${downloadName}"`);
    return new Response(object.body, { headers });
}

async function handleListBackups(env, username) {
    const list = await env.DB.list({ prefix: `backups/${username}/` });
    const files = list.objects.reverse().map(obj => ({ key: obj.key, size: obj.size, uploaded: obj.uploaded }));
    return jsonResponse(files);
}

async function handleRestore(request, env, username) {
    const formData = await request.formData();
    const file = formData.get('backup_file');
    const r2Key = formData.get('r2_key');

    let json;
    try {
        if (file && file instanceof File && file.size > 0) {
            json = JSON.parse(await file.text());
        } else if (r2Key) {
            if (!r2Key.startsWith(`backups/${username}/`)) throw new Error("Access Denied");
            const obj = await env.DB.get(r2Key);
            if (!obj) throw new Error("Backup not found");
            json = await obj.json();
        } else {
            throw new Error("Invalid request");
        }

        if (!json.accounts) throw new Error("Format Error");
        
        // 恢复数据：自动备份 (默认 true)
        await saveUserDataWithBackup(env, username, json);
        
        return new Response(null, { status: 302, headers: { 'Location': '/' } });
    } catch (e) {
        return new Response('Restore failed: ' + e.message, { status: 500 });
    }
}

// --- 前端 UI (全部采用 workers.js 的样式和结构) ---

const commonHead = `
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/app-icon.svg" type="image/svg+xml">
<meta name="theme-color" content="#2563eb">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Auth">
<link rel="apple-touch-icon" href="/app-icon.svg">
<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
<script>
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(err => console.log('SW setup failed', err));
  }
  // [安全修复] 前端 HTML 转义工具
  function escapeHtml(unsafe) {
    if (!unsafe) return "";
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
  }
</script>
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
  
  @supports (padding-top: env(safe-area-inset-top)) {
    body { padding-top: calc(20px + env(safe-area-inset-top)); padding-bottom: calc(20px + env(safe-area-inset-bottom)); }
  }

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

  /* 适配新的登录/注册样式 */
  .auth-container { width: 100%; max-width: 400px; animation: slideUp 0.4s ease-out; margin: auto;}
  .brand-section { text-align: center; margin-bottom: 2rem; }
  .brand-title { font-size: 1.5rem; font-weight: 700; color: var(--text-main); margin-top: 15px; letter-spacing: -0.5px; }
  .brand-subtitle { font-size: 0.9rem; color: var(--text-sub); margin-top: 5px; }
  .input-group { position: relative; margin-bottom: 1.2rem; }
  .input-icon { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: var(--text-sub); pointer-events: none; z-index: 2; transition: color 0.2s; }
  .input-field { padding-left: 48px !important; transition: all 0.2s; background: var(--input-bg); }
  .input-field:focus + .input-icon { color: var(--primary); }
  .toggle-password { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; color: var(--text-sub); padding: 8px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
  .toggle-password:hover { background: var(--list-hover); color: var(--text-main); }
  .turnstile-container { display: flex; justify-content: center; margin-bottom: 15px; min-height: 65px; }
  .btn.loading { position: relative; color: transparent; pointer-events: none; }
  .btn.loading::after { content: ""; position: absolute; top: 50%; left: 50%; width: 20px; height: 20px; margin-top: -10px; margin-left: -10px; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes spin { to { transform: rotate(360deg); } }
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

const appIconSvg = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" style="width:64px;height:64px;border-radius:14px;box-shadow:0 8px 15px -3px rgba(37, 99, 235, 0.3);">
  <rect width="512" height="512" fill="#2563eb"/>
  <path d="M256 48C150 48 64 134 64 240c0 88 57 163 136 186v-56c-49-20-80-69-80-125 0-75 61-136 136-136s136 61 136 136c0 56-31 105-80 125v56c79-23 136-98 136-186C448 134 362 48 256 48z" fill="#fff"/>
  <path d="M256 208c-35.3 0-64 28.7-64 64 0 21.6 10.9 40.4 27.2 52L200 384h112l-19.2-60c16.3-11.6 27.2-30.4 27.2-52 0-35.3-28.7-64-64-64z" fill="#fff"/>
</svg>`;

const userIconSvg = `<svg class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`;
const lockIconSvg = `<svg class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`;
const keyIconSvg = `<svg class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>`;
const editIconSvg = `<svg class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>`;
const shieldIconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`;


function renderLoginPage(isError, msg, siteKey) {
  return `<!DOCTYPE html><html><head><title>登录 - Cloud Auth</title>${commonHead}
  ${siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
  <script>
    (async function clearLocalData() {
        try {
            if ('caches' in window) {
                const keys = await caches.keys();
                await Promise.all(keys.map(key => caches.delete(key)));
            }
            localStorage.clear();
            sessionStorage.clear();
        } catch (e) { console.log('Cleanup error', e); }
    })();
  </script>
  <style>body { align-items: center; background: var(--bg); }</style>
  </head><body>
    <div class="auth-container">
      <div class="brand-section">${appIconSvg}<div class="brand-title">欢迎回来</div><div class="brand-subtitle">请验证您的身份以继续</div></div>
      <div class="card" style="padding: 30px 25px;">
        ${isError ? `<div style="background:var(--danger-bg); color:var(--danger); padding:10px; border-radius:8px; font-size:0.9rem; text-align:center; margin-bottom:15px; display:flex; align-items:center; justify-content:center; gap:8px;"><span style="font-size:1.1rem">⚠️</span> ${msg || '用户名或密码错误'}</div>` : ''}
        <form action="/login" method="POST" onsubmit="this.querySelector('.btn').classList.add('loading')">
          <div class="input-group">
            <input type="text" name="username" class="input-field" required placeholder="用户名" autocomplete="username">
            ${userIconSvg}
          </div>
          <div class="input-group">
            <input type="password" name="password" id="pwdInput" class="input-field" required placeholder="主密码" autocomplete="current-password">
            ${lockIconSvg}
            <button type="button" class="toggle-password" onclick="togglePwd()" tabindex="-1"><span id="eyeIcon">👁️</span></button>
          </div>
          ${siteKey ? `<div class="turnstile-container"><div class="cf-turnstile" data-sitekey="${siteKey}" data-theme="auto"></div></div>` : ''}
          <button type="submit" class="btn" style="margin-top: 5px; padding: 14px;">立即登录</button>
        </form>
      </div>
      
      <div style="display:flex; justify-content:space-between; margin-top:20px; padding:0 10px;">
          <a href="/register" style="color:var(--primary); text-decoration:none; font-size:0.9rem; font-weight:500;">注册新账号</a>
          <a href="/forgot-password" style="color:var(--text-sub); text-decoration:none; font-size:0.9rem;">忘记密码?</a>
      </div>
    </div>
    <script>
        function togglePwd() { const input = document.getElementById('pwdInput'); const icon = document.getElementById('eyeIcon'); if (input.type === 'password') { input.type = 'text'; icon.innerText = '🙈'; icon.style.opacity = '0.7'; } else { input.type = 'password'; icon.innerText = '👁️'; icon.style.opacity = '1'; } }
    </script>
  </body></html>`;
}

function renderRegisterPage(isError, msg, siteKey) {
  return `<!DOCTYPE html><html><head><title>注册 - Cloud Auth</title>${commonHead}
  ${siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
  <style>body { align-items: center; background: var(--bg); }</style>
  </head><body>
    <div class="auth-container">
      <div class="brand-section">${appIconSvg}<div class="brand-title">创建账号</div><div class="brand-subtitle">私有化部署 · R2 加密存储</div></div>
      <div class="card" style="padding: 30px 25px;">
        ${isError ? `<div style="background:var(--danger-bg); color:var(--danger); padding:10px; border-radius:8px; font-size:0.9rem; text-align:center; margin-bottom:15px; display:flex; align-items:center; justify-content:center; gap:8px;"><span style="font-size:1.1rem">⚠️</span> ${msg}</div>` : ''}
        <form action="/register" method="POST" onsubmit="this.querySelector('.btn').classList.add('loading')">
          <div class="input-group">
            <input type="text" name="username" class="input-field" required placeholder="设置用户名" pattern="[a-zA-Z0-9@._-]{3,50}">
            ${userIconSvg}
          </div>
          <div class="input-group">
            <input type="password" name="password" id="pwdInput" class="input-field" required placeholder="设置登录密码 (至少6位)" minlength="6">
            ${lockIconSvg}
            <button type="button" class="toggle-password" onclick="togglePwd()" tabindex="-1"><span id="eyeIcon">👁️</span></button>
          </div>
          
          <div style="background:var(--bg); padding:15px; border-radius:10px; margin-bottom:1.2rem; border:1px solid var(--border);">
              <div style="font-size:0.85rem; color:var(--text-sub); margin-bottom:10px; font-weight:600; display:flex; align-items:center; gap:5px;">
                  ${shieldIconSvg} 设置安全问题 (用于找回密码)
              </div>
              <div class="input-group" style="margin-bottom:10px;">
                  <input type="text" name="question" class="input-field" required placeholder="自定义问题 (如: 班主任名字)">
                  ${editIconSvg}
              </div>
              <div class="input-group" style="margin-bottom:0;">
                  <input type="text" name="answer" class="input-field" required placeholder="输入问题答案">
                  ${keyIconSvg}
              </div>
          </div>

          ${siteKey ? `<div class="turnstile-container"><div class="cf-turnstile" data-sitekey="${siteKey}" data-theme="auto"></div></div>` : ''}
          <button type="submit" class="btn" style="margin-top: 5px; padding: 14px;">立即注册</button>
        </form>
      </div>
      
      <div class="text-center" style="margin-top:20px;">
          <a href="/login" style="color:var(--text-sub); text-decoration:none; font-size:0.9rem;">已有账号？去登录</a>
      </div>
    </div>
    <script>
        function togglePwd() { const input = document.getElementById('pwdInput'); const icon = document.getElementById('eyeIcon'); if (input.type === 'password') { input.type = 'text'; icon.innerText = '🙈'; icon.style.opacity = '0.7'; } else { input.type = 'password'; icon.innerText = '👁️'; icon.style.opacity = '1'; } }
    </script>
  </body></html>`;
}

async function renderForgotPage(env, step, username, msg, siteKey, questionText) {
  const qDisplay = escapeHtml(questionText) || '未知问题';
  return new Response(`<!DOCTYPE html><html><head><title>重置密码 - Cloud Auth</title>${commonHead}
  ${siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
  <style>body { align-items: center; background: var(--bg); }</style>
  </head><body>
    <div class="auth-container">
      <div class="brand-section">${appIconSvg}<div class="brand-title">重置密码</div><div class="brand-subtitle">验证安全问题以找回权限</div></div>
      <div class="card" style="padding: 30px 25px;">
        ${msg ? `<div style="background:var(--danger-bg); color:var(--danger); padding:10px; border-radius:8px; font-size:0.9rem; text-align:center; margin-bottom:15px; display:flex; align-items:center; justify-content:center; gap:8px;"><span style="font-size:1.1rem">⚠️</span> ${msg}</div>` : ''}
        
        ${step === '1' ? `
        <form action="/forgot-password" method="POST" onsubmit="this.querySelector('.btn').classList.add('loading')">
          <input type="hidden" name="step" value="1">
          <div class="input-group">
            <input type="text" name="username" class="input-field" required placeholder="请输入要找回的用户名" autofocus>
            ${userIconSvg}
          </div>
          <button type="submit" class="btn" style="margin-top: 5px; padding: 14px;">下一步</button>
        </form>
        ` : `
        <form action="/forgot-password" method="POST" onsubmit="this.querySelector('.btn').classList.add('loading')">
          <input type="hidden" name="step" value="2">
          <input type="hidden" name="username" value="${escapeHtml(username)}">
          
          <div style="background:var(--primary); color:white; padding:15px; border-radius:10px; margin-bottom:20px; font-weight:600; font-size:0.95rem; text-align:center;">
             ❓ ${qDisplay}
          </div>

          <div class="input-group">
            <input type="text" name="answer" class="input-field" required placeholder="请输入安全问题答案">
            ${keyIconSvg}
          </div>
          
          <div class="input-group">
            <input type="password" name="new_password" id="pwdInput" class="input-field" required placeholder="设置新密码 (至少6位)" minlength="6">
            ${lockIconSvg}
            <button type="button" class="toggle-password" onclick="togglePwd()" tabindex="-1"><span id="eyeIcon">👁️</span></button>
          </div>

          ${siteKey ? `<div class="turnstile-container"><div class="cf-turnstile" data-sitekey="${siteKey}" data-theme="auto"></div></div>` : ''}
          <button type="submit" class="btn" style="margin-top: 5px; padding: 14px;">确认重置</button>
        </form>
        <script>
            function togglePwd() { const input = document.getElementById('pwdInput'); const icon = document.getElementById('eyeIcon'); if (input.type === 'password') { input.type = 'text'; icon.innerText = '🙈'; icon.style.opacity = '0.7'; } else { input.type = 'password'; icon.innerText = '👁️'; icon.style.opacity = '1'; } }
        </script>
        `}
      </div>
      <div class="text-center" style="margin-top:20px;">
          <a href="/login" style="color:var(--text-sub); text-decoration:none; font-size:0.9rem;">返回登录</a>
      </div>
    </div>
  </body></html>`, { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
}

function renderDashboard(username, accounts) {
  const safeUsername = escapeHtml(username);
  const accountsJson = JSON.stringify(accounts || []).replace(/</g, '\\u003c');

  return `<!DOCTYPE html><html><head><title>Authenticator</title>${commonHead}</head><body>
    <div id="toast" class="toast"></div>
    <div class="container">
      <div class="header">
        <div class="user-badge"><span>👤 ${safeUsername}</span></div>
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
          <input type="text" id="inpIssuer" name="issuer" placeholder="例如: Google" required maxlength="64">
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
         document.getElementById('deleteMsg').textContent = \`确定要删除 \${issuer} 吗？\`;
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
                      // 适配多用户路径：提取最后的文件名部分
                      const filename = f.key.split('/').pop();
                      const rawTime = filename.replace('_auto.json', '');
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
        navigator.clipboard.writeText(code).then(() => showToast('已复制: ' + code));
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
              list.innerHTML = accounts.map(acc => {
                  const safeIssuer = escapeHtml(acc.issuer);
                  const safeId = escapeHtml(acc.id);
                  return \`
                  <div class="auth-item">
                      <div class="auth-info">
                          <div class="auth-issuer">\${safeIssuer}</div>
                          <div class="auth-code" id="code-\${safeId}" onclick="copyCode(this.innerText)">...</div>
                          <div class="auth-timer"><div class="auth-timer-bar" id="bar-\${safeId}"></div></div>
                      </div>
                      <button onclick="openDeleteModal('\${safeId}', '\${safeIssuer.replace(/'/g, "\\'")}')" class="delete-btn" title="删除">🗑️</button>
                  </div>
              \`}).join('');
          }

          for (let acc of accounts) {
              const safeId = escapeHtml(acc.id);
              const codeEl = document.getElementById(\`code-\${safeId}\`);
              const barEl = document.getElementById(\`bar-\${safeId}\`);
              if(codeEl && barEl) {
                  if (seconds === 0 || codeEl.innerText === '...' || codeEl.innerText === 'ERROR') {
                      codeEl.innerText = await generateToken(acc.secret);
                      codeEl.style.opacity = '0.5'; setTimeout(()=>codeEl.style.opacity = '1', 200);
                  }
                  barEl.style.width = \`\${percent}%\`;
                  
                  if (percent < 15) {
                      barEl.style.background = 'var(--danger)';
                      codeEl.style.color = 'var(--danger)';
                  } else if (percent < 50) {
                      barEl.style.background = 'var(--primary)';
                      codeEl.style.color = 'var(--code-color)';
                  } else {
                      barEl.style.background = '#10b981';
                      codeEl.style.color = '#10b981';
                  }
              }
          }
      }
      setInterval(updateCodes, 1000);
      updateCodes();
    </script>
  </body></html>`;
}
