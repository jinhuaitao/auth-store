/**
 * Cloud Auth - Ultimate Edition
 * Platform: Cloudflare Workers + R2
 * Version: v2.5.0 (Full UI Polish + Modal Confirmations + Smart Backup)
 */

// --- 全局配置 ---
const SESSION_COOKIE_NAME = 'web_auth_session';
const MAX_BACKUPS = 10; // 每个用户保留的自动备份数量
const PWA_VERSION = 'v2.5.0'; // 版本号更新

// 存储前缀
const PREFIX_USER = 'usr/'; // 用户档案
const PREFIX_DATA = 'dat/'; // 2FA 数据
const PREFIX_SESS = 'sess/'; // 会话

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 检查 R2 绑定
    if (!env.DB || typeof env.DB.put !== 'function') {
        return new Response('Configuration Error: Please bind an R2 Bucket to the variable "DB".', { status: 500 });
    }

    // --- PWA 静态资源 ---
    if (path === '/manifest.json') return handleManifest();
    if (path === '/sw.js') return handleServiceWorker();
    if (path === '/app-icon.svg') return handleAppIcon();

    const siteKey = env.TURNSTILE_SITE_KEY || null;

    // --- 公开路由 ---
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
        return new Response(null, { status: 302, headers: { 'Location': '/login' } });
    }

    // --- 受保护路由 ---
    if (path === '/') return await handleDashboard(env, user);
    if (path === '/add' && request.method === 'POST') return await handleAddAccount(request, env, user);
    if (path === '/delete' && request.method === 'POST') return await handleDeleteAccount(request, env, user);
    if (path === '/backup') return await handleDownloadBackup(request, env, user);
    if (path === '/backups/list') return await handleListBackups(env, user);
    if (path === '/restore' && request.method === 'POST') return await handleRestore(request, env, user);

    return new Response(null, { status: 302, headers: { 'Location': '/' } });
  }
};

// --- R2 存储封装 ---

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
    const data = { u: username, exp: Date.now() + 86400 * 7 * 1000 };
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

// --- 安全工具 ---

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
    if (!stored) return false;
    const [salt, hash] = stored.split('$');
    const newHash = await hashPassword(input, salt);
    return newHash.split('$')[1] === hash;
}

async function verifyTurnstile(env, token, ip) {
    if (!env.TURNSTILE_SECRET_KEY || !env.TURNSTILE_SITE_KEY) return true;
    if (!token) return false;
    const formData = new FormData();
    formData.append('secret', env.TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    formData.append('remoteip', ip);
    try {
        const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { body: formData, method: 'POST' });
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

// --- 数据业务逻辑 ---

async function getUserData(env, username) {
    const data = await r2Get(env, PREFIX_DATA + username);
    return data || { accounts: [] };
}

// 智能备份保存：enableBackup 为 true 时才生成历史版本
async function saveUserData(env, username, data, enableBackup = false) {
    // 1. 始终保存最新数据
    await r2Put(env, PREFIX_DATA + username, data);
    
    // 2. 仅在需要时生成历史备份
    if (enableBackup) {
        const timestamp = getBjTimeFilename(); 
        const backupKey = `backups/${username}/${timestamp}_auto.json`;
        await r2Put(env, backupKey, data);

        // 清理旧备份
        try {
            const list = await env.DB.list({ prefix: `backups/${username}/` });
            if (list.objects && list.objects.length > MAX_BACKUPS) {
                const sorted = list.objects.sort((a, b) => a.key.localeCompare(b.key));
                const deleteCount = sorted.length - MAX_BACKUPS;
                if (deleteCount > 0) {
                    const keysToDelete = sorted.slice(0, deleteCount).map(obj => obj.key);
                    await env.DB.delete(keysToDelete);
                }
            }
        } catch (e) { console.error("Backup cleanup failed", e); }
    }
}

function getBjTimeFilename() {
    const now = new Date();
    const bjTime = new Date(now.getTime() + 28800000);
    return bjTime.toISOString().replace(/\..+/, '').replace('T', '_').replace(/:/g, '-');
}

// --- 路由处理函数 ---

async function handleRegister(request, env) {
    const formData = await request.formData();
    const username = formData.get('username').trim().toLowerCase();
    const password = formData.get('password');
    const question = formData.get('question');
    const answer = formData.get('answer');
    const turnstileToken = formData.get('cf-turnstile-response');

    if (!username || !password || !question || !answer) return new Response('信息不完整', { status: 400 });

    if (!(await verifyTurnstile(env, turnstileToken, request.headers.get('CF-Connecting-IP')))) {
        return new Response(renderRegisterPage(true, '人机验证失败', env.TURNSTILE_SITE_KEY), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
    }

    const existing = await env.DB.get(PREFIX_USER + username);
    if (existing) {
        return new Response(renderRegisterPage(true, '该用户名/邮箱已被注册', env.TURNSTILE_SITE_KEY), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
    }

    const userProfile = {
        username,
        password: await hashPassword(password),
        security: { question: question, answer: await hashPassword(answer) }, // 存储自定义问题
        created_at: Date.now()
    };

    await r2Put(env, PREFIX_USER + username, userProfile);
    await r2Put(env, PREFIX_DATA + username, { accounts: [] });

    return new Response(null, { status: 302, headers: { 'Location': '/login?registered=1' } });
}

async function handleLogin(request, env) {
    const formData = await request.formData();
    const username = formData.get('username').trim().toLowerCase();
    const password = formData.get('password');
    const turnstileToken = formData.get('cf-turnstile-response');
    const siteKey = env.TURNSTILE_SITE_KEY;

    if (!username || !password) return new Response(renderLoginPage(true, '请输入账号和密码', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });

    if (!(await verifyTurnstile(env, turnstileToken, request.headers.get('CF-Connecting-IP')))) {
        return new Response(renderLoginPage(true, '人机验证失败', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
    }

    const userProfile = await r2Get(env, PREFIX_USER + username);
    if (!userProfile) return new Response(renderLoginPage(true, '用户名或密码错误', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });

    const isMatch = await verifyPassword(password, userProfile.password);
    if (!isMatch) return new Response(renderLoginPage(true, '用户名或密码错误', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });

    const sessionToken = crypto.randomUUID();
    await setSession(env, sessionToken, username);

    return new Response(null, {
        status: 302,
        headers: { 
            'Location': '/', 
            'Set-Cookie': `${SESSION_COOKIE_NAME}=${sessionToken}; HttpOnly; Path=/; SameSite=Strict; Secure; Max-Age=604800` 
        }
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
        if (!userProfile) return new Response(renderForgotPage(env, '1', '', '用户不存在', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
        if (!userProfile.security) return new Response(renderForgotPage(env, '1', '', '该账号未设置安全问题', siteKey), { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
        
        return renderForgotPage(env, '2', username, null, siteKey, userProfile.security.question);
    } 
    
    if (step === '2') {
        if (!(await verifyTurnstile(env, turnstileToken, request.headers.get('CF-Connecting-IP')))) return new Response('人机验证失败', {status: 400});

        const answer = formData.get('answer');
        const newPassword = formData.get('new_password');
        
        const userProfile = await r2Get(env, PREFIX_USER + username);
        if (!userProfile) return new Response('Error', {status: 400});
        
        if (!(await verifyPassword(answer, userProfile.security.answer))) {
             return renderForgotPage(env, '2', username, '密保答案错误', siteKey, userProfile.security.question);
        }

        userProfile.password = await hashPassword(newPassword);
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
        headers: { 'Location': '/login', 'Set-Cookie': `${SESSION_COOKIE_NAME}=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict; Secure` }
    });
}

// --- 账户操作与备份策略 ---

async function handleDashboard(env, username) {
    const data = await getUserData(env, username);
    return new Response(renderDashboard(username, data.accounts), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

async function handleAddAccount(request, env, username) {
    const formData = await request.formData();
    let issuer = formData.get('issuer') || 'Unknown';
    let secret = formData.get('secret') || '';
    secret = secret.replace(/\s+/g, '').toUpperCase().replace(/=+$/, ''); 
    
    const data = await getUserData(env, username);
    data.accounts.push({ id: crypto.randomUUID(), issuer, secret, addedAt: Date.now() });
    
    // 添加时触发备份: true
    await saveUserData(env, username, data, true);
    return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleDeleteAccount(request, env, username) {
    const formData = await request.formData();
    const id = formData.get('id');
    const data = await getUserData(env, username);
    data.accounts = data.accounts.filter(acc => acc.id !== id);
    
    // 删除时触发备份: true
    await saveUserData(env, username, data, true);
    return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleDownloadBackup(request, env, username) {
    const url = new URL(request.url);
    const targetKey = url.searchParams.get('file');
    let dbKey, fileName;
    
    if (targetKey) {
        if (!targetKey.startsWith(`backups/${username}/`)) return new Response("Access Denied", { status: 403 });
        dbKey = targetKey;
        fileName = targetKey.split('/').pop().replace('.json', '');
    } else {
        dbKey = PREFIX_DATA + username;
        fileName = `auth_backup_${username}_${getBjTimeFilename()}`;
    }

    const object = await env.DB.get(dbKey);
    if (!object) return new Response("File not found", { status: 404 });
    return new Response(object.body, { 
        headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="${fileName}.json"` } 
    });
}

async function handleListBackups(env, username) {
    const list = await env.DB.list({ prefix: `backups/${username}/` });
    const files = list.objects.reverse().map(obj => ({ key: obj.key, size: obj.size, uploaded: obj.uploaded }));
    return new Response(JSON.stringify(files), { headers: { 'Content-Type': 'application/json' } });
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
            json = await r2Get(env, r2Key);
            if (!json) throw new Error("Backup not found");
        } else { throw new Error("Invalid request"); }

        if (!json.accounts || !Array.isArray(json.accounts)) throw new Error("格式错误: 找不到 accounts 数组");
        
        // 恢复时触发备份: true
        await saveUserData(env, username, json, true);
        return new Response(null, { status: 302, headers: { 'Location': '/' } });
    } catch (e) {
        return new Response('Restore failed: ' + e.message, { status: 500 });
    }
}

// --- PWA 处理 ---

function handleManifest() {
    const manifest = {
        name: "Cloud Authenticator",
        short_name: "Auth",
        start_url: "/",
        display: "standalone",
        background_color: "#f8fafc",
        theme_color: "#4f46e5",
        icons: [{ src: "/app-icon.svg", sizes: "512x512", type: "image/svg+xml", purpose: "any maskable" }]
    };
    return new Response(JSON.stringify(manifest), { headers: { 'Content-Type': 'application/manifest+json' } });
}

function handleAppIcon() {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" style="background:#4f46e5;border-radius:30%"><rect width="512" height="512" fill="#4f46e5"/><path d="M256 48C150 48 64 134 64 240c0 88 57 163 136 186v-56c-49-20-80-69-80-125 0-75 61-136 136-136s136 61 136 136c0 56-31 105-80 125v56c79-23 136-98 136-186C448 134 362 48 256 48z" fill="#fff"/><path d="M256 208c-35.3 0-64 28.7-64 64 0 21.6 10.9 40.4 27.2 52L200 384h112l-19.2-60c16.3-11.6 27.2-30.4 27.2-52 0-35.3-28.7-64-64-64z" fill="#fff"/></svg>`;
    return new Response(svg, { headers: { 'Content-Type': 'image/svg+xml' } });
}

function handleServiceWorker() {
    const js = `
    const CACHE_NAME = 'auth-ui-${PWA_VERSION}';
    const URLS = ['/', '/app-icon.svg', '/login', 'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js'];
    self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(URLS))); self.skipWaiting(); });
    self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.map(k => k !== CACHE_NAME && caches.delete(k))))); self.clients.claim(); });
    self.addEventListener('fetch', e => { if(e.request.method!=='GET')return; e.respondWith(fetch(e.request).catch(()=>caches.match(e.request))); });
    `;
    return new Response(js, { headers: { 'Content-Type': 'application/javascript' } });
}

// --- UI 渲染 (Modern & Beautiful) ---

const commonHead = `
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<link rel="manifest" href="/manifest.json"><link rel="icon" href="/app-icon.svg" type="image/svg+xml">
<meta name="theme-color" content="#4f46e5">
<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
<script>if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js');</script>
<style>
  :root {
    --bg-grad: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    --card-bg: rgba(255, 255, 255, 0.9);
    --text-main: #1e293b; --text-sub: #64748b;
    --primary: #4f46e5; --primary-hover: #4338ca; --primary-light: #e0e7ff;
    --danger: #ef4444; --success: #10b981; --border: #e2e8f0;
    --shadow: 0 20px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1);
    --radius-card: 28px;
    --radius-pill: 50px;
    --radius-input: 20px;
  }
  [data-theme="dark"] {
    --bg-grad: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    --card-bg: rgba(30, 41, 59, 0.95);
    --text-main: #f8fafc; --text-sub: #94a3b8;
    --primary: #6366f1; --primary-hover: #4f46e5; --primary-light: #1e1b4b;
    --danger: #f87171; --success: #34d399; --border: #334155;
    --shadow: 0 20px 25px -5px rgba(0,0,0,0.5);
  }
  * { box-sizing: border-box; transition: background-color 0.2s, border-color 0.2s, color 0.2s; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg-grad); color: var(--text-main); margin: 0; padding: 20px; min-height: 100vh; display:flex; justify-content:center; align-items:center; }
  
  .container { width: 100%; max-width: 400px; animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1); }
  
  .card { 
    background: var(--card-bg); 
    border-radius: var(--radius-card); 
    box-shadow: var(--shadow); 
    padding: 40px 30px; 
    border: 1px solid rgba(255,255,255,0.2); 
    backdrop-filter: blur(12px);
    position: relative; 
    overflow: hidden; 
  }
  
  h2 { margin: 0 0 8px 0; font-size: 1.6rem; font-weight: 700; color: var(--text-main); text-align: center; letter-spacing: -0.5px; }
  p.subtitle { margin: 0 0 30px 0; text-align: center; color: var(--text-sub); font-size: 0.95rem; }
  
  .input-group { position: relative; margin-bottom: 20px; }
  .input-icon { position: absolute; left: 18px; top: 50%; transform: translateY(-50%); color: var(--text-sub); pointer-events: none; z-index: 2; transition: color 0.2s; }
  input, select { 
    width: 100%; padding: 16px 16px 16px 50px; 
    background: var(--primary-light); 
    border: 2px solid transparent; 
    border-radius: var(--radius-pill); 
    color: var(--text-main); 
    font-size: 1rem; 
    outline: none; 
    transition: all 0.2s; 
    -webkit-appearance: none;
  }
  [data-theme="dark"] input { background: rgba(255,255,255,0.05); }
  input:focus, select:focus { background: var(--card-bg); border-color: var(--primary); box-shadow: 0 4px 12px rgba(99, 102, 241, 0.15); }
  input:focus + .input-icon { color: var(--primary); }
  
  .btn { 
    width: 100%; padding: 16px; 
    background: linear-gradient(135deg, var(--primary) 0%, var(--primary-hover) 100%);
    color: white; border: none; 
    border-radius: var(--radius-pill); 
    font-weight: 600; cursor: pointer; 
    font-size: 1.05rem; 
    transition: transform 0.1s, box-shadow 0.2s; 
    display: flex; justify-content: center; align-items: center; gap: 8px;
    box-shadow: 0 10px 20px -5px rgba(79, 70, 229, 0.4);
  }
  .btn:active { transform: scale(0.97); }
  .btn:hover { box-shadow: 0 15px 25px -5px rgba(79, 70, 229, 0.5); transform: translateY(-1px); }
  
  .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-main); box-shadow: none; }
  .btn-outline:hover { background: rgba(0,0,0,0.03); transform: none; box-shadow: none; }
  
  .link { color: var(--primary); text-decoration: none; font-size: 0.9rem; cursor: pointer; font-weight: 500; padding: 5px; border-radius: 5px; }
  .link:hover { background: var(--primary-light); }
  .flex-between { display: flex; justify-content: space-between; align-items: center; margin-top: 25px; }
  .text-center { text-align: center; }
  
  .err-msg { 
    background: rgba(239, 68, 68, 0.1); color: var(--danger); 
    padding: 14px; border-radius: var(--radius-input); 
    margin-bottom: 20px; font-size: 0.9rem; display: flex; align-items: center; gap: 10px; 
    border: 1px solid rgba(239, 68, 68, 0.1);
  }
  
  .steps { display: flex; margin-bottom: 30px; position: relative; justify-content: center; gap: 60px; }
  .step { width: 36px; height: 36px; border-radius: 50%; background: var(--border); color: var(--text-sub); display: flex; align-items: center; justify-content: center; font-weight: bold; z-index: 1; font-size: 0.9rem; position: relative; border: 3px solid var(--card-bg); }
  .step.active { background: var(--primary); color: white; box-shadow: 0 0 0 4px var(--primary-light); }
  .step.finished { background: var(--success); color: white; }
  .step-line { position: absolute; top: 18px; left: 50%; transform: translateX(-50%); width: 70px; height: 3px; background: var(--border); z-index: 0; }
  
  .success-anim { text-align: center; padding: 20px 0; }
  .checkmark-circle { width: 80px; height: 80px; border-radius: 50%; background: var(--success); margin: 0 auto 25px; display: flex; align-items: center; justify-content: center; box-shadow: 0 10px 25px -5px rgba(16, 185, 129, 0.5); animation: popIn 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
  .checkmark { width: 40px; height: 40px; border-left: 5px solid white; border-bottom: 5px solid white; transform: rotate(-45deg) translate(2px, -4px); opacity: 0; animation: check 0.4s 0.4s forwards ease-out; }

  @keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes popIn { from { transform: scale(0); } to { transform: scale(1); } }
  @keyframes check { from { opacity: 0; width: 0; height: 0; } to { opacity: 1; width: 40px; height: 20px; } }

  .auth-item { display: flex; justify-content: space-between; align-items: center; padding: 18px 0; border-bottom: 1px solid var(--border); }
  .auth-item:last-child { border-bottom: none; }
  .auth-code { font-family: 'Courier New', Courier, monospace; font-size: 1.8rem; font-weight: 700; color: var(--primary); letter-spacing: 3px; }
  
  .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); align-items: center; justify-content: center; padding: 20px; z-index: 100; backdrop-filter: blur(8px); opacity: 0; transition: opacity 0.3s; }
  .modal.open { display: flex; opacity: 1; }
</style>
<script>
  function initTheme(){document.documentElement.setAttribute('data-theme',localStorage.getItem('theme')||(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'));}
  function toggleTheme(){const n=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',n);localStorage.setItem('theme',n);}
  initTheme();
</script>
`;

const icons = {
    user: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>',
    lock: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
    shield: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
    key: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>',
    edit: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>'
};

function renderLoginPage(isError, msg, siteKey) {
    return `<!DOCTYPE html><html><head><title>登录</title>${commonHead}
    ${siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
    </head><body>
    <div class="container">
        <div id="success-card" class="card text-center" style="display:none">
            <div class="success-anim">
                <div class="checkmark-circle"><div class="checkmark"></div></div>
                <h2 id="success-title">操作成功</h2>
                <p class="subtitle" id="success-msg">您的账户已准备就绪</p>
                <button onclick="showLogin()" class="btn">立即登录</button>
            </div>
        </div>
        <div id="login-card" class="card">
            <div class="text-center" style="margin-bottom:30px;font-size:3.5rem;">🔒</div>
            <h2>欢迎回来</h2>
            <p class="subtitle">Cloud Authenticator 安全中心</p>
            ${isError ? `<div class="err-msg"><span style="font-size:1.2em">⚠️</span> ${msg}</div>` : ''}
            <form action="/login" method="POST">
                <div class="input-group">
                    <input type="text" name="username" placeholder="用户名 / 邮箱" required autocomplete="username">
                    <span class="input-icon">${icons.user}</span>
                </div>
                <div class="input-group">
                    <input type="password" name="password" placeholder="主密码" required autocomplete="current-password">
                    <span class="input-icon">${icons.lock}</span>
                </div>
                ${siteKey ? `<div class="cf-turnstile" data-sitekey="${siteKey}" style="margin-bottom:20px;display:flex;justify-content:center"></div>` : ''}
                <button type="submit" class="btn">登 录 <span style="font-size:1.2em">➔</span></button>
            </form>
            <div class="flex-between">
                <a href="/register" class="link">注册新账户</a>
                <a href="/forgot-password" class="link" style="color:var(--text-sub)">忘记密码?</a>
            </div>
        </div>
    </div>
    <script>
        const params = new URLSearchParams(window.location.search);
        const loginCard = document.getElementById('login-card');
        const successCard = document.getElementById('success-card');
        if(params.get('registered') || params.get('reset')) {
            loginCard.style.display = 'none';
            successCard.style.display = 'block';
            if(params.get('registered')) {
                document.getElementById('success-title').innerText = '注册成功';
                document.getElementById('success-msg').innerText = '数据已隔离加密，请使用新账号登录';
            } else {
                document.getElementById('success-title').innerText = '重置成功';
                document.getElementById('success-msg').innerText = '密码已更新，请使用新密码登录';
            }
        }
        function showLogin() {
            successCard.style.display = 'none';
            loginCard.style.display = 'block';
            loginCard.style.animation = 'fadeUp 0.5s';
            window.history.replaceState({}, document.title, "/login");
        }
    </script>
    </body></html>`;
}

function renderRegisterPage(isError, msg, siteKey) {
    return `<!DOCTYPE html><html><head><title>注册</title>${commonHead}
    ${siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
    </head><body>
    <div class="container">
        <div class="card">
            <h2>创建账户</h2>
            <p class="subtitle">私有化部署 · R2 加密存储</p>
            ${isError ? `<div class="err-msg">⚠️ ${msg}</div>` : ''}
            <form action="/register" method="POST">
                <div class="input-group">
                    <input type="text" name="username" placeholder="设置用户名或邮箱" required pattern="[a-zA-Z0-9@._-]{3,50}" title="3-50位，允许字母、数字、@、.、_、-">
                    <span class="input-icon">${icons.user}</span>
                </div>
                <div class="input-group">
                    <input type="password" name="password" placeholder="设置登录密码 (至少6位)" required minlength="6">
                    <span class="input-icon">${icons.lock}</span>
                </div>
                
                <div style="background:var(--bg-grad); padding:20px; border-radius:var(--radius-input); margin-bottom:20px; border:1px solid rgba(0,0,0,0.05);">
                    <div style="font-size:0.9rem; color:var(--text-sub); margin-bottom:15px; font-weight:600; display:flex; align-items:center; gap:8px;">
                        ${icons.shield} 设置安全问题 (用于找回密码)
                    </div>
                    <div class="input-group" style="margin-bottom:15px">
                        <input type="text" name="question" placeholder="自定义问题 (如: 我高中班主任的名字?)" required>
                        <span class="input-icon">${icons.edit}</span>
                    </div>
                    <div class="input-group" style="margin-bottom:0">
                        <input type="text" name="answer" placeholder="输入问题的答案" required>
                        <span class="input-icon">${icons.key}</span>
                    </div>
                </div>

                ${siteKey ? `<div class="cf-turnstile" data-sitekey="${siteKey}" style="margin-bottom:20px;display:flex;justify-content:center"></div>` : ''}
                <button type="submit" class="btn">立即注册</button>
            </form>
            <div class="text-center" style="margin-top:25px">
                <a href="/login" class="link">已有账号？去登录</a>
            </div>
        </div>
    </div>
    </body></html>`;
}

async function renderForgotPage(env, step, username, msg, siteKey, questionText) {
    const qDisplay = questionText || '未知问题';
    return new Response(`<!DOCTYPE html><html><head><title>重置密码</title>${commonHead}
    ${siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
    </head><body>
    <div class="container">
        <div class="card">
            <h2>重置密码</h2>
            <div class="steps">
                <div class="step-line"></div>
                <div class="step ${step === '1' ? 'active' : (step === '2' ? 'finished' : '')}">1</div>
                <div class="step ${step === '2' ? 'active' : ''}">2</div>
            </div>
            
            ${msg ? `<div class="err-msg">⚠️ ${msg}</div>` : ''}
            
            ${step === '1' ? `
            <form action="/forgot-password" method="POST">
                <input type="hidden" name="step" value="1">
                <p class="subtitle">请输入您要找回的账号</p>
                <div class="input-group">
                    <input type="text" name="username" placeholder="请输入用户名或邮箱" required autofocus>
                    <span class="input-icon">${icons.user}</span>
                </div>
                <button type="submit" class="btn">下一步 ➔</button>
            </form>
            ` : `
            <form action="/forgot-password" method="POST">
                <input type="hidden" name="step" value="2">
                <input type="hidden" name="username" value="${username}">
                <p class="subtitle">请完成安全验证</p>
                
                <div style="background:var(--primary-light); color:var(--primary); padding:18px; border-radius:var(--radius-input); margin-bottom:25px; font-weight:600; font-size:1rem; text-align:center; border:2px dashed var(--primary);">
                   ❓ ${qDisplay}
                </div>
                
                <div class="input-group">
                    <input type="text" name="answer" placeholder="请输入安全问题答案" required>
                    <span class="input-icon">${icons.key}</span>
                </div>
                
                <div class="input-group" style="margin-top:20px">
                    <input type="password" name="new_password" placeholder="设置新密码 (至少6位)" required minlength="6">
                    <span class="input-icon">${icons.lock}</span>
                </div>
                
                ${siteKey ? `<div class="cf-turnstile" data-sitekey="${siteKey}" style="margin-bottom:20px;display:flex;justify-content:center"></div>` : ''}
                
                <button type="submit" class="btn">确认重置</button>
            </form>
            `}
            
            <div class="text-center" style="margin-top:25px">
                <a href="/login" class="link" style="color:var(--text-sub)">返回登录</a>
            </div>
        </div>
    </div>
    </body></html>`, { headers: {'Content-Type': 'text/html;charset=UTF-8'} });
}

function renderDashboard(username, accounts) {
  return `<!DOCTYPE html><html><head><title>Auth</title>${commonHead}
  <style>
     .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; } 
     .btn-icon { background: var(--card-bg); border: 1px solid transparent; width: 42px; height: 42px; border-radius: 14px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; transition: all 0.2s; color: var(--text-main); box-shadow: var(--shadow); }
     .btn-icon:hover { transform: translateY(-3px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); background: white; }
     .fab { position: fixed; bottom: 40px; right: 30px; width: 64px; height: 64px; background: linear-gradient(135deg, var(--primary) 0%, var(--primary-hover) 100%); border-radius: 50%; display: flex; justify-content: center; align-items: center; color: white; font-size: 32px; box-shadow: 0 10px 25px rgba(79, 70, 229, 0.5); cursor: pointer; border: none; z-index: 90; transition: transform 0.2s; }
     .fab:active { transform: scale(0.9); }
     .empty-state { text-align: center; color: var(--text-sub); padding: 80px 0; }
     .empty-icon { font-size: 5rem; margin-bottom: 20px; display: block; opacity: 0.3; }
  </style>
  </head><body>
    <div class="container" style="max-width:440px">
      <div class="header">
        <div style="font-weight:700; font-size:1.2rem; display:flex; align-items:center; gap:10px;">
            <div style="width:40px;height:40px;background:var(--primary);color:white;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.2rem;box-shadow:0 5px 15px rgba(79, 70, 229, 0.3);">👤</div>
            ${username}
        </div>
        <div style="display:flex; gap:12px;">
            <button onclick="toggleTheme()" class="btn-icon" title="切换主题">🌓</button>
            <button onclick="openSettings()" class="btn-icon" title="设置">⚙️</button>
            <a href="/logout" class="btn-icon" style="text-decoration:none" title="退出">🚪</a>
        </div>
      </div>
      
      <div class="card" style="min-height:450px; padding: 10px 20px 80px 20px;">
        ${accounts.length === 0 ? `
            <div class="empty-state">
                <span class="empty-icon">📭</span>
                <h3>暂无验证码</h3>
                <p>点击右下角 + 号添加账户</p>
            </div>
        ` : '<div id="list"></div>'}
      </div>
    </div>

    <button class="fab" onclick="document.getElementById('addModal').classList.add('open')">+</button>

    <div id="settingsModal" class="modal">
        <div class="card" style="width:100%;max-width:320px;margin:0">
            <h3>⚙️ 数据管理</h3>
            <p class="subtitle">R2 云端备份控制台</p>
            <a href="/backup" class="btn btn-outline" style="display:flex;justify-content:center;text-decoration:none;margin-bottom:15px">⬇️ 下载当前备份</a>
            <button onclick="openBackupHistory()" class="btn btn-outline">🕒 备份历史 & 恢复</button>
            <button onclick="document.getElementById('settingsModal').classList.remove('open')" class="btn" style="margin-top:25px;background:var(--card-bg);color:var(--text-main);box-shadow:none;border:1px solid var(--border)">关闭</button>
        </div>
    </div>

    <div id="historyModal" class="modal">
        <div class="card" style="width:100%;max-width:360px;margin:0;max-height:80vh;display:flex;flex-direction:column">
            <h3>备份历史</h3>
            <div id="historyList" style="overflow-y:auto; flex:1; margin-bottom:15px; border-top:1px solid var(--border); padding-top:10px;">加载中...</div>
            <button onclick="document.getElementById('historyModal').classList.remove('open')" class="btn btn-outline">关闭</button>
        </div>
    </div>

    <div id="addModal" class="modal">
        <div class="card" style="width:100%;max-width:340px;margin:0">
            <h3>添加账户</h3>
            <div id="scanner" style="display:none;background:#000;height:250px;margin-bottom:15px;border-radius:16px;overflow:hidden;"><canvas id="qr-canvas" style="width:100%;height:100%"></canvas></div>
            <button id="scanBtn" onclick="startScan()" class="btn btn-outline" style="margin-bottom:20px">📷 扫描二维码</button>
            <form action="/add" method="POST">
                <div class="input-group">
                    <input id="inpIssuer" type="text" name="issuer" placeholder="服务商 (如 Google, GitHub)" required>
                    <span class="input-icon">${icons.shield}</span>
                </div>
                <div class="input-group">
                    <input id="inpSecret" type="text" name="secret" placeholder="密钥 (Base32)" required>
                    <span class="input-icon">${icons.key}</span>
                </div>
                <div class="flex-between" style="gap:15px; margin-top:30px;">
                    <button type="button" class="btn btn-outline" onclick="closeAdd()">取消</button>
                    <button type="submit" class="btn">保存</button>
                </div>
            </form>
        </div>
    </div>
    
    <div id="delModal" class="modal">
        <div class="card" style="width:300px;text-align:center">
            <div style="font-size:4rem;margin-bottom:10px">🗑️</div>
            <h3>确定删除?</h3>
            <p class="subtitle">此操作无法撤销，请确保已备份。</p>
            <form action="/delete" method="POST">
                <input type="hidden" name="id" id="delId">
                <div class="flex-between" style="gap:15px">
                    <button type="button" class="btn btn-outline" onclick="document.getElementById('delModal').classList.remove('open')">取消</button>
                    <button type="submit" class="btn" style="background:linear-gradient(135deg, #ef4444 0%, #dc2626 100%); box-shadow: 0 10px 20px -5px rgba(239, 68, 68, 0.4);">确认删除</button>
                </div>
            </form>
        </div>
    </div>

    <div id="restoreModal" class="modal">
        <div class="card" style="width:300px;text-align:center">
            <div style="font-size:4rem;margin-bottom:10px">↺</div>
            <h3>确认恢复?</h3>
            <p id="restoreMsg" class="subtitle">当前数据将被覆盖，此操作不可撤销。</p>
            <form action="/restore" method="POST">
                <input type="hidden" name="r2_key" id="restoreKey">
                <div class="flex-between" style="gap:15px">
                    <button type="button" class="btn btn-outline" onclick="document.getElementById('restoreModal').classList.remove('open')">取消</button>
                    <button type="submit" class="btn">确认恢复</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        const accounts = ${JSON.stringify(accounts)};
        function renderList() {
            if(!accounts.length) return;
            document.getElementById('list').innerHTML = accounts.map(acc => \`
                <div class="auth-item">
                    <div style="flex:1;overflow:hidden;padding-right:15px;">
                        <div style="font-size:0.9rem;color:var(--text-sub);font-weight:600;margin-bottom:6px;">\${acc.issuer}</div>
                        <div class="auth-code" id="code-\${acc.id}" onclick="copy('\${acc.id}')">...</div>
                        <div style="height:6px;background:rgba(0,0,0,0.05);border-radius:10px;margin-top:10px;max-width:120px;overflow:hidden;">
                            <div class="auth-timer-bar" id="bar-\${acc.id}" style="width:100%;height:100%;background:var(--success);transition:width 1s linear;border-radius:10px;"></div>
                        </div>
                    </div>
                    <button onclick="openDel('\${acc.id}')" style="background:none;border:none;font-size:1.3rem;cursor:pointer;color:var(--text-sub);padding:10px;border-radius:12px;transition:all 0.2s;" onmouseover="this.style.background='rgba(239,68,68,0.1)';this.style.color='var(--danger)'" onmouseout="this.style.background='none';this.style.color='var(--text-sub)'">🗑️</button>
                </div>
            \`).join('');
        }
        
        async function genToken(secret) {
            try {
                const keyData = base32ToBuf(secret);
                const epoch = Math.floor(Date.now() / 1000);
                const counter = Math.floor(epoch / 30);
                const data = new ArrayBuffer(8);
                new DataView(data).setBigUint64(0, BigInt(counter), false);
                const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
                const sig = await crypto.subtle.sign('HMAC', key, data);
                const h = new Uint8Array(sig);
                const off = h[h.length - 1] & 0x0f;
                const v = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
                return (v % 1000000).toString().padStart(6, '0');
            } catch(e) { return 'ERROR'; }
        }
        
        function base32ToBuf(str) {
            const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            let v = 0, b = 0, out = [];
            str = str.replace(/\\s+/g, '').toUpperCase().replace(/=+$/, '');
            for (let i = 0; i < str.length; i++) {
                const idx = a.indexOf(str[i]);
                if (idx === -1) continue;
                v = (v << 5) | idx; b += 5;
                if (b >= 8) { out.push((v >>> (b - 8)) & 0xff); b -= 8; }
            }
            return new Uint8Array(out);
        }
        
        async function update() {
            const sec = Math.floor(Date.now()/1000) % 30;
            const pct = ((30 - sec) / 30) * 100;
            for (let acc of accounts) {
                const c = document.getElementById('code-'+acc.id);
                const b = document.getElementById('bar-'+acc.id);
                if(c && b) {
                    if (sec === 0 || c.innerText === '...' || c.innerText === 'ERROR') c.innerText = await genToken(acc.secret);
                    b.style.width = pct + '%';
                    if (pct < 17) {
                        b.style.background = 'var(--danger)';
                    } else if (pct < 50) {
                        b.style.background = 'var(--primary)';
                    } else {
                        b.style.background = 'var(--success)';
                    }
                }
            }
        }
        
        function openSettings() { document.getElementById('settingsModal').classList.add('open'); }
        function openDel(id) { document.getElementById('delId').value = id; document.getElementById('delModal').classList.add('open'); }
        function closeAdd() { stopScan(); document.getElementById('addModal').classList.remove('open'); }
        function copy(id) { 
            const t = document.getElementById('code-'+id).innerText;
            navigator.clipboard.writeText(t);
            const el = document.getElementById('code-'+id);
            const raw = el.innerText;
            el.innerText = 'COPIED';
            setTimeout(() => el.innerText = raw, 800);
        }
        
        function openRestoreConfirm(key, date) {
            document.getElementById('restoreKey').value = key;
            document.getElementById('restoreMsg').innerText = \`即将回滚至 \${date}，当前数据将被覆盖。\`;
            document.getElementById('restoreModal').classList.add('open');
        }

        async function openBackupHistory() {
            document.getElementById('settingsModal').classList.remove('open');
            document.getElementById('historyModal').classList.add('open');
            const res = await fetch('/backups/list');
            const list = await res.json();
            const el = document.getElementById('historyList');
            if(list.length === 0) el.innerHTML = '<div class="text-center subtitle">暂无历史备份</div>';
            else {
                el.innerHTML = list.map(f => {
                    const displayTime = f.key.split('/').pop().replace('.json','').replace('_auto','').replace('T',' ');
                    return \`
                    <div style="padding:12px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
                        <div>
                            <div style="font-weight:600;font-size:0.9rem">\${displayTime}</div>
                            <div style="font-size:0.75rem;color:var(--text-sub)">\${(f.size/1024).toFixed(2)} KB</div>
                        </div>
                        <button class="btn btn-outline" style="padding:6px 12px;font-size:0.8rem;width:auto;" onclick="openRestoreConfirm('\${f.key}', '\${displayTime}')">恢复</button>
                    </div>\`;
                }).join('');
            }
        }
        
        let videoStream;
        function startScan() {
            const v = document.createElement('video');
            const c = document.getElementById('qr-canvas');
            const ctx = c.getContext('2d');
            document.getElementById('scanBtn').style.display='none';
            document.getElementById('scanner').style.display='block';
            navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }).then(s => {
                videoStream = s; v.srcObject = s; v.setAttribute("playsinline", true); v.play();
                requestAnimationFrame(tick);
                function tick() {
                    if (v.readyState === v.HAVE_ENOUGH_DATA) {
                        c.height = v.videoHeight; c.width = v.videoWidth;
                        ctx.drawImage(v, 0, 0, c.width, c.height);
                        const i = ctx.getImageData(0, 0, c.width, c.height);
                        const code = jsQR(i.data, i.width, i.height, { inversionAttempts: "dontInvert" });
                        if (code) {
                           try {
                               const u = new URL(code.data);
                               if(u.protocol==='otpauth:') {
                                   document.getElementById('inpSecret').value = u.searchParams.get('secret');
                                   let iss = u.searchParams.get('issuer');
                                   if(!iss && u.pathname.includes(':')) iss = u.pathname.split(':')[0].replace('/','');
                                   if(iss) document.getElementById('inpIssuer').value = iss;
                                   closeAdd(); document.getElementById('addModal').classList.add('open');
                               }
                           } catch(e){}
                           stopScan();
                        }
                    }
                    if(videoStream) requestAnimationFrame(tick);
                }
            });
        }
        function stopScan(){ if(videoStream){videoStream.getTracks().forEach(t=>t.stop());videoStream=null;} document.getElementById('scanner').style.display='none'; document.getElementById('scanBtn').style.display='block'; }
        renderList();
        setInterval(update, 1000); update();
    </script>
  </body></html>`;
}
