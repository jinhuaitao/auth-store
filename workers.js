// --- 配置区 ---
const CONFIG_FILE = 'auth_data.json';
const SESSION_COOKIE_NAME = 'web_auth_session';
const MAX_BACKUPS = 20; 

// --- PWA 配置 ---
const PWA_VERSION = 'v1.1.3'; // 版本升级，配合登录页清理逻辑确保更新

// --- 接口路径 ---
// 这些路径由前端 fetch() 调用并要求 JSON 响应。
// 未登录时必须返回 401 JSON，绝不能返回登录页 HTML ——
// 否则前端 res.json() 解析 HTML 会抛 SyntaxError，界面只能显示一句无信息量的「加载失败」。
const API_PATHS = ['/backups/list', '/settings/turnstile'];
function isApiPath(path) { return API_PATHS.indexOf(path) !== -1; }

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
    // 统一出口：所有响应（含重定向、下载流）都补上安全头
    return withSecurityHeaders(await handleRequest(request, env));
  }
};

async function handleRequest(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CSRF 纵深防御：状态变更请求必须同源（配合 SameSite=Lax 的会话 Cookie）
    if (request.method !== 'GET' && request.method !== 'HEAD' && !isSameOriginRequest(request, url)) {
        return new Response('Forbidden: cross-origin request blocked', { status: 403 });
    }

    // --- PWA 静态资源路由 ---
    if (path === '/manifest.json') return handleManifest();
    if (path === '/sw.js') return handleServiceWorker();
    if (path === '/app-icon.svg') return handleAppIcon();

    // 获取配置
    const configObj = await env.DB.get(CONFIG_FILE);
    let config = configObj ? await configObj.json() : null;

    // 1. 初始化 (未配置时)
    if (!config) {
      if (path === '/setup' && request.method === 'POST') return await handleSetup(request, env);
      return new Response(renderSetupPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // 2. 鉴权 (多设备 Session 支持)
    const cookieStr = request.headers.get('Cookie') || '';
    const tokenMatch = cookieStr.match(new RegExp('(^| )' + SESSION_COOKIE_NAME + '=([^;]+)'));
    const currentToken = tokenMatch ? tokenMatch[2] : null;

    // 检查 Token 是否存在于 sessions 数组中
    const isLoggedIn = currentToken && 
                       config.sessions && 
                       Array.isArray(config.sessions) && 
                       config.sessions.some(s => s.token === currentToken);

    // 人机验证配置：优先应用内设置（存 R2），其次环境变量，两者都没有则自动关闭
    const ts = await resolveTurnstile(env);
    const siteKey = ts.siteKey;

    if (path === '/login' && request.method === 'POST') return await handleLogin(request, env, config, ts);
    if (path === '/logout') return logoutResponse();

    if (!isLoggedIn) {
      // 按请求类型区分响应，别让接口请求拿到一坨 HTML：
      //   接口(fetch) → 401 JSON；下载链接 → 302 到登录页；页面 → 渲染登录页
      if (isApiPath(path)) return jsonResponse({ error: 'unauthorized' }, 401);
      if (path === '/backup') return new Response(null, { status: 302, headers: { 'Location': '/login' } });
      return new Response(renderLoginPage(false, null, siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // --- 登录后功能 ---
    if (path === '/') return await handleDashboard(env, config);
    if (path === '/add' && request.method === 'POST') return await handleAddAccount(request, env, config);
    if (path === '/delete' && request.method === 'POST') return await handleDeleteAccount(request, env, config);
    
    // 备份与恢复
    if (path === '/backup') return await handleDownloadBackup(request, env);
    if (path === '/backups/list') return await handleListBackups(env);
    if (path === '/restore' && request.method === 'POST') return await handleRestore(request, env);

    // 应用内设置：人机验证密钥（免去登录 Cloudflare 控制台配置环境变量）
    if (path === '/settings/turnstile' && request.method === 'GET') return await handleGetTurnstileSettings(env);
    if (path === '/settings/turnstile' && request.method === 'POST') return await handleSaveTurnstileSettings(request, env);

    return new Response('Not Found', { status: 404 });
}

// --- 安全响应头 ---
// 统一给每个响应加安全头。CSP 里保留 'unsafe-inline'：本应用大量使用内联
// <script> 与 onclick 属性，去掉会直接让界面失效。即便如此，CSP 仍能：
// 限制外部脚本/连接来源、禁止被 iframe 嵌套（防点击劫持）、禁用 object/base 逃逸。
const SECURITY_HEADERS = {
    'Content-Security-Policy': [
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://challenges.cloudflare.com",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https://challenges.cloudflare.com",
        "font-src 'self' data:",
        "connect-src 'self' https://challenges.cloudflare.com",
        "frame-src https://challenges.cloudflare.com",
        "media-src 'self' blob:",
        "worker-src 'self' blob:"
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    // 注意：不能用 no-referrer —— Origin 头由 referrer policy 派生，no-referrer 会让
    // 浏览器把同源 POST 的 Origin 写成字面量 "null"，从而被下面的同源校验误杀。
    // same-origin 既能保住同源请求的真实 Origin，又不会把 Referer 泄漏给外站。
    'Referrer-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(self), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'X-Robots-Tag': 'noindex, nofollow',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
};

function withSecurityHeaders(response) {
    const headers = new Headers(response.headers);
    for (const key in SECURITY_HEADERS) headers.set(key, SECURITY_HEADERS[key]);
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
    });
}

// 同源校验（CSRF 纵深防御）：
//  - Origin 是真实来源时，比对 host；
//  - Origin 缺失、或为字面量 "null"（sandbox iframe / referrer policy 抑制等）时，退回看 Referer；
//  - 两者都判定不了时放行 —— 真正的防线是 SameSite=Lax 的会话 Cookie，这里只做加码。
//    宁可少拦，也不能把正常用户锁在门外（曾因 Referrer-Policy: no-referrer 误杀全部同源 POST）。
function isSameOriginRequest(request, url) {
    const origin = request.headers.get('Origin');
    if (origin && origin !== 'null') {
        try { return new URL(origin).host === url.host; } catch (e) { /* 解析不了，继续看 Referer */ }
    }
    const referer = request.headers.get('Referer');
    if (referer) {
        try { return new URL(referer).host === url.host; } catch (e) { return false; }
    }
    return true;
}

// --- 通用安全工具 ---

function randomHex(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return bytesToHex(buf);
}

function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
}

// 恒定时间比较，避免用 === 比较哈希带来的时序侧信道
function timingSafeEqualHex(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
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

    // [安全修复] 白名单：只有这里列出的静态资源才允许被缓存
    const STATIC_ASSET_PATHS = ['/app-icon.svg', '/manifest.json'];

    self.addEventListener('fetch', event => {
        if (event.request.method !== 'GET') return;

        const url = new URL(event.request.url);

        // [安全修复] 改为白名单策略。原实现只排除 '/' 和 '/api'，
        // 而本应用的数据接口并不在 /api 下（/backups/list、/backup 等），
        // 它们的响应会被写进 Cache，导致同一设备换账号后读到上一个人的
        // 备份列表 / 备份文件（隐私泄漏）。白名单之外一律不拦截、不缓存。
        const isSameOriginStatic = url.origin === self.location.origin && STATIC_ASSET_PATHS.indexOf(url.pathname) !== -1;
        const isCdnStatic = url.hostname === 'cdn.jsdelivr.net';
        if (!isSameOriginStatic && !isCdnStatic) return;

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

// --- 安全核心工具：密码哈希 ---
// 原实现是单轮 SHA-256(password + salt)：盐是随机的，但单轮哈希太快，
// 拿到 R2 数据后可被 GPU 高速爆破。改为 PBKDF2-SHA256 迭代派生。
//
// 哈希串自带算法标识与迭代次数（pbkdf2$迭代$盐$哈希），因此：
//  - 提高迭代数后，旧密码依然能验证，并在下次登录时自动升级；
//  - 旧的 `盐$哈希`（单轮 SHA-256）与更旧的无 `$` 明文密码仍可登录。
//
// 迭代次数受 Workers 的 CPU 时间上限约束：免费版 10ms/请求，付费版默认 50ms。
// 实测 50000 次约 6-8ms，可稳定跑在免费版；付费版可把 PBKDF2_ITERATIONS 提到 100000+。
const PBKDF2_ITERATIONS = 50000;
const PBKDF2_PREFIX = 'pbkdf2';    // 不带 Pepper
const PBKDF2P_PREFIX = 'pbkdf2p';  // 带 Pepper（HMAC 预哈希）

// 可选的 Pepper（密码胡椒）：独立于 R2 的高熵密钥，放在环境变量 PBKDF2_PEPPER。
// 即便 R2 被全量导出，攻击者没有 Pepper 也无法离线爆破。
// ⚠️ 启用后务必长期保管：丢失 Pepper = 所有密码都无法验证（等于把所有人锁在门外）。
function resolvePepper(env) {
    return (env && typeof env.PBKDF2_PEPPER === 'string') ? env.PBKDF2_PEPPER.trim() : '';
}

// 配了 Pepper 就先做一次 HMAC-SHA256(pepper, password)，再送进 PBKDF2
async function deriveKeyMaterial(password, pepper) {
    const raw = new TextEncoder().encode(password);
    if (!pepper) return raw;
    const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, raw));
}

async function pbkdf2Hex(password, saltHex, iterations, pepper = '') {
    const material = await deriveKeyMaterial(password, pepper);
    const keyMaterial = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations, hash: 'SHA-256' },
        keyMaterial, 256
    );
    return bytesToHex(new Uint8Array(bits));
}

async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return bytesToHex(new Uint8Array(digest));
}

async function hashPassword(password, pepper = '', salt = null, iterations = PBKDF2_ITERATIONS) {
    if (!salt) salt = randomHex(16);
    const hash = await pbkdf2Hex(password, salt, iterations, pepper);
    const prefix = pepper ? PBKDF2P_PREFIX : PBKDF2_PREFIX;
    return `${prefix}$${iterations}$${salt}$${hash}`;
}

// 返回值：'OK' | 'OK_UPGRADE'（可登录，且应重哈希）| 'LEGACY_MATCH'（可登录，应重哈希）| false
async function verifyPassword(input, stored, pepper = '') {
    if (!stored) return false;
    const parts = String(stored).split('$');

    if ((parts[0] === PBKDF2_PREFIX || parts[0] === PBKDF2P_PREFIX) && parts.length === 4) {
        const needPepper = parts[0] === PBKDF2P_PREFIX;
        // 哈希带 Pepper 但当前环境没配 Pepper —— 无法校验，直接失败（不静默放行）
        if (needPepper && !pepper) return false;
        const iterations = parseInt(parts[1], 10) || PBKDF2_ITERATIONS;
        const actual = await pbkdf2Hex(input, parts[2], iterations, needPepper ? pepper : '');
        if (!timingSafeEqualHex(actual, parts[3])) return false;
        // 迭代数偏低、或该加 Pepper 却没加，都提示登录后自动升级
        const upToDate = iterations >= PBKDF2_ITERATIONS && needPepper === Boolean(pepper);
        return upToDate ? 'OK' : 'OK_UPGRADE';
    }

    // 旧版格式：单轮 SHA-256(password + salt)
    if (parts.length === 2) {
        const legacy = await sha256Hex(input + parts[0]);
        return timingSafeEqualHex(legacy, parts[1]) ? 'LEGACY_MATCH' : false;
    }

    // 更旧：明文比较
    return input === stored ? 'LEGACY_MATCH' : false;
}

// --- Turnstile 验证工具 ---
async function verifyTurnstileToken(secret, token, ip) {
    const formData = new FormData();
    formData.append('secret', secret);
    formData.append('response', token);
    formData.append('remoteip', ip);

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        body: formData,
        method: 'POST',
    });

    const outcome = await result.json();
    return outcome.success;
}

// --- 应用内设置：人机验证密钥（存 R2，部署后无需再登录 Cloudflare 控制台）---
const SETTINGS_KEY = 'sys/settings.json';
const DEFAULT_SETTINGS = { turnstileSiteKey: '', turnstileSecretKey: '' };

async function getSettings(env) {
    const obj = await env.DB.get(SETTINGS_KEY);
    const data = obj ? await obj.json() : null;
    return Object.assign({}, DEFAULT_SETTINGS, data || {});
}

async function saveSettings(env, settings) {
    await env.DB.put(SETTINGS_KEY, JSON.stringify(settings), {
        httpMetadata: { contentType: 'application/json' }
    });
}

// [设计] 不引入额外的 enabled 开关字段 —— 两个密钥都填了就算启用，
// 少一个状态就少一类 bug（不会出现「开关是开的但密钥是空的」这种矛盾态）。
// 优先级：应用内设置 > 环境变量。保留 env 回退，方便随时切回控制台配置。
async function resolveTurnstile(env) {
    const s = await getSettings(env);
    if (s.turnstileSiteKey && s.turnstileSecretKey) {
        return { enabled: true, siteKey: s.turnstileSiteKey, secretKey: s.turnstileSecretKey, source: 'settings' };
    }
    if (env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY) {
        return { enabled: true, siteKey: env.TURNSTILE_SITE_KEY, secretKey: env.TURNSTILE_SECRET_KEY, source: 'env' };
    }
    return { enabled: false, siteKey: null, secretKey: null, source: 'none' };
}

// Secret 永不回显：只返回掩码，前端拿它当 placeholder 提示
function maskSecret(v) {
    if (!v) return '';
    if (v.length <= 12) return v.slice(0, 3) + '••••••••';
    return v.slice(0, 6) + '••••••••' + v.slice(-4);
}

// 统一的「当前状态视图」，GET / POST 返回同一形状，前端无需分支处理
async function buildTurnstileView(env) {
    const s = await getSettings(env);
    const ts = await resolveTurnstile(env);
    return {
        siteKey: s.turnstileSiteKey || '',
        siteKeySet: Boolean(s.turnstileSiteKey),
        secretSet: Boolean(s.turnstileSecretKey),
        secretMasked: maskSecret(s.turnstileSecretKey),
        enabled: ts.enabled,
        source: ts.source
    };
}

// [核心保存函数]
// needBackup: true (默认) = 触发历史备份
// needBackup: false = 仅保存当前状态，不备份 (用于登录)
async function saveDataWithBackup(env, data, needBackup = true) {
    const jsonString = JSON.stringify(data);
    
    // 1. 始终保存当前最新配置 (覆盖 auth_data.json)
    await env.DB.put(CONFIG_FILE, jsonString);

    // 2. 根据开关决定是否创建历史备份
    if (needBackup) {
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
        headers: { 'Location': '/', 'Set-Cookie': `${SESSION_COOKIE_NAME}=; Max-Age=0; HttpOnly; Path=/; SameSite=Lax; Secure` }
    });
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function handleSetup(request, env) {
  const formData = await request.formData();
  const username = formData.get('username');
  const password = formData.get('password'); 
  if (!username || !password) return new Response('Incomplete data', { status: 400 });

  const hashedPassword = await hashPassword(password, resolvePepper(env));
  // [修改] 初始化 Sessions 数组
  const newConfig = { 
      username, 
      password: hashedPassword, 
      sessions: [], 
      accounts: [], 
      security: { failedAttempts: 0, lockoutUntil: 0 } 
  };
  // Setup 视为重要变更，执行备份 (默认 true)
  await saveDataWithBackup(env, newConfig);
  return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleLogin(request, env, config, ts) {
  // 成对才启用：resolveTurnstile 已保证 siteKey / secretKey 要么都有、要么都没有。
  // 因此「只配了一半」不会再返回 500 把管理员锁在门外，只会静默关闭验证。
  const siteKey = ts.siteKey;
  const secretKey = ts.secretKey;

  await new Promise(r => setTimeout(r, 2000)); // 基础防爆破延时
  
  const now = Date.now();
  if (config.security && config.security.lockoutUntil > now) {
      const waitMin = Math.ceil((config.security.lockoutUntil - now) / 60000);
      return new Response(renderLoginPage(true, `已锁定，请 ${waitMin} 分钟后再试`, siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  const formData = await request.formData();
  const inputUser = formData.get('username');
  const inputPass = formData.get('password');
  const turnstileToken = formData.get('cf-turnstile-response');

  // --- Turnstile 验证 ---
  if (siteKey) {
      if (!turnstileToken) {
          return new Response(renderLoginPage(true, '请完成人机验证', siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
      }
      const ip = request.headers.get('CF-Connecting-IP');
      const isVerified = await verifyTurnstileToken(secretKey, turnstileToken, ip);
      if (!isVerified) {
          return new Response(renderLoginPage(true, '人机验证失败，请重试', siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
      }
  }

  // [安全修复] 恒定时间比较
  const userMatch = (inputUser === config.username);
  const passMatchResult = await verifyPassword(inputPass, config.password, resolvePepper(env));
  const isAuthSuccess = userMatch && (passMatchResult !== false);

  if (!isAuthSuccess) {
      if (!config.security) config.security = { failedAttempts: 0, lockoutUntil: 0 };
      config.security.failedAttempts += 1;
      if (config.security.failedAttempts >= 5) config.security.lockoutUntil = Date.now() + 15 * 60 * 1000;
      
      // [智能备份] 登录失败不触发备份 (false)
      await saveDataWithBackup(env, config, false);
      
      return new Response(renderLoginPage(true, '用户名或密码错误', siteKey), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  // 旧哈希（单轮 SHA-256 / 明文）或迭代数偏低的哈希，登录成功后原地升级为当前 PBKDF2 参数
  if (passMatchResult === 'LEGACY_MATCH' || passMatchResult === 'OK_UPGRADE') config.password = await hashPassword(inputPass, resolvePepper(env));
  if (config.security) { config.security.failedAttempts = 0; config.security.lockoutUntil = 0; }
  
  // [修改] 多设备 Session 管理
  const newToken = randomHex(32); // 256 位随机会话令牌
  const deviceInfo = (request.headers.get('User-Agent') || 'Unknown').substring(0, 50);

  if (!config.sessions || !Array.isArray(config.sessions)) config.sessions = [];
  
  // 追加新 Session
  config.sessions.push({ token: newToken, device: deviceInfo, created: Date.now() });

  // 限制最大在线设备数 (5)
  if (config.sessions.length > 5) {
      config.sessions = config.sessions.slice(-5);
  }

  // 清理旧版数据
  if (config.sessionToken) delete config.sessionToken;

  // [智能备份] 登录成功不触发备份 (false)
  await saveDataWithBackup(env, config, false);

  return new Response(null, {
    status: 302,
    headers: { 'Location': '/', 'Set-Cookie': `${SESSION_COOKIE_NAME}=${newToken}; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=2592000` } // 30天
  });
}

async function handleDashboard(env, config) {
  const turnstileView = await buildTurnstileView(env);
  return new Response(renderDashboard(config.username, config.accounts, turnstileView), { 
      headers: { 
          'Content-Type': 'text/html;charset=UTF-8',
          // [安全增强] 添加基础安全头
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff'
      } 
  });
}

// --- 应用内设置接口：人机验证密钥 ---

// GET 只返回掩码 + 是否已配置，Secret 永不回显
async function handleGetTurnstileSettings(env) {
    return jsonResponse(await buildTurnstileView(env));
}

// POST 语义：字段不传 = 不修改；显式传空串 = 清空
async function handleSaveTurnstileSettings(request, env) {
    const formData = await request.formData();
    const s = await getSettings(env);

    const nextSiteKey = formData.has('site_key') ? String(formData.get('site_key')).trim() : s.turnstileSiteKey;
    const nextSecret  = formData.has('secret_key') ? String(formData.get('secret_key')).trim() : s.turnstileSecretKey;

    if (nextSiteKey.length > 128 || nextSecret.length > 256) {
        return new Response('密钥长度超出限制', { status: 400 });
    }

    // 成对校验：只填一半直接拒绝。否则用户会以为配好了，实际验证码永远过不去。
    if (Boolean(nextSiteKey) !== Boolean(nextSecret)) {
        return new Response('Site Key 与 Secret Key 必须成对配置（或同时留空以关闭验证）', { status: 400 });
    }

    s.turnstileSiteKey = nextSiteKey;
    s.turnstileSecretKey = nextSecret;
    await saveSettings(env, s);

    return jsonResponse(await buildTurnstileView(env));
}

async function handleAddAccount(request, env, config) {
    const formData = await request.formData();
    let issuer = formData.get('issuer') || 'Unknown';
    let secret = formData.get('secret') || '';
    
    // [安全修复] 输入长度限制
    if (issuer.length > 64) issuer = issuer.substring(0, 64);
    if (secret.length > 256) return new Response('Secret too long', { status: 400 });
    
    secret = secret.replace(/\s+/g, '').toUpperCase().replace(/=+$/, ''); 
    const newAccount = { id: crypto.randomUUID(), issuer, secret, addedAt: Date.now() };
    if (!config.accounts) config.accounts = [];
    config.accounts.push(newAccount);
    
    // 添加账户：自动备份 (默认 true)
    await saveDataWithBackup(env, config);
    
    return new Response(null, { status: 302, headers: { 'Location': '/' } });
}

async function handleDeleteAccount(request, env, config) {
    const formData = await request.formData();
    const id = formData.get('id');
    if (config.accounts) {
        config.accounts = config.accounts.filter(acc => acc.id !== id);
        // 删除账户：自动备份 (默认 true)
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
    // 兜底清洗文件名，杜绝引号/换行注入响应头
    const safeDownloadName = String(downloadName).replace(/[^A-Za-z0-9._-]/g, '_');
    headers.set('Content-Disposition', `attachment; filename="${safeDownloadName}"`);
    headers.set('Content-Type', 'application/json');
    return new Response(object.body, { headers });
}

// 只保留「备份目录下的直接子文件」，并排除 0 字节对象。
// 背景：在 R2 控制台「新建文件夹」会写入一个 key 以 "/" 结尾的 0 字节占位对象，
// list() 会把它一并返回；前端解析文件名后得到的是一个**空白条目**，点「恢复」必然失败。
// 因此这里在服务端就把它过滤掉，前端拿到的列表里不会再出现空条目。
function pickBackupFiles(objects, prefix) {
    return (objects || [])
        .filter(obj => {
            const rest = String(obj.key).slice(prefix.length);
            return rest.length > 0 && rest.indexOf('/') === -1 && obj.size !== 0;
        })
        .map(obj => ({ key: obj.key, size: obj.size, uploaded: obj.uploaded }))
        // R2 list() 按 key 字典序升序返回，这里显式降序排出「最新的在最前」
        .sort((a, b) => String(b.key).localeCompare(String(a.key)));
}

async function handleListBackups(env) {
    try {
        const prefix = 'backups/';
        const list = await env.DB.list({ prefix });
        return jsonResponse(pickBackupFiles(list.objects, prefix));
    } catch (e) {
        // 兜底：把异常转成 JSON，前端才能显示可读原因，而不是拿到一个 500 HTML 错误页
        return jsonResponse({ error: 'list_failed', message: String((e && e.message) || e) }, 500);
    }
}

async function handleRestore(request, env) {
    const formData = await request.formData();
    const file = formData.get('backup_file');
    const r2Key = formData.get('r2_key');

    let json;
    try {
        if (file && file instanceof File && file.size > 0) {
            if (file.size > 2 * 1024 * 1024) throw new Error("File too large (max 2MB)");
            try {
                json = JSON.parse(await file.text());
            } catch (e) {
                throw new Error("上传的文件不是有效的 JSON");
            }
        } else if (r2Key) {
            // 只允许回滚备份目录下的对象，避免被用来读取任意 key（如配置本体）
            if (!String(r2Key).startsWith('backups/')) throw new Error("Access Denied");
            // 目录占位符（key 以 "/" 结尾）不是备份文件，给出明确提示而不是让它走到解析失败
            if (String(r2Key).endsWith('/')) throw new Error("该条目不是备份文件");
            const obj = await env.DB.get(r2Key);
            if (!obj) throw new Error("Backup not found");
            if (obj.size === 0) throw new Error("该备份文件为空，无法恢复");
            try {
                json = await obj.json();
            } catch (e) {
                throw new Error("备份文件不是有效的 JSON");
            }
        } else {
            throw new Error("Invalid request");
        }

        if (!json || !json.username || !Array.isArray(json.accounts)) throw new Error("Format Error");
        // [修改] 恢复时也确保 sessions 结构正确
        if (!json.sessions) json.sessions = [];
        
        // 恢复数据：自动备份 (默认 true)
        await saveDataWithBackup(env, json);
        
        return logoutResponse();
    } catch (e) {
        return new Response('Restore failed: ' + e.message, { status: 500 });
    }
}

// --- 前端 UI ---

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

  /* 人机验证设置 */
  .ts-status { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; font-weight: 600; padding: 10px 12px; border-radius: 10px; margin-bottom: 15px; border: 1px solid var(--border); background: var(--bg); }
  .ts-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .ts-msg { font-size: 0.85rem; margin-bottom: 10px; line-height: 1.4; }
  .ts-msg.error { color: var(--danger); }
  .ts-msg.ok { color: #10b981; }
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

// --- UI 渲染函数 ---

function renderSetupPage() {
  return `<!DOCTYPE html><html><head><title>初始化</title>${commonHead}
  <style>body { align-items: center; }</style>
  </head><body>
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

function renderLoginPage(isError, msg, siteKey) {
  const appIconSvg = `
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" style="width:64px;height:64px;border-radius:14px;box-shadow:0 8px 15px -3px rgba(37, 99, 235, 0.3);">
    <rect width="512" height="512" fill="#2563eb"/>
    <path d="M256 48C150 48 64 134 64 240c0 88 57 163 136 186v-56c-49-20-80-69-80-125 0-75 61-136 136-136s136 61 136 136c0 56-31 105-80 125v56c79-23 136-98 136-186C448 134 362 48 256 48z" fill="#fff"/>
    <path d="M256 208c-35.3 0-64 28.7-64 64 0 21.6 10.9 40.4 27.2 52L200 384h112l-19.2-60c16.3-11.6 27.2-30.4 27.2-52 0-35.3-28.7-64-64-64z" fill="#fff"/>
  </svg>`;

  return `<!DOCTYPE html><html><head><title>登录 - Cloud Auth</title>${commonHead}
  ${siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
  <script>
    // [安全清理] 每次进入登录页，自动清理所有本地缓存和 Storage
    (async function clearLocalData() {
        try {
            if ('caches' in window) {
                const keys = await caches.keys();
                await Promise.all(keys.map(key => caches.delete(key)));
            }
            localStorage.clear();
            sessionStorage.clear();
            // [修复] 删除强制卸载 Service Worker 的逻辑，保留 PWA 能力
        } catch (e) { console.log('Cleanup error', e); }
    })();
  </script>
  <style>
    body { align-items: center; background: var(--bg); }
    .login-container { width: 100%; max-width: 400px; animation: slideUp 0.4s ease-out; }
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
  </head><body>
    <div class="login-container">
      <div class="brand-section">${appIconSvg}<div class="brand-title">欢迎回来</div><div class="brand-subtitle">请验证您的身份以继续</div></div>
      <div class="card" style="padding: 30px 25px;">
        ${isError ? `<div style="background:var(--danger-bg); color:var(--danger); padding:10px; border-radius:8px; font-size:0.9rem; text-align:center; margin-bottom:15px; display:flex; align-items:center; justify-content:center; gap:8px;"><span style="font-size:1.1rem">⚠️</span> ${msg || '用户名或密码错误'}</div>` : ''}
        <form action="/login" method="POST" onsubmit="this.querySelector('.btn').classList.add('loading')">
          <div class="input-group">
            <input type="text" name="username" class="input-field" required placeholder="用户名" autocomplete="username">
            <svg class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
          </div>
          <div class="input-group">
            <input type="password" name="password" id="pwdInput" class="input-field" required placeholder="主密码" autocomplete="current-password">
            <svg class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            <button type="button" class="toggle-password" onclick="togglePwd()" tabindex="-1"><span id="eyeIcon">👁️</span></button>
          </div>
          ${siteKey ? `<div class="turnstile-container"><div class="cf-turnstile" data-sitekey="${siteKey}" data-theme="auto"></div></div>` : ''}
          <button type="submit" class="btn" style="margin-top: 5px; padding: 14px;">立即登录</button>
        </form>
      </div>
      <p class="text-center text-sub" style="font-size:0.8rem; margin-top:25px; opacity:0.6;">Cloud Authenticator · 安全加密存储</p>
    </div>
    <script>
        function togglePwd() { const input = document.getElementById('pwdInput'); const icon = document.getElementById('eyeIcon'); if (input.type === 'password') { input.type = 'text'; icon.innerText = '🙈'; icon.style.opacity = '0.7'; } else { input.type = 'password'; icon.innerText = '👁️'; icon.style.opacity = '1'; } }
    </script>
  </body></html>`;
}

function renderDashboard(username, accounts, turnstileView) {
  // [安全修复] 后端转义用户名，防止 XSS
  const safeUsername = escapeHtml(username);
  
  // [安全修复] 在注入 JSON 到 script 标签时，防止 </script> 闭合标签逃逸攻击
  const accountsJson = JSON.stringify(accounts || []).replace(/</g, '\\u003c');
  const tv = turnstileView || { siteKey: '', siteKeySet: false, secretSet: false, secretMasked: '', enabled: false, source: 'none' };
  const tvJson = JSON.stringify(tv).replace(/</g, '\\u003c');

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
             <h2>⚙️ 设置</h2>
             
             <div class="settings-section">
                <div class="settings-title">数据备份</div>
                <div class="settings-grid">
                    <a href="/backup" class="btn btn-outline btn-block">⬇️ 下载当前</a>
                    <button onclick="openBackupModal()" class="btn btn-outline btn-block">🕒 备份历史</button>
                </div>
             </div>

             <div class="settings-section">
                <div class="settings-title">安全设置</div>
                <button onclick="openTurnstileModal()" class="btn btn-outline btn-block">🛡️ 人机验证 (Turnstile)</button>
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

    <div id="turnstileModal" class="modal">
      <div class="card" style="width:100%; max-width:360px; margin:0; max-height:88vh; overflow-y:auto;">
        <h2>🛡️ 人机验证</h2>
        <p class="text-sub text-center" style="margin-bottom:15px;">Cloudflare Turnstile 密钥，直接保存在 R2 中，无需再登录控制台配环境变量</p>

        <div id="tsStatus" class="ts-status"></div>

        <label class="text-sub">Site Key（公开值）</label>
        <input type="text" id="tsSiteKey" placeholder="0x4AAAAAAA..." autocomplete="off" spellcheck="false">

        <label class="text-sub">Secret Key（密钥，不会回显）</label>
        <input type="password" id="tsSecretKey" placeholder="留空则不修改" autocomplete="new-password" spellcheck="false">

        <div id="tsMsg" class="ts-msg"></div>

        <div class="flex-gap mt-4">
          <button type="button" class="btn btn-outline" onclick="backToSettings()">返回</button>
          <button type="button" class="btn" id="tsSaveBtn" onclick="saveTurnstile()">保存</button>
        </div>
        <div class="mt-4">
          <button type="button" class="btn btn-outline btn-block" id="tsClearBtn" onclick="clearTurnstile()" style="color:var(--danger); border-color:var(--danger);">清空密钥（关闭验证）</button>
        </div>
      </div>
    </div>

    <script>
      // JSON 数据已在后端进行转义处理
      const accounts = ${accountsJson};
      // 人机验证当前状态（Secret 只有掩码，永不回显）
      const TV = ${tvJson};
      
      // 设置中心逻辑
      function openSettings() { document.getElementById('settingsModal').classList.add('open'); }
      function closeSettings() { document.getElementById('settingsModal').classList.remove('open'); }
      
      function backToSettings() {
          document.getElementById('backupModal').classList.remove('open');
          document.getElementById('restoreModal').classList.remove('open');
          document.getElementById('turnstileModal').classList.remove('open');
          openSettings();
      }

      // --- 人机验证设置 ---
      let tsClearArmed = false;
      let tsClearTimer = null;

      function tsSetMsg(text, kind) {
          const el = document.getElementById('tsMsg');
          el.textContent = text || '';
          el.className = 'ts-msg' + (kind ? ' ' + kind : '');
      }

      function tsRenderStatus() {
          const box = document.getElementById('tsStatus');
          let color, text;
          if (TV.enabled && TV.source === 'settings') {
              color = '#10b981'; text = '已启用（来自应用内设置）';
          } else if (TV.enabled && TV.source === 'env') {
              color = '#f59e0b'; text = '已启用（来自环境变量，应用内尚未配置）';
          } else {
              color = '#9ca3af'; text = '未启用 — 登录页不会显示验证码';
          }
          box.innerHTML = '<span class="ts-dot"></span><span></span>';
          box.firstChild.style.background = color;
          box.lastChild.textContent = text;
      }

      function tsRefreshSecretHint() {
          const el = document.getElementById('tsSecretKey');
          el.value = '';
          el.placeholder = TV.secretSet
              ? ('已配置：' + TV.secretMasked + '（留空则不修改）')
              : '尚未配置';
      }

      function tsDisarmClear() {
          tsClearArmed = false;
          if (tsClearTimer) { clearTimeout(tsClearTimer); tsClearTimer = null; }
          const b = document.getElementById('tsClearBtn');
          b.textContent = '清空密钥（关闭验证）';
          b.style.background = 'transparent';
          b.style.color = 'var(--danger)';
      }

      function openTurnstileModal() {
          closeSettings();
          document.getElementById('tsSiteKey').value = TV.siteKey || '';
          tsRefreshSecretHint();
          tsSetMsg('');
          tsDisarmClear();
          tsRenderStatus();
          document.getElementById('turnstileModal').classList.add('open');
      }

      function tsApplyView(view) {
          TV.siteKey = view.siteKey || '';
          TV.siteKeySet = !!view.siteKeySet;
          TV.secretSet = !!view.secretSet;
          TV.secretMasked = view.secretMasked || '';
          TV.enabled = !!view.enabled;
          TV.source = view.source;
      }

      // secretKey 传 null 表示「不修改」（不发送该字段），传空串表示「清空」
      async function tsPost(siteKey, secretKey) {
          const body = new FormData();
          body.append('site_key', siteKey);
          if (secretKey !== null) body.append('secret_key', secretKey);
          const res = await fetch('/settings/turnstile', { method: 'POST', body: body });
          if (!res.ok) throw new Error((await res.text()) || '保存失败');
          return await res.json();
      }

      async function saveTurnstile() {
          const btn = document.getElementById('tsSaveBtn');
          const siteKey = document.getElementById('tsSiteKey').value.trim();
          const secretRaw = document.getElementById('tsSecretKey').value.trim();
          btn.classList.add('loading');
          tsSetMsg('');
          try {
              const view = await tsPost(siteKey, secretRaw === '' ? null : secretRaw);
              tsApplyView(view);
              document.getElementById('tsSiteKey').value = TV.siteKey;
              tsRefreshSecretHint();
              tsRenderStatus();
              tsSetMsg('已保存。密钥是服务端渲染进登录页的，下次打开登录页生效。', 'ok');
          } catch (e) {
              tsSetMsg(e.message, 'error');
          } finally {
              btn.classList.remove('loading');
          }
      }

      async function clearTurnstile() {
          const btn = document.getElementById('tsClearBtn');
          // 危险操作二次确认：4 秒后自动复位
          if (!tsClearArmed) {
              tsClearArmed = true;
              btn.textContent = '再点一次确认清空';
              btn.style.background = 'var(--danger)';
              btn.style.color = '#fff';
              tsClearTimer = setTimeout(tsDisarmClear, 4000);
              return;
          }
          tsDisarmClear();
          tsSetMsg('');
          try {
              const view = await tsPost('', '');
              tsApplyView(view);
              document.getElementById('tsSiteKey').value = '';
              tsRefreshSecretHint();
              tsRenderStatus();
              tsSetMsg('已清空，人机验证已关闭。', 'ok');
          } catch (e) {
              tsSetMsg(e.message, 'error');
          }
      }

      function openAddModal() { document.getElementById('addModal').classList.add('open'); }
      function closeAddModal() { stopScan(); document.getElementById('addModal').classList.remove('open'); }
      function closeBackupModal() { document.getElementById('backupModal').classList.remove('open'); }
      function closeRestoreModal() { document.getElementById('restoreModal').classList.remove('open'); }

      function openDeleteModal(id, issuer) {
         document.getElementById('deleteId').value = id;
         // [安全修复] 使用 textContent 而不是 innerText/innerHTML 防止 XSS
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

      // 从备份文件名解析出可读时间；解析不出来就退回显示原始文件名，
      // 绝不让一个命名不规范的文件把整个列表搞崩。
      function fmtBackupName(key) {
          const filename = String(key).split('/').pop();
          const raw = filename.split('_auto.json')[0].split('.json')[0];
          const parts = raw.split('_');
          if (parts.length >= 2 && parts[0].length === 10 && parts[1].length === 8) {
              return parts[0] + ' ' + parts[1].replace(/-/g, ':');
          }
          return filename;
      }

      function renderBackupError(container, mode, msg) {
          container.innerHTML = '';
          const box = document.createElement('div');
          box.className = 'text-center';
          box.style.padding = '20px';
          const p = document.createElement('div');
          p.className = 'text-sub';
          p.style.color = 'var(--danger)';
          p.style.marginBottom = '10px';
          p.textContent = msg;
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'btn btn-outline btn-sm';
          btn.textContent = '重试';
          btn.addEventListener('click', function () { loadBackupList(container, mode); });
          box.appendChild(p);
          box.appendChild(btn);
          container.appendChild(box);
      }

      async function loadBackupList(container, mode) {
          container.innerHTML = '<div class="text-center text-sub" style="padding:20px;">加载中...</div>';

          let res;
          try {
              res = await fetch('/backups/list', { credentials: 'same-origin' });
          } catch (e) {
              return renderBackupError(container, mode, '网络请求失败，请检查网络后重试');
          }

          // 先按状态码给出可读原因，避免把 HTML 错误页当成 JSON 去解析
          if (res.status === 401) return renderBackupError(container, mode, '登录已过期，请重新登录');
          if (res.status === 403) return renderBackupError(container, mode, '没有权限查看备份列表');

          let files;
          try {
              files = await res.json();
          } catch (e) {
              return renderBackupError(container, mode, '服务端返回了非 JSON 内容（HTTP ' + res.status + '）');
          }

          if (!res.ok) {
              const detail = (files && files.message) ? files.message : ('HTTP ' + res.status);
              return renderBackupError(container, mode, '服务端错误：' + detail);
          }
          if (!Array.isArray(files)) {
              return renderBackupError(container, mode, '备份列表格式异常');
          }
          // 双保险：即使服务端漏掉，这里也把解析不出文件名的异常条目（如 R2 文件夹占位符）过滤掉
          const valid = files.filter(function (f) { return fmtBackupName(f.key); });
          if (valid.length === 0) {
              container.innerHTML = '<div class="text-center text-sub" style="padding:20px;">暂无历史备份<br><span style="font-size:0.8rem;opacity:0.7">增删账户后会自动生成备份</span></div>';
              return;
          }

          // 用 DOM 构建而不是拼 HTML 字符串：既免去多层引号转义，也天然免疫 XSS
          container.innerHTML = '';
          valid.forEach(function (f) {
              const display = fmtBackupName(f.key);

              const label = document.createElement('div');
              label.className = 'backup-date';
              label.textContent = display;

              if (mode === 'download') {
                  const a = document.createElement('a');
                  a.className = 'backup-item';
                  a.href = '/backup?file=' + encodeURIComponent(f.key);
                  a.appendChild(label);
                  const d = document.createElement('div');
                  d.className = 'backup-size';
                  d.textContent = '下载';
                  a.appendChild(d);
                  container.appendChild(a);
                  return;
              }

              const item = document.createElement('div');
              item.className = 'backup-item';
              item.appendChild(label);

              const form = document.createElement('form');
              form.action = '/restore';
              form.method = 'POST';
              form.style.margin = '0';
              const input = document.createElement('input');
              input.type = 'hidden';
              input.name = 'r2_key';
              input.value = f.key;
              form.appendChild(input);
              const btn = document.createElement('button');
              btn.type = 'submit';
              btn.className = 'restore-action-btn';
              btn.textContent = '恢复';
              form.appendChild(btn);
              form.addEventListener('submit', function (ev) {
                  if (!confirm('确定回滚到 ' + display + ' 吗？')) ev.preventDefault();
              });
              item.appendChild(form);
              container.appendChild(item);
          });
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
              list.innerHTML = accounts.map(acc => {
                  // [安全修复] 前端 XSS 防护，转义渲染
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
