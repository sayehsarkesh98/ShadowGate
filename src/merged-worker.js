// ============================================
// Edge Tunnel + Management System - Merged Worker
// Version: 1.0.0
// Features: UUID Management, Bandwidth Control, Admin Panel
// ============================================

// ============================================
// Management System Configuration
// ============================================
const ADMIN_PASSWORD = 'admin123';
const REQUESTS_PER_KB = 5;

// ============================================
// Main Fetch Handler
// ============================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // CORS headers
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        // Handle preflight
        if (method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        // ============================================
        // Management System Routes (Priority)
        // ============================================

        // Admin panel routes
        if (path === '/' || path === '/admin' || path === '/admin/') {
            return getAdminPanel(env, corsHeaders);
        }
        if (path === '/status') {
            return getStatusPanel(env, corsHeaders);
        }

        // API routes
        if (path === '/api/auth/login' && method === 'POST') {
            return handleLogin(request, env, corsHeaders);
        }
        if (path === '/api/auth/logout' && method === 'POST') {
            return handleLogout(request, env, corsHeaders);
        }
        if (path.startsWith('/api/admin/')) {
            return handleAdminRoutes(request, env, ctx, path, method, corsHeaders);
        }
        if (path.startsWith('/api/user/')) {
            return handleUserRoutes(request, env, ctx, path, method, corsHeaders);
        }
        if (path === '/api/health') {
            return jsonResponse({ status: 'ok', timestamp: Date.now() }, 200, corsHeaders);
        }

        // ============================================
        // Edge Tunnel Routes (Original Functionality)
        // ============================================

        try {
            // Edge Tunnel original code starts here
            const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
            const contentType = (request.headers.get('content-type') || '').toLowerCase();

            // Admin password from env
            const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
            const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';

            // UUID handling
            const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
            const envUUID = env.UUID || env.uuid;
            const userID = envUUID && uuidRegex.test(envUUID) ? envUUID.toLowerCase() : await generateDefaultUUID(管理员密码, 加密秘钥);

            // Check if this is a UUID validation request
            if (path === '/' && method === 'GET') {
                const 请求UUID = (url.searchParams.get('uuid') || '').toLowerCase();
                if (uuidRegex.test(请求UUID)) {
                    // Validate UUID against database
                    const isValid = await validateUUID(env, 请求UUID);
                    if (isValid) {
                        return new Response(JSON.stringify({ Version: 1 }), {
                            status: 200,
                            headers: { 'Content-Type': 'application/json;charset=utf-8' }
                        });
                    }
                }
            }

            // WebSocket proxy
            if (管理员密码 && upgradeHeader === 'websocket') {
                // Check UUID validity before allowing connection
                if (envUUID) {
                    const isValid = await validateUUID(env, envUUID);
                    if (!isValid) {
                        return new Response('UUID not valid or expired', { status: 403 });
                    }
                    // Track bandwidth
                    await trackBandwidth(env, envUUID, 1);
                }
                // Original WebSocket handling would go here
                // For now, return a placeholder
                return new Response('WebSocket proxy - original code needed', { status: 101 });
            }

            // gRPC/XHTTP proxy
            if (管理员密码 && !path.startsWith('admin/') && path !== 'login' && method === 'POST') {
                // Check UUID validity
                if (envUUID) {
                    const isValid = await validateUUID(env, envUUID);
                    if (!isValid) {
                        return new Response('UUID not valid or expired', { status: 403 });
                    }
                    // Track bandwidth
                    await trackBandwidth(env, envUUID, 1);
                }
                // Original gRPC handling would go here
                return new Response('gRPC proxy - original code needed', { status: 200 });
            }

            // Return 404 for unmatched routes
            return new Response('Not found', { status: 404 });

        } catch (error) {
            console.error('Worker error:', error);
            return new Response('Internal server error', { status: 500 });
        }
    }
};

// ============================================
// Management System Functions
// ============================================

async function validateUUID(env, uuid) {
    try {
        const user = await env.DB.prepare(
            'SELECT * FROM users WHERE uuid = ? AND is_active = 1'
        ).bind(uuid).first();

        if (!user) return false;

        // Check expiration
        if (user.expires_at && new Date(user.expires_at) < new Date()) {
            return false;
        }

        // Check bandwidth limit
        if (user.max_bandwidth_mb > 0) {
            const totalUsed = await env.DB.prepare(
                'SELECT SUM(total_bytes) as total FROM bandwidth_usage WHERE user_id = ?'
            ).bind(user.id).first();

            if ((totalUsed?.total || 0) >= user.max_bandwidth_mb * 1024 * 1024) {
                return false;
            }
        }

        return true;
    } catch (error) {
        console.error('UUID validation error:', error);
        return true; // Allow on error
    }
}

async function trackBandwidth(env, uuid, requestCount = 1) {
    try {
        const user = await env.DB.prepare(
            'SELECT id FROM users WHERE uuid = ?'
        ).bind(uuid).first();

        if (!user) return;

        const bytes = Math.ceil(requestCount / REQUESTS_PER_KB) * 1024;
        const today = new Date().toISOString().split('T')[0];

        await env.DB.prepare(
            `INSERT INTO bandwidth_usage (user_id, date, bytes_up, total_bytes, request_count)
             VALUES (?, ?, 0, ?, ?)
             ON CONFLICT(user_id, date)
             DO UPDATE SET
                total_bytes = total_bytes + ?,
                request_count = request_count + ?`
        ).bind(user.id, today, bytes, requestCount, bytes, requestCount).run();

        // Update last used
        await env.DB.prepare(
            'UPDATE users SET last_used_at = datetime("now") WHERE id = ?'
        ).bind(user.id).run();
    } catch (error) {
        console.error('Track bandwidth error:', error);
    }
}

async function generateDefaultUUID(password, key) {
    const md5 = await MD5MD5(password + key);
    return [md5.slice(0, 8), md5.slice(8, 12), '4' + md5.slice(13, 16), '8' + md5.slice(17, 20), md5.slice(20)].join('-');
}

// ============================================
// Authentication
// ============================================

async function handleLogin(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const password = body?.password;

        if (!password) {
            return jsonResponse({ error: 'Password required' }, 400, corsHeaders);
        }

        if (password !== ADMIN_PASSWORD) {
            return jsonResponse({ error: 'Invalid password' }, 401, corsHeaders);
        }

        const token = generateToken();
        return jsonResponse({ success: true, token }, 200, corsHeaders);

    } catch (error) {
        return jsonResponse({ error: 'Login failed' }, 500, corsHeaders);
    }
}

async function handleLogout(request, env, corsHeaders) {
    return jsonResponse({ success: true }, 200, corsHeaders);
}

async function verifyAuth(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
    const token = authHeader.slice(7);
    return token && token.length > 10;
}

// ============================================
// Admin Routes
// ============================================

async function handleAdminRoutes(request, env, ctx, path, method, corsHeaders) {
    if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, corsHeaders);
    }

    const route = path.replace('/api/admin/', '');

    if (route === 'stats' && method === 'GET') return getDashboardStats(env, corsHeaders);
    if (route === 'users' && method === 'GET') return getUsers(env, request, corsHeaders);
    if (route === 'users' && method === 'POST') return createUser(request, env, corsHeaders);
    if (route.startsWith('users/') && method === 'GET') {
        const uuid = route.split('/')[1];
        return getUserDetails(uuid, env, corsHeaders);
    }
    if (route.startsWith('users/') && method === 'PUT') {
        const uuid = route.split('/')[1];
        return updateUser(uuid, request, env, corsHeaders);
    }
    if (route.startsWith('users/') && method === 'DELETE') {
        const uuid = route.split('/')[1];
        return deleteUser(uuid, env, corsHeaders);
    }
    if (route === 'users/bulk' && method === 'POST') return bulkCreateUsers(request, env, corsHeaders);
    if (route === 'bandwidth' && method === 'GET') return getBandwidthStats(env, request, corsHeaders);
    if (route === 'logs' && method === 'GET') return getLogs(env, request, corsHeaders);
    if (route === 'settings' && method === 'GET') return getSettings(env, corsHeaders);
    if (route === 'settings' && method === 'PUT') return updateSettings(request, env, corsHeaders);

    return jsonResponse({ error: 'Not found' }, 404, corsHeaders);
}

// ============================================
// User Routes
// ============================================

async function handleUserRoutes(request, env, ctx, path, method, corsHeaders) {
    const route = path.replace('/api/user/', '');

    if (route === 'status' && method === 'GET') {
        const uuid = new URL(request.url).searchParams.get('uuid');
        if (!uuid) return jsonResponse({ error: 'UUID required' }, 400, corsHeaders);
        return getUserStatus(uuid, env, corsHeaders);
    }

    if (route === 'track' && method === 'POST') {
        return trackBandwidthAPI(request, env, corsHeaders);
    }

    return jsonResponse({ error: 'Not found' }, 404, corsHeaders);
}

// ============================================
// Helper Functions
// ============================================

function generateToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 32; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function jsonResponse(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json;charset=utf-8',
            ...headers
        }
    });
}

// ============================================
// Dashboard Stats
// ============================================

async function getDashboardStats(env, corsHeaders) {
    try {
        const totalUsers = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();
        const activeUsers = await env.DB.prepare('SELECT COUNT(*) as count FROM users WHERE is_active = 1').first();
        const expiredUsers = await env.DB.prepare('SELECT COUNT(*) as count FROM users WHERE expires_at < datetime("now")').first();
        const totalBandwidth = await env.DB.prepare('SELECT SUM(total_bytes) as total FROM bandwidth_usage').first();
        const todayBandwidth = await env.DB.prepare('SELECT SUM(total_bytes) as total FROM bandwidth_usage WHERE date = date("now")').first();
        const activeConnections = await env.DB.prepare('SELECT COUNT(*) as count FROM active_connections').first();

        return jsonResponse({
            stats: {
                totalUsers: totalUsers?.count || 0,
                activeUsers: activeUsers?.count || 0,
                expiredUsers: expiredUsers?.count || 0,
                totalBandwidth: totalBandwidth?.total || 0,
                todayBandwidth: todayBandwidth?.total || 0,
                activeConnections: activeConnections?.count || 0
            }
        }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to get stats' }, 500, corsHeaders);
    }
}

// ============================================
// User Management
// ============================================

async function getUsers(env, request, corsHeaders) {
    try {
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '20');
        const search = url.searchParams.get('search') || '';
        const offset = (page - 1) * limit;

        let query = 'SELECT * FROM users';
        let countQuery = 'SELECT COUNT(*) as count FROM users';

        if (search) {
            query += ' WHERE uuid LIKE ? OR username LIKE ?';
            countQuery += ' WHERE uuid LIKE ? OR username LIKE ?';
        }

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';

        const users = search
            ? await env.DB.prepare(query).bind(`%${search}%`, `%${search}%`, limit, offset).all()
            : await env.DB.prepare(query).bind(limit, offset).all();

        const total = search
            ? await env.DB.prepare(countQuery).bind(`%${search}%`, `%${search}%`).first()
            : await env.DB.prepare(countQuery).first();

        return jsonResponse({
            users: users.results,
            pagination: {
                page,
                limit,
                total: total?.count || 0,
                pages: Math.ceil((total?.count || 0) / limit)
            }
        }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to get users' }, 500, corsHeaders);
    }
}

async function createUser(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const { username, max_connections, max_bandwidth_mb, expires_at, notes } = body;
        const uuid = generateUUID();

        const result = await env.DB.prepare(
            `INSERT INTO users (uuid, username, max_connections, max_bandwidth_mb, expires_at, notes)
             VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(uuid, username || '', max_connections || 1, max_bandwidth_mb || 0, expires_at || null, notes || '').run();

        await env.DB.prepare(
            'INSERT INTO connection_logs (event_type, details) VALUES (?, ?)'
        ).bind('user_created', `UUID: ${uuid}`).run();

        return jsonResponse({
            success: true,
            user: { id: result.meta?.last_row_id, uuid, username, max_connections, max_bandwidth_mb, expires_at, notes }
        }, 201, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to create user' }, 500, corsHeaders);
    }
}

async function getUserDetails(uuid, env, corsHeaders) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();
        if (!user) return jsonResponse({ error: 'User not found' }, 404, corsHeaders);

        const bandwidth = await env.DB.prepare(
            'SELECT * FROM bandwidth_usage WHERE user_id = ? ORDER BY date DESC LIMIT 30'
        ).bind(user.id).all();

        const connections = await env.DB.prepare(
            'SELECT * FROM active_connections WHERE user_id = ?'
        ).bind(user.id).all();

        return jsonResponse({ user, bandwidth: bandwidth.results, connections: connections.results }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to get user' }, 500, corsHeaders);
    }
}

async function updateUser(uuid, request, env, corsHeaders) {
    try {
        const body = await request.json();
        const { username, max_connections, max_bandwidth_mb, expires_at, is_active, notes } = body;

        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();
        if (!user) return jsonResponse({ error: 'User not found' }, 404, corsHeaders);

        await env.DB.prepare(
            `UPDATE users SET
                username = COALESCE(?, username),
                max_connections = COALESCE(?, max_connections),
                max_bandwidth_mb = COALESCE(?, max_bandwidth_mb),
                expires_at = COALESCE(?, expires_at),
                is_active = COALESCE(?, is_active),
                notes = COALESCE(?, notes),
                updated_at = datetime('now')
             WHERE uuid = ?`
        ).bind(username, max_connections, max_bandwidth_mb, expires_at, is_active, notes, uuid).run();

        return jsonResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to update user' }, 500, corsHeaders);
    }
}

async function deleteUser(uuid, env, corsHeaders) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();
        if (!user) return jsonResponse({ error: 'User not found' }, 404, corsHeaders);

        await env.DB.prepare('DELETE FROM users WHERE uuid = ?').bind(uuid).run();
        await env.DB.prepare('DELETE FROM bandwidth_usage WHERE user_id = ?').bind(user.id).run();
        await env.DB.prepare('DELETE FROM active_connections WHERE user_id = ?').bind(user.id).run();

        return jsonResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to delete user' }, 500, corsHeaders);
    }
}

async function bulkCreateUsers(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const { count, prefix, max_connections, max_bandwidth_mb, expires_at } = body;
        const users = [];

        for (let i = 0; i < count; i++) {
            const uuid = generateUUID();
            const username = prefix ? `${prefix}-${i + 1}` : '';

            await env.DB.prepare(
                `INSERT INTO users (uuid, username, max_connections, max_bandwidth_mb, expires_at)
                 VALUES (?, ?, ?, ?, ?)`
            ).bind(uuid, username, max_connections || 1, max_bandwidth_mb || 0, expires_at || null).run();

            users.push({ uuid, username });
        }

        return jsonResponse({ success: true, users }, 201, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to bulk create users' }, 500, corsHeaders);
    }
}

// ============================================
// Bandwidth Tracking
// ============================================

async function trackBandwidthAPI(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const { uuid, request_count = 1 } = body;

        if (!uuid) return jsonResponse({ error: 'UUID required' }, 400, corsHeaders);

        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ? AND is_active = 1').bind(uuid).first();
        if (!user) return jsonResponse({ error: 'Invalid or inactive UUID' }, 401, corsHeaders);

        if (user.expires_at && new Date(user.expires_at) < new Date()) {
            return jsonResponse({ error: 'UUID expired' }, 403, corsHeaders);
        }

        const bytes = Math.ceil(request_count / REQUESTS_PER_KB) * 1024;

        if (user.max_bandwidth_mb > 0) {
            const totalUsed = await env.DB.prepare(
                'SELECT SUM(total_bytes) as total FROM bandwidth_usage WHERE user_id = ?'
            ).bind(user.id).first();

            if ((totalUsed?.total || 0) + bytes > user.max_bandwidth_mb * 1024 * 1024) {
                return jsonResponse({ error: 'Bandwidth limit exceeded' }, 403, corsHeaders);
            }
        }

        const today = new Date().toISOString().split('T')[0];
        await env.DB.prepare(
            `INSERT INTO bandwidth_usage (user_id, date, bytes_up, total_bytes, request_count)
             VALUES (?, ?, 0, ?, ?)
             ON CONFLICT(user_id, date)
             DO UPDATE SET total_bytes = total_bytes + ?, request_count = request_count + ?`
        ).bind(user.id, today, bytes, request_count, bytes, request_count).run();

        await env.DB.prepare('UPDATE users SET last_used_at = datetime("now") WHERE id = ?').bind(user.id).run();

        return jsonResponse({ success: true, bytes_added: bytes }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to track bandwidth' }, 500, corsHeaders);
    }
}

async function getBandwidthStats(env, request, corsHeaders) {
    try {
        const url = new URL(request.url);
        const days = parseInt(url.searchParams.get('days') || '7');

        const stats = await env.DB.prepare(
            `SELECT date, SUM(total_bytes) as total_bytes, SUM(request_count) as total_requests
             FROM bandwidth_usage
             WHERE date >= date('now', '-' || ? || ' days')
             GROUP BY date ORDER BY date DESC`
        ).bind(days).all();

        return jsonResponse({ stats: stats.results }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to get bandwidth stats' }, 500, corsHeaders);
    }
}

// ============================================
// User Status
// ============================================

async function getUserStatus(uuid, env, corsHeaders) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();
        if (!user) return jsonResponse({ error: 'Invalid UUID' }, 404, corsHeaders);

        const totalBandwidth = await env.DB.prepare(
            'SELECT SUM(total_bytes) as total FROM bandwidth_usage WHERE user_id = ?'
        ).bind(user.id).first();

        const todayBandwidth = await env.DB.prepare(
            'SELECT total_bytes FROM bandwidth_usage WHERE user_id = ? AND date = date("now")'
        ).bind(user.id).first();

        const isExpired = user.expires_at && new Date(user.expires_at) < new Date();

        return jsonResponse({
            user: {
                uuid: user.uuid,
                username: user.username,
                is_active: user.is_active === 1 && !isExpired,
                expires_at: user.expires_at,
                max_bandwidth_mb: user.max_bandwidth_mb,
                total_used_bytes: totalBandwidth?.total || 0,
                today_used_bytes: todayBandwidth?.total_bytes || 0,
                last_used_at: user.last_used_at
            }
        }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to get user status' }, 500, corsHeaders);
    }
}

// ============================================
// Logs & Settings
// ============================================

async function getLogs(env, request, corsHeaders) {
    try {
        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit') || '50');

        const logs = await env.DB.prepare(
            'SELECT * FROM connection_logs ORDER BY created_at DESC LIMIT ?'
        ).bind(limit).all();

        return jsonResponse({ logs: logs.results }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to get logs' }, 500, corsHeaders);
    }
}

async function getSettings(env, corsHeaders) {
    try {
        const settings = await env.DB.prepare('SELECT * FROM settings').all();
        const settingsObj = {};
        settings.results.forEach(s => { settingsObj[s.key] = s.value; });
        return jsonResponse({ settings: settingsObj }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to get settings' }, 500, corsHeaders);
    }
}

async function updateSettings(request, env, corsHeaders) {
    try {
        const body = await request.json();
        for (const [key, value] of Object.entries(body)) {
            await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind(key, String(value)).run();
        }
        return jsonResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
        return jsonResponse({ error: 'Failed to update settings' }, 500, corsHeaders);
    }
}

// ============================================
// Admin Panel HTML (Compact)
// ============================================

function getAdminPanel(env, corsHeaders) {
    const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edge Manager</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',Tahoma,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
        .login-container{display:flex;justify-content:center;align-items:center;min-height:100vh;background:linear-gradient(135deg,#1e293b,#0f172a)}
        .login-box{background:#1e293b;padding:2rem;border-radius:1rem;width:100%;max-width:400px}
        .login-box h1{text-align:center;color:#60a5fa;margin-bottom:1.5rem}
        .login-box input{width:100%;padding:.75rem;margin-bottom:1rem;border:1px solid #334155;border-radius:.5rem;background:#0f172a;color:#e2e8f0}
        .login-box button{width:100%;padding:.75rem;background:#3b82f6;color:white;border:none;border-radius:.5rem;cursor:pointer}
        .login-box button:hover{background:#2563eb}
        .dashboard{display:none}
        .header{background:#1e293b;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #334155}
        .header h1{color:#60a5fa;font-size:1.25rem}
        .header button{background:#ef4444;color:white;padding:.5rem 1rem;border:none;border-radius:.5rem;cursor:pointer}
        .container{padding:2rem;max-width:1400px;margin:0 auto}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}
        .stat-card{background:#1e293b;padding:1.5rem;border-radius:.75rem;border:1px solid #334155}
        .stat-card h3{color:#94a3b8;font-size:.875rem;margin-bottom:.5rem}
        .stat-card .value{font-size:1.75rem;font-weight:bold;color:#60a5fa}
        .stat-card.success .value{color:#10b981}
        .stat-card.warning .value{color:#f59e0b}
        .stat-card.danger .value{color:#ef4444}
        .tabs{display:flex;gap:.5rem;margin-bottom:1.5rem;flex-wrap:wrap}
        .tab{padding:.75rem 1.5rem;background:#1e293b;border:1px solid #334155;border-radius:.5rem;cursor:pointer}
        .tab:hover,.tab.active{background:#3b82f6;border-color:#3b82f6}
        .panel{display:none;background:#1e293b;border-radius:.75rem;padding:1.5rem;border:1px solid #334155}
        .panel.active{display:block}
        .table-container{overflow-x:auto}
        table{width:100%;border-collapse:collapse}
        th,td{padding:.75rem;text-align:right;border-bottom:1px solid #334155}
        th{background:#0f172a;color:#94a3b8}
        tr:hover{background:#334155}
        .btn{padding:.5rem 1rem;border:none;border-radius:.375rem;cursor:pointer;font-size:.875rem}
        .btn-primary{background:#3b82f6;color:white}
        .btn-success{background:#10b981;color:white}
        .btn-danger{background:#ef4444;color:white}
        .btn-sm{padding:.25rem .5rem;font-size:.75rem}
        .form-group{margin-bottom:1rem}
        .form-group label{display:block;margin-bottom:.5rem;color:#94a3b8}
        .form-group input,.form-group select{width:100%;padding:.75rem;border:1px solid #334155;border-radius:.5rem;background:#0f172a;color:#e2e8f0}
        .modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.8);z-index:1000;justify-content:center;align-items:center}
        .modal.active{display:flex}
        .modal-content{background:#1e293b;padding:2rem;border-radius:1rem;width:100%;max-width:500px;max-height:90vh;overflow-y:auto}
        .badge{padding:.25rem .5rem;border-radius:.25rem;font-size:.75rem}
        .badge-success{background:#10b981;color:white}
        .badge-danger{background:#ef4444;color:white}
    </style>
</head>
<body>
    <div id="loginPage" class="login-container">
        <div class="login-box">
            <h1>🔐 Edge Manager</h1>
            <input type="password" id="loginPassword" placeholder="رمز عبور" onkeypress="if(event.key==='Enter')login()">
            <button onclick="login()">ورود</button>
        </div>
    </div>
    <div id="dashboardPage" class="dashboard">
        <div class="header">
            <h1>⚡ Edge Manager</h1>
            <button onclick="logout()">خروج</button>
        </div>
        <div class="container">
            <div class="stats-grid">
                <div class="stat-card"><h3>کل کاربران</h3><div class="value" id="totalUsers">0</div></div>
                <div class="stat-card success"><h3>فعال</h3><div class="value" id="activeUsers">0</div></div>
                <div class="stat-card warning"><h3>حجم امروز</h3><div class="value" id="todayBandwidth">0 KB</div></div>
                <div class="stat-card danger"><h3>اتصالات</h3><div class="value" id="activeConnections">0</div></div>
            </div>
            <div class="tabs">
                <div class="tab active" onclick="showTab('users')">👥 کاربران</div>
                <div class="tab" onclick="showTab('bandwidth')">📊 پهنای باند</div>
                <div class="tab" onclick="showTab('logs')">📋 لاگ‌ها</div>
            </div>
            <div id="usersPanel" class="panel active">
                <button class="btn btn-primary" onclick="showCreateModal()" style="margin-bottom:1rem">➕ کاربر جدید</button>
                <div class="table-container">
                    <table>
                        <thead><tr><th>UUID</th><th>نام</th><th>وضعیت</th><th>حجم</th><th>انقضا</th><th>عملیات</th></tr></thead>
                        <tbody id="usersTable"></tbody>
                    </table>
                </div>
            </div>
            <div id="bandwidthPanel" class="panel">
                <div class="table-container">
                    <table>
                        <thead><tr><th>تاریخ</th><th>حجم</th><th>درخواست</th></tr></thead>
                        <tbody id="bandwidthTable"></tbody>
                    </table>
                </div>
            </div>
            <div id="logsPanel" class="panel">
                <div class="table-container">
                    <table>
                        <thead><tr><th>زمان</th><th>نوع</th><th>جزئیات</th></tr></thead>
                        <tbody id="logsTable"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <div id="createModal" class="modal">
        <div class="modal-content">
            <h2 style="margin-bottom:1rem;color:#60a5fa">➕ کاربر جدید</h2>
            <div class="form-group"><label>نام</label><input type="text" id="newUsername"></div>
            <div class="form-group"><label>حد اتصال</label><input type="number" id="newMaxConn" value="1"></div>
            <div class="form-group"><label>حجم (MB, 0=نامحدود)</label><input type="number" id="newMaxBW" value="0"></div>
            <div class="form-group"><label>انقضا</label><input type="date" id="newExpires"></div>
            <button class="btn btn-primary" onclick="createUser()" style="width:100%">ایجاد</button>
            <button class="btn btn-danger" onclick="closeModal()" style="width:100%;margin-top:.5rem">لغو</button>
        </div>
    </div>
    <script>
        let token=localStorage.getItem('admin_token');
        if(token)showDashboard();
        async function login(){
            const res=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('loginPassword').value})});
            const data=await res.json();
            if(data.success){token=data.token;localStorage.setItem('admin_token',token);showDashboard()}else alert(data.error);
        }
        function logout(){token=null;localStorage.removeItem('admin_token');document.getElementById('loginPage').style.display='flex';document.getElementById('dashboardPage').style.display='none'}
        function showDashboard(){document.getElementById('loginPage').style.display='none';document.getElementById('dashboardPage').style.display='block';loadStats();loadUsers()}
        async function loadStats(){
            const res=await fetch('/api/admin/stats',{headers:{'Authorization':'Bearer '+token}});
            const data=await res.json();
            if(data.stats){document.getElementById('totalUsers').textContent=data.stats.totalUsers;document.getElementById('activeUsers').textContent=data.stats.activeUsers;document.getElementById('todayBandwidth').textContent=formatBytes(data.stats.todayBandwidth);document.getElementById('activeConnections').textContent=data.stats.activeConnections}
        }
        async function loadUsers(){
            const res=await fetch('/api/admin/users',{headers:{'Authorization':'Bearer '+token}});
            const data=await res.json();
            document.getElementById('usersTable').innerHTML=(data.users||[]).map(u=>{
                const expired=u.expires_at&&new Date(u.expires_at)<new Date();
                const badge=u.is_active&&!expired?'<span class="badge badge-success">فعال</span>':'<span class="badge badge-danger">غیرفعال</span>';
                return '<tr><td style="font-family:monospace;font-size:.75rem">'+u.uuid+'</td><td>'+(u.username||'-')+'</td><td>'+badge+'</td><td>'+(u.max_bandwidth_mb>0?u.max_bandwidth_mb+' MB':'نامحدود')+'</td><td>'+(u.expires_at||'ندارد')+'</td><td><button class="btn btn-primary btn-sm" onclick="copyUUID(\\''+u.uuid+'\\')">کپی</button> <button class="btn btn-danger btn-sm" onclick="deleteUser(\\''+u.uuid+'\\')">حذف</button></td></tr>';
            }).join('');
        }
        function showCreateModal(){document.getElementById('createModal').classList.add('active')}
        function closeModal(){document.getElementById('createModal').classList.remove('active')}
        async function createUser(){
            await fetch('/api/admin/users',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({username:document.getElementById('newUsername').value,max_connections:parseInt(document.getElementById('newMaxConn').value),max_bandwidth_mb:parseInt(document.getElementById('newMaxBW').value),expires_at:document.getElementById('newExpires').value||null})});
            closeModal();loadUsers();loadStats();
        }
        async function deleteUser(uuid){if(!confirm('حذف شود؟'))return;await fetch('/api/admin/users/'+uuid,{method:'DELETE',headers:{'Authorization':'Bearer '+token}});loadUsers();loadStats()}
        function copyUUID(uuid){navigator.clipboard.writeText(uuid);alert('کپی شد!')}
        async function loadBandwidth(){
            const res=await fetch('/api/admin/bandwidth?days=30',{headers:{'Authorization':'Bearer '+token}});
            const data=await res.json();
            document.getElementById('bandwidthTable').innerHTML=(data.stats||[]).map(s=>'<tr><td>'+s.date+'</td><td>'+formatBytes(s.total_bytes)+'</td><td>'+(s.total_requests||0)+'</td></tr>').join('');
        }
        async function loadLogs(){
            const res=await fetch('/api/admin/logs?limit=50',{headers:{'Authorization':'Bearer '+token}});
            const data=await res.json();
            document.getElementById('logsTable').innerHTML=(data.logs||[]).map(l=>'<tr><td>'+l.created_at+'</td><td>'+l.event_type+'</td><td>'+(l.details||'-')+'</td></tr>').join('');
        }
        function showTab(name){
            document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(name+'Panel').classList.add('active');
            if(name==='bandwidth')loadBandwidth();
            if(name==='logs')loadLogs();
        }
        function formatBytes(b){if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i]}
    </script>
</body>
</html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders } });
}

// ============================================
// User Status Panel HTML
// ============================================

function getStatusPanel(env, corsHeaders) {
    const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>بررسی وضعیت</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',Tahoma,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;justify-content:center;align-items:center}
        .container{background:#1e293b;padding:2rem;border-radius:1rem;width:100%;max-width:400px;text-align:center}
        h1{color:#60a5fa;margin-bottom:1.5rem}
        input{width:100%;padding:.75rem;margin-bottom:1rem;border:1px solid #334155;border-radius:.5rem;background:#0f172a;color:#e2e8f0;text-align:center}
        button{width:100%;padding:.75rem;background:#3b82f6;color:white;border:none;border-radius:.5rem;cursor:pointer}
        .result{margin-top:1.5rem;padding:1rem;background:#0f172a;border-radius:.5rem;display:none;text-align:right}
        .result.show{display:block}
        .row{display:flex;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid #334155}
        .label{color:#94a3b8}.value{color:#60a5fa;font-weight:bold}
        .active{color:#10b981}.inactive{color:#ef4444}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 بررسی وضعیت</h1>
        <input type="text" id="uuidInput" placeholder="UUID خود را وارد کنید">
        <button onclick="checkStatus()">بررسی</button>
        <div id="result" class="result">
            <div class="row"><span class="label">وضعیت:</span><span class="value" id="status">-</span></div>
            <div class="row"><span class="label">نام:</span><span class="value" id="username">-</span></div>
            <div class="row"><span class="label">حجم مصرفی:</span><span class="value" id="used">-</span></div>
            <div class="row"><span class="label">باقی‌مانده:</span><span class="value" id="remain">-</span></div>
            <div class="row"><span class="label">انقضا:</span><span class="value" id="expires">-</span></div>
        </div>
    </div>
    <script>
        async function checkStatus(){
            const uuid=document.getElementById('uuidInput').value;
            if(!uuid){alert('UUID را وارد کنید');return}
            const res=await fetch('/api/user/status?uuid='+encodeURIComponent(uuid));
            const data=await res.json();
            if(data.user){
                const u=data.user;
                document.getElementById('result').classList.add('show');
                document.getElementById('status').textContent=u.is_active?'فعال ✅':'غیرفعال ❌';
                document.getElementById('status').className='value '+(u.is_active?'active':'inactive');
                document.getElementById('username').textContent=u.username||'-';
                document.getElementById('used').textContent=formatBytes(u.total_used_bytes);
                document.getElementById('remain').textContent=u.max_bandwidth_mb>0?formatBytes(u.max_bandwidth_mb*1024*1024-u.total_used_bytes):'نامحدود';
                document.getElementById('expires').textContent=u.expires_at||'ندارد';
            }else alert('UUID یافت نشد');
        }
        function formatBytes(b){if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i]}
    </script>
</body>
</html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders } });
}

// ============================================
// MD5 Helper (for Edge Tunnel compatibility)
// ============================================

async function MD5MD5(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('MD5', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
