// ============================================
// Edge Tunnel Manager - Cloudflare Worker
// Professional UUID Management + Bandwidth Control
// Version: 1.0.0
// ============================================

// Admin password - CHANGE THIS IN PRODUCTION
const ADMIN_PASSWORD = 'admin123';

// Bandwidth calculation: 5 requests = 1KB
const REQUESTS_PER_KB = 5;

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

        try {
            // API Routes
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

            // Serve admin panel
            if (path === '/' || path === '/admin' || path === '/admin/') {
                return getAdminPanel(env, corsHeaders);
            }

            // Serve user status page
            if (path === '/status') {
                return getStatusPanel(env, corsHeaders);
            }

            return jsonResponse({ error: 'Not found' }, 404, corsHeaders);
        } catch (error) {
            console.error('Worker error:', error);
            return jsonResponse({ error: 'Internal server error' }, 500, corsHeaders);
        }
    }
};

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

        // Get password from DB settings, fallback to env vars
        let storedPassword = ADMIN_PASSWORD;
        try {
            const dbSetting = await env.DB.prepare(
                'SELECT value FROM settings WHERE key = ?'
            ).bind('admin_password').first();
            if (dbSetting && dbSetting.value) {
                storedPassword = dbSetting.value;
            }
        } catch (e) {
            // DB not available, use env fallback
        }
        if (env.ADMIN_PASSWORD) storedPassword = env.ADMIN_PASSWORD;
        if (env.ADMIN) storedPassword = env.ADMIN;

        // Check password
        if (password !== storedPassword) {
            return jsonResponse({ error: 'Invalid password' }, 401, corsHeaders);
        }

        // Generate session token
        const token = generateToken();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        // Store session in DB for proper validation
        try {
            await env.DB.prepare(
                'INSERT INTO active_connections (user_id, connection_id, ip_address, user_agent, connected_at, last_activity) VALUES (0, ?, ?, ?, datetime(\'now\'), datetime(\'now\'))'
            ).bind(token, request.headers.get('CF-Connecting-IP') || 'admin', 'admin-session').run();
        } catch (e) {
            console.error('Session store error:', e);
        }

        return jsonResponse({
            success: true,
            token,
            expiresAt
        }, 200, corsHeaders);

    } catch (error) {
        console.error('Login error:', error);
        return jsonResponse({ error: 'Login failed: ' + error.message }, 500, corsHeaders);
    }
}

async function handleLogout(request, env, corsHeaders) {
    // Delete session from DB
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.slice(7);
        try {
            await env.DB.prepare(
                'DELETE FROM active_connections WHERE connection_id = ? AND user_id = 0'
            ).bind(token).run();
        } catch (e) {
            console.error('Logout delete error:', e);
        }
    }
    return jsonResponse({ success: true }, 200, corsHeaders);
}

async function verifyAuth(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return false;
    }

    const token = authHeader.slice(7);
    if (!token || token.length < 10) return false;

    // Check session in DB with 24h expiry
    try {
        const session = await env.DB.prepare(
            'SELECT * FROM active_connections WHERE connection_id = ? AND user_id = 0'
        ).bind(token).first();

        if (!session) return false;

        // Check if session is older than 24 hours
        const connectedAt = new Date(session.connected_at);
        const now = new Date();
        const hoursSinceConnect = (now - connectedAt) / (1000 * 60 * 60);

        if (hoursSinceConnect > 24) {
            // Session expired, delete it
            await env.DB.prepare(
                'DELETE FROM active_connections WHERE connection_id = ?'
            ).bind(token).run();
            return false;
        }

        // Update last activity
        await env.DB.prepare(
            'UPDATE active_connections SET last_activity = datetime(\'now\') WHERE connection_id = ?'
        ).bind(token).run();

        return true;
    } catch (e) {
        // Fallback: basic token validation if DB fails
        return token && token.length > 10;
    }
}

// ============================================
// Admin Routes
// ============================================

async function handleAdminRoutes(request, env, ctx, path, method, corsHeaders) {
    if (!(await verifyAuth(request, env))) {
        return jsonResponse({ error: 'Unauthorized' }, 401, corsHeaders);
    }

    const route = path.replace('/api/admin/', '');

    // Dashboard stats
    if (route === 'stats' && method === 'GET') {
        return getDashboardStats(env, corsHeaders);
    }

    // User management
    if (route === 'users' && method === 'GET') {
        return getUsers(env, request, corsHeaders);
    }
    if (route === 'users' && method === 'POST') {
        return createUser(request, env, corsHeaders);
    }
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

    // Bulk operations
    if (route === 'users/bulk' && method === 'POST') {
        return bulkCreateUsers(request, env, corsHeaders);
    }

    // Bandwidth tracking
    if (route === 'bandwidth' && method === 'GET') {
        return getBandwidthStats(env, request, corsHeaders);
    }
    if (route.startsWith('bandwidth/') && method === 'GET') {
        const userId = route.split('/')[1];
        return getUserBandwidth(userId, env, corsHeaders);
    }

    // Connection logs
    if (route === 'logs' && method === 'GET') {
        return getLogs(env, request, corsHeaders);
    }

    // Settings
    if (route === 'settings' && method === 'GET') {
        return getSettings(env, corsHeaders);
    }
    if (route === 'settings' && method === 'PUT') {
        return updateSettings(request, env, corsHeaders);
    }

    // Generate VLESS config
    if (route === 'generate/vless' && method === 'POST') {
        return generateVLESSConfig(request, env, corsHeaders);
    }

    return jsonResponse({ error: 'Not found' }, 404, corsHeaders);
}

// ============================================
// User Routes (for user status page)
// ============================================

async function handleUserRoutes(request, env, ctx, path, method, corsHeaders) {
    const route = path.replace('/api/user/', '');

    // User status check
    if (route === 'status' && method === 'GET') {
        const uuid = new URL(request.url).searchParams.get('uuid');
        if (!uuid) {
            return jsonResponse({ error: 'UUID required' }, 400, corsHeaders);
        }
        return getUserStatus(uuid, env, corsHeaders);
    }

    // Track bandwidth (called by Edge Tunnel)
    if (route === 'track' && method === 'POST') {
        return trackBandwidth(request, env, corsHeaders);
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

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
        console.error('Stats error:', error);
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
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';

            const users = await env.DB.prepare(query)
                .bind(`%${search}%`, `%${search}%`, limit, offset)
                .all();
            const total = await env.DB.prepare(countQuery)
                .bind(`%${search}%`, `%${search}%`)
                .first();

            return jsonResponse({
                users: users.results,
                pagination: {
                    page,
                    limit,
                    total: total?.count || 0,
                    pages: Math.ceil((total?.count || 0) / limit)
                }
            }, 200, corsHeaders);
        }

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        const users = await env.DB.prepare(query).bind(limit, offset).all();
        const total = await env.DB.prepare(countQuery).first();

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
        console.error('Get users error:', error);
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
        ).bind(
            uuid,
            username || '',
            max_connections || 1,
            max_bandwidth_mb || 0,
            expires_at || null,
            notes || ''
        ).run();

        // Log the creation
        await env.DB.prepare(
            'INSERT INTO connection_logs (event_type, details) VALUES (?, ?)'
        ).bind('user_created', `UUID: ${uuid}`).run();

        return jsonResponse({
            success: true,
            user: {
                id: result.meta?.last_row_id,
                uuid,
                username,
                max_connections,
                max_bandwidth_mb,
                expires_at,
                notes
            }
        }, 201, corsHeaders);
    } catch (error) {
        console.error('Create user error:', error);
        return jsonResponse({ error: 'Failed to create user' }, 500, corsHeaders);
    }
}

async function getUserDetails(uuid, env, corsHeaders) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();

        if (!user) {
            return jsonResponse({ error: 'User not found' }, 404, corsHeaders);
        }

        // Get bandwidth usage
        const bandwidth = await env.DB.prepare(
            'SELECT * FROM bandwidth_usage WHERE user_id = ? ORDER BY date DESC LIMIT 30'
        ).bind(user.id).all();

        // Get active connections
        const connections = await env.DB.prepare(
            'SELECT * FROM active_connections WHERE user_id = ?'
        ).bind(user.id).all();

        return jsonResponse({
            user,
            bandwidth: bandwidth.results,
            connections: connections.results
        }, 200, corsHeaders);
    } catch (error) {
        console.error('Get user error:', error);
        return jsonResponse({ error: 'Failed to get user' }, 500, corsHeaders);
    }
}

async function updateUser(uuid, request, env, corsHeaders) {
    try {
        const body = await request.json();
        const { username, max_connections, max_bandwidth_mb, expires_at, is_active, notes } = body;

        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();
        if (!user) {
            return jsonResponse({ error: 'User not found' }, 404, corsHeaders);
        }

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
        ).bind(
            username,
            max_connections,
            max_bandwidth_mb,
            expires_at,
            is_active,
            notes,
            uuid
        ).run();

        return jsonResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
        console.error('Update user error:', error);
        return jsonResponse({ error: 'Failed to update user' }, 500, corsHeaders);
    }
}

async function deleteUser(uuid, env, corsHeaders) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();
        if (!user) {
            return jsonResponse({ error: 'User not found' }, 404, corsHeaders);
        }

        await env.DB.prepare('DELETE FROM users WHERE uuid = ?').bind(uuid).run();
        await env.DB.prepare('DELETE FROM bandwidth_usage WHERE user_id = ?').bind(user.id).run();
        await env.DB.prepare('DELETE FROM active_connections WHERE user_id = ?').bind(user.id).run();

        return jsonResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
        console.error('Delete user error:', error);
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
        console.error('Bulk create error:', error);
        return jsonResponse({ error: 'Failed to bulk create users' }, 500, corsHeaders);
    }
}

// ============================================
// Bandwidth Tracking
// ============================================

async function trackBandwidth(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const { uuid, request_count = 1 } = body;

        if (!uuid) {
            return jsonResponse({ error: 'UUID required' }, 400, corsHeaders);
        }

        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ? AND is_active = 1').bind(uuid).first();
        if (!user) {
            return jsonResponse({ error: 'Invalid or inactive UUID' }, 401, corsHeaders);
        }

        // Check expiration
        if (user.expires_at && new Date(user.expires_at) < new Date()) {
            return jsonResponse({ error: 'UUID expired' }, 403, corsHeaders);
        }

        // Calculate bytes: 5 requests = 1KB
        const bytes = Math.ceil(request_count / REQUESTS_PER_KB) * 1024;

        // Check bandwidth limit
        if (user.max_bandwidth_mb > 0) {
            const totalUsed = await env.DB.prepare(
                'SELECT SUM(total_bytes) as total FROM bandwidth_usage WHERE user_id = ?'
            ).bind(user.id).first();

            if ((totalUsed?.total || 0) + bytes > user.max_bandwidth_mb * 1024 * 1024) {
                return jsonResponse({ error: 'Bandwidth limit exceeded' }, 403, corsHeaders);
            }
        }

        // Update daily bandwidth
        const today = new Date().toISOString().split('T')[0];
        await env.DB.prepare(
            `INSERT INTO bandwidth_usage (user_id, date, bytes_up, total_bytes, request_count)
             VALUES (?, ?, 0, ?, ?)
             ON CONFLICT(user_id, date)
             DO UPDATE SET
                total_bytes = total_bytes + ?,
                request_count = request_count + ?`
        ).bind(user.id, today, bytes, request_count, bytes, request_count).run();

        // Update last used
        await env.DB.prepare(
            'UPDATE users SET last_used_at = datetime("now") WHERE id = ?'
        ).bind(user.id).run();

        return jsonResponse({ success: true, bytes_added: bytes }, 200, corsHeaders);
    } catch (error) {
        console.error('Track bandwidth error:', error);
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
             GROUP BY date
             ORDER BY date DESC`
        ).bind(days).all();

        return jsonResponse({ stats: stats.results }, 200, corsHeaders);
    } catch (error) {
        console.error('Get bandwidth stats error:', error);
        return jsonResponse({ error: 'Failed to get bandwidth stats' }, 500, corsHeaders);
    }
}

async function getUserBandwidth(userId, env, corsHeaders) {
    try {
        const bandwidth = await env.DB.prepare(
            'SELECT * FROM bandwidth_usage WHERE user_id = ? ORDER BY date DESC LIMIT 30'
        ).bind(userId).all();

        return jsonResponse({ bandwidth: bandwidth.results }, 200, corsHeaders);
    } catch (error) {
        console.error('Get user bandwidth error:', error);
        return jsonResponse({ error: 'Failed to get user bandwidth' }, 500, corsHeaders);
    }
}

// ============================================
// User Status (for user-facing page)
// ============================================

async function getUserStatus(uuid, env, corsHeaders) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();

        if (!user) {
            return jsonResponse({ error: 'Invalid UUID' }, 404, corsHeaders);
        }

        // Get total bandwidth used
        const totalBandwidth = await env.DB.prepare(
            'SELECT SUM(total_bytes) as total FROM bandwidth_usage WHERE user_id = ?'
        ).bind(user.id).first();

        // Get today's bandwidth
        const todayBandwidth = await env.DB.prepare(
            'SELECT total_bytes FROM bandwidth_usage WHERE user_id = ? AND date = date("now")'
        ).bind(user.id).first();

        // Check expiration
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
        console.error('Get user status error:', error);
        return jsonResponse({ error: 'Failed to get user status' }, 500, corsHeaders);
    }
}

// ============================================
// Logs
// ============================================

async function getLogs(env, request, corsHeaders) {
    try {
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '50');
        const offset = (page - 1) * limit;

        const logs = await env.DB.prepare(
            'SELECT * FROM connection_logs ORDER BY created_at DESC LIMIT ? OFFSET ?'
        ).bind(limit, offset).all();

        const total = await env.DB.prepare('SELECT COUNT(*) as count FROM connection_logs').first();

        return jsonResponse({
            logs: logs.results,
            pagination: {
                page,
                limit,
                total: total?.count || 0,
                pages: Math.ceil((total?.count || 0) / limit)
            }
        }, 200, corsHeaders);
    } catch (error) {
        console.error('Get logs error:', error);
        return jsonResponse({ error: 'Failed to get logs' }, 500, corsHeaders);
    }
}

// ============================================
// Settings
// ============================================

async function getSettings(env, corsHeaders) {
    try {
        const settings = await env.DB.prepare('SELECT * FROM settings').all();
        const settingsObj = {};
        settings.results.forEach(s => {
            settingsObj[s.key] = s.value;
        });

        return jsonResponse({ settings: settingsObj }, 200, corsHeaders);
    } catch (error) {
        console.error('Get settings error:', error);
        return jsonResponse({ error: 'Failed to get settings' }, 500, corsHeaders);
    }
}

async function updateSettings(request, env, corsHeaders) {
    try {
        const body = await request.json();

        for (const [key, value] of Object.entries(body)) {
            await env.DB.prepare(
                'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)'
            ).bind(key, String(value)).run();
        }

        return jsonResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
        console.error('Update settings error:', error);
        return jsonResponse({ error: 'Failed to update settings' }, 500, corsHeaders);
    }
}

// ============================================
// VLESS Config Generation
// ============================================

async function generateVLESSConfig(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const { uuid, server, port = 443, sni, flow = 'xtls-rprx-vision' } = body;

        if (!uuid || !server) {
            return jsonResponse({ error: 'UUID and server required' }, 400, corsHeaders);
        }

        // VLESS URL format
        const vlessUrl = `vless://${uuid}@${server}:${port}?encryption=none&security=tls&sni=${sni || server}&fp=chrome&flow=${flow}#EdgeManager`;

        return jsonResponse({
            success: true,
            config: {
                vless_url: vlessUrl,
                uuid,
                server,
                port,
                sni: sni || server,
                flow
            }
        }, 200, corsHeaders);
    } catch (error) {
        console.error('Generate VLESS error:', error);
        return jsonResponse({ error: 'Failed to generate config' }, 500, corsHeaders);
    }
}

// ============================================
// Admin Panel HTML
// ============================================

function getAdminPanel(env, corsHeaders) {
    const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edge Manager - پنل مدیریت</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }

        .login-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); }
        .login-box { background: #1e293b; padding: 2rem; border-radius: 1rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); width: 100%; max-width: 400px; }
        .login-box h1 { text-align: center; color: #60a5fa; margin-bottom: 1.5rem; font-size: 1.5rem; }
        .login-box input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #334155; border-radius: 0.5rem; background: #0f172a; color: #e2e8f0; font-size: 1rem; }
        .login-box button { width: 100%; padding: 0.75rem; background: #3b82f6; color: white; border: none; border-radius: 0.5rem; font-size: 1rem; cursor: pointer; transition: background 0.3s; }
        .login-box button:hover { background: #2563eb; }

        .dashboard { display: none; }
        .header { background: #1e293b; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
        .header h1 { color: #60a5fa; font-size: 1.25rem; }
        .header button { background: #ef4444; color: white; padding: 0.5rem 1rem; border: none; border-radius: 0.5rem; cursor: pointer; }

        .container { padding: 2rem; max-width: 1400px; margin: 0 auto; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: #1e293b; padding: 1.5rem; border-radius: 0.75rem; border: 1px solid #334155; }
        .stat-card h3 { color: #94a3b8; font-size: 0.875rem; margin-bottom: 0.5rem; }
        .stat-card .value { font-size: 1.75rem; font-weight: bold; color: #60a5fa; }
        .stat-card.success .value { color: #10b981; }
        .stat-card.warning .value { color: #f59e0b; }
        .stat-card.danger .value { color: #ef4444; }

        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
        .tab { padding: 0.75rem 1.5rem; background: #1e293b; border: 1px solid #334155; border-radius: 0.5rem; cursor: pointer; transition: all 0.3s; }
        .tab:hover, .tab.active { background: #3b82f6; border-color: #3b82f6; }

        .panel { display: none; background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; border: 1px solid #334155; }
        .panel.active { display: block; }

        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: right; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        tr:hover { background: #334155; }

        .btn { padding: 0.5rem 1rem; border: none; border-radius: 0.375rem; cursor: pointer; font-size: 0.875rem; transition: all 0.3s; }
        .btn-primary { background: #3b82f6; color: white; }
        .btn-primary:hover { background: #2563eb; }
        .btn-success { background: #10b981; color: white; }
        .btn-success:hover { background: #059669; }
        .btn-danger { background: #ef4444; color: white; }
        .btn-danger:hover { background: #dc2626; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }

        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #94a3b8; }
        .form-group input, .form-group select { width: 100%; padding: 0.75rem; border: 1px solid #334155; border-radius: 0.5rem; background: #0f172a; color: #e2e8f0; }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center; }
        .modal.active { display: flex; }
        .modal-content { background: #1e293b; padding: 2rem; border-radius: 1rem; width: 100%; max-width: 500px; max-height: 90vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .modal-header h2 { color: #60a5fa; }
        .modal-close { background: none; border: none; color: #94a3b8; font-size: 1.5rem; cursor: pointer; }

        .badge { padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; }
        .badge-success { background: #10b981; color: white; }
        .badge-danger { background: #ef4444; color: white; }
        .badge-warning { background: #f59e0b; color: white; }

        .search-box { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
        .search-box input { flex: 1; padding: 0.75rem; border: 1px solid #334155; border-radius: 0.5rem; background: #0f172a; color: #e2e8f0; }

        .actions { display: flex; gap: 0.5rem; margin-bottom: 1rem; }

        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr 1fr; }
            .container { padding: 1rem; }
        }
    </style>
</head>
<body>
    <!-- Login Page -->
    <div id="loginPage" class="login-container">
        <div class="login-box">
            <h1>🔐 Edge Manager</h1>
            <input type="password" id="loginPassword" placeholder="رمز عبور" onkeypress="if(event.key==='Enter')login()">
            <button onclick="login()">ورود</button>
        </div>
    </div>

    <!-- Dashboard -->
    <div id="dashboardPage" class="dashboard">
        <div class="header">
            <h1>⚡ Edge Manager</h1>
            <button onclick="logout()">خروج</button>
        </div>

        <div class="container">
            <!-- Stats -->
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>کل کاربران</h3>
                    <div class="value" id="totalUsers">0</div>
                </div>
                <div class="stat-card success">
                    <h3>کاربران فعال</h3>
                    <div class="value" id="activeUsers">0</div>
                </div>
                <div class="stat-card warning">
                    <h3>حجم مصرفی امروز</h3>
                    <div class="value" id="todayBandwidth">0 KB</div>
                </div>
                <div class="stat-card danger">
                    <h3>اتصالات فعال</h3>
                    <div class="value" id="activeConnections">0</div>
                </div>
            </div>

            <!-- Tabs -->
            <div class="tabs">
                <div class="tab active" onclick="showTab('users')">👥 کاربران</div>
                <div class="tab" onclick="showTab('bandwidth')">📊 پهنای باند</div>
                <div class="tab" onclick="showTab('logs')">📋 لاگ‌ها</div>
                <div class="tab" onclick="showTab('settings')">⚙️ تنظیمات</div>
            </div>

            <!-- Users Panel -->
            <div id="usersPanel" class="panel active">
                <div class="actions">
                    <button class="btn btn-primary" onclick="showCreateUserModal()">➕ کاربر جدید</button>
                    <button class="btn btn-success" onclick="showBulkCreateModal()">📦 ساخت گروهی</button>
                </div>
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="جستجوی UUID یا نام..." oninput="searchUsers()">
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>UUID</th>
                                <th>نام</th>
                                <th>وضعیت</th>
                                <th>حجم مصرفی</th>
                                <th>تاریخ انقضا</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>
                        <tbody id="usersTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- Bandwidth Panel -->
            <div id="bandwidthPanel" class="panel">
                <h3 style="margin-bottom: 1rem; color: #60a5fa;">📊 آمار پهنای باند</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>تاریخ</th>
                                <th>حجم کل</th>
                                <th>تعداد درخواست</th>
                            </tr>
                        </thead>
                        <tbody id="bandwidthTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- Logs Panel -->
            <div id="logsPanel" class="panel">
                <h3 style="margin-bottom: 1rem; color: #60a5fa;">📋 لاگ‌های سیستم</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>زمان</th>
                                <th>نوع</th>
                                <th>جزئیات</th>
                            </tr>
                        </thead>
                        <tbody id="logsTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- Settings Panel -->
            <div id="settingsPanel" class="panel">
                <h3 style="margin-bottom: 1rem; color: #60a5fa;">⚙️ تنظیمات سیستم</h3>
                <div class="form-group">
                    <label>نام سیستم</label>
                    <input type="text" id="settingSystemName" placeholder="Edge Manager">
                </div>
                <div class="form-group">
                    <label>حداکثر پهنای باند پیش‌فرض (MB, 0 = نامحدود)</label>
                    <input type="number" id="settingMaxBandwidth" value="0">
                </div>
                <div class="form-group">
                    <label>حداکثر اتصالات پیش‌فرض</label>
                    <input type="number" id="settingMaxConnections" value="1">
                </div>
                <div class="form-group">
                    <label>روزهای انقضای پیش‌فرض</label>
                    <input type="number" id="settingExpiryDays" value="30">
                </div>
                <div class="form-group">
                    <label>تعداد درخواست برای هر کیلوبایت</label>
                    <input type="number" id="settingRequestsPerKb" value="5">
                </div>
                <button class="btn btn-primary" onclick="saveSettings()">💾 ذخیره تنظیمات</button>
            </div>
        </div>
    </div>

    <!-- Create User Modal -->
    <div id="createUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>➕ کاربر جدید</h2>
                <button class="modal-close" onclick="closeModal('createUserModal')">&times;</button>
            </div>
            <div class="form-group">
                <label>نام کاربری</label>
                <input type="text" id="newUsername" placeholder="نام کاربری (اختیاری)">
            </div>
            <div class="form-group">
                <label>حداکثر اتصالات</label>
                <input type="number" id="newMaxConnections" value="1">
            </div>
            <div class="form-group">
                <label>حداکثر حجم (MB, 0 = نامحدود)</label>
                <input type="number" id="newMaxBandwidth" value="0">
            </div>
            <div class="form-group">
                <label>تاریخ انقضا</label>
                <input type="date" id="newExpiresAt">
            </div>
            <div class="form-group">
                <label>یادداشت</label>
                <input type="text" id="newNotes" placeholder="یادداشت (اختیاری)">
            </div>
            <button class="btn btn-primary" onclick="createUser()" style="width: 100%;">ایجاد کاربر</button>
        </div>
    </div>

    <!-- Bulk Create Modal -->
    <div id="bulkCreateModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>📦 ساخت گروهی</h2>
                <button class="modal-close" onclick="closeModal('bulkCreateModal')">&times;</button>
            </div>
            <div class="form-group">
                <label>تعداد کاربر</label>
                <input type="number" id="bulkCount" value="10" min="1" max="100">
            </div>
            <div class="form-group">
                <label>پیشوند نام</label>
                <input type="text" id="bulkPrefix" placeholder="user">
            </div>
            <div class="form-group">
                <label>حداکثر اتصالات</label>
                <input type="number" id="bulkMaxConnections" value="1">
            </div>
            <div class="form-group">
                <label>حداکثر حجم (MB, 0 = نامحدود)</label>
                <input type="number" id="bulkMaxBandwidth" value="0">
            </div>
            <div class="form-group">
                <label>تاریخ انقضا</label>
                <input type="date" id="bulkExpiresAt">
            </div>
            <button class="btn btn-primary" onclick="bulkCreateUsers()" style="width: 100%;">ایجاد گروهی</button>
        </div>
    </div>

    <!-- Edit User Modal -->
    <div id="editUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>✏️ ویرایش کاربر</h2>
                <button class="modal-close" onclick="closeModal('editUserModal')">&times;</button>
            </div>
            <input type="hidden" id="editUserUuid">
            <div class="form-group">
                <label>نام کاربری</label>
                <input type="text" id="editUsername">
            </div>
            <div class="form-group">
                <label>حداکثر اتصالات</label>
                <input type="number" id="editMaxConnections" value="1">
            </div>
            <div class="form-group">
                <label>حداکثر حجم (MB, 0 = نامحدود)</label>
                <input type="number" id="editMaxBandwidth" value="0">
            </div>
            <div class="form-group">
                <label>تاریخ انقضا</label>
                <input type="date" id="editExpiresAt">
            </div>
            <div class="form-group">
                <label>وضعیت</label>
                <select id="editIsActive">
                    <option value="1">فعال</option>
                    <option value="0">غیرفعال</option>
                </select>
            </div>
            <div class="form-group">
                <label>یادداشت</label>
                <input type="text" id="editNotes">
            </div>
            <button class="btn btn-primary" onclick="saveEditUser()" style="width: 100%;">ذخیره تغییرات</button>
        </div>
    </div>

    <!-- Loading Spinner -->
    <div id="loadingSpinner" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; justify-content: center; align-items: center;">
        <div style="background: #1e293b; padding: 2rem; border-radius: 1rem; text-align: center;">
            <div style="width: 40px; height: 40px; border: 4px solid #334155; border-top: 4px solid #3b82f6; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 1rem;"></div>
            <p style="color: #94a3b8;">در حال بارگذاری...</p>
        </div>
    </div>
    <style>@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }</style>

    <script>
        let token = sessionStorage.getItem('admin_token');
        let users = [];

        // Check if logged in
        if (token) {
            showDashboard();
        }

        async function login() {
            const password = document.getElementById('loginPassword').value;
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                if (data.success) {
                    token = data.token;
                    sessionStorage.setItem('admin_token', token);
                    showDashboard();
                } else {
                    alert('خطا: ' + (data.error || 'رمز عبور اشتباه است'));
                }
            } catch (e) {
                alert('خطا در اتصال');
            }
        }

        function logout() {
            token = null;
            sessionStorage.removeItem('admin_token');
            document.getElementById('loginPage').style.display = 'flex';
            document.getElementById('dashboardPage').style.display = 'none';
        }

        function showDashboard() {
            document.getElementById('loginPage').style.display = 'none';
            document.getElementById('dashboardPage').style.display = 'block';
            loadStats();
            loadUsers();
        }

        async function loadStats() {
            try {
                const res = await fetch('/api/admin/stats', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const data = await res.json();
                if (data.stats) {
                    document.getElementById('totalUsers').textContent = data.stats.totalUsers;
                    document.getElementById('activeUsers').textContent = data.stats.activeUsers;
                    document.getElementById('todayBandwidth').textContent = formatBytes(data.stats.todayBandwidth);
                    document.getElementById('activeConnections').textContent = data.stats.activeConnections;
                } else {
                    document.getElementById('totalUsers').textContent = 'خطا';
                    document.getElementById('activeUsers').textContent = 'خطا';
                }
            } catch (e) {
                console.error('Stats error:', e);
                document.getElementById('totalUsers').textContent = 'خطا';
                document.getElementById('activeUsers').textContent = 'خطا';
                document.getElementById('todayBandwidth').textContent = 'خطا';
                document.getElementById('activeConnections').textContent = 'خطا';
            }
        }

        async function loadUsers(search = '') {
            try {
                let url = '/api/admin/users?limit=50';
                if (search) url += '&search=' + encodeURIComponent(search);

                const res = await fetch(url, {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const data = await res.json();
                users = data.users || [];
                renderUsers();
            } catch (e) {
                console.error('Users error:', e);
                const tbody = document.getElementById('usersTable');
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #ef4444;">خطا در بارگذاری کاربران</td></tr>';
            }
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function renderUsers() {
            const tbody = document.getElementById('usersTable');
            tbody.innerHTML = users.map(u => {
                const isExpired = u.expires_at && new Date(u.expires_at) < new Date();
                const statusBadge = u.is_active && !isExpired
                    ? '<span class="badge badge-success">فعال</span>'
                    : '<span class="badge badge-danger">غیرفعال</span>';

                return '<tr>' +
                    '<td style="font-family: monospace; font-size: 0.75rem;">' + escapeHtml(u.uuid) + '</td>' +
                    '<td>' + escapeHtml(u.username || '-') + '</td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' + (u.max_bandwidth_mb > 0 ? u.max_bandwidth_mb + ' MB' : 'نامحدود') + '</td>' +
                    '<td>' + escapeHtml(u.expires_at || 'ندارد') + '</td>' +
                    '<td>' +
                        '<button class="btn btn-primary btn-sm" onclick="editUser(\\'' + escapeHtml(u.uuid) + '\\')">ویرایش</button> ' +
                        '<button class="btn btn-success btn-sm" onclick="copyUUID(\\'' + escapeHtml(u.uuid) + '\\')">کپی</button> ' +
                        '<button class="btn btn-danger btn-sm" onclick="deleteUser(\\'' + escapeHtml(u.uuid) + '\\')">حذف</button>' +
                    '</td>' +
                '</tr>';
            }).join('');
        }

        function searchUsers() {
            const search = document.getElementById('searchInput').value;
            loadUsers(search);
        }

        function showCreateUserModal() {
            document.getElementById('createUserModal').classList.add('active');
        }

        function showBulkCreateModal() {
            document.getElementById('bulkCreateModal').classList.add('active');
        }

        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        async function createUser() {
            const data = {
                username: document.getElementById('newUsername').value,
                max_connections: parseInt(document.getElementById('newMaxConnections').value),
                max_bandwidth_mb: parseInt(document.getElementById('newMaxBandwidth').value),
                expires_at: document.getElementById('newExpiresAt').value || null,
                notes: document.getElementById('newNotes').value
            };

            try {
                const res = await fetch('/api/admin/users', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (result.success) {
                    alert('کاربر ایجاد شد!\\nUUID: ' + result.user.uuid);
                    closeModal('createUserModal');
                    loadUsers();
                    loadStats();
                } else {
                    alert('خطا: ' + result.error);
                }
            } catch (e) {
                alert('خطا در ایجاد کاربر');
            }
        }

        async function bulkCreateUsers() {
            const data = {
                count: parseInt(document.getElementById('bulkCount').value),
                prefix: document.getElementById('bulkPrefix').value,
                max_connections: parseInt(document.getElementById('bulkMaxConnections').value),
                max_bandwidth_mb: parseInt(document.getElementById('bulkMaxBandwidth').value),
                expires_at: document.getElementById('bulkExpiresAt').value || null
            };

            try {
                const res = await fetch('/api/admin/users/bulk', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (result.success) {
                    alert('تعداد ' + data.count + ' کاربر ایجاد شد!');
                    closeModal('bulkCreateModal');
                    loadUsers();
                    loadStats();
                } else {
                    alert('خطا: ' + result.error);
                }
            } catch (e) {
                alert('خطا در ایجاد گروهی');
            }
        }

        async function deleteUser(uuid) {
            if (!confirm('آیا مطمئن هستید؟')) return;
            try {
                await fetch('/api/admin/users/' + uuid, {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                loadUsers();
                loadStats();
            } catch (e) {
                alert('خطا در حذف کاربر');
            }
        }

        function copyUUID(uuid) {
            navigator.clipboard.writeText(uuid);
            alert('UUID کپی شد!');
        }

        function editUser(uuid) {
            showLoading();
            fetch('/api/admin/users/' + uuid, {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(res => res.json())
            .then(data => {
                hideLoading();
                if (data.user) {
                    const u = data.user;
                    document.getElementById('editUserUuid').value = u.uuid;
                    document.getElementById('editUsername').value = u.username || '';
                    document.getElementById('editMaxConnections').value = u.max_connections || 1;
                    document.getElementById('editMaxBandwidth').value = u.max_bandwidth_mb || 0;
                    document.getElementById('editExpiresAt').value = u.expires_at ? u.expires_at.split('T')[0] : '';
                    document.getElementById('editIsActive').value = u.is_active;
                    document.getElementById('editNotes').value = u.notes || '';
                    document.getElementById('editUserModal').classList.add('active');
                } else {
                    alert('خطا: کاربر یافت نشد');
                }
            })
            .catch(e => {
                hideLoading();
                alert('خطا در دریافت اطلاعات کاربر');
            });
        }

        async function saveEditUser() {
            const uuid = document.getElementById('editUserUuid').value;
            const data = {
                username: document.getElementById('editUsername').value,
                max_connections: parseInt(document.getElementById('editMaxConnections').value),
                max_bandwidth_mb: parseInt(document.getElementById('editMaxBandwidth').value),
                expires_at: document.getElementById('editExpiresAt').value || null,
                is_active: parseInt(document.getElementById('editIsActive').value),
                notes: document.getElementById('editNotes').value
            };

            showLoading();
            try {
                const res = await fetch('/api/admin/users/' + uuid, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                hideLoading();
                if (result.success) {
                    alert('کاربر با موفقیت ویرایش شد!');
                    closeModal('editUserModal');
                    loadUsers();
                    loadStats();
                } else {
                    alert('خطا: ' + (result.error || 'خطای ناشناخته'));
                }
            } catch (e) {
                hideLoading();
                alert('خطا در ذخیره تغییرات');
            }
        }

        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

            event.target.classList.add('active');
            document.getElementById(tabName + 'Panel').classList.add('active');

            if (tabName === 'bandwidth') loadBandwidth();
            if (tabName === 'logs') loadLogs();
            if (tabName === 'settings') loadSettings();
        }

        async function loadBandwidth() {
            try {
                const res = await fetch('/api/admin/bandwidth?days=30', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const data = await res.json();
                const tbody = document.getElementById('bandwidthTable');
                tbody.innerHTML = (data.stats || []).map(s => {
                    return '<tr>' +
                        '<td>' + s.date + '</td>' +
                        '<td>' + formatBytes(s.total_bytes) + '</td>' +
                        '<td>' + (s.total_requests || 0) + '</td>' +
                    '</tr>';
                }).join('');
            } catch (e) {
                console.error('Bandwidth error:', e);
            }
        }

        async function loadLogs() {
            try {
                const res = await fetch('/api/admin/logs?limit=100', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const data = await res.json();
                const tbody = document.getElementById('logsTable');
                tbody.innerHTML = (data.logs || []).map(l => {
                    return '<tr>' +
                        '<td>' + l.created_at + '</td>' +
                        '<td>' + l.event_type + '</td>' +
                        '<td>' + (l.details || '-') + '</td>' +
                    '</tr>';
                }).join('');
            } catch (e) {
                console.error('Logs error:', e);
            }
        }

        async function loadSettings() {
            try {
                const res = await fetch('/api/admin/settings', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const data = await res.json();
                const s = data.settings || {};
                document.getElementById('settingSystemName').value = s.system_name || 'Edge Manager';
                document.getElementById('settingMaxBandwidth').value = s.max_bandwidth_default || 0;
                document.getElementById('settingMaxConnections').value = s.max_connections_default || 1;
                document.getElementById('settingExpiryDays').value = s.default_expiry_days || 30;
                document.getElementById('settingRequestsPerKb').value = s.requests_per_kb || 5;
            } catch (e) {
                console.error('Settings error:', e);
            }
        }

        async function saveSettings() {
            const settings = {
                system_name: document.getElementById('settingSystemName').value,
                max_bandwidth_default: document.getElementById('settingMaxBandwidth').value,
                max_connections_default: document.getElementById('settingMaxConnections').value,
                default_expiry_days: document.getElementById('settingExpiryDays').value,
                requests_per_kb: document.getElementById('settingRequestsPerKb').value
            };

            try {
                await fetch('/api/admin/settings', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify(settings)
                });
                alert('تنظیمات ذخیره شد!');
            } catch (e) {
                alert('خطا در ذخیره تنظیمات');
            }
        }

        function showLoading() {
            document.getElementById('loadingSpinner').style.display = 'flex';
        }

        function hideLoading() {
            document.getElementById('loadingSpinner').style.display = 'none';
        }

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    </script>
</body>
</html>`;

    return new Response(html, {
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            ...corsHeaders
        }
    });
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
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .container { background: #1e293b; padding: 2rem; border-radius: 1rem; width: 100%; max-width: 400px; text-align: center; }
        h1 { color: #60a5fa; margin-bottom: 1.5rem; }
        input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #334155; border-radius: 0.5rem; background: #0f172a; color: #e2e8f0; text-align: center; }
        button { width: 100%; padding: 0.75rem; background: #3b82f6; color: white; border: none; border-radius: 0.5rem; cursor: pointer; }
        button:hover { background: #2563eb; }
        .result { margin-top: 1.5rem; padding: 1rem; background: #0f172a; border-radius: 0.5rem; display: none; text-align: right; }
        .result.show { display: block; }
        .result-row { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #334155; }
        .result-row:last-child { border-bottom: none; }
        .label { color: #94a3b8; }
        .value { color: #60a5fa; font-weight: bold; }
        .status-active { color: #10b981; }
        .status-inactive { color: #ef4444; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 بررسی وضعیت</h1>
        <input type="text" id="uuidInput" placeholder="UUID خود را وارد کنید">
        <button onclick="checkStatus()">بررسی</button>
        <div id="result" class="result">
            <div class="result-row">
                <span class="label">وضعیت:</span>
                <span class="value" id="status">-</span>
            </div>
            <div class="result-row">
                <span class="label">نام:</span>
                <span class="value" id="username">-</span>
            </div>
            <div class="result-row">
                <span class="label">حجم مصرفی:</span>
                <span class="value" id="usedBandwidth">-</span>
            </div>
            <div class="result-row">
                <span class="label">حجم باقی‌مانده:</span>
                <span class="value" id="remainingBandwidth">-</span>
            </div>
            <div class="result-row">
                <span class="label">تاریخ انقضا:</span>
                <span class="value" id="expiresAt">-</span>
            </div>
            <div class="result-row">
                <span class="label">آخرین استفاده:</span>
                <span class="value" id="lastUsed">-</span>
            </div>
        </div>
    </div>

    <script>
        async function checkStatus() {
            const uuid = document.getElementById('uuidInput').value;
            if (!uuid) { alert('UUID را وارد کنید'); return; }

            try {
                const res = await fetch('/api/user/status?uuid=' + encodeURIComponent(uuid));
                const data = await res.json();

                if (data.user) {
                    const u = data.user;
                    document.getElementById('result').classList.add('show');
                    document.getElementById('status').textContent = u.is_active ? 'فعال ✅' : 'غیرفعال ❌';
                    document.getElementById('status').className = 'value ' + (u.is_active ? 'status-active' : 'status-inactive');
                    document.getElementById('username').textContent = u.username || '-';
                    document.getElementById('usedBandwidth').textContent = formatBytes(u.total_used_bytes);
                    document.getElementById('remainingBandwidth').textContent = u.max_bandwidth_mb > 0 ? formatBytes(u.max_bandwidth_mb * 1024 * 1024 - u.total_used_bytes) : 'نامحدود';
                    document.getElementById('expiresAt').textContent = u.expires_at || 'ندارد';
                    document.getElementById('lastUsed').textContent = u.last_used_at || 'هرگز';
                } else {
                    alert('UUID یافت نشد');
                }
            } catch (e) {
                alert('خطا در بررسی');
            }
        }

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    </script>
</body>
</html>`;

    return new Response(html, {
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            ...corsHeaders
        }
    });
}
