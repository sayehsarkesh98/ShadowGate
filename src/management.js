// ============================================
// EDGE TUNNEL MANAGEMENT SYSTEM v2
// Professional VPN Management Panel
// ============================================

import { runMigrations } from './migrations.js';

// ============================================
// CONSTANTS
// ============================================
const MGMT_ADMIN_PASSWORD = 'admin123';
const REQUESTS_PER_KB = 5;
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours
const ACTIVE_UUID_CACHE_TTL = 60 * 1000; // 1 minute

// ============================================
// INITIALIZATION
// ============================================
let initialized = false;

export async function initManagement(env) {
    if (initialized) return;
    await runMigrations(env);
    initialized = true;
}

// ============================================
// UUID MANAGEMENT
// ============================================

export function mgmtGenerateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

let activeUUIDsCache = null;
let activeUUIDsCacheTime = 0;

export async function 获取活跃UUID列表(env) {
    if (!env.DB) return null;
    const now = Date.now();
    if (activeUUIDsCache && (now - activeUUIDsCacheTime) < ACTIVE_UUID_CACHE_TTL) {
        return activeUUIDsCache;
    }
    try {
        const result = await env.DB.prepare('SELECT uuid FROM users WHERE is_active = 1').all();
        if (result.results && result.results.length > 0) {
            activeUUIDsCache = result.results.map(r => r.uuid.toLowerCase());
            activeUUIDsCacheTime = now;
            return activeUUIDsCache;
        }
    } catch (e) {
        console.error(`[D1] Failed to load active UUIDs: ${e.message}`);
    }
    return null;
}

export function clearUUIDCache() {
    activeUUIDsCache = null;
    activeUUIDsCacheTime = 0;
}

// ============================================
// UUID VALIDATION
// ============================================

export async function mgmtValidateUUID(env, uuid) {
    try {
        if (!env.DB) return true;
        const user = await env.DB.prepare(
            'SELECT * FROM users WHERE uuid = ? AND is_active = 1'
        ).bind(uuid).first();

        if (!user) return false;

        // Check if frozen
        if (user.is_frozen) return false;

        // Check expiration
        if (user.expires_at && new Date(user.expires_at) < new Date()) {
            return false;
        }

        // Check bandwidth limit (v2: use max_bandwidth_bytes)
        const maxBW = user.max_bandwidth_bytes || (user.max_bandwidth_mb || 0) * 1024 * 1024;
        if (maxBW > 0) {
            if (user.used_bandwidth_bytes >= maxBW) {
                return false;
            }
        }

        // Check connection limit
        if (user.max_connections > 0 && user.current_connections >= user.max_connections) {
            return false;
        }

        return true;
    } catch (e) {
        console.error('UUID validation error:', e);
        return true;
    }
}

// ============================================
// BANDWIDTH TRACKING
// ============================================

export async function mgmtTrackBandwidth(env, uuid, requestCount) {
    try {
        if (!env.DB) return;

        const user = await env.DB.prepare(
            'SELECT id FROM users WHERE uuid = ?'
        ).bind(uuid).first();

        if (!user) return;

        const bytes = Math.ceil(requestCount / REQUESTS_PER_KB) * 1024;
        const today = new Date().toISOString().split('T')[0];

        // Update bandwidth_usage table
        await env.DB.prepare(`
            INSERT INTO bandwidth_usage (user_id, date, bytes_up, total_bytes, request_count)
            VALUES (?, ?, 0, ?, ?)
            ON CONFLICT(user_id, date)
            DO UPDATE SET
                total_bytes = total_bytes + ?,
                request_count = request_count + ?
        `).bind(user.id, today, bytes, requestCount, bytes, requestCount).run();

        // Update user's total used bandwidth
        await env.DB.prepare(
            'UPDATE users SET used_bandwidth_bytes = used_bandwidth_bytes + ?, last_used_at = datetime("now") WHERE id = ?'
        ).bind(bytes, user.id).run();

        // Check for bandwidth alerts
        await checkBandwidthAlerts(env, user.id, uuid);
    } catch (e) {
        console.error('Bandwidth tracking error:', e);
    }
}

async function checkBandwidthAlerts(env, userId, uuid) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
        if (!user) return;

        const maxBW = user.max_bandwidth_bytes || (user.max_bandwidth_mb || 0) * 1024 * 1024;
        if (maxBW <= 0) return;

        const usagePercent = (user.used_bandwidth_bytes / maxBW) * 100;
        const threshold = parseInt(await getSetting(env, 'traffic_alert_threshold') || '80');

        if (usagePercent >= threshold) {
            await queueNotification(env, userId, 'bandwidth_alert',
                `⚠️ هشدار: مصرف حجم ${Math.round(usagePercent)}% رسیده است`);
        }

        // Auto-disable at 100%
        if (usagePercent >= 100) {
            await env.DB.prepare(
                'UPDATE users SET is_active = 0 WHERE id = ?'
            ).bind(userId).run();
            clearUUIDCache();
        }
    } catch (e) {
        console.error('Bandwidth alert error:', e);
    }
}

// ============================================
// AUTHENTICATION
// ============================================

export function mgmtCorsHeaders() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
}

export function mgmtJsonResponse(data, status, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status: status || 200,
        headers: {
            'Content-Type': 'application/json;charset=utf-8',
            ...mgmtCorsHeaders(),
            ...extraHeaders
        }
    });
}

export async function mgmtHandleLogin(request, env) {
    try {
        const { username, password } = await request.json();

        // Check admin_users table first
        if (env.DB) {
            const admin = await env.DB.prepare(
                'SELECT * FROM admin_users WHERE username = ? AND is_active = 1'
            ).bind(username || 'admin').first();

            if (admin) {
                const passwordHash = await simpleHash(password);
                if (admin.password_hash === passwordHash) {
                    const token = await generateToken(env, admin.id, admin.username, admin.role);
                    return mgmtJsonResponse({ success: true, token, role: admin.role });
                }
            }
        }

        // Fallback to env password
        if (password === MGMT_ADMIN_PASSWORD || password === env.ADMIN) {
            const token = await generateToken(env, 0, 'admin', 'superadmin');
            return mgmtJsonResponse({ success: true, token, role: 'superadmin' });
        }

        return mgmtJsonResponse({ error: 'Invalid credentials' }, 401);
    } catch (e) {
        return mgmtJsonResponse({ error: 'Login failed' }, 500);
    }
}

async function generateToken(env, adminId, username, role) {
    const token = Array.from({length: 64}, () =>
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        [Math.floor(Math.random() * 62)]
    ).join('');

    const expiresAt = new Date(Date.now() + TOKEN_EXPIRY).toISOString();

    if (env.DB) {
        await env.DB.prepare(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)"
        ).bind(`auth_token_${token}`, JSON.stringify({ adminId, username, role, expiresAt })).run();
    }

    return token;
}

export async function mgmtVerifyAuth(request, env) {
    const auth = request.headers.get('Authorization');
    if (!auth || !auth.startsWith('Bearer ') || auth.length < 10) {
        return null;
    }
    const token = auth.slice(7);

    if (env.DB) {
        const tokenData = await env.DB.prepare(
            "SELECT value FROM settings WHERE key = ?"
        ).bind(`auth_token_${token}`).first();

        if (tokenData) {
            const data = JSON.parse(tokenData.value);
            if (new Date(data.expiresAt) > new Date()) {
                return data;
            }
        }
    }

    return null;
}

// ============================================
// USER MANAGEMENT
// ============================================

export async function mgmtGetUsers(env, params = {}) {
    try {
        let query = 'SELECT u.*, p.name as plan_name FROM users u LEFT JOIN plans p ON u.plan_id = p.id WHERE 1=1';
        const bindings = [];

        // Search
        if (params.search) {
            query += ' AND (u.username LIKE ? OR u.uuid LIKE ?)';
            bindings.push(`%${params.search}%`, `%${params.search}%`);
        }

        // Filter by status
        if (params.status === 'active') {
            query += ' AND u.is_active = 1 AND (u.expires_at IS NULL OR u.expires_at > datetime("now"))';
        } else if (params.status === 'inactive') {
            query += ' AND u.is_active = 0';
        } else if (params.status === 'expired') {
            query += ' AND u.expires_at <= datetime("now")';
        }

        // Filter by plan
        if (params.plan_id) {
            query += ' AND u.plan_id = ?';
            bindings.push(params.plan_id);
        }

        // Filter by tag
        if (params.tag) {
            query += ' AND u.tags LIKE ?';
            bindings.push(`%${params.tag}%`);
        }

        // Sorting
        const sortField = params.sort || 'created_at';
        const sortOrder = params.order === 'asc' ? 'ASC' : 'DESC';
        query += ` ORDER BY u.${sortField} ${sortOrder}`;

        // Pagination
        const page = parseInt(params.page) || 1;
        const limit = parseInt(params.limit) || 50;
        const offset = (page - 1) * limit;
        query += ' LIMIT ? OFFSET ?';
        bindings.push(limit, offset);

        const users = await env.DB.prepare(query).bind(...bindings).all();

        // Get total count
        let countQuery = 'SELECT COUNT(*) as c FROM users u WHERE 1=1';
        const countBindings = [];
        if (params.search) {
            countQuery += ' AND (u.username LIKE ? OR u.uuid LIKE ?)';
            countBindings.push(`%${params.search}%`, `%${params.search}%`);
        }
        const count = await env.DB.prepare(countQuery).bind(...countBindings).first();

        return mgmtJsonResponse({
            users: users.results,
            total: count?.c || 0,
            page,
            limit
        });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get users: ' + e.message }, 500);
    }
}

export async function mgmtCreateUser(request, env) {
    try {
        const data = await request.json();
        const {
            username, max_connections, max_bandwidth_bytes, max_bandwidth_mb,
            expires_at, plan_id, protocols, tags, notes,
            telegram_id, telegram_username
        } = data;

        const uuid = mgmtGenerateUUID();

        // Calculate bandwidth from plan if provided
        let bandwidthBytes = max_bandwidth_bytes || 0;
        let connections = max_connections || 1;

        if (plan_id && env.DB) {
            const plan = await env.DB.prepare('SELECT * FROM plans WHERE id = ?').bind(plan_id).first();
            if (plan) {
                bandwidthBytes = plan.max_bandwidth_bytes;
                connections = plan.max_connections;

                // Calculate expiry from plan duration
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + plan.duration_days);
                var computedExpiry = expiryDate.toISOString();
            }
        }

        // Convert MB to bytes if provided
        if (max_bandwidth_mb && !max_bandwidth_bytes) {
            bandwidthBytes = max_bandwidth_mb * 1024 * 1024;
        }

        await env.DB.prepare(`
            INSERT INTO users (uuid, username, max_connections, max_bandwidth_bytes, expires_at,
                plan_id, protocols, tags, notes, telegram_id, telegram_username, start_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `).bind(
            uuid,
            username || '',
            connections,
            bandwidthBytes,
            computedExpiry || expires_at || null,
            plan_id || null,
            protocols || '{"vless": true, "trojan": true}',
            tags || '',
            notes || '',
            telegram_id || '',
            telegram_username || ''
        ).run();

        clearUUIDCache();

        // Log action
        await auditLog(env, 0, 'create_user', 'user', uuid, `Created user ${username}`);

        return mgmtJsonResponse({
            success: true,
            user: { uuid, username }
        }, 201);
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to create user: ' + e.message }, 500);
    }
}

export async function mgmtUpdateUser(uuid, request, env) {
    try {
        const data = await request.json();
        const allowedFields = [
            'username', 'max_connections', 'max_bandwidth_bytes', 'max_bandwidth_mb',
            'expires_at', 'is_active', 'plan_id', 'protocols', 'tags', 'notes',
            'telegram_id', 'telegram_username', 'is_frozen'
        ];

        const updates = [];
        const bindings = [];

        for (const field of allowedFields) {
            if (data[field] !== undefined) {
                updates.push(`${field} = ?`);
                bindings.push(data[field]);
            }
        }

        // Convert MB to bytes if provided
        if (data.max_bandwidth_mb !== undefined && data.max_bandwidth_bytes === undefined) {
            const idx = updates.findIndex(u => u.startsWith('max_bandwidth_mb'));
            if (idx >= 0) {
                updates[idx] = 'max_bandwidth_bytes = ?';
                bindings[idx] = data.max_bandwidth_mb * 1024 * 1024;
            }
        }

        if (updates.length === 0) {
            return mgmtJsonResponse({ error: 'No fields to update' }, 400);
        }

        updates.push('updated_at = datetime("now")');
        bindings.push(uuid);

        await env.DB.prepare(
            `UPDATE users SET ${updates.join(', ')} WHERE uuid = ?`
        ).bind(...bindings).run();

        clearUUIDCache();

        await auditLog(env, 0, 'update_user', 'user', uuid, `Updated fields: ${Object.keys(data).join(', ')}`);

        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to update user: ' + e.message }, 500);
    }
}

export async function mgmtDeleteUser(uuid, env) {
    try {
        await env.DB.prepare('DELETE FROM users WHERE uuid = ?').bind(uuid).run();
        clearUUIDCache();

        await auditLog(env, 0, 'delete_user', 'user', uuid, `Deleted user`);

        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to delete user' }, 500);
    }
}

export async function mgmtBulkDeleteUsers(uuids, env) {
    try {
        const placeholders = uuids.map(() => '?').join(',');
        await env.DB.prepare(`DELETE FROM users WHERE uuid IN (${placeholders})`).bind(...uuids).run();
        clearUUIDCache();

        await auditLog(env, 0, 'bulk_delete', 'user', uuids.join(','), `Deleted ${uuids.length} users`);

        return mgmtJsonResponse({ success: true, deleted: uuids.length });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to bulk delete' }, 500);
    }
}

export async function mgmtBulkResetBandwidth(uuids, env) {
    try {
        const placeholders = uuids.map(() => '?').join(',');
        await env.DB.prepare(
            `UPDATE users SET used_bandwidth_bytes = 0 WHERE uuid IN (${placeholders})`
        ).bind(...uuids).run();

        await env.DB.prepare(
            `DELETE FROM bandwidth_usage WHERE user_id IN (SELECT id FROM users WHERE uuid IN (${placeholders}))`
        ).bind(...uuids).run();

        await auditLog(env, 0, 'bulk_reset_bandwidth', 'user', uuids.join(','), `Reset bandwidth for ${uuids.length} users`);

        return mgmtJsonResponse({ success: true, reset: uuids.length });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to bulk reset bandwidth' }, 500);
    }
}

export async function mgmtGetUserStatus(uuid, env) {
    try {
        const user = await env.DB.prepare(
            'SELECT * FROM users WHERE uuid = ?'
        ).bind(uuid).first();

        if (!user) {
            return mgmtJsonResponse({ error: 'User not found' }, 404);
        }

        const bw = await env.DB.prepare(
            'SELECT SUM(total_bytes) as t FROM bandwidth_usage WHERE user_id = ?'
        ).bind(user.id).first();

        const isExpired = user.expires_at && new Date(user.expires_at) < new Date();
        const maxBW = user.max_bandwidth_bytes || (user.max_bandwidth_mb || 0) * 1024 * 1024;

        return mgmtJsonResponse({
            user: {
                uuid: user.uuid,
                username: user.username,
                is_active: user.is_active === 1 && !isExpired && !user.is_frozen,
                is_frozen: user.is_frozen === 1,
                expires_at: user.expires_at,
                start_date: user.start_date,
                max_bandwidth_bytes: maxBW,
                used_bandwidth_bytes: user.used_bandwidth_bytes || bw?.t || 0,
                bandwidth_usage_percent: maxBW > 0 ? Math.round(((user.used_bandwidth_bytes || 0) / maxBW) * 100) : 0,
                max_connections: user.max_connections,
                current_connections: user.current_connections,
                last_used_at: user.last_used_at,
                is_online: user.is_online === 1,
                last_ip: user.last_ip,
                plan_id: user.plan_id,
                tags: user.tags,
                notes: user.notes,
                protocols: user.protocols,
                telegram_id: user.telegram_id
            }
        });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get user status' }, 500);
    }
}

// ============================================
// BANDWIDTH TRACKING API
// ============================================

export async function mgmtTrackBandwidthAPI(request, env) {
    try {
        const { uuid, request_count } = await request.json();

        if (!uuid) {
            return mgmtJsonResponse({ error: 'UUID required' }, 400);
        }

        await mgmtTrackBandwidth(env, uuid, request_count || 1);

        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to track bandwidth' }, 500);
    }
}

// ============================================
// SUBSCRIPTION & CONFIG
// ============================================

export async function mgmtGenerateSubscriptionUrl(uuid, hostname) {
    const text = hostname + uuid;

    const encoder = new TextEncoder();
    const firstHashBuffer = await crypto.subtle.digest('MD5', encoder.encode(text));
    const firstHashArray = Array.from(new Uint8Array(firstHashBuffer));
    const firstHex = firstHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const middlePart = firstHex.slice(7, 27);

    const secondHashBuffer = await crypto.subtle.digest('MD5', encoder.encode(middlePart));
    const secondHashArray = Array.from(new Uint8Array(secondHashBuffer));
    const token = secondHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const subscriptionUrl = `https://${hostname}/sub?token=${token}`;

    return {
        subscription: subscriptionUrl,
        token: token,
        hostname: hostname
    };
}

export async function mgmtTestConnection(hostname) {
    const startTime = Date.now();
    try {
        const response = await fetch(`https://${hostname}`, {
            method: 'HEAD',
            signal: AbortSignal.timeout(5000)
        });
        const ping = Date.now() - startTime;
        return {
            status: response.ok ? 'excellent' : response.status === 403 ? 'good' : 'poor',
            ping: ping,
            code: response.status
        };
    } catch (e) {
        return { status: 'unreachable', ping: -1, code: 0 };
    }
}

export async function mgmtGetUserConfigs(uuid, env, request) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ?').bind(uuid).first();
        if (!user) return mgmtJsonResponse({ error: 'User not found' }, 404);

        const requestUrl = new URL(request.url);
        const hostname = requestUrl.hostname;

        const subConfig = await mgmtGenerateSubscriptionUrl(uuid, hostname);
        const connectionTest = await mgmtTestConnection(hostname);

        return mgmtJsonResponse({
            user: {
                uuid: user.uuid,
                username: user.username,
                is_active: user.is_active === 1,
                expires_at: user.expires_at,
                max_bandwidth_bytes: user.max_bandwidth_bytes || (user.max_bandwidth_mb || 0) * 1024 * 1024,
                protocols: user.protocols
            },
            config: subConfig,
            connection: connectionTest
        });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get configs' }, 500);
    }
}

export async function mgmtResetUUID(uuid, env) {
    try {
        const newUUID = mgmtGenerateUUID();
        await env.DB.prepare(
            'UPDATE users SET uuid = ?, updated_at = datetime("now") WHERE uuid = ?'
        ).bind(newUUID, uuid).run();
        clearUUIDCache();

        await auditLog(env, 0, 'reset_uuid', 'user', uuid, `Reset to ${newUUID}`);

        return mgmtJsonResponse({ success: true, newUUID });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to reset UUID' }, 500);
    }
}

// ============================================
// STATS & DASHBOARD
// ============================================

export async function mgmtGetStats(env) {
    try {
        const total = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
        const active = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE is_active = 1').first();
        const today = await env.DB.prepare(
            'SELECT SUM(total_bytes) as t FROM bandwidth_usage WHERE date = date("now")'
        ).first();
        const online = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE is_online = 1').first();
        const expired = await env.DB.prepare(
            'SELECT COUNT(*) as c FROM users WHERE expires_at <= datetime("now") AND expires_at IS NOT NULL'
        ).first();

        // Bandwidth by day (last 7 days)
        const dailyBandwidth = await env.DB.prepare(`
            SELECT date, SUM(total_bytes) as total
            FROM bandwidth_usage
            WHERE date >= date('now', '-7 days')
            GROUP BY date
            ORDER BY date
        `).all();

        return mgmtJsonResponse({
            stats: {
                totalUsers: total?.c || 0,
                activeUsers: active?.c || 0,
                todayBandwidth: today?.t || 0,
                onlineUsers: online?.c || 0,
                expiredUsers: expired?.c || 0,
                dailyBandwidth: dailyBandwidth.results || []
            }
        });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get stats' }, 500);
    }
}

// ============================================
// PLANS MANAGEMENT
// ============================================

export async function mgmtGetPlans(env) {
    try {
        const plans = await env.DB.prepare(
            'SELECT * FROM plans ORDER BY sort_order ASC, created_at DESC'
        ).all();
        return mgmtJsonResponse({ plans: plans.results });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get plans' }, 500);
    }
}

export async function mgmtCreatePlan(request, env) {
    try {
        const { name, description, max_bandwidth_bytes, max_connections, duration_days, price, currency, protocols } = await request.json();

        if (!name) return mgmtJsonResponse({ error: 'Plan name required' }, 400);

        await env.DB.prepare(`
            INSERT INTO plans (name, description, max_bandwidth_bytes, max_connections, duration_days, price, currency, protocols)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
            name,
            description || '',
            max_bandwidth_bytes || 0,
            max_connections || 1,
            duration_days || 30,
            price || 0,
            currency || 'IRR',
            protocols || '{"vless": true, "trojan": true}'
        ).run();

        return mgmtJsonResponse({ success: true }, 201);
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to create plan' }, 500);
    }
}

export async function mgmtUpdatePlan(id, request, env) {
    try {
        const data = await request.json();
        const allowedFields = ['name', 'description', 'max_bandwidth_bytes', 'max_connections', 'duration_days', 'price', 'currency', 'protocols', 'is_active', 'sort_order'];

        const updates = [];
        const bindings = [];

        for (const field of allowedFields) {
            if (data[field] !== undefined) {
                updates.push(`${field} = ?`);
                bindings.push(data[field]);
            }
        }

        if (updates.length === 0) return mgmtJsonResponse({ error: 'No fields to update' }, 400);

        updates.push('updated_at = datetime("now")');
        bindings.push(id);

        await env.DB.prepare(
            `UPDATE plans SET ${updates.join(', ')} WHERE id = ?`
        ).bind(...bindings).run();

        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to update plan' }, 500);
    }
}

export async function mgmtDeletePlan(id, env) {
    try {
        await env.DB.prepare('DELETE FROM plans WHERE id = ?').bind(id).run();
        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to delete plan' }, 500);
    }
}

// ============================================
// TAGS MANAGEMENT
// ============================================

export async function mgmtGetTags(env) {
    try {
        const tags = await env.DB.prepare('SELECT * FROM tags ORDER BY name').all();
        return mgmtJsonResponse({ tags: tags.results });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get tags' }, 500);
    }
}

export async function mgmtCreateTag(request, env) {
    try {
        const { name, color } = await request.json();
        if (!name) return mgmtJsonResponse({ error: 'Tag name required' }, 400);

        await env.DB.prepare(
            'INSERT INTO tags (name, color) VALUES (?, ?)'
        ).bind(name, color || '#3b82f6').run();

        return mgmtJsonResponse({ success: true }, 201);
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to create tag' }, 500);
    }
}

export async function mgmtDeleteTag(id, env) {
    try {
        await env.DB.prepare('DELETE FROM tags WHERE id = ?').bind(id).run();
        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to delete tag' }, 500);
    }
}

// ============================================
// CONNECTION MANAGEMENT
// ============================================

export async function mgmtGetActiveConnections(env) {
    try {
        const connections = await env.DB.prepare(`
            SELECT ac.*, u.username, u.uuid
            FROM active_connections ac
            LEFT JOIN users u ON ac.user_id = u.id
            ORDER BY ac.last_activity DESC
        `).all();
        return mgmtJsonResponse({ connections: connections.results });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get connections' }, 500);
    }
}

export async function mgmtDisconnectUser(connectionId, env) {
    try {
        await env.DB.prepare('DELETE FROM active_connections WHERE connection_id = ?').bind(connectionId).run();
        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to disconnect' }, 500);
    }
}

// ============================================
// CONNECTION LOGS
// ============================================

export async function mgmtGetConnectionLogs(env, params = {}) {
    try {
        let query = 'SELECT cl.*, u.username, u.uuid FROM connection_logs cl LEFT JOIN users u ON cl.user_id = u.id WHERE 1=1';
        const bindings = [];

        if (params.user_id) {
            query += ' AND cl.user_id = ?';
            bindings.push(params.user_id);
        }

        if (params.event_type) {
            query += ' AND cl.event_type = ?';
            bindings.push(params.event_type);
        }

        query += ' ORDER BY cl.created_at DESC LIMIT ?';
        bindings.push(parseInt(params.limit) || 100);

        const logs = await env.DB.prepare(query).bind(...bindings).all();
        return mgmtJsonResponse({ logs: logs.results });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get logs' }, 500);
    }
}

// ============================================
// NOTIFICATIONS
// ============================================

async function queueNotification(env, userId, type, message) {
    try {
        await env.DB.prepare(
            'INSERT INTO notification_queue (user_id, type, message) VALUES (?, ?, ?)'
        ).bind(userId, type, message).run();
    } catch (e) {
        console.error('Queue notification error:', e);
    }
}

export async function mgmtSendTelegramNotification(env, userId, message) {
    try {
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
        if (!user || !user.telegram_id) return;

        const botToken = await getSetting(env, 'telegram_bot_token');
        if (!botToken) return;

        await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: user.telegram_id,
                text: message,
                parse_mode: 'HTML'
            })
        });
    } catch (e) {
        console.error('Telegram notification error:', e);
    }
}

// ============================================
// AUDIT LOG
// ============================================

async function auditLog(env, adminId, action, targetType, targetId, details, ipAddress = '') {
    try {
        await env.DB.prepare(
            'INSERT INTO audit_log (admin_id, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(adminId, action, targetType, targetId, details, ipAddress).run();
    } catch (e) {
        console.error('Audit log error:', e);
    }
}

export async function mgmtGetAuditLog(env, params = {}) {
    try {
        let query = 'SELECT * FROM audit_log WHERE 1=1';
        const bindings = [];

        if (params.admin_id) {
            query += ' AND admin_id = ?';
            bindings.push(params.admin_id);
        }

        if (params.action) {
            query += ' AND action = ?';
            bindings.push(params.action);
        }

        query += ' ORDER BY created_at DESC LIMIT ?';
        bindings.push(parseInt(params.limit) || 100);

        const logs = await env.DB.prepare(query).bind(...bindings).all();
        return mgmtJsonResponse({ logs: logs.results });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get audit log' }, 500);
    }
}

// ============================================
// SETTINGS
// ============================================

async function getSetting(env, key) {
    try {
        const setting = await env.DB.prepare(
            'SELECT value FROM settings WHERE key = ?'
        ).bind(key).first();
        return setting?.value;
    } catch (e) {
        return null;
    }
}

export async function mgmtGetSettings(env) {
    try {
        const settings = await env.DB.prepare('SELECT * FROM settings').all();
        const obj = {};
        for (const s of settings.results) {
            if (!s.key.startsWith('auth_token_')) {
                obj[s.key] = s.value;
            }
        }
        return mgmtJsonResponse({ settings: obj });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get settings' }, 500);
    }
}

export async function mgmtUpdateSettings(request, env) {
    try {
        const data = await request.json();

        for (const [key, value] of Object.entries(data)) {
            if (key.startsWith('auth_token_')) continue;
            await env.DB.prepare(
                'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)'
            ).bind(key, String(value)).run();
        }

        return mgmtJsonResponse({ success: true });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to update settings' }, 500);
    }
}

// ============================================
// EXPORT (CSV)
// ============================================

export async function mgmtExportUsers(env, format = 'csv') {
    try {
        const users = await env.DB.prepare(`
            SELECT u.*, p.name as plan_name
            FROM users u
            LEFT JOIN plans p ON u.plan_id = p.id
            ORDER BY u.created_at DESC
        `).all();

        if (format === 'csv') {
            const headers = ['UUID', 'Username', 'Status', 'Plan', 'Bandwidth Used', 'Max Bandwidth', 'Expires', 'Created', 'Last Used'];
            const rows = users.results.map(u => [
                u.uuid,
                u.username,
                u.is_active ? 'Active' : 'Inactive',
                u.plan_name || '-',
                u.used_bandwidth_bytes || 0,
                u.max_bandwidth_bytes || 0,
                u.expires_at || '-',
                u.created_at,
                u.last_used_at || '-'
            ]);

            const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');

            return new Response(csv, {
                headers: {
                    'Content-Type': 'text/csv;charset=utf-8',
                    'Content-Disposition': 'attachment; filename="users.csv"',
                    ...mgmtCorsHeaders()
                }
            });
        }

        return mgmtJsonResponse({ users: users.results });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to export users' }, 500);
    }
}

// ============================================
// BANDWIDTH CHART DATA
// ============================================

export async function mgmtGetBandwidthChart(env, params = {}) {
    try {
        const period = params.period || 'daily';
        let groupBy, dateFormat;

        if (period === 'weekly') {
            groupBy = "strftime('%Y-W%W', date)";
            dateFormat = '%Y-W%W';
        } else if (period === 'monthly') {
            groupBy = "strftime('%Y-%m', date)";
            dateFormat = '%Y-%m';
        } else {
            groupBy = 'date';
            dateFormat = '%Y-%m-%d';
        }

        const data = await env.DB.prepare(`
            SELECT ${groupBy} as period, SUM(total_bytes) as total, SUM(request_count) as requests
            FROM bandwidth_usage
            WHERE date >= date('now', '-30 days')
            GROUP BY ${groupBy}
            ORDER BY period
        `).all();

        return mgmtJsonResponse({ chart: data.results, period });
    } catch (e) {
        return mgmtJsonResponse({ error: 'Failed to get chart data' }, 500);
    }
}

// ============================================
// HELPER FUNCTIONS
// ============================================

async function simpleHash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// MAIN REQUEST HANDLER
// ============================================

export async function mgmtHandleRequest(request, env, ctx) {
    // Initialize on first request
    await initManagement(env);

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
    const isWebSocket = upgradeHeader === 'websocket' || !!request.headers.get('Sec-WebSocket-Key');

    // Let WebSocket and gRPC connections pass through to Edge Tunnel
    if (isWebSocket) return null;
    if (method === 'POST') {
        const contentType = (request.headers.get('content-type') || '').toLowerCase();
        if (contentType.startsWith('application/grpc')) return null;
    }

    // Handle CORS preflight
    if (method === 'OPTIONS') {
        return new Response(null, { headers: mgmtCorsHeaders() });
    }

    // ============================================
    // PUBLIC ROUTES
    // ============================================

    // Serve admin panel
    if ((path === '/' || path === '' || path === '/manager' || path === '/manager/') && method === 'GET') {
        return new Response(mgmtAdminHTML(), {
            headers: { 'Content-Type': 'text/html;charset=utf-8', ...mgmtCorsHeaders() }
        });
    }

    // Redirect root to /manager
    if (path === '/' || path === '') {
        return new Response(null, {
            status: 302,
            headers: { 'Location': '/manager', ...mgmtCorsHeaders() }
        });
    }

    // Serve status panel
    if (path === '/user-status' || path === '/user-status/') {
        return new Response(mgmtStatusHTML(), {
            headers: { 'Content-Type': 'text/html;charset=utf-8', ...mgmtCorsHeaders() }
        });
    }

    // Admin login
    if (path === '/api/auth/login' && method === 'POST') {
        return mgmtHandleLogin(request, env);
    }

    // User status API (public)
    if (path === '/api/user/status' && method === 'GET') {
        const uuid = url.searchParams.get('uuid');
        if (!uuid) return mgmtJsonResponse({ error: 'UUID parameter required' }, 400);
        return mgmtGetUserStatus(uuid, env);
    }

    // Bandwidth tracking API
    if (path === '/api/user/track' && method === 'POST') {
        return mgmtTrackBandwidthAPI(request, env);
    }

    // ============================================
    // AUTHENTICATED ROUTES
    // ============================================

    if (path.startsWith('/api/')) {
        const authData = await mgmtVerifyAuth(request, env);
        if (!authData && path !== '/api/auth/login' && path !== '/api/user/status' && path !== '/api/user/track') {
            return mgmtJsonResponse({ error: 'Unauthorized' }, 401);
        }

        // Stats
        if (path === '/api/admin/stats' && method === 'GET') {
            return mgmtGetStats(env);
        }

        // Users CRUD
        if (path === '/api/admin/users' && method === 'GET') {
            const params = {
                search: url.searchParams.get('search'),
                status: url.searchParams.get('status'),
                plan_id: url.searchParams.get('plan_id'),
                tag: url.searchParams.get('tag'),
                sort: url.searchParams.get('sort'),
                order: url.searchParams.get('order'),
                page: url.searchParams.get('page'),
                limit: url.searchParams.get('limit')
            };
            return mgmtGetUsers(env, params);
        }

        if (path === '/api/admin/users' && method === 'POST') {
            return mgmtCreateUser(request, env);
        }

        // Bulk operations
        if (path === '/api/admin/users/bulk-delete' && method === 'POST') {
            const { uuids } = await request.json();
            return mgmtBulkDeleteUsers(uuids, env);
        }

        if (path === '/api/admin/users/bulk-reset-bandwidth' && method === 'POST') {
            const { uuids } = await request.json();
            return mgmtBulkResetBandwidth(uuids, env);
        }

        // Single user operations
        const userMatch = path.match(/^\/api\/admin\/users\/([a-f0-9-]+)$/);
        if (userMatch) {
            const uuid = userMatch[1];
            if (method === 'GET') return mgmtGetUserStatus(uuid, env);
            if (method === 'PUT') return mgmtUpdateUser(uuid, request, env);
            if (method === 'DELETE') return mgmtDeleteUser(uuid, env);
        }

        // User config
        const configMatch = path.match(/^\/api\/admin\/users\/([a-f0-9-]+)\/config$/);
        if (configMatch && method === 'GET') {
            return mgmtGetUserConfigs(configMatch[1], env, request);
        }

        // Reset UUID
        const resetMatch = path.match(/^\/api\/admin\/users\/([a-f0-9-]+)\/reset-uuid$/);
        if (resetMatch && method === 'POST') {
            return mgmtResetUUID(resetMatch[1], env);
        }

        // Plans
        if (path === '/api/admin/plans' && method === 'GET') return mgmtGetPlans(env);
        if (path === '/api/admin/plans' && method === 'POST') return mgmtCreatePlan(request, env);

        const planMatch = path.match(/^\/api\/admin\/plans\/(\d+)$/);
        if (planMatch) {
            if (method === 'PUT') return mgmtUpdatePlan(planMatch[1], request, env);
            if (method === 'DELETE') return mgmtDeletePlan(planMatch[1], env);
        }

        // Tags
        if (path === '/api/admin/tags' && method === 'GET') return mgmtGetTags(env);
        if (path === '/api/admin/tags' && method === 'POST') return mgmtCreateTag(request, env);

        const tagMatch = path.match(/^\/api\/admin\/tags\/(\d+)$/);
        if (tagMatch && method === 'DELETE') return mgmtDeleteTag(tagMatch[1], env);

        // Connections
        if (path === '/api/admin/connections' && method === 'GET') return mgmtGetActiveConnections(env);

        const disconnectMatch = path.match(/^\/api\/admin\/connections\/(.+)\/disconnect$/);
        if (disconnectMatch && method === 'POST') return mgmtDisconnectUser(disconnectMatch[1], env);

        // Logs
        if (path === '/api/admin/logs' && method === 'GET') {
            const params = {
                user_id: url.searchParams.get('user_id'),
                event_type: url.searchParams.get('event_type'),
                limit: url.searchParams.get('limit')
            };
            return mgmtGetConnectionLogs(env, params);
        }

        // Audit log
        if (path === '/api/admin/audit-log' && method === 'GET') {
            const params = {
                admin_id: url.searchParams.get('admin_id'),
                action: url.searchParams.get('action'),
                limit: url.searchParams.get('limit')
            };
            return mgmtGetAuditLog(env, params);
        }

        // Settings
        if (path === '/api/admin/settings' && method === 'GET') return mgmtGetSettings(env);
        if (path === '/api/admin/settings' && method === 'PUT') return mgmtUpdateSettings(request, env);

        // Export
        if (path === '/api/admin/export/users' && method === 'GET') {
            const format = url.searchParams.get('format') || 'csv';
            return mgmtExportUsers(env, format);
        }

        // Bandwidth chart
        if (path === '/api/admin/charts/bandwidth' && method === 'GET') {
            const params = { period: url.searchParams.get('period') };
            return mgmtGetBandwidthChart(env, params);
        }
    }

    // Not a management route
    return null;
}

// ============================================
// ADMIN PANEL HTML (Professional UI)
// ============================================
function mgmtAdminHTML() {
    return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edge Manager - پنل مدیریت</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: #334155;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; }

        /* Login */
        .login-box { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-form { background: var(--bg-secondary); padding: 2rem; border-radius: 1rem; width: 100%; max-width: 400px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
        .login-form h1 { text-align: center; color: var(--accent); margin-bottom: 1.5rem; font-size: 1.5rem; }
        .login-form input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid var(--border); border-radius: 0.5rem; background: var(--bg-primary); color: var(--text-primary); font-size: 1rem; }
        .login-form button { width: 100%; padding: 0.75rem; background: var(--accent); color: white; border: none; border-radius: 0.5rem; cursor: pointer; font-size: 1rem; font-weight: 600; }
        .login-form button:hover { background: var(--accent-hover); }

        /* Header */
        .header { background: var(--bg-secondary); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }
        .header h1 { color: var(--accent); font-size: 1.25rem; }
        .header-actions { display: flex; gap: 0.5rem; }

        /* Navigation */
        .nav { background: var(--bg-secondary); padding: 0.5rem 2rem; display: flex; gap: 0.5rem; border-bottom: 1px solid var(--border); overflow-x: auto; }
        .nav-item { padding: 0.5rem 1rem; border-radius: 0.375rem; cursor: pointer; color: var(--text-secondary); transition: all 0.2s; white-space: nowrap; }
        .nav-item:hover { background: var(--bg-tertiary); color: var(--text-primary); }
        .nav-item.active { background: var(--accent); color: white; }

        /* Container */
        .container { padding: 2rem; max-width: 1400px; margin: 0 auto; }

        /* Stats */
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat { background: var(--bg-secondary); padding: 1.25rem; border-radius: 0.75rem; border: 1px solid var(--border); }
        .stat h3 { color: var(--text-secondary); font-size: 0.8rem; margin-bottom: 0.5rem; }
        .stat .val { font-size: 1.5rem; font-weight: bold; color: var(--accent); }
        .stat .val.success { color: var(--success); }
        .stat .val.warning { color: var(--warning); }
        .stat .val.danger { color: var(--danger); }

        /* Buttons */
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 0.375rem; cursor: pointer; font-size: 0.875rem; margin: 0.25rem; transition: all 0.2s; }
        .btn-primary { background: var(--accent); color: white; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-success { background: var(--success); color: white; }
        .btn-danger { background: var(--danger); color: white; }
        .btn-warning { background: var(--warning); color: white; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-primary); }

        /* Table */
        .table-container { overflow-x: auto; background: var(--bg-secondary); border-radius: 0.75rem; border: 1px solid var(--border); }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: right; border-bottom: 1px solid var(--border); }
        th { background: var(--bg-primary); color: var(--text-secondary); font-weight: 600; font-size: 0.8rem; }
        tr:hover { background: var(--bg-tertiary); }
        .uuid-copy { font-family: monospace; font-size: 0.75rem; word-break: break-all; max-width: 200px; }

        /* Forms */
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: var(--text-secondary); font-size: 0.875rem; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 0.75rem; border: 1px solid var(--border); border-radius: 0.5rem; background: var(--bg-primary); color: var(--text-primary); }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

        /* Modal */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center; }
        .modal.active { display: flex; }
        .modal-content { background: var(--bg-secondary); padding: 2rem; border-radius: 1rem; width: 100%; max-width: 600px; max-height: 90vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
        .modal-content h2 { margin-bottom: 1.5rem; color: var(--accent); }

        /* Search & Filter */
        .toolbar { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center; }
        .search-box { flex: 1; min-width: 200px; }
        .search-box input { width: 100%; padding: 0.5rem 1rem; border: 1px solid var(--border); border-radius: 0.5rem; background: var(--bg-primary); color: var(--text-primary); }

        /* Status badges */
        .badge { padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600; }
        .badge-success { background: rgba(16,185,129,0.2); color: var(--success); }
        .badge-danger { background: rgba(239,68,68,0.2); color: var(--danger); }
        .badge-warning { background: rgba(245,158,11,0.2); color: var(--warning); }

        /* Progress bar */
        .progress { height: 8px; background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; }
        .progress-bar { height: 100%; background: var(--accent); transition: width 0.3s; }
        .progress-bar.warning { background: var(--warning); }
        .progress-bar.danger { background: var(--danger); }

        /* Chart container */
        .chart-container { background: var(--bg-secondary); padding: 1.5rem; border-radius: 0.75rem; border: 1px solid var(--border); margin-bottom: 1.5rem; }
        .chart-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .chart-header h3 { color: var(--text-secondary); }

        /* Config modal */
        .config-modal { max-width: 800px; }
        .config-box { background: var(--bg-primary); padding: 1rem; border-radius: 0.5rem; font-family: monospace; font-size: 0.8rem; word-break: break-all; margin-bottom: 1rem; border: 1px solid var(--border); }
        .connection-info { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
        .connection-info div { background: var(--bg-primary); padding: 1rem; border-radius: 0.5rem; border: 1px solid var(--border); text-align: center; }
        .connection-info h4 { color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 0.5rem; }
        .connection-info .value { color: var(--accent); font-weight: bold; font-size: 1.25rem; }

        /* Tabs */
        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
        .tab { padding: 0.5rem 1rem; cursor: pointer; color: var(--text-secondary); border-radius: 0.375rem 0.375rem 0 0; }
        .tab.active { color: var(--accent); border-bottom: 2px solid var(--accent); }

        /* Pagination */
        .pagination { display: flex; justify-content: center; gap: 0.5rem; margin-top: 1rem; }
        .page-btn { padding: 0.5rem 1rem; border: 1px solid var(--border); border-radius: 0.375rem; cursor: pointer; background: var(--bg-secondary); color: var(--text-primary); }
        .page-btn.active { background: var(--accent); color: white; }
        .page-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .stats { grid-template-columns: 1fr 1fr; }
            .form-row { grid-template-columns: 1fr; }
            .connection-info { grid-template-columns: 1fr; }
        }

        /* Tags */
        .tag { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem; margin: 0.125rem; background: var(--accent); color: white; }
    </style>
</head>
<body>
    <div id="loginPage" class="login-box">
        <div class="login-form">
            <h1>🔐 Edge Manager</h1>
            <input type="text" id="loginUsername" placeholder="نام کاربری" value="admin">
            <input type="password" id="loginPassword" placeholder="رمز عبور" onkeypress="if(event.key==='Enter')doLogin()">
            <button onclick="doLogin()">ورود</button>
        </div>
    </div>

    <div id="dashboard" style="display:none">
        <div class="header">
            <h1>⚡ Edge Manager</h1>
            <div class="header-actions">
                <button class="btn btn-outline btn-sm" onclick="loadStats();loadUsers();">🔄 بروزرسانی</button>
                <button class="btn btn-danger btn-sm" onclick="doLogout()">خروج</button>
            </div>
        </div>
        <div class="nav">
            <div class="nav-item active" onclick="showSection('dashboard-section', this)">📊 داشبورد</div>
            <div class="nav-item" onclick="showSection('users-section', this)">👥 کاربران</div>
            <div class="nav-item" onclick="showSection('plans-section', this)">📦 پلن‌ها</div>
            <div class="nav-item" onclick="showSection('connections-section', this)">🔗 اتصالات</div>
            <div class="nav-item" onclick="showSection('logs-section', this)">📋 لاگ‌ها</div>
            <div class="nav-item" onclick="showSection('settings-section', this)">⚙️ تنظیمات</div>
        </div>

        <div class="container">
            <!-- Dashboard Section -->
            <div id="dashboard-section" class="section">
                <div class="stats">
                    <div class="stat"><h3>کل کاربران</h3><div class="val" id="statTotal">0</div></div>
                    <div class="stat"><h3>فعال</h3><div class="val success" id="statActive">0</div></div>
                    <div class="stat"><h3>آفلاین</h3><div class="val warning" id="statOnline">0</div></div>
                    <div class="stat"><h3>منقضی شده</h3><div class="val danger" id="statExpired">0</div></div>
                    <div class="stat"><h3>مصرف امروز</h3><div class="val" id="statBandwidth">0 B</div></div>
                </div>
                <div class="chart-container">
                    <div class="chart-header">
                        <h3>📈 نمودار مصرف ترافیک (۳۰ روز اخیر)</h3>
                        <div>
                            <button class="btn btn-sm btn-outline" onclick="loadChart('daily')">روزانه</button>
                            <button class="btn btn-sm btn-outline" onclick="loadChart('weekly')">هفتگی</button>
                            <button class="btn btn-sm btn-outline" onclick="loadChart('monthly')">ماهانه</button>
                        </div>
                    </div>
                    <canvas id="bandwidthChart" height="100"></canvas>
                </div>
            </div>

            <!-- Users Section -->
            <div id="users-section" class="section" style="display:none">
                <div class="toolbar">
                    <div class="search-box">
                        <input type="text" id="userSearch" placeholder="جستجو بر اساس نام یا UUID..." oninput="debounceSearch()">
                    </div>
                    <select id="statusFilter" onchange="loadUsers()">
                        <option value="">همه وضعیت‌ها</option>
                        <option value="active">فعال</option>
                        <option value="inactive">غیرفعال</option>
                        <option value="expired">منقضی شده</option>
                    </select>
                    <select id="planFilter" onchange="loadUsers()">
                        <option value="">همه پلن‌ها</option>
                    </select>
                    <button class="btn btn-primary" onclick="showCreateModal()">➕ کاربر جدید</button>
                    <button class="btn btn-success" onclick="exportUsers()">📥 خروجی CSV</button>
                    <button class="btn btn-warning" onclick="bulkResetBandwidth()">🔄 ریست گروهی حجم</button>
                    <button class="btn btn-danger" onclick="bulkDeleteUsers()">🗑️ حذف گروهی</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                                <th>UUID</th>
                                <th>نام</th>
                                <th>وضعیت</th>
                                <th>پلن</th>
                                <th>مصرف حجم</th>
                                <th>اتصالات</th>
                                <th>انقضا</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>
                        <tbody id="usersTable"></tbody>
                    </table>
                </div>
                <div class="pagination" id="pagination"></div>
            </div>

            <!-- Plans Section -->
            <div id="plans-section" class="section" style="display:none">
                <div class="toolbar">
                    <h3 style="color:var(--text-secondary)">📦 مدیریت پلن‌ها</h3>
                    <button class="btn btn-primary" onclick="showCreatePlanModal()">➕ پلن جدید</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>نام</th>
                                <th>توضیحات</th>
                                <th>حجم</th>
                                <th>اتصالات</th>
                                <th>مدت (روز)</th>
                                <th>قیمت</th>
                                <th>وضعیت</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>
                        <tbody id="plansTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- Connections Section -->
            <div id="connections-section" class="section" style="display:none">
                <div class="toolbar">
                    <h3 style="color:var(--text-secondary)">🔗 اتصالات فعال</h3>
                    <button class="btn btn-success" onclick="loadConnections()">🔄 بروزرسانی</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>کاربر</th>
                                <th>پروتکل</th>
                                <th>IP</th>
                                <th>اتصال</th>
                                <th>آخرین فعالیت</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>
                        <tbody id="connectionsTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- Logs Section -->
            <div id="logs-section" class="section" style="display:none">
                <div class="toolbar">
                    <h3 style="color:var(--text-secondary)">📋 تاریخچه اتصالات</h3>
                    <select id="logEventType" onchange="loadLogs()">
                        <option value="">همه رویدادها</option>
                        <option value="connect">اتصال</option>
                        <option value="disconnect">قطع اتصال</option>
                        <option value="error">خطا</option>
                    </select>
                    <button class="btn btn-success" onclick="loadLogs()">🔄 بروزرسانی</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>زمان</th>
                                <th>کاربر</th>
                                <th>رویداد</th>
                                <th>پروتکل</th>
                                <th>IP</th>
                                <th>جزئیات</th>
                            </tr>
                        </thead>
                        <tbody id="logsTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- Settings Section -->
            <div id="settings-section" class="section" style="display:none">
                <h3 style="color:var(--text-secondary); margin-bottom:1rem;">⚙️ تنظیمات سیستم</h3>
                <div style="background:var(--bg-secondary); padding:1.5rem; border-radius:0.75rem; border:1px solid var(--border); max-width:600px;">
                    <div class="form-group">
                        <label>نام سیستم</label>
                        <input type="text" id="settingSystemName" value="Edge Manager">
                    </div>
                    <div class="form-group">
                        <label>آستانه هشدار حجم (%)</label>
                        <input type="number" id="settingTrafficAlert" value="80" min="0" max="100">
                    </div>
                    <div class="form-group">
                        <label>هشدار قبل از انقضا (روز)</label>
                        <input type="number" id="settingExpiryWarning" value="7" min="0">
                    </div>
                    <div class="form-group">
                        <label>توکن ربات تلگرام</label>
                        <input type="text" id="settingTelegramToken" placeholder="Bot Token">
                    </div>
                    <div class="form-group">
                        <label>آیدی ادمین تلگرام</label>
                        <input type="text" id="settingTelegramAdmin" placeholder="Chat ID">
                    </div>
                    <button class="btn btn-primary" onclick="saveSettings()">💾 ذخیره تنظیمات</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Create User Modal -->
    <div id="createModal" class="modal">
        <div class="modal-content">
            <h2>➕ ایجاد کاربر جدید</h2>
            <div class="form-group">
                <label>نام کاربری</label>
                <input type="text" id="newUsername" placeholder="نام کاربری">
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>پلن</label>
                    <select id="newPlan" onchange="applyPlan()">
                        <option value="">بدون پلن</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>حد اتصالات همزمان</label>
                    <input type="number" id="newMaxConn" value="1" min="0">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>حجم مصرفی (GB)</label>
                    <input type="number" id="newMaxBandwidth" value="0" min="0" step="0.1">
                </div>
                <div class="form-group">
                    <label>تاریخ انقضا</label>
                    <input type="date" id="newExpiry">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>آیدی تلگرام</label>
                    <input type="text" id="newTelegramId" placeholder="اختیاری">
                </div>
                <div class="form-group">
                    <label>یادداشت</label>
                    <input type="text" id="newNotes" placeholder="اختیاری">
                </div>
            </div>
            <div style="display:flex; gap:0.5rem;">
                <button class="btn btn-primary" onclick="doCreateUser()" style="flex:1">ایجاد کاربر</button>
                <button class="btn btn-danger" onclick="hideCreateModal()" style="flex:1">لغو</button>
            </div>
        </div>
    </div>

    <!-- Config Modal -->
    <div id="configModal" class="modal">
        <div class="modal-content config-modal">
            <h2>📋 اطلاعات اشتراک</h2>
            <div class="connection-info">
                <div>
                    <h4>وضعیت اتصال</h4>
                    <div class="value" id="connStatus">-</div>
                </div>
                <div>
                    <h4>پینگ</h4>
                    <div class="value" id="connPing">-</div>
                </div>
                <div>
                    <h4>کد پاسخ</h4>
                    <div class="value" id="connCode">-</div>
                </div>
            </div>
            <div class="config-box" id="subConfig">-</div>
            <div style="display:flex; gap:0.5rem;">
                <button class="btn btn-primary" onclick="copySubConfig()" style="flex:1">کپی لینک</button>
                <button class="btn btn-danger" onclick="hideConfigModal()" style="flex:1">بستن</button>
            </div>
        </div>
    </div>

    <!-- Create Plan Modal -->
    <div id="createPlanModal" class="modal">
        <div class="modal-content">
            <h2>➕ ایجاد پلن جدید</h2>
            <div class="form-group">
                <label>نام پلن</label>
                <input type="text" id="planName" placeholder="نام پلن">
            </div>
            <div class="form-group">
                <label>توضیحات</label>
                <input type="text" id="planDesc" placeholder="توضیحات">
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>حجم (GB)</label>
                    <input type="number" id="planBandwidth" value="10" min="0" step="0.1">
                </div>
                <div class="form-group">
                    <label>حد اتصالات</label>
                    <input type="number" id="planConnections" value="1" min="1">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>مدت (روز)</label>
                    <input type="number" id="planDuration" value="30" min="1">
                </div>
                <div class="form-group">
                    <label>قیمت (ریال)</label>
                    <input type="number" id="planPrice" value="0" min="0">
                </div>
            </div>
            <div style="display:flex; gap:0.5rem;">
                <button class="btn btn-primary" onclick="doCreatePlan()" style="flex:1">ایجاد پلن</button>
                <button class="btn btn-danger" onclick="hideCreatePlanModal()" style="flex:1">لغو</button>
            </div>
        </div>
    </div>

    <script>
        let token = localStorage.getItem('em_token');
        let currentPage = 1;
        let selectedUsers = [];
        let bandwidthChart = null;
        let searchTimeout = null;
        let plans = [];

        if (token) showDashboard();

        // ============================================
        // AUTH
        // ============================================
        async function doLogin() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            try {
                const r = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                const d = await r.json();
                if (d.success) {
                    token = d.token;
                    localStorage.setItem('em_token', token);
                    showDashboard();
                } else {
                    alert('خطا: ' + (d.error || 'رمز عبور اشتباه است'));
                }
            } catch (e) {
                alert('خطا در اتصال');
            }
        }

        function doLogout() {
            token = null;
            localStorage.removeItem('em_token');
            location.reload();
        }

        function showDashboard() {
            document.getElementById('loginPage').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            loadStats();
            loadUsers();
            loadPlans();
        }

        // ============================================
        // NAVIGATION
        // ============================================
        function showSection(id, el) {
            document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(id).style.display = 'block';
            if (el) el.classList.add('active');

            if (id === 'plans-section') loadPlans();
            if (id === 'connections-section') loadConnections();
            if (id === 'logs-section') loadLogs();
            if (id === 'settings-section') loadSettings();
        }

        // ============================================
        // STATS
        // ============================================
        async function loadStats() {
            try {
                const r = await fetch('/api/admin/stats', {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();
                if (d.stats) {
                    document.getElementById('statTotal').textContent = d.stats.totalUsers;
                    document.getElementById('statActive').textContent = d.stats.activeUsers;
                    document.getElementById('statOnline').textContent = d.stats.onlineUsers || 0;
                    document.getElementById('statExpired').textContent = d.stats.expiredUsers || 0;
                    document.getElementById('statBandwidth').textContent = formatBytes(d.stats.todayBandwidth);
                }
            } catch (e) { console.error('Stats error:', e); }
        }

        // ============================================
        // USERS
        // ============================================
        async function loadUsers() {
            try {
                const search = document.getElementById('userSearch')?.value || '';
                const status = document.getElementById('statusFilter')?.value || '';
                const planId = document.getElementById('planFilter')?.value || '';

                let url = '/api/admin/users?page=' + currentPage + '&limit=20';
                if (search) url += '&search=' + encodeURIComponent(search);
                if (status) url += '&status=' + status;
                if (planId) url += '&plan_id=' + planId;

                const r = await fetch(url, {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();
                const users = d.users || [];
                selectedUsers = [];

                document.getElementById('usersTable').innerHTML = users.map(u => {
                    const maxBW = u.max_bandwidth_bytes || 0;
                    const usedBW = u.used_bandwidth_bytes || 0;
                    const percent = maxBW > 0 ? Math.round((usedBW / maxBW) * 100) : 0;
                    const isExpired = u.expires_at && new Date(u.expires_at) < new Date();
                    const statusBadge = u.is_active && !isExpired && !u.is_frozen
                        ? '<span class="badge badge-success">فعال</span>'
                        : u.is_frozen ? '<span class="badge badge-warning">فریز</span>'
                        : isExpired ? '<span class="badge badge-danger">منقضی</span>'
                        : '<span class="badge badge-danger">غیرفعال</span>';

                    const progressClass = percent >= 90 ? 'danger' : percent >= 70 ? 'warning' : '';

                    return '<tr>' +
                        '<td><input type="checkbox" value="' + u.uuid + '" onchange="toggleUserSelect(this)"></td>' +
                        '<td class="uuid-copy">' + u.uuid + '</td>' +
                        '<td>' + (u.username || '-') + '</td>' +
                        '<td>' + statusBadge + '</td>' +
                        '<td>' + (u.plan_name || '-') + '</td>' +
                        '<td>' +
                            '<div style="font-size:0.75rem">' + formatBytes(usedBW) + (maxBW > 0 ? ' / ' + formatBytes(maxBW) : '') + '</div>' +
                            (maxBW > 0 ? '<div class="progress"><div class="progress-bar ' + progressClass + '" style="width:' + percent + '%"></div></div>' : '') +
                        '</td>' +
                        '<td>' + (u.current_connections || 0) + '/' + u.max_connections + '</td>' +
                        '<td>' + (u.expires_at ? new Date(u.expires_at).toLocaleDateString('fa-IR') : '∞') + '</td>' +
                        '<td style="white-space:nowrap">' +
                            '<button class="btn btn-primary btn-sm" onclick="showConfigModal(\\'' + u.uuid + '\\')">📋</button> ' +
                            '<button class="btn btn-success btn-sm" onclick="showEditModal(\\'' + u.uuid + '\\')">✏️</button> ' +
                            '<button class="btn btn-warning btn-sm" onclick="resetUUID(\\'' + u.uuid + '\\')">🔄</button> ' +
                            '<button class="btn btn-danger btn-sm" onclick="doDeleteUser(\\'' + u.uuid + '\\')">🗑️</button>' +
                        '</td></tr>';
                }).join('');

                // Pagination
                const totalPages = Math.ceil((d.total || 0) / 20);
                let paginationHtml = '';
                for (let i = 1; i <= totalPages && i <= 10; i++) {
                    paginationHtml += '<button class="page-btn ' + (i === currentPage ? 'active' : '') + '" onclick="goToPage(' + i + ')">' + i + '</button>';
                }
                document.getElementById('pagination').innerHTML = paginationHtml;
            } catch (e) { console.error('Users error:', e); }
        }

        function goToPage(page) {
            currentPage = page;
            loadUsers();
        }

        function debounceSearch() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => { currentPage = 1; loadUsers(); }, 300);
        }

        function toggleSelectAll() {
            const checked = document.getElementById('selectAll').checked;
            document.querySelectorAll('#usersTable input[type=checkbox]').forEach(cb => {
                cb.checked = checked;
                toggleUserSelect(cb);
            });
        }

        function toggleUserSelect(cb) {
            const uuid = cb.value;
            if (cb.checked) {
                if (!selectedUsers.includes(uuid)) selectedUsers.push(uuid);
            } else {
                selectedUsers = selectedUsers.filter(u => u !== uuid);
            }
        }

        // ============================================
        // USER CRUD
        // ============================================
        function showCreateModal() {
            document.getElementById('createModal').classList.add('active');
            loadPlanOptions();
        }

        function hideCreateModal() { document.getElementById('createModal').classList.remove('active'); }

        async function doCreateUser() {
            try {
                const bandwidthGB = parseFloat(document.getElementById('newMaxBandwidth').value) || 0;
                await fetch('/api/admin/users', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                    body: JSON.stringify({
                        username: document.getElementById('newUsername').value,
                        max_connections: parseInt(document.getElementById('newMaxConn').value) || 1,
                        max_bandwidth_bytes: bandwidthGB * 1024 * 1024 * 1024,
                        expires_at: document.getElementById('newExpiry').value || null,
                        plan_id: document.getElementById('newPlan').value || null,
                        telegram_id: document.getElementById('newTelegramId').value || '',
                        notes: document.getElementById('newNotes').value || ''
                    })
                });
                hideCreateModal();
                loadUsers();
                loadStats();
            } catch (e) { alert('خطا در ایجاد کاربر'); }
        }

        async function doDeleteUser(uuid) {
            if (!confirm('آیا از حذف این کاربر اطمینان دارید؟')) return;
            try {
                await fetch('/api/admin/users/' + uuid, {
                    method: 'DELETE',
                    headers: {'Authorization': 'Bearer ' + token}
                });
                loadUsers();
                loadStats();
            } catch (e) { alert('خطا در حذف کاربر'); }
        }

        async function resetUUID(uuid) {
            if (!confirm('آیا میخواهید UUID این کاربر ریست شود؟')) return;
            try {
                const r = await fetch('/api/admin/users/' + uuid + '/reset-uuid', {
                    method: 'POST',
                    headers: {'Authorization': 'Bearer ' + token}
                });
                const d = await r.json();
                if (d.success) {
                    alert('UUID جدید: ' + d.newUUID);
                    loadUsers();
                }
            } catch (e) { alert('خطا در ریست UUID'); }
        }

        // ============================================
        // BULK OPERATIONS
        // ============================================
        async function bulkDeleteUsers() {
            if (selectedUsers.length === 0) return alert('ابتدا کاربران را انتخاب کنید');
            if (!confirm('آیا از حذف ' + selectedUsers.length + ' کاربر اطمینان دارید؟')) return;
            try {
                await fetch('/api/admin/users/bulk-delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                    body: JSON.stringify({uuids: selectedUsers})
                });
                loadUsers();
                loadStats();
            } catch (e) { alert('خطا در حذف گروهی'); }
        }

        async function bulkResetBandwidth() {
            if (selectedUsers.length === 0) return alert('ابتدا کاربران را انتخاب کنید');
            if (!confirm('آیا از ریست حجم ' + selectedUsers.length + ' کاربر اطمینان دارید؟')) return;
            try {
                await fetch('/api/admin/users/bulk-reset-bandwidth', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                    body: JSON.stringify({uuids: selectedUsers})
                });
                loadUsers();
            } catch (e) { alert('خطا در ریست گروهی'); }
        }

        // ============================================
        // CONFIG MODAL
        // ============================================
        async function showConfigModal(uuid) {
            document.getElementById('configModal').classList.add('active');
            document.getElementById('subConfig').textContent = 'در حال بارگذاری...';
            try {
                const r = await fetch('/api/admin/users/' + uuid + '/config', {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();
                if (d.config) {
                    document.getElementById('subConfig').textContent = d.config.subscription;
                    if (d.connection) {
                        document.getElementById('connStatus').textContent = d.connection.status === 'excellent' ? 'عالی ✅' : d.connection.status === 'good' ? 'خوب ⚠️' : 'ضعیف ❌';
                        document.getElementById('connPing').textContent = d.connection.ping > 0 ? d.connection.ping + ' ms' : '-';
                        document.getElementById('connCode').textContent = d.connection.code || '-';
                    }
                }
            } catch (e) { document.getElementById('subConfig').textContent = 'خطا'; }
        }

        function hideConfigModal() { document.getElementById('configModal').classList.remove('active'); }
        function copySubConfig() {
            navigator.clipboard.writeText(document.getElementById('subConfig').textContent);
            alert('کپی شد!');
        }

        // ============================================
        // PLANS
        // ============================================
        async function loadPlans() {
            try {
                const r = await fetch('/api/admin/plans', {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();
                plans = d.plans || [];

                document.getElementById('plansTable').innerHTML = plans.map(p => '<tr>' +
                    '<td>' + p.name + '</td>' +
                    '<td>' + (p.description || '-') + '</td>' +
                    '<td>' + formatBytes(p.max_bandwidth_bytes) + '</td>' +
                    '<td>' + p.max_connections + '</td>' +
                    '<td>' + p.duration_days + '</td>' +
                    '<td>' + formatPrice(p.price) + '</td>' +
                    '<td>' + (p.is_active ? '<span class="badge badge-success">فعال</span>' : '<span class="badge badge-danger">غیرفعال</span>') + '</td>' +
                    '<td><button class="btn btn-danger btn-sm" onclick="deletePlan(' + p.id + ')">🗑️</button></td>' +
                '</tr>').join('');

                // Update plan dropdown in create modal
                const select = document.getElementById('newPlan');
                const planFilter = document.getElementById('planFilter');
                if (select) {
                    select.innerHTML = '<option value="">بدون پلن</option>' + plans.filter(p => p.is_active).map(p =>
                        '<option value="' + p.id + '">' + p.name + ' - ' + formatBytes(p.max_bandwidth_bytes) + ' - ' + p.duration_days + ' روز</option>'
                    ).join('');
                }
                if (planFilter) {
                    planFilter.innerHTML = '<option value="">همه پلن‌ها</option>' + plans.map(p =>
                        '<option value="' + p.id + '">' + p.name + '</option>'
                    ).join('');
                }
            } catch (e) { console.error('Plans error:', e); }
        }

        function loadPlanOptions() { loadPlans(); }
        function applyPlan() {
            const planId = document.getElementById('newPlan').value;
            const plan = plans.find(p => p.id == planId);
            if (plan) {
                document.getElementById('newMaxConn').value = plan.max_connections;
                document.getElementById('newMaxBandwidth').value = (plan.max_bandwidth_bytes / (1024*1024*1024)).toFixed(1);
                if (plan.duration_days) {
                    const exp = new Date();
                    exp.setDate(exp.getDate() + plan.duration_days);
                    document.getElementById('newExpiry').value = exp.toISOString().split('T')[0];
                }
            }
        }

        function showCreatePlanModal() { document.getElementById('createPlanModal').classList.add('active'); }
        function hideCreatePlanModal() { document.getElementById('createPlanModal').classList.remove('active'); }

        async function doCreatePlan() {
            try {
                const bwGB = parseFloat(document.getElementById('planBandwidth').value) || 0;
                await fetch('/api/admin/plans', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                    body: JSON.stringify({
                        name: document.getElementById('planName').value,
                        description: document.getElementById('planDesc').value,
                        max_bandwidth_bytes: bwGB * 1024 * 1024 * 1024,
                        max_connections: parseInt(document.getElementById('planConnections').value) || 1,
                        duration_days: parseInt(document.getElementById('planDuration').value) || 30,
                        price: parseInt(document.getElementById('planPrice').value) || 0
                    })
                });
                hideCreatePlanModal();
                loadPlans();
            } catch (e) { alert('خطا در ایجاد پلن'); }
        }

        async function deletePlan(id) {
            if (!confirm('آیا از حذف این پلن اطمینان دارید؟')) return;
            try {
                await fetch('/api/admin/plans/' + id, {method: 'DELETE', headers: {'Authorization': 'Bearer ' + token}});
                loadPlans();
            } catch (e) { alert('خطا'); }
        }

        // ============================================
        // CONNECTIONS
        // ============================================
        async function loadConnections() {
            try {
                const r = await fetch('/api/admin/connections', {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();
                document.getElementById('connectionsTable').innerHTML = (d.connections || []).map(c => '<tr>' +
                    '<td>' + (c.username || c.uuid) + '</td>' +
                    '<td>' + (c.protocol || '-') + '</td>' +
                    '<td>' + (c.ip_address || '-') + '</td>' +
                    '<td>' + (c.connected_at || '-') + '</td>' +
                    '<td>' + (c.last_activity || '-') + '</td>' +
                    '<td><button class="btn btn-danger btn-sm" onclick="disconnectUser(\\'' + c.connection_id + '\\')">قطع</button></td>' +
                '</tr>').join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary)">اتصال فعالی وجود ندارد</td></tr>';
            } catch (e) { console.error('Connections error:', e); }
        }

        async function disconnectUser(id) {
            try {
                await fetch('/api/admin/connections/' + id + '/disconnect', {method: 'POST', headers: {'Authorization': 'Bearer ' + token}});
                loadConnections();
            } catch (e) { alert('خطا'); }
        }

        // ============================================
        // LOGS
        // ============================================
        async function loadLogs() {
            try {
                const eventType = document.getElementById('logEventType')?.value || '';
                let url = '/api/admin/logs?limit=100';
                if (eventType) url += '&event_type=' + eventType;

                const r = await fetch(url, {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();
                document.getElementById('logsTable').innerHTML = (d.logs || []).map(l => '<tr>' +
                    '<td>' + (l.created_at || '-') + '</td>' +
                    '<td>' + (l.username || l.uuid || '-') + '</td>' +
                    '<td><span class="badge badge-' + (l.event_type === 'connect' ? 'success' : l.event_type === 'error' ? 'danger' : 'warning') + '">' + l.event_type + '</span></td>' +
                    '<td>' + (l.protocol || '-') + '</td>' +
                    '<td>' + (l.ip_address || '-') + '</td>' +
                    '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">' + (l.details || '-') + '</td>' +
                '</tr>').join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary)">لاگی وجود ندارد</td></tr>';
            } catch (e) { console.error('Logs error:', e); }
        }

        // ============================================
        // SETTINGS
        // ============================================
        async function loadSettings() {
            try {
                const r = await fetch('/api/admin/settings', {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();
                if (d.settings) {
                    document.getElementById('settingSystemName').value = d.settings.system_name || 'Edge Manager';
                    document.getElementById('settingTrafficAlert').value = d.settings.traffic_alert_threshold || 80;
                    document.getElementById('settingExpiryWarning').value = d.settings.expiry_warning_days || 7;
                    document.getElementById('settingTelegramToken').value = d.settings.telegram_bot_token || '';
                    document.getElementById('settingTelegramAdmin').value = d.settings.telegram_admin_id || '';
                }
            } catch (e) { console.error('Settings error:', e); }
        }

        async function saveSettings() {
            try {
                await fetch('/api/admin/settings', {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                    body: JSON.stringify({
                        system_name: document.getElementById('settingSystemName').value,
                        traffic_alert_threshold: document.getElementById('settingTrafficAlert').value,
                        expiry_warning_days: document.getElementById('settingExpiryWarning').value,
                        telegram_bot_token: document.getElementById('settingTelegramToken').value,
                        telegram_admin_id: document.getElementById('settingTelegramAdmin').value
                    })
                });
                alert('تنظیمات ذخیره شد');
            } catch (e) { alert('خطا در ذخیره'); }
        }

        // ============================================
        // EXPORT
        // ============================================
        function exportUsers() {
            window.open('/api/admin/export/users?format=csv', '_blank');
        }

        // ============================================
        // CHART
        // ============================================
        async function loadChart(period = 'daily') {
            try {
                const r = await fetch('/api/admin/charts/bandwidth?period=' + period, {headers: {'Authorization': 'Bearer ' + token}});
                const d = await r.json();

                const labels = (d.chart || []).map(c => c.period);
                const data = (d.chart || []).map(c => c.total / (1024 * 1024)); // MB

                const ctx = document.getElementById('bandwidthChart').getContext('2d');
                if (bandwidthChart) bandwidthChart.destroy();

                bandwidthChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [{
                            label: 'مصرف ترافیک (MB)',
                            data,
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59,130,246,0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#94a3b8' } } },
                        scales: {
                            x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                            y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }
                        }
                    }
                });
            } catch (e) { console.error('Chart error:', e); }
        }

        // ============================================
        // HELPERS
        // ============================================
        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatPrice(price) {
            if (!price) return 'رایگان';
            return new Intl.NumberFormat('fa-IR').format(price) + ' ریال';
        }

        // Init chart on dashboard load
        setTimeout(() => { if (token) loadChart(); }, 500);
    </script>
</body>
</html>`;
}

// ============================================
// STATUS PANEL HTML
// ============================================
function mgmtStatusHTML() {
    return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>بررسی وضعیت - Edge Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .container { background: #1e293b; padding: 2rem; border-radius: 1rem; width: 100%; max-width: 400px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
        h1 { color: #60a5fa; margin-bottom: 1.5rem; text-align: center; }
        .form-group { margin-bottom: 1rem; }
        .form-group input { width: 100%; padding: 0.75rem; border: 1px solid #334155; border-radius: 0.5rem; background: #0f172a; color: #e2e8f0; text-align: center; font-size: 1rem; }
        .btn { width: 100%; padding: 0.75rem; background: #3b82f6; color: white; border: none; border-radius: 0.5rem; cursor: pointer; font-size: 1rem; font-weight: 600; }
        .btn:hover { background: #2563eb; }
        .result { margin-top: 1.5rem; padding: 1rem; background: #0f172a; border-radius: 0.5rem; display: none; }
        .result.show { display: block; }
        .row { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #334155; }
        .row:last-child { border-bottom: none; }
        .label { color: #94a3b8; }
        .value { color: #60a5fa; font-weight: bold; }
        .active { color: #10b981 !important; }
        .inactive { color: #ef4444 !important; }
        .progress { height: 8px; background: #334155; border-radius: 4px; overflow: hidden; margin-top: 0.5rem; }
        .progress-bar { height: 100%; background: #3b82f6; }
        .progress-bar.warning { background: #f59e0b; }
        .progress-bar.danger { background: #ef4444; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 بررسی وضعیت اشتراک</h1>
        <div class="form-group">
            <input type="text" id="uuidInput" placeholder="UUID خود را وارد کنید">
        </div>
        <button class="btn" onclick="checkStatus()">بررسی وضعیت</button>
        <div id="resultBox" class="result">
            <div class="row"><span class="label">وضعیت:</span><span class="value" id="resStatus">-</span></div>
            <div class="row"><span class="label">نام کاربری:</span><span class="value" id="resUsername">-</span></div>
            <div class="row"><span class="label">حجم مصرفی:</span><span class="value" id="resBandwidth">-</span></div>
            <div class="row"><span class="label">تاریخ انقضا:</span><span class="value" id="resExpiry">-</span></div>
            <div class="row"><span class="label">آخرین استفاده:</span><span class="value" id="resLastUsed">-</span></div>
            <div id="bwProgress"></div>
        </div>
    </div>
    <script>
        async function checkStatus() {
            const uuid = document.getElementById('uuidInput').value.trim();
            if (!uuid) { alert('لطفا UUID خود را وارد کنید'); return; }
            try {
                const r = await fetch('/api/user/status?uuid=' + encodeURIComponent(uuid));
                const d = await r.json();
                if (d.user) {
                    const u = d.user;
                    document.getElementById('resultBox').classList.add('show');
                    document.getElementById('resStatus').textContent = u.is_active ? 'فعال ✅' : 'غیرفعال ❌';
                    document.getElementById('resStatus').className = 'value ' + (u.is_active ? 'active' : 'inactive');
                    document.getElementById('resUsername').textContent = u.username || '-';

                    const maxBW = u.max_bandwidth_bytes || 0;
                    const usedBW = u.used_bandwidth_bytes || 0;
                    document.getElementById('resBandwidth').textContent = formatBytes(usedBW) + (maxBW > 0 ? ' / ' + formatBytes(maxBW) : ' / ∞');

                    if (maxBW > 0) {
                        const percent = Math.round((usedBW / maxBW) * 100);
                        const cls = percent >= 90 ? 'danger' : percent >= 70 ? 'warning' : '';
                        document.getElementById('bwProgress').innerHTML = '<div class="progress"><div class="progress-bar ' + cls + '" style="width:' + percent + '%"></div></div><div style="text-align:center;font-size:0.8rem;color:#94a3b8;margin-top:0.25rem">' + percent + '% مصرف شده</div>';
                    }

                    document.getElementById('resExpiry').textContent = u.expires_at ? new Date(u.expires_at).toLocaleDateString('fa-IR') : 'بدون محدودیت زمانی';
                    document.getElementById('resLastUsed').textContent = u.last_used_at || 'هرگز';
                } else { alert('خطا: ' + (d.error || 'UUID یافت نشد')); }
            } catch (e) { alert('خطا در بررسی وضعیت'); }
        }
        function formatBytes(bytes) {
            if (!bytes) return '0 B';
            const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    </script>
</body>
</html>`;
}
