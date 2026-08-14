// ============================================
// Database Migration System
// Safe, non-destructive schema upgrades
// ============================================

export async function runMigrations(env) {
    if (!env.DB) return;

    const MIGRATION_VERSION = 2;
    const currentVersion = await getMigrationVersion(env);

    if (currentVersion >= MIGRATION_VERSION) return;

    console.log(`[Migration] Running migrations from v${currentVersion} to v${MIGRATION_VERSION}`);

    try {
        if (currentVersion < 2) {
            await migrateToV2(env);
        }

        await setMigrationVersion(env, MIGRATION_VERSION);
        console.log(`[Migration] Completed successfully to v${MIGRATION_VERSION}`);
    } catch (e) {
        console.error(`[Migration] Error: ${e.message}`);
    }
}

async function getMigrationVersion(env) {
    try {
        // Check if migration_version table exists
        const tableCheck = await env.DB.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='migration_version'"
        ).first();

        if (!tableCheck) {
            // Create migration_version table
            await env.DB.exec(`
                CREATE TABLE IF NOT EXISTS migration_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT DEFAULT (datetime('now'))
                )
            `);
            return 0;
        }

        const version = await env.DB.prepare(
            'SELECT version FROM migration_version ORDER BY version DESC LIMIT 1'
        ).first();

        return version?.version || 0;
    } catch (e) {
        return 0;
    }
}

async function setMigrationVersion(env, version) {
    await env.DB.prepare(
        'INSERT INTO migration_version (version) VALUES (?)'
    ).bind(version).run();
}

async function migrateToV2(env) {
    console.log('[Migration] Running v2 migration...');

    // ============================================
    // Add new columns to users table
    // ============================================
    const userColumns = [
        'ALTER TABLE users ADD COLUMN current_connections INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN max_bandwidth_bytes INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN used_bandwidth_bytes INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN bandwidth_reset_period TEXT DEFAULT "monthly"',
        'ALTER TABLE users ADD COLUMN last_bandwidth_reset TEXT',
        'ALTER TABLE users ADD COLUMN start_date TEXT DEFAULT (datetime(\'now\'))',
        'ALTER TABLE users ADD COLUMN is_frozen INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN frozen_at TEXT',
        'ALTER TABLE users ADD COLUMN plan_id INTEGER',
        'ALTER TABLE users ADD COLUMN created_by INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN protocols TEXT DEFAULT \'{"vless": true, "trojan": true}\'',
        'ALTER TABLE users ADD COLUMN tags TEXT DEFAULT \'\'',
        'ALTER TABLE users ADD COLUMN telegram_id TEXT DEFAULT \'\'',
        'ALTER TABLE users ADD COLUMN telegram_username TEXT DEFAULT \'\'',
        'ALTER TABLE users ADD COLUMN is_online INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN last_online_at TEXT',
        'ALTER TABLE users ADD COLUMN last_ip TEXT'
    ];

    for (const sql of userColumns) {
        try {
            await env.DB.exec(sql);
        } catch (e) {
            // Column might already exist, ignore
            if (!e.message.includes('duplicate column')) {
                console.error(`[Migration] Column error: ${e.message}`);
            }
        }
    }

    // ============================================
    // Migrate max_bandwidth_mb to max_bandwidth_bytes
    // ============================================
    try {
        await env.DB.exec(`
            UPDATE users SET max_bandwidth_bytes = max_bandwidth_mb * 1024 * 1024
            WHERE max_bandwidth_mb > 0 AND max_bandwidth_bytes = 0
        `);
    } catch (e) {
        console.error(`[Migration] Bandwidth migration error: ${e.message}`);
    }

    // ============================================
    // Migrate total_bytes from bandwidth_usage to used_bandwidth_bytes
    // ============================================
    try {
        await env.DB.exec(`
            UPDATE users SET used_bandwidth_bytes = (
                SELECT COALESCE(SUM(total_bytes), 0)
                FROM bandwidth_usage
                WHERE bandwidth_usage.user_id = users.id
            )
        `);
    } catch (e) {
        console.error(`[Migration] Bandwidth migration error: ${e.message}`);
    }

    // ============================================
    // Create plans table
    // ============================================
    try {
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                max_bandwidth_bytes INTEGER DEFAULT 0,
                max_connections INTEGER DEFAULT 1,
                duration_days INTEGER DEFAULT 30,
                price INTEGER DEFAULT 0,
                currency TEXT DEFAULT 'IRR',
                protocols TEXT DEFAULT '{"vless": true, "trojan": true}',
                is_active INTEGER DEFAULT 1,
                sort_order INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
        `);
    } catch (e) {
        console.error(`[Migration] Plans table error: ${e.message}`);
    }

    // ============================================
    // Create admin_users table
    // ============================================
    try {
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'reseller',
                max_users INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                two_factor_secret TEXT,
                two_factor_enabled INTEGER DEFAULT 0,
                allowed_ips TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                last_login_at TEXT
            )
        `);
    } catch (e) {
        console.error(`[Migration] Admin users table error: ${e.message}`);
    }

    // ============================================
    // Create tags table
    // ============================================
    try {
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                color TEXT DEFAULT '#3b82f6',
                created_at TEXT DEFAULT (datetime('now'))
            )
        `);
    } catch (e) {
        console.error(`[Migration] Tags table error: ${e.message}`);
    }

    // ============================================
    // Create user_tags table
    // ============================================
    try {
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS user_tags (
                user_id INTEGER NOT NULL,
                tag_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, tag_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (tag_id) REFERENCES tags(id)
            )
        `);
    } catch (e) {
        console.error(`[Migration] User tags table error: ${e.message}`);
    }

    // ============================================
    // Create notification_queue table
    // ============================================
    try {
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS notification_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT NOT NULL,
                message TEXT NOT NULL,
                sent INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
    } catch (e) {
        console.error(`[Migration] Notification queue table error: ${e.message}`);
    }

    // ============================================
    // Create audit_log table
    // ============================================
    try {
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER DEFAULT 0,
                action TEXT NOT NULL,
                target_type TEXT DEFAULT '',
                target_id TEXT DEFAULT '',
                details TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            )
        `);
    } catch (e) {
        console.error(`[Migration] Audit log table error: ${e.message}`);
    }

    // ============================================
    // Add new indexes
    // ============================================
    const indexes = [
        'CREATE INDEX IF NOT EXISTS idx_users_plan ON users(plan_id)',
        'CREATE INDEX IF NOT EXISTS idx_users_created_by ON users(created_by)',
        'CREATE INDEX IF NOT EXISTS idx_users_tags ON users(tags)',
        'CREATE INDEX IF NOT EXISTS idx_logs_created ON connection_logs(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_plans_active ON plans(is_active)',
        'CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username)',
        'CREATE INDEX IF NOT EXISTS idx_audit_admin ON audit_log(admin_id)',
        'CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_notification_sent ON notification_queue(sent)'
    ];

    for (const sql of indexes) {
        try {
            await env.DB.exec(sql);
        } catch (e) {
            // Index might already exist
        }
    }

    // ============================================
    // Insert default settings
    // ============================================
    const defaultSettings = [
        ['traffic_alert_threshold', '80'],
        ['expiry_warning_days', '7'],
        ['telegram_bot_token', ''],
        ['telegram_admin_id', '']
    ];

    for (const [key, value] of defaultSettings) {
        try {
            await env.DB.prepare(
                'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)'
            ).bind(key, value).run();
        } catch (e) {
            // Setting might already exist
        }
    }

    // ============================================
    // Insert default plans
    // ============================================
    const defaultPlans = [
        { name: 'پلن ۱ ماهه', description: 'حجم ۱۰ گیگ', max_bandwidth_bytes: 10 * 1024 * 1024 * 1024, max_connections: 1, duration_days: 30, price: 50000 },
        { name: 'پلن ۳ ماهه', description: 'حجم ۳۰ گیگ', max_bandwidth_bytes: 30 * 1024 * 1024 * 1024, max_connections: 2, duration_days: 90, price: 120000 },
        { name: 'پلن ۱ ساله', description: 'حجم ۱۰۰ گیگ', max_bandwidth_bytes: 100 * 1024 * 1024 * 1024, max_connections: 3, duration_days: 365, price: 400000 },
    ];

    for (const plan of defaultPlans) {
        try {
            await env.DB.prepare(`
                INSERT OR IGNORE INTO plans (name, description, max_bandwidth_bytes, max_connections, duration_days, price)
                VALUES (?, ?, ?, ?, ?, ?)
            `).bind(plan.name, plan.description, plan.max_bandwidth_bytes, plan.max_connections, plan.duration_days, plan.price).run();
        } catch (e) {
            // Plan might already exist
        }
    }

    // ============================================
    // Create default superadmin
    // ============================================
    try {
        const adminExists = await env.DB.prepare(
            'SELECT id FROM admin_users WHERE username = ?'
        ).bind('admin').first();

        if (!adminExists) {
            // Simple hash for default password
            const passwordHash = await simpleHash('admin123');
            await env.DB.prepare(`
                INSERT INTO admin_users (username, password_hash, role)
                VALUES (?, ?, 'superadmin')
            `).bind('admin', passwordHash).run();
        }
    } catch (e) {
        console.error(`[Migration] Admin user error: ${e.message}`);
    }

    console.log('[Migration] v2 migration completed');
}

// Simple hash function for Cloudflare Workers
async function simpleHash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
