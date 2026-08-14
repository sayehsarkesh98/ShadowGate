-- ============================================
-- Edge Tunnel Manager - D1 Database Schema v2
-- Professional VPN Management Panel
-- Version: 2.0.0
-- ============================================

-- ============================================
-- 1. Users Table (Enhanced)
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    username TEXT DEFAULT '',

    -- Connection limits
    max_connections INTEGER DEFAULT 1,
    current_connections INTEGER DEFAULT 0,

    -- Bandwidth limits
    max_bandwidth_bytes INTEGER DEFAULT 0,
    used_bandwidth_bytes INTEGER DEFAULT 0,
    bandwidth_reset_period TEXT DEFAULT 'monthly', -- daily/weekly/monthly/none
    last_bandwidth_reset TEXT,

    -- Subscription period
    start_date TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    is_frozen INTEGER DEFAULT 0,
    frozen_at TEXT,

    -- Status
    is_active INTEGER DEFAULT 1,

    -- Plan reference
    plan_id INTEGER,

    -- Admin/Reseller
    created_by INTEGER DEFAULT 0,

    -- Protocol settings (JSON)
    protocols TEXT DEFAULT '{"vless": true, "trojan": true}',

    -- Tags (comma-separated)
    tags TEXT DEFAULT '',

    -- Notes
    notes TEXT DEFAULT '',

    -- Telegram
    telegram_id TEXT DEFAULT '',
    telegram_username TEXT DEFAULT '',

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    last_used_at TEXT,

    -- Online status
    is_online INTEGER DEFAULT 0,
    last_online_at TEXT,
    last_ip TEXT
);

-- ============================================
-- 2. Plans Table
-- ============================================
CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',

    -- Limits
    max_bandwidth_bytes INTEGER DEFAULT 0,
    max_connections INTEGER DEFAULT 1,

    -- Duration
    duration_days INTEGER DEFAULT 30,

    -- Price
    price INTEGER DEFAULT 0,
    currency TEXT DEFAULT 'IRR',

    -- Protocols allowed
    protocols TEXT DEFAULT '{"vless": true, "trojan": true}',

    -- Status
    is_active INTEGER DEFAULT 1,

    -- Sort order
    sort_order INTEGER DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- ============================================
-- 3. Admin Users Table
-- ============================================
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,

    -- Role: superadmin, reseller, support
    role TEXT DEFAULT 'reseller',

    -- Limits (for resellers)
    max_users INTEGER DEFAULT 0,

    -- Status
    is_active INTEGER DEFAULT 1,

    -- 2FA
    two_factor_secret TEXT,
    two_factor_enabled INTEGER DEFAULT 0,

    -- IP restriction
    allowed_ips TEXT DEFAULT '',

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    last_login_at TEXT
);

-- ============================================
-- 4. Bandwidth Usage (Enhanced)
-- ============================================
CREATE TABLE IF NOT EXISTS bandwidth_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    bytes_up INTEGER DEFAULT 0,
    bytes_down INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bandwidth_user_date ON bandwidth_usage(user_id, date);

-- ============================================
-- 5. Active Connections (Enhanced)
-- ============================================
CREATE TABLE IF NOT EXISTS active_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    connection_id TEXT UNIQUE NOT NULL,
    protocol TEXT DEFAULT 'vless',
    ip_address TEXT,
    user_agent TEXT,
    connected_at TEXT DEFAULT (datetime('now')),
    last_activity TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================
-- 6. Connection Logs (Enhanced)
-- ============================================
CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    protocol TEXT DEFAULT '',
    ip_address TEXT,
    user_agent TEXT,
    details TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

-- ============================================
-- 7. Settings
-- ============================================
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', 'admin123');
INSERT OR REPLACE INTO settings (key, value) VALUES ('system_name', 'Edge Manager');
INSERT OR REPLACE INTO settings (key, value) VALUES ('max_bandwidth_default', '0');
INSERT OR REPLACE INTO settings (key, value) VALUES ('max_connections_default', '1');
INSERT OR REPLACE INTO settings (key, value) VALUES ('default_expiry_days', '30');
INSERT OR REPLACE INTO settings (key, value) VALUES ('requests_per_kb', '5');
INSERT OR REPLACE INTO settings (key, value) VALUES ('hostname', 'your-domain.com');
INSERT OR REPLACE INTO settings (key, value) VALUES ('port', '443');
INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_bot_token', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_admin_id', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('traffic_alert_threshold', '80');
INSERT OR REPLACE INTO settings (key, value) VALUES ('expiry_warning_days', '7');

-- ============================================
-- 8. Tags Table
-- ============================================
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    color TEXT DEFAULT '#3b82f6',
    created_at TEXT DEFAULT (datetime('now'))
);

-- ============================================
-- 9. User Tags (Many-to-Many)
-- ============================================
CREATE TABLE IF NOT EXISTS user_tags (
    user_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, tag_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
);

-- ============================================
-- 10. Notification Queue
-- ============================================
CREATE TABLE IF NOT EXISTS notification_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    sent INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================
-- 11. Audit Log
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER DEFAULT 0,
    action TEXT NOT NULL,
    target_type TEXT DEFAULT '',
    target_id TEXT DEFAULT '',
    details TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

-- ============================================
-- Indexes
-- ============================================
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_expires ON users(expires_at);
CREATE INDEX IF NOT EXISTS idx_users_plan ON users(plan_id);
CREATE INDEX IF NOT EXISTS idx_users_created_by ON users(created_by);
CREATE INDEX IF NOT EXISTS idx_users_tags ON users(tags);
CREATE INDEX IF NOT EXISTS idx_connections_user ON active_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_connections_active ON active_connections(last_activity);
CREATE INDEX IF NOT EXISTS idx_logs_user ON connection_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_type ON connection_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_logs_created ON connection_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_plans_active ON plans(is_active);
CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS idx_audit_admin ON audit_log(admin_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_notification_sent ON notification_queue(sent);
