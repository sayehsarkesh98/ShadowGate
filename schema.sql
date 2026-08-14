-- ============================================
-- Edge Tunnel Manager - D1 Database Schema
-- Version: 1.0.0
-- ============================================

-- Users/UUIDs table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    username TEXT DEFAULT '',
    max_connections INTEGER DEFAULT 1,
    max_bandwidth_mb INTEGER DEFAULT 0,
    expires_at TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    last_used_at TEXT,
    notes TEXT DEFAULT ''
);

-- Bandwidth usage tracking
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

-- Active connections
CREATE TABLE IF NOT EXISTS active_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    connection_id TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    connected_at TEXT DEFAULT (datetime('now')),
    last_activity TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Connection logs
CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

-- Settings
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

CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_expires ON users(expires_at);
CREATE INDEX IF NOT EXISTS idx_connections_user ON active_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_connections_active ON active_connections(last_activity);
CREATE INDEX IF NOT EXISTS idx_logs_user ON connection_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_type ON connection_logs(event_type);
