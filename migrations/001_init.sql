-- DistribUp D1 database initialization migration.
-- Run: wrangler d1 execute <database_name> --file=migrations/001_init.sql --remote

-- Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
    team_id INTEGER,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Teams
CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    owner_id INTEGER,
    max_users INTEGER DEFAULT 10,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Apps (iOS / Android)
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    platform TEXT DEFAULT 'ios' CHECK(platform IN ('ios', 'android')),
    bundle_id TEXT NOT NULL,
    package_name TEXT,
    version TEXT DEFAULT '1.0.0',
    description TEXT,
    icon_path TEXT,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Certificates (iOS p12 + Android keystore)
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('ios_p12', 'android_keystore')),
    certificate_p12 TEXT,
    certificate_password TEXT,
    mobileprovision TEXT,
    expires_at DATETIME,
    keystore_file TEXT,
    keystore_password TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id)
);

-- Devices (iOS UDID enrollment)
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    udid TEXT UNIQUE NOT NULL,
    name TEXT,
    platform TEXT DEFAULT 'iOS',
    apple_id TEXT,
    registered_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id)
);

-- Upload records
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT,
    file_size INTEGER,
    file_type TEXT,
    storage_path TEXT,
    version TEXT,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'uploaded', 'signed', 'failed')),
    signed_url TEXT,
    download_count INTEGER DEFAULT 0,
    md5 TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_id) REFERENCES apps(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Download records
CREATE TABLE IF NOT EXISTS downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_id INTEGER NOT NULL,
    device_udid TEXT,
    user_agent TEXT,
    ip_address TEXT,
    downloaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (upload_id) REFERENCES uploads(id)
);

-- Signed file records
CREATE TABLE IF NOT EXISTS signed_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (upload_id) REFERENCES uploads(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_apps_team ON apps(team_id);
CREATE INDEX IF NOT EXISTS idx_apps_bundle ON apps(bundle_id);
CREATE INDEX IF NOT EXISTS idx_uploads_app ON uploads(app_id);
CREATE INDEX IF NOT EXISTS idx_uploads_created ON uploads(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_team ON devices(team_id);
CREATE INDEX IF NOT EXISTS idx_devices_udid ON devices(udid);
