const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../data/distribup.db');

// 确保数据目录存在
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

let db;

// 初始化数据库
async function init() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) return reject(err);
      console.log('📦 SQLite 数据库连接成功');
      createTables().then(resolve).catch(reject);
    });
  });
}

// 创建表结构
async function createTables() {
  const stmts = [
    // 用户表
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      team_id INTEGER,
      is_active BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    
    // 团队表
    `CREATE TABLE IF NOT EXISTS teams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      owner_id INTEGER,
      max_users INTEGER DEFAULT 10,
      is_active BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )`,
    
    // 应用表
    `CREATE TABLE IF NOT EXISTS apps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      team_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      bundle_id TEXT NOT NULL,
      version TEXT DEFAULT '1.0.0',
      description TEXT,
      icon_path TEXT,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`,
    
    // 证书表
    `CREATE TABLE IF NOT EXISTS certificates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      team_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      certificate_p12 TEXT,
      certificate_password TEXT,
      mobileprovision TEXT,
      expires_at DATETIME,
      is_active BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`,
    
    // 设备表 (UDID)
    `CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      team_id INTEGER NOT NULL,
      udid TEXT UNIQUE NOT NULL,
      name TEXT,
      platform TEXT DEFAULT 'iOS',
      apple_id TEXT,
      registered_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`,
    
    // 上传记录表
    `CREATE TABLE IF NOT EXISTS uploads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      original_name TEXT,
      file_size INTEGER,
      file_type TEXT,
      storage_path TEXT,
      version TEXT,
      status TEXT DEFAULT 'pending',
      signed_url TEXT,
      download_count INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (app_id) REFERENCES apps(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`,
    
    // 下载记录表
    `CREATE TABLE IF NOT EXISTS downloads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      upload_id INTEGER NOT NULL,
      device_udid TEXT,
      user_agent TEXT,
      ip_address TEXT,
      downloaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (upload_id) REFERENCES uploads(id)
    )`
  ];

  return new Promise((resolve, reject) => {
    let completed = 0;
    stmts.forEach(stmt => {
      db.run(stmt, (err) => {
        if (err) return reject(err);
        completed++;
        if (completed === stmts.length) resolve();
      });
    });
  });
}

// 数据库查询方法
const dbMethods = {
  all: (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  }),
  
  get: (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  }),
  
  run: (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      err ? reject(err) : resolve({ id: this.lastID, changes: this.changes });
    });
  }),
  
  // 事务支持
  transaction: async (callbacks) => {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        callbacks(db)
          .then(() => db.run('COMMIT'))
          .then(resolve)
          .catch(err => {
            db.run('ROLLBACK');
            reject(err);
          });
      });
    });
  }
};

module.exports = { init, ...dbMethods };
