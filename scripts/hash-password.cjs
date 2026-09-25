#!/usr/bin/env node
// Generate a password hash compatible with the Worker's bcryptHash format.
// Usage: node scripts/hash-password.cjs yourpassword
// Then run the printed SQL via: wrangler d1 execute distribup-db --remote --command "..."

const crypto = require('crypto');

function bcryptHash(password, rounds = 10) {
  const salt = crypto.randomBytes(16);
  const iterations = 2 ** rounds;
  let derivedKey = salt;
  for (let i = 0; i < iterations; i++) {
    const data = Buffer.concat([derivedKey, Buffer.from(password, 'utf8')]);
    derivedKey = crypto.createHash('sha256').update(data).digest();
  }
  return `$sha256$${rounds}$${salt.toString('base64')}$${derivedKey.toString('base64')}`;
}

const password = process.argv[2];
if (!password) {
  console.error('Usage: node scripts/hash-password.cjs <password>');
  process.exit(1);
}

const hash = bcryptHash(password);
console.log('Password hash:');
console.log(hash);
console.log('');
console.log('Run this SQL to create the first admin (replace team_id/name as needed):');
console.log(`
-- 1. Create a default team
INSERT INTO teams (name, description, max_users) VALUES ('Default Team', 'Personal', 10);

-- 2. Create admin user (replace USERNAME / EMAIL / TEAM_ID)
INSERT INTO users (username, email, password_hash, role, team_id, is_active)
VALUES ('admin', 'admin@example.com', '${hash}', 'admin', (SELECT id FROM teams ORDER BY id LIMIT 1), 1);
`);
