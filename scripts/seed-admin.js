require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const username = process.env.SEED_ADMIN_USER || 'admin';
const password = process.env.SEED_ADMIN_PASSWORD;

async function main() {
  if (!password || password.length < 6) {
    console.error('Задай SEED_ADMIN_PASSWORD (минимум 6 символов), например:');
    console.error('  set SEED_ADMIN_PASSWORD=yourpass && npm run seed:admin');
    process.exit(1);
  }
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl:
      process.env.PGSSLMODE === 'require' || process.env.DATABASE_URL?.includes('sslmode=require')
        ? { rejectUnauthorized: false }
        : false,
  });
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    `INSERT INTO users (username, password_hash, role)
     VALUES ($1, $2, 'admin')
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin', is_blocked = FALSE`,
    [username, hash]
  );
  console.log('Админ готов, логин:', username);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
