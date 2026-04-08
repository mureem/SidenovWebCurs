require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const file = process.argv[2];
if (!file) {
  console.error('Usage: node scripts/run-sql.js sql/init.sql');
  process.exit(1);
}

const sqlPath = path.resolve(process.cwd(), file);
const sql = fs.readFileSync(sqlPath, 'utf8');

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl:
      process.env.PGSSLMODE === 'require' || process.env.DATABASE_URL?.includes('sslmode=require')
        ? { rejectUnauthorized: false }
        : false,
  });
  await client.connect();
  try {
    await client.query(sql);
    console.log('OK:', file);
  } finally {
    await client.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
