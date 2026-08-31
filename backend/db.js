import mysql from 'mysql2/promise';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mysqlPool = null;

// Read database configurations from environment
const dbHost = process.env.DB_HOST || '';
const dbUser = process.env.DB_USER || '';
const dbPassword = process.env.DB_PASSWORD || '';
const dbName = process.env.DB_NAME || '';
const dbPort = process.env.DB_PORT || '3306';

// Initialization function
export async function initDB() {
  if (!dbHost || !dbUser || !dbName) {
    console.error('CRITICAL: MySQL environment variables not fully set. DB_HOST, DB_USER, and DB_NAME are required.');
    process.exit(1);
  }

  const MAX_RETRIES = 10;
  const RETRY_DELAY_MS = 3000;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`Attempting to connect to MySQL database at ${dbHost} (attempt ${attempt}/${MAX_RETRIES})...`);
      mysqlPool = mysql.createPool({
        host: dbHost,
        user: dbUser,
        password: dbPassword,
        database: dbName,
        port: parseInt(dbPort),
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
      });
      // Test connection
      const conn = await mysqlPool.getConnection();
      conn.release();
      console.log('Successfully connected to MySQL database.');
      break;
    } catch (err) {
      console.error(`MySQL connection attempt ${attempt} failed: ${err.message}`);
      if (attempt < MAX_RETRIES) {
        console.log(`Retrying in ${RETRY_DELAY_MS / 1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS));
      } else {
        console.error('CRITICAL: All MySQL connection attempts exhausted. Database connection failed.');
        process.exit(1);
      }
    }
  }

  await createTables();
}

// Unified query wrapper
export function query(sql, params = []) {
  return mysqlPool.execute(sql, params).then(([rows]) => rows);
}

// Get single record helper
export async function queryOne(sql, params = []) {
  const rows = await query(sql, params);
  return rows && rows.length > 0 ? rows[0] : null;
}

// Table creation schemas
async function createTables() {
  const usersTable = `CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const filesTable = `CREATE TABLE IF NOT EXISTS files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        size INT NOT NULL,
        type VARCHAR(100) NOT NULL,
        path VARCHAR(500) NOT NULL,
        download_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const shareLinksTable = `CREATE TABLE IF NOT EXISTS share_links (
        id VARCHAR(100) PRIMARY KEY,
        file_id INT NOT NULL,
        user_id INT NOT NULL,
        expires_at TIMESTAMP NULL,
        password VARCHAR(255) DEFAULT NULL,
        download_limit INT DEFAULT NULL,
        download_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  const activityLogsTable = `CREATE TABLE IF NOT EXISTS activity_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        action VARCHAR(255) NOT NULL,
        details VARCHAR(1000) DEFAULT NULL,
        ip_address VARCHAR(100) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`;

  try {
    await query(usersTable);
    await query(filesTable);
    await query(shareLinksTable);
    await query(activityLogsTable);
    console.log('Database tables verified/created successfully.');
  } catch (err) {
    console.error('Error creating database tables:', err.message);
  }
}
