import mysql from 'mysql2/promise';

let mysqlPool = null;

// Read database configuration from environment variables
const dbHost = process.env.DB_HOST || '';
const dbUser = process.env.DB_USER || '';
const dbPassword = process.env.DB_PASSWORD || '';
const dbName = process.env.DB_NAME || '';
const dbPort = process.env.DB_PORT || '3306';

/**
 * Initialize MySQL database connection
 */
export async function initDB() {
  // Validate required environment variables
  if (!dbHost || !dbUser || !dbName) {
    console.error(
      'CRITICAL: MySQL environment variables are not fully set.'
    );
    console.error(
      'Required: DB_HOST, DB_USER, DB_NAME'
    );

    process.exit(1);
  }

  const MAX_RETRIES = 10;
  const RETRY_DELAY_MS = 3000;

  // Try connecting multiple times
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(
        `Attempting to connect to MySQL database at ${dbHost} ` +
        `(attempt ${attempt}/${MAX_RETRIES})...`
      );

      mysqlPool = mysql.createPool({
        host: dbHost,
        user: dbUser,
        password: dbPassword,
        database: dbName,
        port: parseInt(dbPort, 10),

        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
      });

      // Test the database connection
      const connection = await mysqlPool.getConnection();

      console.log('Successfully connected to MySQL database.');

      connection.release();

      break;
    } catch (err) {
      console.error(
        `MySQL connection attempt ${attempt} failed: ${err.message}`
      );

      if (attempt < MAX_RETRIES) {
        console.log(
          `Retrying in ${RETRY_DELAY_MS / 1000} seconds...`
        );

        await new Promise(resolve =>
          setTimeout(resolve, RETRY_DELAY_MS)
        );
      } else {
        console.error(
          'CRITICAL: All MySQL connection attempts exhausted.'
        );

        console.error(
          'Database connection failed. Server cannot continue.'
        );

        process.exit(1);
      }
    }
  }

  // Create/verify required tables
  await createTables();
}

/**
 * General database query wrapper
 *
 * mysqlPool.query() is used instead of execute()
 * so CREATE TABLE and other SQL statements work correctly.
 *
 * Parameters are still safely parameterized when provided.
 */
export async function query(sql, params = []) {
  if (!mysqlPool) {
    throw new Error(
      'Database pool has not been initialized. Call initDB() first.'
    );
  }

  const [rows] = await mysqlPool.query(sql, params);

  return rows;
}

/**
 * Get a single database record
 */
export async function queryOne(sql, params = []) {
  const rows = await query(sql, params);

  if (rows && rows.length > 0) {
    return rows[0];
  }

  return null;
}

/**
 * Create/verify all CloudVault database tables
 */
async function createTables() {
  console.log('Creating/verifying CloudVault database tables...');

  /**
   * Users table
   */
  const usersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  /**
   * Files table
   */
  const filesTable = `
    CREATE TABLE IF NOT EXISTS files (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      name VARCHAR(255) NOT NULL,
      size INT NOT NULL,
      type VARCHAR(100) NOT NULL,
      path VARCHAR(500) NOT NULL,
      download_count INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  /**
   * Share links table
   */
  const shareLinksTable = `
    CREATE TABLE IF NOT EXISTS share_links (
      id VARCHAR(100) PRIMARY KEY,
      file_id INT NOT NULL,
      user_id INT NOT NULL,
      expires_at TIMESTAMP NULL,
      password VARCHAR(255) DEFAULT NULL,
      download_limit INT DEFAULT NULL,
      download_count INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  /**
   * Activity logs table
   */
  const activityLogsTable = `
    CREATE TABLE IF NOT EXISTS activity_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      action VARCHAR(255) NOT NULL,
      details VARCHAR(1000) DEFAULT NULL,
      ip_address VARCHAR(100) DEFAULT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  try {
    // Users
    await query(usersTable);
    console.log('✓ users table verified/created.');

    // Files
    await query(filesTable);
    console.log('✓ files table verified/created.');

    // Share links
    await query(shareLinksTable);
    console.log('✓ share_links table verified/created.');

    // Activity logs
    await query(activityLogsTable);
    console.log('✓ activity_logs table verified/created.');

    console.log(
      'Database tables verified/created successfully.'
    );
  } catch (err) {
    console.error(
      'ERROR: Failed to create/verify database tables.'
    );

    console.error('Message:', err.message);
    console.error('Code:', err.code);
    console.error('Errno:', err.errno);
    console.error('SQL State:', err.sqlState);
    console.error('SQL Message:', err.sqlMessage);

    // Stop startup instead of allowing the application
    // to run with a broken database schema.
    throw err;
  }
}