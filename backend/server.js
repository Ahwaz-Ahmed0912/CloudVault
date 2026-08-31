import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { BlobServiceClient } from '@azure/storage-blob';
import { initDB, query, queryOne } from './db.js';

dotenv.config();

// Azure Blob Storage configuration
const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING || '';
const AZURE_CONTAINER_NAME = process.env.AZURE_CONTAINER_NAME || 'cloudvault';

let blobServiceClient = null;
let containerClient = null;

if (AZURE_STORAGE_CONNECTION_STRING) {
  blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_STORAGE_CONNECTION_STRING);
  containerClient = blobServiceClient.getContainerClient(AZURE_CONTAINER_NAME);
  containerClient.createIfNotExists().then(() => {
    console.log(`Azure Blob container "${AZURE_CONTAINER_NAME}" ready.`);
  }).catch(err => {
    console.error('Failed to create Azure Blob container:', err.message);
  });
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'cloudvault_super_secret_key_9988';

// Middlewares
const corsOrigin = process.env.CORS_ORIGIN || '*'; // In production, this should be set to the specific domain
app.use(cors({ origin: corsOrigin }));
app.use(express.json());

// Set up local file storage path
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage engine configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Save with unique name to avoid collision
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB file size limit
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await query('SELECT 1'); // verify database connection
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    res.status(503).json({ status: 'error', database: 'disconnected', error: err.message });
  }
});

// Helper to log user activities
async function logActivity(userId, action, details, req) {
  const ip = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : 'system';
  try {
    await query(
      'INSERT INTO activity_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [userId || null, action, details, ip]
    );
  } catch (err) {
    console.error('Failed to write activity log:', err.message);
  }
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token expired or invalid' });
    req.user = user;
    next();
  });
}

// Admin Middleware
async function checkAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admin access required' });
  }
  next();
}

// ==========================================
// 1. AUTHENTICATION ROUTERS
// ==========================================

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, first_name, last_name } = req.body;
  // Support both: direct username OR first_name + last_name
  const finalUsername = username || (first_name && last_name ? `${first_name} ${last_name}` : first_name || null);

  if (!finalUsername || !email || !password) {
    return res.status(400).json({ success: false, message: 'Missing registration details' });
  }

  try {
    // Check if user already exists
    const existing = await queryOne('SELECT id FROM users WHERE username = ? OR email = ?', [finalUsername, email]);
    if (existing) {
      return res.status(400).json({ success: false, message: 'Username or Email is already registered' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // If first user, make admin
    const userCount = await queryOne('SELECT COUNT(id) AS count FROM users');
    const totalUsers = userCount ? userCount.count : 0;
    const role = totalUsers === 0 ? 'admin' : 'user';

    const result = await query(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [finalUsername, email, hashedPassword, role]
    );

    const newUserId = result.insertId;
    await logActivity(newUserId, 'REGISTER', `User created with role: ${role}`, req);

    // Sign JWT token so user is logged in immediately after registration
    const token = jwt.sign(
      { id: newUserId, username: finalUsername, email, role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: { id: newUserId, username: finalUsername, email, role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }

  try {
    const user = await queryOne('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    // Sign JWT
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await logActivity(user.id, 'LOGIN', 'Logged into dashboard', req);

    res.json({
      success: true,
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await queryOne('SELECT id, username, email, role, created_at FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Profile endpoint (alias for /me, used by frontend)
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const user = await queryOne('SELECT id, username, email, role, created_at FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Logout endpoint (stateless JWT - just acknowledge)
app.post('/api/auth/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// ==========================================
// 2. FILES ROUTERS
// ==========================================

app.post('/api/files/upload', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const { originalname, size, mimetype, filename, path: tempFilePath } = req.file;

  try {
    // Upload to Azure if configured
    if (containerClient) {
      const blockBlobClient = containerClient.getBlockBlobClient(filename);
      await blockBlobClient.uploadFile(tempFilePath);
      fs.unlinkSync(tempFilePath); // Delete local temp file
    }

    const result = await query(
      'INSERT INTO files (user_id, name, size, type, path) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, originalname, size, mimetype, filename]
    );

    await logActivity(req.user.id, 'FILE_UPLOAD', `Uploaded file: ${originalname} (${(size / 1024).toFixed(1)} KB)`, req);

    res.status(201).json({
      message: 'File uploaded successfully',
      file: {
        id: result.insertId,
        name: originalname,
        size,
        type: mimetype
      }
    });
  } catch (err) {
    console.error(err);
    if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/api/files', authenticateToken, async (req, res) => {
  const { search, category, sort } = req.query;

  try {
    let sql = 'SELECT * FROM files WHERE user_id = ?';
    let params = [req.user.id];

    if (search) {
      sql += ' AND name LIKE ?';
      params.push(`%${search}%`);
    }

    if (category) {
      if (category === 'image') {
        sql += " AND type LIKE 'image/%'";
      } else if (category === 'pdf') {
        sql += " AND type = 'application/pdf'";
      } else if (category === 'document') {
        sql += " AND (type LIKE '%word%' OR type LIKE '%text%' OR type LIKE '%spreadsheet%' OR type LIKE '%pdf%' OR type LIKE '%presentation%')";
      } else if (category === 'other') {
        sql += " AND NOT (type LIKE 'image/%' OR type = 'application/pdf' OR type LIKE '%word%' OR type LIKE '%text%')";
      }
    }

    if (sort === 'oldest') {
      sql += ' ORDER BY created_at ASC';
    } else if (sort === 'size-desc') {
      sql += ' ORDER BY size DESC';
    } else if (sort === 'size-asc') {
      sql += ' ORDER BY size ASC';
    } else {
      sql += ' ORDER BY created_at DESC'; // default newest
    }

    const files = await query(sql, params);
    res.json(files);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to retrieve files' });
  }
});

// Serve download securely
app.get('/api/files/:id/download', authenticateToken, async (req, res) => {
  try {
    const file = await queryOne('SELECT * FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!file) return res.status(404).json({ error: 'File not found or unauthorized' });

    // Increment downloads
    await query('UPDATE files SET download_count = download_count + 1 WHERE id = ?', [file.id]);
    await logActivity(req.user.id, 'FILE_DOWNLOAD', `Downloaded file: ${file.name}`, req);

    if (containerClient) {
      const blockBlobClient = containerClient.getBlockBlobClient(file.path);
      const exists = await blockBlobClient.exists();
      if (!exists) return res.status(404).json({ error: 'File physical storage not found in Azure' });
      
      res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
      res.setHeader('Content-Type', file.type);
      const downloadResponse = await blockBlobClient.download(0);
      downloadResponse.readableStreamBody.pipe(res);
    } else {
      const filePath = path.join(uploadDir, file.path);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File physical storage not found locally' });
      }
      res.download(filePath, file.name);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Preview files securely in browser
app.get('/api/files/:id/preview', authenticateToken, async (req, res) => {
  try {
    const file = await queryOne('SELECT * FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!file) return res.status(404).json({ error: 'File not found' });

    res.setHeader('Content-Type', file.type);

    if (containerClient) {
      const blockBlobClient = containerClient.getBlockBlobClient(file.path);
      const exists = await blockBlobClient.exists();
      if (!exists) return res.status(404).json({ error: 'File physical storage not found in Azure' });
      
      const downloadResponse = await blockBlobClient.download(0);
      downloadResponse.readableStreamBody.pipe(res);
    } else {
      const filePath = path.join(uploadDir, file.path);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File physical storage not found locally' });
      }
      res.sendFile(filePath);
    }
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete file
app.delete('/api/files/:id', authenticateToken, async (req, res) => {
  try {
    const file = await queryOne('SELECT * FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!file) return res.status(404).json({ error: 'File not found or unauthorized' });

    if (containerClient) {
      const blockBlobClient = containerClient.getBlockBlobClient(file.path);
      await blockBlobClient.deleteIfExists();
    } else {
      const filePath = path.join(uploadDir, file.path);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    await query('DELETE FROM files WHERE id = ?', [file.id]);
    // Also delete any share links associated
    await query('DELETE FROM share_links WHERE file_id = ?', [file.id]);

    await logActivity(req.user.id, 'FILE_DELETE', `Deleted file: ${file.name}`, req);
    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// ==========================================
// 3. SHARE LINKS ROUTERS
// ==========================================

app.post('/api/share/create', authenticateToken, async (req, res) => {
  const { file_id, expires_in_hours, password, download_limit } = req.body;
  if (!file_id) return res.status(400).json({ error: 'File ID is required' });

  try {
    const file = await queryOne('SELECT * FROM files WHERE id = ? AND user_id = ?', [file_id, req.user.id]);
    if (!file) return res.status(404).json({ error: 'File not found or unauthorized' });

    // Generate unique link ID
    const shareId = Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);
    
    let expiresAt = null;
    if (expires_in_hours) {
      expiresAt = new Date(Date.now() + parseFloat(expires_in_hours) * 60 * 60 * 1000);
    }

    let hashedPassword = null;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    await query(
      'INSERT INTO share_links (id, file_id, user_id, expires_at, password, download_limit) VALUES (?, ?, ?, ?, ?, ?)',
      [shareId, file_id, req.user.id, expiresAt, hashedPassword, download_limit || null]
    );

    await logActivity(req.user.id, 'SHARE_LINK_CREATE', `Created share link for: ${file.name}`, req);

    res.status(201).json({
      message: 'Share link created successfully',
      shareId,
      link: `/share/${shareId}`
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to generate share link' });
  }
});

app.get('/api/share/links', authenticateToken, async (req, res) => {
  try {
    const links = await query(
      `SELECT s.*, f.name as file_name, f.size as file_size, f.type as file_type 
       FROM share_links s 
       JOIN files f ON s.file_id = f.id 
       WHERE s.user_id = ? 
       ORDER BY s.created_at DESC`,
      [req.user.id]
    );
    res.json(links);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch share links' });
  }
});

app.delete('/api/share/links/:id', authenticateToken, async (req, res) => {
  try {
    const link = await queryOne('SELECT * FROM share_links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!link) return res.status(404).json({ error: 'Link not found or unauthorized' });

    await query('DELETE FROM share_links WHERE id = ?', [req.params.id]);
    res.json({ message: 'Share link revoked successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete share link' });
  }
});

// Get public share details (public page check)
app.get('/api/share/public/:id', async (req, res) => {
  try {
    const link = await queryOne(
      `SELECT s.id, s.expires_at, s.download_limit, s.download_count, s.password as has_password,
              f.name as file_name, f.size as file_size, f.type as file_type
       FROM share_links s
       JOIN files f ON s.file_id = f.id
       WHERE s.id = ?`,
      [req.params.id]
    );

    if (!link) return res.status(404).json({ error: 'Share link not found or expired' });

    // Validate expiration
    if (link.expires_at && new Date(link.expires_at) < new Date()) {
      return res.status(410).json({ error: 'This share link has expired' });
    }

    // Validate download limit
    if (link.download_limit && link.download_count >= link.download_limit) {
      return res.status(410).json({ error: 'Download limit reached for this share link' });
    }

    res.json({
      id: link.id,
      file_name: link.file_name,
      file_size: link.file_size,
      file_type: link.file_type,
      requires_password: !!link.has_password,
      expires_at: link.expires_at
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to retrieve link details' });
  }
});

// Download public shared file
app.post('/api/share/public/:id/download', async (req, res) => {
  const { password } = req.body;

  try {
    const link = await queryOne('SELECT * FROM share_links WHERE id = ?', [req.params.id]);
    if (!link) return res.status(404).json({ error: 'Share link not found' });

    // Validate expiration
    if (link.expires_at && new Date(link.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Share link expired' });
    }

    // Validate download limit
    if (link.download_limit && link.download_count >= link.download_limit) {
      return res.status(410).json({ error: 'Download limit exceeded' });
    }

    // Password validation
    if (link.password) {
      if (!password) return res.status(401).json({ error: 'Password required' });
      const validPass = await bcrypt.compare(password, link.password);
      if (!validPass) return res.status(401).json({ error: 'Incorrect password' });
    }

    const file = await queryOne('SELECT * FROM files WHERE id = ?', [link.file_id]);
    if (!file) return res.status(404).json({ error: 'File is missing or deleted' });

    // Increment downloads count in both link and file tables
    await query('UPDATE share_links SET download_count = download_count + 1 WHERE id = ?', [link.id]);
    await query('UPDATE files SET download_count = download_count + 1 WHERE id = ?', [file.id]);
    
    await logActivity(link.user_id, 'SHARE_LINK_DOWNLOAD', `Anonymous downloaded: ${file.name} via share link`, req);

    if (containerClient) {
      const blockBlobClient = containerClient.getBlockBlobClient(file.path);
      const exists = await blockBlobClient.exists();
      if (!exists) return res.status(404).json({ error: 'File physical storage missing in Azure' });
      
      res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
      res.setHeader('Content-Type', file.type);
      const downloadResponse = await blockBlobClient.download(0);
      downloadResponse.readableStreamBody.pipe(res);
    } else {
      const filePath = path.join(uploadDir, file.path);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File physical storage missing locally' });
      }
      res.download(filePath, file.name);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Download processing error' });
  }
});

// ==========================================
// 4. ADMIN ROUTERS
// ==========================================

app.get('/api/admin/stats', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const usersCount = await queryOne('SELECT COUNT(id) AS count FROM users');
    const filesCount = await queryOne('SELECT COUNT(id) AS count, SUM(size) as total_size FROM files');
    const downloadsCount = await queryOne('SELECT SUM(download_count) AS count FROM files');
    const activeShares = await queryOne('SELECT COUNT(id) AS count FROM share_links');

    const totalUsers = usersCount ? usersCount.count : 0;
    const totalFiles = filesCount ? filesCount.count : 0;
    const totalSize = filesCount ? filesCount.total_size || 0 : 0;
    const totalDownloads = downloadsCount ? downloadsCount.count || 0 : 0;
    const totalShares = activeShares ? activeShares.count : 0;

    res.json({
      totalUsers,
      totalFiles,
      totalSize,
      totalDownloads,
      totalShares
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to retrieve administrator statistics' });
  }
});

app.get('/api/admin/users', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const users = await query('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.get('/api/admin/files', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const files = await query(
      `SELECT f.*, u.username as owner_username 
       FROM files f 
       JOIN users u ON f.user_id = u.id 
       ORDER BY f.created_at DESC`
    );
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load user files' });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, checkAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (parseInt(targetId) === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own admin account' });
  }

  try {
    // Get all user files and delete them from storage
    const files = await query('SELECT path FROM files WHERE user_id = ?', [targetId]);
    for (const f of files) {
      if (containerClient) {
        const blockBlobClient = containerClient.getBlockBlobClient(f.path);
        await blockBlobClient.deleteIfExists();
      } else {
        const filePath = path.join(uploadDir, f.path);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
    }

    // Delete db transactions
    await query('DELETE FROM files WHERE user_id = ?', [targetId]);
    await query('DELETE FROM share_links WHERE user_id = ?', [targetId]);
    await query('DELETE FROM activity_logs WHERE user_id = ?', [targetId]);
    await query('DELETE FROM users WHERE id = ?', [targetId]);

    await logActivity(req.user.id, 'ADMIN_DELETE_USER', `Deleted user account ID: ${targetId}`, req);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Admin action: failed to delete user' });
  }
});

app.delete('/api/admin/files/:id', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const file = await queryOne('SELECT * FROM files WHERE id = ?', [req.params.id]);
    if (!file) return res.status(404).json({ error: 'File not found' });

    if (containerClient) {
      const blockBlobClient = containerClient.getBlockBlobClient(file.path);
      await blockBlobClient.deleteIfExists();
    } else {
      const filePath = path.join(uploadDir, file.path);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    await query('DELETE FROM files WHERE id = ?', [file.id]);
    await query('DELETE FROM share_links WHERE file_id = ?', [file.id]);

    await logActivity(req.user.id, 'ADMIN_DELETE_FILE', `Deleted file: ${file.name} belonging to userId: ${file.user_id}`, req);
    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Admin action: failed to delete file' });
  }
});

// ==========================================
// 5. USER PROFILE & ACTIVITY ROUTERS
// ==========================================

app.get('/api/activity-logs', authenticateToken, async (req, res) => {
  try {
    const logs = await query(
      'SELECT action, details, ip_address, created_at FROM activity_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
      [req.user.id]
    );
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load activity logs' });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  const { username, currentPassword, newPassword } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  try {
    // If username is being changed, verify it doesn't conflict
    if (username !== req.user.username) {
      const conflict = await queryOne('SELECT id FROM users WHERE username = ?', [username]);
      if (conflict) return res.status(400).json({ error: 'Username is already taken' });
    }

    if (newPassword) {
      if (!currentPassword) return res.status(400).json({ error: 'Current password is required to change password' });
      
      const user = await queryOne('SELECT password FROM users WHERE id = ?', [req.user.id]);
      const validPass = await bcrypt.compare(currentPassword, user.password);
      if (!validPass) return res.status(400).json({ error: 'Current password is incorrect' });

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      await query('UPDATE users SET username = ?, password = ? WHERE id = ?', [username, hashedPassword, req.user.id]);
      await logActivity(req.user.id, 'PROFILE_UPDATE', 'Updated username and changed password', req);
    } else {
      await query('UPDATE users SET username = ? WHERE id = ?', [username, req.user.id]);
      await logActivity(req.user.id, 'PROFILE_UPDATE', 'Updated username', req);
    }

    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Server boot-up logic
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`CloudVault API Server is running on port ${PORT}`);
  });
});
