const express = require('express');
const multer  = require('multer');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const sharp   = require('sharp');
const FileStore = require('session-file-store')(session);

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Directories ──────────────────────────────────────────────────
const DATA_DIR     = process.env.DATA_DIR || '/data';
const PHOTOS_DIR   = path.join(DATA_DIR, 'photos');
const THUMBS_DIR   = path.join(DATA_DIR, 'thumbs');
const DB_FILE      = path.join(DATA_DIR, 'db.json');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');

[PHOTOS_DIR, THUMBS_DIR, SESSIONS_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ─── Encryption ───────────────────────────────────────────────────
function deriveKey(seed) {
  if (!seed) { console.warn('WARNING: No ENCRYPTION_KEY – ephemeral key!'); return crypto.randomBytes(32); }
  if (seed.length === 64) return Buffer.from(seed, 'hex');
  return crypto.createHash('sha256').update(seed).digest();
}
const ENCRYPTION_KEY = deriveKey(process.env.ENCRYPTION_KEY);
const IV_LEN = 16;
function encrypt(buf) {
  const iv = crypto.randomBytes(IV_LEN);
  const c  = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  return { iv: iv.toString('hex'), data: Buffer.concat([c.update(buf), c.final()]) };
}
function decrypt(data, ivHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const d  = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  return Buffer.concat([d.update(data), d.final()]);
}

// ─── Database ─────────────────────────────────────────────────────
/*
  DB schema:
  {
    users:  [{ id, username, passwordHash, role, createdAt, canViewAlbums: [albumId] }],
    albums: [{ id, name, ownerId, parentId|null, createdAt, description, _shared?, _inbox?,
               views: number }],
    photos: [{ id, albumId, ownerId, originalName, mimeType, size,
               uploadedAt, iv, thumbIv, shared: bool,
               views: number, downloads: number,
               viewLog: [{ userId, ts }]  // last 500 entries, for unique viewer stats
             }]
  }
*/
const SHARED_ALBUM_ID = '__shared__';
const MAX_VIEW_LOG    = 500; // max entries per photo

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const db = { users: [], albums: [], photos: [] };
    db.users.push({
      id: uid(), username: 'admin',
      passwordHash: bcrypt.hashSync('admin', 12),
      role: 'admin', canViewAlbums: [], createdAt: Date.now()
    });
    saveDB(db); return db;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!db.albums) db.albums = [];
  if (!db.photos) db.photos = [];
  db.users.forEach(u => { if (!u.canViewAlbums) u.canViewAlbums = []; });
  db.albums.forEach(a => { if (!a.views) a.views = 0; });
  db.photos.forEach(p => {
    if (!p.albumId) {
      let inbox = db.albums.find(a => a.ownerId === p.ownerId && a._inbox);
      if (!inbox) {
        inbox = { id: uid(), name: 'Inbox', ownerId: p.ownerId, parentId: null, createdAt: Date.now(), description: '', _inbox: true, views: 0 };
        db.albums.push(inbox);
      }
      p.albumId = inbox.id;
    }
    if (p.shared    === undefined) p.shared    = false;
    if (p.views     === undefined) p.views     = 0;
    if (p.downloads === undefined) p.downloads = 0;
    if (p.viewLog   === undefined) p.viewLog   = [];
  });
  return db;
}

// Track a photo view (called when thumbnail is served)
function trackPhotoView(db, photoId, userId) {
  const photo = db.photos.find(p => p.id === photoId);
  if (!photo) return;
  photo.views = (photo.views || 0) + 1;
  // Append to rolling view log (cap at MAX_VIEW_LOG)
  photo.viewLog = photo.viewLog || [];
  photo.viewLog.push({ userId, ts: Date.now() });
  if (photo.viewLog.length > MAX_VIEW_LOG) photo.viewLog.shift();
  // Track album view as well
  const album = db.albums.find(a => a.id === photo.albumId);
  if (album) album.views = (album.views || 0) + 1;
}

// Track a download
function trackDownload(db, photoId) {
  const photo = db.photos.find(p => p.id === photoId);
  if (photo) photo.downloads = (photo.downloads || 0) + 1;
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function uid() { return crypto.randomBytes(8).toString('hex'); }

// ─── Access control ───────────────────────────────────────────────
function visibleAlbumIds(db, userId) {
  const user = db.users.find(u => u.id === userId);
  if (!user) return [];
  if (user.role === 'admin') return db.albums.map(a => a.id);
  const owned   = db.albums.filter(a => a.ownerId === userId).map(a => a.id);
  const granted = user.canViewAlbums || [];
  return expandAlbumIds(db, [...new Set([...owned, ...granted])]);
}
function expandAlbumIds(db, ids) {
  const set = new Set(ids);
  let changed = true;
  while (changed) {
    changed = false;
    db.albums.forEach(a => { if (a.parentId && set.has(a.parentId) && !set.has(a.id)) { set.add(a.id); changed = true; } });
  }
  return [...set];
}
function canViewAlbum(db, userId, albumId) {
  if (albumId === SHARED_ALBUM_ID) return true; // shared album visible to all
  return visibleAlbumIds(db, userId).includes(albumId);
}
function canUploadToAlbum(db, userId, albumId) {
  if (albumId === SHARED_ALBUM_ID) return false; // nobody uploads directly to shared
  const user = db.users.find(u => u.id === userId);
  if (user?.role === 'admin') return true;
  return db.albums.find(a => a.id === albumId)?.ownerId === userId;
}
function canManageAlbum(db, userId, albumId) {
  if (albumId === SHARED_ALBUM_ID) return false;
  const user = db.users.find(u => u.id === userId);
  if (user?.role === 'admin') return true;
  return db.albums.find(a => a.id === albumId)?.ownerId === userId;
}
function descendantAlbumIds(db, albumId) {
  const result = []; const queue = [albumId];
  while (queue.length) { const cur = queue.shift(); db.albums.forEach(a => { if (a.parentId === cur) { result.push(a.id); queue.push(a.id); } }); }
  return result;
}

// ─── Middleware ───────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new FileStore({ path: SESSIONS_DIR, retries: 1, ttl: 86400 }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));
app.use(express.static(path.join(__dirname, '../frontend')));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const db = loadDB();
  if (db.users.find(u => u.id === req.session.userId)?.role !== 'admin')
    return res.status(403).json({ error: 'Admins only' });
  next();
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 50 },
  fileFilter: (_, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Images only'));
    cb(null, true);
  }
});

// ═══════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  res.json({ id: user.id, username: user.username, role: user.role });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ success: true })));
app.get('/api/me', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, role: user.role });
});
app.put('/api/me/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!bcrypt.compareSync(currentPassword, user.passwordHash))
    return res.status(401).json({ error: 'Wrong current password' });
  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  saveDB(db); res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
// USER MANAGEMENT
// ═══════════════════════════════════════════════════════════════════
app.get('/api/users', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => ({ id: u.id, username: u.username, role: u.role, createdAt: u.createdAt, canViewAlbums: u.canViewAlbums || [] })));
});
app.post('/api/users', requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  const db = loadDB();
  if (db.users.find(u => u.username === username)) return res.status(409).json({ error: 'Username taken' });
  const user = { id: uid(), username: username.trim(), passwordHash: bcrypt.hashSync(password, 12), role: role === 'admin' ? 'admin' : 'user', canViewAlbums: [], createdAt: Date.now() };
  db.users.push(user); saveDB(db);
  res.status(201).json({ id: user.id, username: user.username, role: user.role });
});
app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (db.users[idx].id === req.session.userId) return res.status(400).json({ error: 'Cannot delete own account' });
  db.users.splice(idx, 1); saveDB(db); res.json({ success: true });
});
app.put('/api/users/:id/password', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.passwordHash = bcrypt.hashSync(password, 12); saveDB(db); res.json({ success: true });
});
app.put('/api/users/:id/album-permissions', requireAdmin, (req, res) => {
  const { canViewAlbums } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.canViewAlbums = Array.isArray(canViewAlbums) ? canViewAlbums : [];
  saveDB(db); res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
// ALBUMS
// ═══════════════════════════════════════════════════════════════════
app.get('/api/albums', requireAuth, (req, res) => {
  const db      = loadDB();
  const allowed = visibleAlbumIds(db, req.session.userId);
  const currentUser = db.users.find(u => u.id === req.session.userId);

  const albums = db.albums
    .filter(a => allowed.includes(a.id))
    .map(a => {
      const owner = db.users.find(u => u.id === a.ownerId);
      return {
        id: a.id, name: a.name, parentId: a.parentId,
        ownerId: a.ownerId, ownerName: owner?.username ?? '?',
        description: a.description || '', createdAt: a.createdAt,
        photoCount: db.photos.filter(p => p.albumId === a.id).length,
        canUpload:  canUploadToAlbum(db, req.session.userId, a.id),
        canManage:  canManageAlbum(db, req.session.userId, a.id)
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  // Prepend virtual shared album if there are any shared photos
  const sharedCount = db.photos.filter(p => p.shared).length;
  if (sharedCount > 0 || currentUser.role === 'admin') {
    albums.unshift({
      id: SHARED_ALBUM_ID, name: '📢 Shared Photos', parentId: null,
      ownerId: null, ownerName: '', description: '',
      createdAt: 0, photoCount: sharedCount,
      canUpload: false, canManage: false, _virtual: true
    });
  }

  res.json(albums);
});

app.post('/api/albums', requireAuth, (req, res) => {
  const { name, parentId, description } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  const db = loadDB();
  if (parentId) {
    const parent = db.albums.find(a => a.id === parentId);
    if (!parent) return res.status(404).json({ error: 'Parent album not found' });
    if (!canManageAlbum(db, req.session.userId, parentId))
      return res.status(403).json({ error: 'No permission on parent album' });
  }
  const album = { id: uid(), name: name.trim(), parentId: parentId || null, ownerId: req.session.userId, description: description?.trim() || '', createdAt: Date.now() };
  db.albums.push(album); saveDB(db);
  res.status(201).json(album);
});

app.put('/api/albums/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id)) return res.status(403).json({ error: 'No permission' });
  const { name, description } = req.body;
  if (name?.trim()) album.name = name.trim();
  if (description !== undefined) album.description = description.trim();
  saveDB(db); res.json({ success: true });
});

app.delete('/api/albums/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id)) return res.status(403).json({ error: 'No permission' });
  const toDelete = [req.params.id, ...descendantAlbumIds(db, req.params.id)];
  db.photos = db.photos.filter(p => {
    if (!toDelete.includes(p.albumId)) return true;
    [path.join(PHOTOS_DIR, `${p.id}.enc`), path.join(THUMBS_DIR, `${p.id}.enc`)].forEach(f => { try { fs.unlinkSync(f); } catch {} });
    return false;
  });
  db.users.forEach(u => { u.canViewAlbums = (u.canViewAlbums || []).filter(id => !toDelete.includes(id)); });
  db.albums = db.albums.filter(a => !toDelete.includes(a.id));
  saveDB(db); res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
// PHOTO UPLOAD
// ═══════════════════════════════════════════════════════════════════
app.post('/api/photos/upload', requireAuth, (req, res) => {
  upload.array('photos', 50)(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large (max 50 MB)' });
      if (err.code === 'LIMIT_FILE_COUNT') return res.status(400).json({ error: 'Too many files (max 50)' });
      return res.status(400).json({ error: err.message });
    }
    const { albumId } = req.body;
    if (!albumId) return res.status(400).json({ error: 'albumId required' });
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files received' });
    const db = loadDB();
    if (!db.albums.find(a => a.id === albumId)) return res.status(404).json({ error: 'Album not found' });
    if (!canUploadToAlbum(db, req.session.userId, albumId)) return res.status(403).json({ error: 'No upload permission' });
    const uploaded = [], errors = [];
    for (const file of req.files) {
      try {
        const thumbBuffer = await sharp(file.buffer).resize(400, 400, { fit: 'cover', position: 'centre' }).jpeg({ quality: 75 }).toBuffer();
        const photoId = uid();
        const { iv: photoIv, data: encPhoto } = encrypt(file.buffer);
        fs.writeFileSync(path.join(PHOTOS_DIR, `${photoId}.enc`), encPhoto);
        const { iv: thumbIv, data: encThumb } = encrypt(thumbBuffer);
        fs.writeFileSync(path.join(THUMBS_DIR, `${photoId}.enc`), encThumb);
        db.photos.push({ id: photoId, albumId, ownerId: req.session.userId, originalName: file.originalname, mimeType: file.mimetype, size: file.size, uploadedAt: Date.now(), iv: photoIv, thumbIv, shared: false });
        uploaded.push({ id: photoId, name: file.originalname });
        file.buffer = null;
      } catch (e) { console.error(`Upload error ${file.originalname}:`, e.message); errors.push(file.originalname); }
    }
    saveDB(db); res.json({ uploaded, errors });
  });
});

// ═══════════════════════════════════════════════════════════════════
// SHARE / UNSHARE
// ═══════════════════════════════════════════════════════════════════

// Share multiple photos (bulk)
app.post('/api/photos/share', requireAuth, (req, res) => {
  const { photoIds, shared } = req.body;
  if (!Array.isArray(photoIds) || photoIds.length === 0)
    return res.status(400).json({ error: 'photoIds required' });

  const db = loadDB();
  const currentUser = db.users.find(u => u.id === req.session.userId);
  let updated = 0;

  for (const id of photoIds) {
    const photo = db.photos.find(p => p.id === id);
    if (!photo) continue;
    // Only owner or admin can share/unshare
    if (photo.ownerId !== req.session.userId && currentUser.role !== 'admin') continue;
    photo.shared = shared !== false; // default true
    updated++;
  }

  saveDB(db);
  res.json({ success: true, updated });
});

// ═══════════════════════════════════════════════════════════════════
// PHOTO LISTING
// ═══════════════════════════════════════════════════════════════════
app.get('/api/albums/:albumId/photos', requireAuth, (req, res) => {
  const db = loadDB();
  const currentUser = db.users.find(u => u.id === req.session.userId);
  const albumId = req.params.albumId;

  // Virtual shared album
  if (albumId === SHARED_ALBUM_ID) {
    const photos = db.photos
      .filter(p => p.shared)
      .map(p => {
        const owner = db.users.find(u => u.id === p.ownerId);
        return {
          id: p.id, albumId: p.albumId,
          originalName: p.originalName, uploadedAt: p.uploadedAt, size: p.size,
          ownerId: p.ownerId, ownerName: owner?.username ?? '?',
          shared: true,
          canDownload: p.ownerId === req.session.userId || currentUser.role === 'admin',
          canShare: p.ownerId === req.session.userId || currentUser.role === 'admin'
        };
      })
      .sort((a, b) => b.uploadedAt - a.uploadedAt);
    return res.json(photos);
  }

  if (!canViewAlbum(db, req.session.userId, albumId))
    return res.status(403).json({ error: 'No access to album' });

  const photos = db.photos
    .filter(p => p.albumId === albumId)
    .map(p => {
      const owner = db.users.find(u => u.id === p.ownerId);
      return {
        id: p.id, albumId: p.albumId,
        originalName: p.originalName, uploadedAt: p.uploadedAt, size: p.size,
        ownerId: p.ownerId, ownerName: owner?.username ?? '?',
        shared: p.shared || false,
        canDownload: p.ownerId === req.session.userId || currentUser.role === 'admin',
        canShare: p.ownerId === req.session.userId || currentUser.role === 'admin'
      };
    })
    .sort((a, b) => b.uploadedAt - a.uploadedAt);

  res.json(photos);
});

// Move photo
app.put('/api/photos/:id/move', requireAuth, (req, res) => {
  const { targetAlbumId } = req.body;
  const db = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const currentUser = db.users.find(u => u.id === req.session.userId);
  if (photo.ownerId !== req.session.userId && currentUser.role !== 'admin') return res.status(403).json({ error: 'Not your photo' });
  if (!canUploadToAlbum(db, req.session.userId, targetAlbumId)) return res.status(403).json({ error: 'No upload permission for target album' });
  photo.albumId = targetAlbumId; saveDB(db); res.json({ success: true });
});

// Thumbnail
app.get('/api/photos/:id/thumb', requireAuth, (req, res) => {
  const db = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  // Can view if: photo is shared OR user can view the album
  const canView = photo.shared || canViewAlbum(db, req.session.userId, photo.albumId);
  if (!canView) return res.status(403).json({ error: 'No access' });
  const f = path.join(THUMBS_DIR, `${photo.id}.enc`);
  if (!fs.existsSync(f)) return res.status(404).json({ error: 'Thumbnail missing' });
  try {
    res.set('Content-Type', 'image/jpeg');
    res.set('Cache-Control', 'private, max-age=3600');
    res.send(decrypt(fs.readFileSync(f), photo.thumbIv));
  } catch { res.status(500).json({ error: 'Decryption failed' }); }
});

// Download (owner or admin only)
app.get('/api/photos/:id/download', requireAuth, (req, res) => {
  const db = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const currentUser = db.users.find(u => u.id === req.session.userId);
  if (photo.ownerId !== req.session.userId && currentUser.role !== 'admin')
    return res.status(403).json({ error: 'Only the owner can download this photo' });
  const f = path.join(PHOTOS_DIR, `${photo.id}.enc`);
  if (!fs.existsSync(f)) return res.status(404).json({ error: 'File not found' });
  try {
    res.set('Content-Type', photo.mimeType || 'image/jpeg');
    res.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(photo.originalName)}`);
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('X-Content-Type-Options', 'nosniff');
    trackDownload(db, photo.id);
    saveDB(db);
    res.send(decrypt(fs.readFileSync(f), photo.iv));
  } catch { res.status(500).json({ error: 'Decryption failed' }); }
});

// Delete (owner or admin)
app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const idx = db.photos.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Photo not found' });
  const photo = db.photos[idx];
  const currentUser = db.users.find(u => u.id === req.session.userId);
  if (photo.ownerId !== req.session.userId && currentUser.role !== 'admin') return res.status(403).json({ error: 'No permission' });
  [path.join(PHOTOS_DIR, `${photo.id}.enc`), path.join(THUMBS_DIR, `${photo.id}.enc`)].forEach(f => { try { fs.unlinkSync(f); } catch {} });
  db.photos.splice(idx, 1); saveDB(db); res.json({ success: true });
});


// ═══════════════════════════════════════════════════════════════════
// STATISTICS (Admin only)
// ═══════════════════════════════════════════════════════════════════
app.get('/api/stats', requireAdmin, (req, res) => {
  const db = loadDB();

  // ── Overview ──
  const totalPhotos    = db.photos.length;
  const totalAlbums    = db.albums.length;
  const totalUsers     = db.users.length;
  const totalViews     = db.photos.reduce((s, p) => s + (p.views || 0), 0);
  const totalDownloads = db.photos.reduce((s, p) => s + (p.downloads || 0), 0);
  const sharedPhotos   = db.photos.filter(p => p.shared).length;
  const totalStorageMB = parseFloat((db.photos.reduce((s, p) => s + (p.size || 0), 0) / 1024 / 1024).toFixed(2));

  // ── Top photos by views (top 10) ──
  const topPhotos = db.photos
    .filter(p => p.views > 0)
    .sort((a, b) => (b.views || 0) - (a.views || 0))
    .slice(0, 10)
    .map(p => {
      const owner = db.users.find(u => u.id === p.ownerId);
      const album = db.albums.find(a => a.id === p.albumId);
      // unique viewers = distinct userIds in viewLog
      const uniqueViewers = new Set((p.viewLog || []).map(e => e.userId)).size;
      return {
        id: p.id,
        name: p.originalName,
        views: p.views || 0,
        downloads: p.downloads || 0,
        uniqueViewers,
        shared: p.shared,
        ownerName: owner?.username ?? '?',
        albumName: album?.name ?? '?',
        uploadedAt: p.uploadedAt
      };
    });

  // ── Top albums by views (top 10) ──
  const topAlbums = db.albums
    .filter(a => (a.views || 0) > 0)
    .sort((a, b) => (b.views || 0) - (a.views || 0))
    .slice(0, 10)
    .map(a => {
      const owner      = db.users.find(u => u.id === a.ownerId);
      const photoCount = db.photos.filter(p => p.albumId === a.id).length;
      return {
        id: a.id, name: a.name,
        views: a.views || 0,
        photoCount,
        ownerName: owner?.username ?? '?'
      };
    });

  // ── Views per user (who viewed most) ──
  const viewsPerUser = {};
  db.photos.forEach(p => {
    (p.viewLog || []).forEach(e => {
      viewsPerUser[e.userId] = (viewsPerUser[e.userId] || 0) + 1;
    });
  });
  const topViewers = Object.entries(viewsPerUser)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([userId, views]) => {
      const user = db.users.find(u => u.id === userId);
      return { username: user?.username ?? '?', views };
    });

  // ── Uploads per user ──
  const uploadsPerUser = {};
  db.photos.forEach(p => { uploadsPerUser[p.ownerId] = (uploadsPerUser[p.ownerId] || 0) + 1; });
  const topUploaders = Object.entries(uploadsPerUser)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([userId, count]) => {
      const user = db.users.find(u => u.id === userId);
      const sizeMB = parseFloat((db.photos.filter(p => p.ownerId === userId).reduce((s, p) => s + (p.size || 0), 0) / 1024 / 1024).toFixed(2));
      return { username: user?.username ?? '?', photos: count, sizeMB };
    });

  // ── Views over time (last 30 days, grouped by day) ──
  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const viewsByDay = {};
  db.photos.forEach(p => {
    (p.viewLog || []).forEach(e => {
      if (e.ts < thirtyDaysAgo) return;
      const day = new Date(e.ts).toISOString().slice(0, 10);
      viewsByDay[day] = (viewsByDay[day] || 0) + 1;
    });
  });
  const viewsTimeline = Object.entries(viewsByDay)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([date, count]) => ({ date, count }));

  res.json({
    overview: { totalPhotos, totalAlbums, totalUsers, totalViews, totalDownloads, sharedPhotos, totalStorageMB },
    topPhotos,
    topAlbums,
    topViewers,
    topUploaders,
    viewsTimeline
  });
});

// ─── Start ────────────────────────────────────────────────────────
app.listen(PORT, () => { console.log(`PixelVault running on port ${PORT}`); loadDB(); });
