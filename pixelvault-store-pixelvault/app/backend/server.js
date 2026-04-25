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
  if (!seed) {
    console.warn('WARNING: No ENCRYPTION_KEY – using ephemeral key!');
    return crypto.randomBytes(32);
  }
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
    users:  [{ id, username, passwordHash, role, createdAt,
               canViewAlbums: [albumId, ...]   // album-level access grant
             }],
    albums: [{ id, name, ownerId, parentId|null, createdAt, description }],
    photos: [{ id, albumId, ownerId, originalName, mimeType, size,
               uploadedAt, iv, thumbIv }]
  }

  Access rules:
  - Admin sees & manages everything
  - Album owner always has full access to their album (+ sub-albums)
  - Other users can view an album if their canViewAlbums[] contains the albumId
    (this grants read access to the album AND all its sub-albums)
  - Download is only for photo owner or admin
*/

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const db = {
      users:  [],
      albums: [],
      photos: []
    };
    db.users.push({
      id: uid(), username: 'admin',
      passwordHash: bcrypt.hashSync('admin', 12),
      role: 'admin', canViewAlbums: [], createdAt: Date.now()
    });
    saveDB(db);
    return db;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  // migrate: add albums/canViewAlbums if missing (upgrade from old schema)
  if (!db.albums) db.albums = [];
  if (!db.photos) db.photos = [];
  db.users.forEach(u => {
    if (!u.canViewAlbums) u.canViewAlbums = [];
  });
  // migrate old photos without albumId to a synthetic "Uncategorized" root album per owner
  db.photos.forEach(p => {
    if (!p.albumId) {
      let inbox = db.albums.find(a => a.ownerId === p.ownerId && a._inbox);
      if (!inbox) {
        inbox = { id: uid(), name: 'Inbox', ownerId: p.ownerId, parentId: null, createdAt: Date.now(), description: '', _inbox: true };
        db.albums.push(inbox);
      }
      p.albumId = inbox.id;
    }
  });
  return db;
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function uid() { return crypto.randomBytes(8).toString('hex'); }

// ─── Helpers: access control ──────────────────────────────────────
// Returns all albumIds that userId is allowed to view
function visibleAlbumIds(db, userId) {
  const user = db.users.find(u => u.id === userId);
  if (!user) return [];
  if (user.role === 'admin') return db.albums.map(a => a.id);

  // Albums owned by user
  const owned = db.albums.filter(a => a.ownerId === userId).map(a => a.id);

  // Albums explicitly granted
  const granted = user.canViewAlbums || [];

  // Also include all sub-albums of granted albums (recursively)
  const grantedWithSubs = expandAlbumIds(db, [...new Set([...owned, ...granted])]);
  return grantedWithSubs;
}

// Given a list of albumIds, expand to include all descendant sub-albums
function expandAlbumIds(db, ids) {
  const set = new Set(ids);
  let changed = true;
  while (changed) {
    changed = false;
    db.albums.forEach(a => {
      if (a.parentId && set.has(a.parentId) && !set.has(a.id)) {
        set.add(a.id);
        changed = true;
      }
    });
  }
  return [...set];
}

// Can user view this specific album?
function canViewAlbum(db, userId, albumId) {
  return visibleAlbumIds(db, userId).includes(albumId);
}

// Can user upload to this album? (must be owner)
function canUploadToAlbum(db, userId, albumId) {
  const user = db.users.find(u => u.id === userId);
  if (user?.role === 'admin') return true;
  const album = db.albums.find(a => a.id === albumId);
  return album?.ownerId === userId;
}

// Can user manage (rename/delete) this album?
function canManageAlbum(db, userId, albumId) {
  const user = db.users.find(u => u.id === userId);
  if (user?.role === 'admin') return true;
  const album = db.albums.find(a => a.id === albumId);
  return album?.ownerId === userId;
}

// Get all descendant album IDs of a given album
function descendantAlbumIds(db, albumId) {
  const result = [];
  const queue = [albumId];
  while (queue.length) {
    const cur = queue.shift();
    db.albums.forEach(a => { if (a.parentId === cur) { result.push(a.id); queue.push(a.id); } });
  }
  return result;
}

// ─── Middleware ───────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new FileStore({ path: SESSIONS_DIR, retries: 1, ttl: 86400 }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));
app.use(express.static(path.join(__dirname, '../frontend')));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
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
  const db   = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  res.json({ id: user.id, username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ success: true })));

app.get('/api/me', requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, role: user.role });
});

app.put('/api/me/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6)
    return res.status(400).json({ error: 'Password min 6 chars' });
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!bcrypt.compareSync(currentPassword, user.passwordHash))
    return res.status(401).json({ error: 'Wrong current password' });
  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  saveDB(db);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
// USER MANAGEMENT (Admin)
// ═══════════════════════════════════════════════════════════════════

app.get('/api/users', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => ({
    id: u.id, username: u.username, role: u.role,
    createdAt: u.createdAt, canViewAlbums: u.canViewAlbums || []
  })));
});

app.post('/api/users', requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6)    return res.status(400).json({ error: 'Password min 6 chars' });
  const db = loadDB();
  if (db.users.find(u => u.username === username))
    return res.status(409).json({ error: 'Username taken' });
  const user = {
    id: uid(), username: username.trim(),
    passwordHash: bcrypt.hashSync(password, 12),
    role: role === 'admin' ? 'admin' : 'user',
    canViewAlbums: [], createdAt: Date.now()
  };
  db.users.push(user);
  saveDB(db);
  res.status(201).json({ id: user.id, username: user.username, role: user.role });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const db  = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (db.users[idx].id === req.session.userId)
    return res.status(400).json({ error: 'Cannot delete own account' });
  db.users.splice(idx, 1);
  saveDB(db);
  res.json({ success: true });
});

app.put('/api/users/:id/password', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.passwordHash = bcrypt.hashSync(password, 12);
  saveDB(db);
  res.json({ success: true });
});

// Grant album access to a user (replaces entire list)
app.put('/api/users/:id/album-permissions', requireAdmin, (req, res) => {
  const { canViewAlbums } = req.body;
  const db   = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.canViewAlbums = Array.isArray(canViewAlbums) ? canViewAlbums : [];
  saveDB(db);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
// ALBUM ROUTES
// ═══════════════════════════════════════════════════════════════════

// List albums visible to current user (tree-aware)
app.get('/api/albums', requireAuth, (req, res) => {
  const db      = loadDB();
  const allowed = visibleAlbumIds(db, req.session.userId);
  const user    = db.users.find(u => u.id === req.session.userId);

  const albums = db.albums
    .filter(a => allowed.includes(a.id))
    .map(a => {
      const owner      = db.users.find(u => u.id === a.ownerId);
      const photoCount = db.photos.filter(p => p.albumId === a.id).length;
      return {
        id: a.id, name: a.name, parentId: a.parentId,
        ownerId: a.ownerId, ownerName: owner?.username ?? '?',
        description: a.description || '',
        createdAt: a.createdAt, photoCount,
        canUpload:  canUploadToAlbum(db, req.session.userId, a.id),
        canManage:  canManageAlbum(db, req.session.userId, a.id)
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  res.json(albums);
});

// Create album (or sub-album)
app.post('/api/albums', requireAuth, (req, res) => {
  const { name, parentId, description } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });

  const db   = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);

  // If creating a sub-album, must be able to manage the parent
  if (parentId) {
    const parent = db.albums.find(a => a.id === parentId);
    if (!parent) return res.status(404).json({ error: 'Parent album not found' });
    if (!canManageAlbum(db, req.session.userId, parentId))
      return res.status(403).json({ error: 'No permission on parent album' });
  }

  const album = {
    id: uid(), name: name.trim(),
    parentId: parentId || null,
    ownerId: req.session.userId,
    description: description?.trim() || '',
    createdAt: Date.now()
  };
  db.albums.push(album);
  saveDB(db);
  res.status(201).json(album);
});

// Rename / update album
app.put('/api/albums/:id', requireAuth, (req, res) => {
  const db    = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id))
    return res.status(403).json({ error: 'No permission' });

  const { name, description } = req.body;
  if (name?.trim()) album.name = name.trim();
  if (description !== undefined) album.description = description.trim();
  saveDB(db);
  res.json({ success: true });
});

// Delete album (and all sub-albums and their photos)
app.delete('/api/albums/:id', requireAuth, (req, res) => {
  const db    = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id))
    return res.status(403).json({ error: 'No permission' });

  const toDelete = [req.params.id, ...descendantAlbumIds(db, req.params.id)];

  // Delete all photos in these albums
  db.photos = db.photos.filter(p => {
    if (!toDelete.includes(p.albumId)) return true;
    [path.join(PHOTOS_DIR, `${p.id}.enc`), path.join(THUMBS_DIR, `${p.id}.enc`)].forEach(f => {
      try { fs.unlinkSync(f); } catch {}
    });
    return false;
  });

  // Remove album grants from users
  db.users.forEach(u => {
    u.canViewAlbums = (u.canViewAlbums || []).filter(id => !toDelete.includes(id));
  });

  db.albums = db.albums.filter(a => !toDelete.includes(a.id));
  saveDB(db);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
// PHOTO ROUTES
// ═══════════════════════════════════════════════════════════════════

// Upload photos into an album
app.post('/api/photos/upload', requireAuth, upload.array('photos', 20), async (req, res) => {
  const { albumId } = req.body;
  if (!albumId) return res.status(400).json({ error: 'albumId required' });

  const db = loadDB();
  if (!db.albums.find(a => a.id === albumId))
    return res.status(404).json({ error: 'Album not found' });
  if (!canUploadToAlbum(db, req.session.userId, albumId))
    return res.status(403).json({ error: 'No upload permission for this album' });

  const uploaded = [], errors = [];

  for (const file of req.files) {
    try {
      const thumbBuffer = await sharp(file.buffer)
        .resize(400, 400, { fit: 'cover', position: 'centre' })
        .jpeg({ quality: 75 })
        .toBuffer();

      const photoId = uid();
      const { iv: photoIv, data: encPhoto } = encrypt(file.buffer);
      fs.writeFileSync(path.join(PHOTOS_DIR, `${photoId}.enc`), encPhoto);
      const { iv: thumbIv, data: encThumb } = encrypt(thumbBuffer);
      fs.writeFileSync(path.join(THUMBS_DIR, `${photoId}.enc`), encThumb);

      db.photos.push({
        id: photoId, albumId,
        ownerId: req.session.userId,
        originalName: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
        uploadedAt: Date.now(),
        iv: photoIv, thumbIv
      });
      uploaded.push({ id: photoId, name: file.originalname });
    } catch (err) {
      console.error(`Upload error ${file.originalname}:`, err.message);
      errors.push(file.originalname);
    }
  }

  saveDB(db);
  res.json({ uploaded, errors });
});

// List photos in an album
app.get('/api/albums/:albumId/photos', requireAuth, (req, res) => {
  const db = loadDB();
  if (!canViewAlbum(db, req.session.userId, req.params.albumId))
    return res.status(403).json({ error: 'No access to album' });

  const currentUser = db.users.find(u => u.id === req.session.userId);
  const photos = db.photos
    .filter(p => p.albumId === req.params.albumId)
    .map(p => {
      const owner = db.users.find(u => u.id === p.ownerId);
      return {
        id: p.id, albumId: p.albumId,
        originalName: p.originalName,
        uploadedAt: p.uploadedAt, size: p.size,
        ownerId: p.ownerId, ownerName: owner?.username ?? '?',
        canDownload: p.ownerId === req.session.userId || currentUser.role === 'admin'
      };
    })
    .sort((a, b) => b.uploadedAt - a.uploadedAt);

  res.json(photos);
});

// Move photo to another album
app.put('/api/photos/:id/move', requireAuth, (req, res) => {
  const { targetAlbumId } = req.body;
  const db    = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });

  const currentUser = db.users.find(u => u.id === req.session.userId);
  if (photo.ownerId !== req.session.userId && currentUser.role !== 'admin')
    return res.status(403).json({ error: 'Not your photo' });
  if (!canUploadToAlbum(db, req.session.userId, targetAlbumId))
    return res.status(403).json({ error: 'No upload permission for target album' });

  photo.albumId = targetAlbumId;
  saveDB(db);
  res.json({ success: true });
});

// Thumbnail
app.get('/api/photos/:id/thumb', requireAuth, (req, res) => {
  const db    = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  if (!canViewAlbum(db, req.session.userId, photo.albumId))
    return res.status(403).json({ error: 'No access' });

  const f = path.join(THUMBS_DIR, `${photo.id}.enc`);
  if (!fs.existsSync(f)) return res.status(404).json({ error: 'Thumbnail missing' });
  try {
    res.set('Content-Type', 'image/jpeg');
    res.set('Cache-Control', 'private, max-age=3600');
    res.send(decrypt(fs.readFileSync(f), photo.thumbIv));
  } catch { res.status(500).json({ error: 'Decryption failed' }); }
});

// Download original (owner or admin only)
app.get('/api/photos/:id/download', requireAuth, (req, res) => {
  const db    = loadDB();
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
    res.send(decrypt(fs.readFileSync(f), photo.iv));
  } catch { res.status(500).json({ error: 'Decryption failed' }); }
});

// Delete photo (owner or admin)
app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const db  = loadDB();
  const idx = db.photos.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Photo not found' });

  const photo       = db.photos[idx];
  const currentUser = db.users.find(u => u.id === req.session.userId);
  if (photo.ownerId !== req.session.userId && currentUser.role !== 'admin')
    return res.status(403).json({ error: 'No permission' });

  [path.join(PHOTOS_DIR, `${photo.id}.enc`), path.join(THUMBS_DIR, `${photo.id}.enc`)].forEach(f => {
    try { fs.unlinkSync(f); } catch {}
  });
  db.photos.splice(idx, 1);
  saveDB(db);
  res.json({ success: true });
});

// ─── Start ────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`PixelVault running on port ${PORT}`);
  loadDB();
});
