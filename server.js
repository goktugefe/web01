const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const path = require('path');
const fs = require('fs');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const archiver = require('archiver');

const app = express();
const PORT = 3003;

const uploadRootDir = path.join(__dirname, 'uploads');
const backupsDir = path.join(__dirname, 'backups');
const publicDir = path.join(__dirname, 'public');

const dataFile = path.join(__dirname, 'documents.json');
const usersFile = path.join(__dirname, 'users.json');
const logsFile = path.join(__dirname, 'logs.json');
const departmentsFile = path.join(__dirname, 'departments.json');
const notificationsFile = path.join(__dirname, 'notifications.json');

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const SESSION_MAX_AGE = 1000 * 60 * 30;
const SESSION_WARNING_MS = 1000 * 60 * 2;

const ALLOWED_EXTENSIONS = [
  '.pdf', '.png', '.jpg', '.jpeg', '.webp', '.txt',
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
];

const ROLE_PERMISSIONS = {
  admin: [
    'doc:view', 'doc:download', 'doc:upload', 'doc:delete', 'doc:restore',
    'doc:workflow:submit', 'doc:workflow:approve', 'doc:workflow:reject',
    'doc:workflow:publish', 'doc:workflow:archive',
    'user:manage', 'department:manage', 'logs:view',
    'backup:create', 'export:zip', 'notifications:view', 'stats:view', 'history:view'
  ],
  manager: [
    'doc:view', 'doc:download', 'doc:upload', 'doc:delete',
    'doc:workflow:submit', 'doc:workflow:approve', 'doc:workflow:reject',
    'doc:workflow:publish', 'doc:workflow:archive',
    'notifications:view', 'stats:view', 'history:view', 'export:zip'
  ],
  editor: [
    'doc:view', 'doc:download', 'doc:upload', 'doc:delete',
    'doc:workflow:submit',
    'notifications:view', 'stats:view', 'history:view'
  ],
  viewer: [
    'doc:view', 'doc:download',
    'notifications:view', 'stats:view', 'history:view'
  ]
};

const DEFAULT_DEPARTMENTS = [
  { id: '1', name: 'Ortak', isActive: true },
  { id: '2', name: 'BT', isActive: true },
  { id: '3', name: 'İK', isActive: true },
  { id: '4', name: 'MALİ VE İDARİ İŞLER', isActive: true },
  { id: '5', name: 'HUKUK', isActive: true },
  { id: '6', name: 'HASAR', isActive: true },
  { id: '7', name: 'RÜCU', isActive: true },
  { id: '8', name: 'İÇ DENETİM', isActive: true },
  { id: '9', name: 'YÖNETİM', isActive: true }
];

[
  uploadRootDir,
  backupsDir,
  publicDir
].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

[
  [dataFile, []],
  [usersFile, []],
  [logsFile, []],
  [departmentsFile, DEFAULT_DEPARTMENTS],
  [notificationsFile, []]
].forEach(([file, initValue]) => {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(initValue, null, 2), 'utf8');
  }
});

function readJson(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw || '[]');
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function sanitizeFileName(name) {
  return String(name || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9-_]/g, '_');
}

function ensureDepartmentFolder(departmentName) {
  const safe = sanitizeFileName(departmentName || 'Ortak');
  const folder = path.join(uploadRootDir, safe);
  if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
  return folder;
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket?.remoteAddress
    || req.ip
    || '-';
}

function getPermissions(role) {
  return ROLE_PERMISSIONS[role] || [];
}

function hasPermission(user, permission) {
  if (!user) return false;
  return getPermissions(user.role).includes(permission);
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Oturum bulunamadı.' });
  }
  next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.session.user || !hasPermission(req.session.user, permission)) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok.' });
    }
    next();
  };
}

function addLog(action, user, details = {}, req = null) {
  const logs = readJson(logsFile);
  logs.unshift({
    id: Date.now().toString(),
    action,
    user: user ? user.fullName : 'Sistem',
    username: user ? user.username : 'system',
    department: user ? user.department : '-',
    role: user ? user.role : '-',
    ip: req ? getClientIp(req) : '-',
    createdAt: new Date().toISOString(),
    details
  });
  writeJson(logsFile, logs);
}

function addNotification(type, title, message, targetRole = 'all', targetDepartment = 'all') {
  const notifications = readJson(notificationsFile);
  notifications.unshift({
    id: Date.now().toString(),
    type,
    title,
    message,
    targetRole,
    targetDepartment,
    createdAt: new Date().toISOString()
  });
  writeJson(notificationsFile, notifications);
}

function getActiveDepartments() {
  return readJson(departmentsFile).filter(dep => dep.isActive);
}

function isRestrictedApprovalStage(doc) {
  return ['Taslak', 'Onay Bekliyor', 'Reddedildi'].includes(doc.status);
}

function canAccessDocument(user, doc) {
  if (doc.deleted) return false;
  if (!hasPermission(user, 'doc:view')) return false;

  const isAdmin = user.role === 'admin';
  const isOwner = doc.uploadedByUsername === user.username;
  const isDepartmentManager = user.role === 'manager' && user.department === doc.department;

  if (isAdmin) return true;

  if (isRestrictedApprovalStage(doc)) {
    return isOwner || isDepartmentManager;
  }

  return doc.department === user.department || doc.department === 'Ortak';
}

function canManageDocument(user, doc) {
  const isAdmin = user.role === 'admin';
  const isOwner = doc.uploadedByUsername === user.username;
  const isDepartmentManager = user.role === 'manager' && user.department === doc.department;

  if (isAdmin) return true;

  if (isRestrictedApprovalStage(doc)) {
    return isOwner || isDepartmentManager;
  }

  return doc.department === user.department || doc.department === 'Ortak';
}

function getPreviewType(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  if (ext === '.pdf') return 'pdf';
  if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) return 'image';
  if (ext === '.txt') return 'text';
  return 'other';
}

function getFileIcon(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  if (ext === '.pdf') return 'PDF';
  if (['.doc', '.docx'].includes(ext)) return 'WORD';
  if (['.xls', '.xlsx'].includes(ext)) return 'EXCEL';
  if (['.ppt', '.pptx'].includes(ext)) return 'PPT';
  if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) return 'IMG';
  if (ext === '.txt') return 'TXT';
  return 'DOSYA';
}

async function extractTextFromFile(filePath, ext) {
  try {
    if (ext === '.txt') {
      return fs.readFileSync(filePath, 'utf8');
    }
    if (ext === '.pdf') {
      const buffer = fs.readFileSync(filePath);
      const parsed = await pdfParse(buffer);
      return parsed.text || '';
    }
    if (ext === '.docx') {
      const result = await mammoth.extractRawText({ path: filePath });
      return result.value || '';
    }
    return '';
  } catch {
    return '';
  }
}

function getWorkflowActions(user, doc) {
  const actions = [];

  if (doc.status === 'Taslak' && hasPermission(user, 'doc:workflow:submit') && canManageDocument(user, doc)) {
    actions.push('submit');
  }
  if (doc.status === 'Onay Bekliyor' && hasPermission(user, 'doc:workflow:approve') && canManageDocument(user, doc)) {
    actions.push('approve', 'reject');
  }
  if (doc.status === 'Onaylandı' && hasPermission(user, 'doc:workflow:publish') && canManageDocument(user, doc)) {
    actions.push('publish');
  }
  if (doc.status === 'Yayınlandı' && hasPermission(user, 'doc:workflow:archive') && canManageDocument(user, doc)) {
    actions.push('archive');
  }

  return actions;
}

function applyWorkflowAction(doc, action, actorName) {
  const now = new Date().toISOString();
  const history = Array.isArray(doc.workflowHistory) ? doc.workflowHistory : [];

  const map = {
    submit: { status: 'Onay Bekliyor', label: 'Onaya Gönderildi' },
    approve: { status: 'Onaylandı', label: 'Onaylandı' },
    reject: { status: 'Reddedildi', label: 'Reddedildi' },
    publish: { status: 'Yayınlandı', label: 'Yayınlandı' },
    archive: { status: 'Arşivlendi', label: 'Arşivlendi' }
  };

  const selected = map[action];
  if (!selected) return doc;

  return {
    ...doc,
    status: selected.status,
    approvalTargetRole: action === 'submit' ? 'manager' : null,
    approvalTargetDepartment: action === 'submit' ? doc.department : null,
    workflowHistory: [
      ...history,
      {
        action,
        label: selected.label,
        actor: actorName,
        createdAt: now
      }
    ],
    statusUpdatedAt: now,
    statusUpdatedBy: actorName
  };
}

function seedDefaultUsers() {
  const users = readJson(usersFile);
  if (users.length) return;

  const now = new Date().toISOString();
  const defaults = [
    {
      id: '1',
      username: 'admin',
      password: bcrypt.hashSync('1234', 10),
      fullName: 'Sistem Yöneticisi',
      role: 'admin',
      department: 'YÖNETİM',
      isActive: true,
      mustChangePassword: true,
      createdAt: now,
      lastLoginAt: null
    },
    {
      id: '2',
      username: 'manager',
      password: bcrypt.hashSync('1234', 10),
      fullName: 'Birim Yöneticisi',
      role: 'manager',
      department: 'BT',
      isActive: true,
      mustChangePassword: true,
      createdAt: now,
      lastLoginAt: null
    },
    {
      id: '3',
      username: 'editor',
      password: bcrypt.hashSync('1234', 10),
      fullName: 'Editör Kullanıcı',
      role: 'editor',
      department: 'BT',
      isActive: true,
      mustChangePassword: true,
      createdAt: now,
      lastLoginAt: null
    },
    {
      id: '4',
      username: 'viewer',
      password: bcrypt.hashSync('1234', 10),
      fullName: 'Görüntüleyici Kullanıcı',
      role: 'viewer',
      department: 'BT',
      isActive: true,
      mustChangePassword: true,
      createdAt: now,
      lastLoginAt: null
    }
  ];

  writeJson(usersFile, defaults);
}
seedDefaultUsers();

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

app.use(
  session({
    secret: 'document-management-secret',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      secure: false,
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_MAX_AGE
    }
  })
);

const csrfProtection = csrf({ sessionKey: 'session' });

app.use(express.static(publicDir));
app.use('/uploads', express.static(uploadRootDir));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Çok fazla giriş denemesi yapıldı. Lütfen daha sonra tekrar deneyin.' },
  standardHeaders: true,
  legacyHeaders: false
});

const failedLoginTracker = new Map();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const department = req.body.department || 'Ortak';
    cb(null, ensureDepartmentFolder(department));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext);
    cb(null, `${Date.now()}-${sanitizeFileName(base)}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error('Bu dosya uzantısına izin verilmiyor.'));
    }
    cb(null, true);
  }
});

app.get('/api/csrf-token', requireAuth, csrfProtection, (req, res) => {
  res.json({
    csrfToken: req.csrfToken(),
    sessionMaxAge: SESSION_MAX_AGE,
    warningMs: SESSION_WARNING_MS
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    ...req.session.user,
    permissions: getPermissions(req.session.user.role)
  });
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const key = `${username}:${getClientIp(req)}`;
    const entry = failedLoginTracker.get(key);

    if (entry && entry.lockUntil && entry.lockUntil > Date.now()) {
      return res.status(429).json({ error: 'Bu hesap geçici olarak kilitlendi. Daha sonra tekrar deneyin.' });
    }

    const users = readJson(usersFile);
    const user = users.find(u => u.username === username);

    if (!user || !user.isActive) {
      const nextCount = entry ? entry.count + 1 : 1;
      failedLoginTracker.set(key, {
        count: nextCount,
        lockUntil: nextCount >= 5 ? Date.now() + 15 * 60 * 1000 : 0
      });
      return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      const nextCount = entry ? entry.count + 1 : 1;
      failedLoginTracker.set(key, {
        count: nextCount,
        lockUntil: nextCount >= 5 ? Date.now() + 15 * 60 * 1000 : 0
      });
      return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
    }

    failedLoginTracker.delete(key);

    user.lastLoginAt = new Date().toISOString();
    writeJson(usersFile, users);

    req.session.user = {
      id: user.id,
      username: user.username,
      fullName: user.fullName,
      role: user.role,
      department: user.department,
      mustChangePassword: user.mustChangePassword,
      isActive: user.isActive
    };

    addLog('LOGIN', req.session.user, {}, req);

    res.json({
      message: 'Giriş başarılı.',
      user: {
        ...req.session.user,
        permissions: getPermissions(user.role)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Giriş işlemi başarısız.' });
  }
});

app.post('/api/logout', requireAuth, csrfProtection, (req, res) => {
  addLog('LOGOUT', req.session.user, {}, req);
  req.session.destroy(() => {
    res.json({ message: 'Çıkış yapıldı.' });
  });
});

app.post('/api/change-password', requireAuth, csrfProtection, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ error: 'Yeni şifre en az 4 karakter olmalıdır.' });
    }

    const users = readJson(usersFile);
    const index = users.findIndex(u => u.id === req.session.user.id);

    if (index === -1) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    }

    users[index].password = await bcrypt.hash(newPassword, 10);
    users[index].mustChangePassword = false;
    writeJson(usersFile, users);

    req.session.user.mustChangePassword = false;
    addLog('CHANGE_PASSWORD', req.session.user, {}, req);

    res.json({ message: 'Şifre başarıyla değiştirildi.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Şifre değiştirilemedi.' });
  }
});

app.get('/api/my-history', requireAuth, requirePermission('history:view'), (req, res) => {
  try {
    const logs = readJson(logsFile).filter(log => log.username === req.session.user.username);
    res.json(logs.slice(0, 100));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'İşlem geçmişi okunamadı.' });
  }
});

app.get('/api/departments', requireAuth, (req, res) => {
  res.json(getActiveDepartments().map(dep => dep.name));
});

app.get('/api/admin/departments', requireAuth, requirePermission('department:manage'), (req, res) => {
  res.json(readJson(departmentsFile));
});

app.post('/api/admin/departments', requireAuth, requirePermission('department:manage'), csrfProtection, (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Departman adı zorunludur.' });
    }

    const departments = readJson(departmentsFile);
    const normalized = name.trim().toUpperCase();

    if (departments.some(dep => dep.name.toUpperCase() === normalized)) {
      return res.status(400).json({ error: 'Bu departman zaten var.' });
    }

    const dep = {
      id: Date.now().toString(),
      name: name.trim(),
      isActive: true
    };

    departments.push(dep);
    writeJson(departmentsFile, departments);
    ensureDepartmentFolder(dep.name);

    addLog('CREATE_DEPARTMENT', req.session.user, { name: dep.name }, req);
    res.json({ message: 'Departman eklendi.', department: dep });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Departman eklenemedi.' });
  }
});

app.put('/api/admin/departments/:id', requireAuth, requirePermission('department:manage'), csrfProtection, (req, res) => {
  try {
    const departments = readJson(departmentsFile);
    const index = departments.findIndex(d => d.id === req.params.id);

    if (index === -1) {
      return res.status(404).json({ error: 'Departman bulunamadı.' });
    }

    departments[index] = {
      ...departments[index],
      name: req.body.name?.trim() || departments[index].name,
      isActive: typeof req.body.isActive === 'boolean' ? req.body.isActive : departments[index].isActive
    };

    writeJson(departmentsFile, departments);
    ensureDepartmentFolder(departments[index].name);

    addLog('UPDATE_DEPARTMENT', req.session.user, { name: departments[index].name }, req);
    res.json({ message: 'Departman güncellendi.', department: departments[index] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Departman güncellenemedi.' });
  }
});

app.get('/api/admin/users', requireAuth, requirePermission('user:manage'), (req, res) => {
  res.json(readJson(usersFile));
});

app.post('/api/admin/users', requireAuth, requirePermission('user:manage'), csrfProtection, async (req, res) => {
  try {
    const { username, password, fullName, role, department, isActive, mustChangePassword } = req.body;

    if (!username || !password || !fullName || !role || !department) {
      return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
    }

    const users = readJson(usersFile);

    if (users.some(user => user.username === username.trim())) {
      return res.status(400).json({ error: 'Bu kullanıcı adı zaten var.' });
    }

    const user = {
      id: Date.now().toString(),
      username: username.trim(),
      password: await bcrypt.hash(password.trim(), 10),
      fullName: fullName.trim(),
      role,
      department,
      isActive: isActive !== false,
      mustChangePassword: mustChangePassword !== false,
      createdAt: new Date().toISOString(),
      lastLoginAt: null
    };

    users.push(user);
    writeJson(usersFile, users);

    addLog('CREATE_USER', req.session.user, { username: user.username, role: user.role }, req);
    res.json({ message: 'Kullanıcı eklendi.', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kullanıcı eklenemedi.' });
  }
});

app.put('/api/admin/users/:id', requireAuth, requirePermission('user:manage'), csrfProtection, async (req, res) => {
  try {
    const users = readJson(usersFile);
    const index = users.findIndex(u => u.id === req.params.id);

    if (index === -1) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    }

    users[index] = {
      ...users[index],
      username: req.body.username?.trim() || users[index].username,
      fullName: req.body.fullName?.trim() || users[index].fullName,
      role: req.body.role || users[index].role,
      department: req.body.department || users[index].department,
      isActive: typeof req.body.isActive === 'boolean' ? req.body.isActive : users[index].isActive,
      mustChangePassword: typeof req.body.mustChangePassword === 'boolean' ? req.body.mustChangePassword : users[index].mustChangePassword
    };

    if (req.body.password && req.body.password.trim()) {
      users[index].password = await bcrypt.hash(req.body.password.trim(), 10);
    }

    writeJson(usersFile, users);

    addLog('UPDATE_USER', req.session.user, { username: users[index].username, role: users[index].role }, req);
    res.json({ message: 'Kullanıcı güncellendi.', user: users[index] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kullanıcı güncellenemedi.' });
  }
});

app.post('/api/admin/users/:id/reset-password', requireAuth, requirePermission('user:manage'), csrfProtection, async (req, res) => {
  try {
    const users = readJson(usersFile);
    const index = users.findIndex(u => u.id === req.params.id);

    if (index === -1) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    }

    users[index].password = await bcrypt.hash('1234', 10);
    users[index].mustChangePassword = true;
    writeJson(usersFile, users);

    addLog('RESET_PASSWORD', req.session.user, { username: users[index].username }, req);
    res.json({ message: 'Şifre 1234 olarak sıfırlandı.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Şifre sıfırlanamadı.' });
  }
});

app.delete('/api/admin/users/:id', requireAuth, requirePermission('user:manage'), csrfProtection, (req, res) => {
  try {
    const users = readJson(usersFile);
    const found = users.find(u => u.id === req.params.id);

    if (!found) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    }

    writeJson(usersFile, users.filter(u => u.id !== req.params.id));
    addLog('DELETE_USER', req.session.user, { username: found.username }, req);

    res.json({ message: 'Kullanıcı silindi.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kullanıcı silinemedi.' });
  }
});

app.get('/api/documents', requireAuth, (req, res) => {
  try {
    const user = req.session.user;
    const { search = '', department = '', category = '', startDate = '', endDate = '', status = '' } = req.query;

    let docs = readJson(dataFile).filter(doc => canAccessDocument(user, doc));

    if (search) {
      const q = search.toLowerCase();
      docs = docs.filter(doc =>
        doc.title.toLowerCase().includes(q) ||
        doc.category.toLowerCase().includes(q) ||
        doc.department.toLowerCase().includes(q) ||
        doc.originalName.toLowerCase().includes(q) ||
        doc.uploadedBy.toLowerCase().includes(q) ||
        (doc.contentText || '').toLowerCase().includes(q)
      );
    }

    if (department) docs = docs.filter(doc => doc.department === department);
    if (category) docs = docs.filter(doc => doc.category === category);
    if (status) docs = docs.filter(doc => doc.status === status);

    if (startDate) {
      const start = new Date(startDate);
      start.setHours(0, 0, 0, 0);
      docs = docs.filter(doc => new Date(doc.createdAt) >= start);
    }

    if (endDate) {
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      docs = docs.filter(doc => new Date(doc.createdAt) <= end);
    }

    docs = docs
      .map(doc => ({
        ...doc,
        previewType: getPreviewType(doc.fileName),
        fileIcon: getFileIcon(doc.fileName),
        allowedActions: getWorkflowActions(user, doc)
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json(docs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Dokümanlar okunamadı.' });
  }
});

app.get('/api/documents/:id/view-url', requireAuth, (req, res) => {
  try {
    const docs = readJson(dataFile);
    const index = docs.findIndex(d => d.id === req.params.id);

    if (index === -1) return res.status(404).json({ error: 'Doküman bulunamadı.' });

    const doc = docs[index];
    if (!canAccessDocument(req.session.user, doc)) {
      return res.status(403).json({ error: 'Bu dokümana erişim yetkiniz yok.' });
    }

    docs[index].viewCount = (docs[index].viewCount || 0) + 1;
    writeJson(dataFile, docs);
    addLog('VIEW_DOCUMENT', req.session.user, { title: doc.title }, req);

    res.json({
      fileUrl: doc.fileUrl,
      previewType: getPreviewType(doc.fileName)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Önizleme alınamadı.' });
  }
});

app.get('/api/documents/:id/download', requireAuth, requirePermission('doc:download'), (req, res) => {
  try {
    const docs = readJson(dataFile);
    const index = docs.findIndex(d => d.id === req.params.id);

    if (index === -1) return res.status(404).json({ error: 'Doküman bulunamadı.' });

    const doc = docs[index];
    if (!canAccessDocument(req.session.user, doc)) {
      return res.status(403).json({ error: 'Bu dokümana erişim yetkiniz yok.' });
    }

    docs[index].downloadCount = (docs[index].downloadCount || 0) + 1;
    writeJson(dataFile, docs);
    addLog('DOWNLOAD_DOCUMENT', req.session.user, { title: doc.title }, req);

    const fullPath = path.join(uploadRootDir, sanitizeFileName(doc.department), doc.fileName);
    return res.download(fullPath, doc.originalName);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Dosya indirilemedi.' });
  }
});

app.post('/api/documents', requireAuth, requirePermission('doc:upload'), csrfProtection, (req, res) => {
  upload.single('documentFile')(req, res, async err => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Dosya yüklenemedi.' });
    }

    try {
      const user = req.session.user;
      const { title, category, department, status } = req.body;

      if (!req.file) return res.status(400).json({ error: 'Dosya seçilmedi.' });
      if (!title || !title.trim() || title.trim().length < 2) {
        return res.status(400).json({ error: 'Başlık en az 2 karakter olmalıdır.' });
      }
      if (!category || !department) {
        return res.status(400).json({ error: 'Kategori ve departman zorunludur.' });
      }

      const activeDepartments = getActiveDepartments().map(dep => dep.name);
      if (!activeDepartments.includes(department)) {
        return res.status(400).json({ error: 'Geçersiz departman seçildi.' });
      }

      if (user.role !== 'admin' && department !== user.department && department !== 'Ortak') {
        return res.status(403).json({ error: 'Bu departmana yükleme yetkiniz yok.' });
      }

      const docs = readJson(dataFile);
      const sameSeries = docs.filter(doc =>
        !doc.deleted &&
        doc.title.trim().toLowerCase() === title.trim().toLowerCase() &&
        doc.department === department
      );

      const version = sameSeries.length
        ? Math.max(...sameSeries.map(d => d.version || 1)) + 1
        : 1;

      const seriesId = sameSeries.length ? sameSeries[0].seriesId : Date.now().toString();
      const ext = path.extname(req.file.originalname).toLowerCase();
      const contentText = await extractTextFromFile(req.file.path, ext);
      const relativeFolder = sanitizeFileName(department);

      const newDoc = {
        id: Date.now().toString(),
        seriesId,
        title: title.trim(),
        category,
        department,
        status: status || 'Taslak',
        uploadedBy: user.fullName,
        uploadedByUsername: user.username,
        originalName: req.file.originalname,
        fileName: req.file.filename,
        fileUrl: `/uploads/${relativeFolder}/${req.file.filename}`,
        fileSize: req.file.size,
        version,
        viewCount: 0,
        downloadCount: 0,
        contentText,
        approvalTargetRole: status === 'Onay Bekliyor' ? 'manager' : null,
        approvalTargetDepartment: status === 'Onay Bekliyor' ? department : null,
        workflowHistory: [
          {
            action: 'create',
            label: 'Doküman Oluşturuldu',
            actor: user.fullName,
            createdAt: new Date().toISOString()
          }
        ],
        createdAt: new Date().toISOString(),
        deleted: false,
        deletedAt: null,
        deletedBy: null
      };

      docs.push(newDoc);
      writeJson(dataFile, docs);

      addLog('UPLOAD_DOCUMENT', user, {
        title: newDoc.title,
        department: newDoc.department,
        version: newDoc.version
      }, req);

      addNotification('success', 'Yeni Doküman', `${newDoc.title} belgesi v${newDoc.version} yüklendi.`, 'all', newDoc.department);

      res.json({
        message: 'Doküman başarıyla yüklendi.',
        document: {
          ...newDoc,
          previewType: getPreviewType(newDoc.fileName),
          fileIcon: getFileIcon(newDoc.fileName),
          allowedActions: getWorkflowActions(user, newDoc)
        }
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Doküman yüklenemedi.' });
    }
  });
});

app.put('/api/documents/:id/workflow', requireAuth, csrfProtection, (req, res) => {
  try {
    const { action } = req.body;
    const docs = readJson(dataFile);
    const index = docs.findIndex(d => d.id === req.params.id);

    if (index === -1) {
      return res.status(404).json({ error: 'Doküman bulunamadı.' });
    }

    const doc = docs[index];
    if (!canAccessDocument(req.session.user, doc) || !canManageDocument(req.session.user, doc)) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok.' });
    }

    const allowed = getWorkflowActions(req.session.user, doc);
    if (!allowed.includes(action)) {
      return res.status(403).json({ error: 'Bu akış adımını uygulama yetkiniz yok.' });
    }

    docs[index] = applyWorkflowAction(doc, action, req.session.user.fullName);
    writeJson(dataFile, docs);

    addLog('UPDATE_DOCUMENT_WORKFLOW', req.session.user, {
      title: doc.title,
      action,
      newStatus: docs[index].status
    }, req);

    addNotification('info', 'Doküman Akışı Güncellendi', `${doc.title} belgesi ${docs[index].status} durumuna geçti.`, 'all', doc.department);

    res.json({
      message: 'Doküman akışı güncellendi.',
      document: {
        ...docs[index],
        previewType: getPreviewType(docs[index].fileName),
        fileIcon: getFileIcon(docs[index].fileName),
        allowedActions: getWorkflowActions(req.session.user, docs[index])
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Doküman akışı güncellenemedi.' });
  }
});

app.delete('/api/documents/:id', requireAuth, requirePermission('doc:delete'), csrfProtection, (req, res) => {
  try {
    const docs = readJson(dataFile);
    const index = docs.findIndex(d => d.id === req.params.id);

    if (index === -1) return res.status(404).json({ error: 'Doküman bulunamadı.' });

    const doc = docs[index];
    if (!canManageDocument(req.session.user, doc)) {
      return res.status(403).json({ error: 'Bu dokümanı silme yetkiniz yok.' });
    }

    docs[index] = {
      ...doc,
      deleted: true,
      deletedAt: new Date().toISOString(),
      deletedBy: req.session.user.fullName
    };

    writeJson(dataFile, docs);
    addLog('DELETE_DOCUMENT', req.session.user, { title: doc.title }, req);

    res.json({ message: 'Doküman silinmiş öğelere taşındı.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Doküman silinemedi.' });
  }
});

app.get('/api/deleted-documents', requireAuth, requirePermission('doc:restore'), (req, res) => {
  try {
    const docs = readJson(dataFile)
      .filter(doc => doc.deleted)
      .map(doc => ({
        ...doc,
        previewType: getPreviewType(doc.fileName),
        fileIcon: getFileIcon(doc.fileName)
      }))
      .sort((a, b) => new Date(b.deletedAt || b.createdAt) - new Date(a.deletedAt || a.createdAt));

    res.json(docs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Silinmiş dokümanlar okunamadı.' });
  }
});

app.post('/api/deleted-documents/:id/restore', requireAuth, requirePermission('doc:restore'), csrfProtection, (req, res) => {
  try {
    const docs = readJson(dataFile);
    const index = docs.findIndex(d => d.id === req.params.id);

    if (index === -1) return res.status(404).json({ error: 'Doküman bulunamadı.' });

    docs[index] = {
      ...docs[index],
      deleted: false,
      deletedAt: null,
      deletedBy: null
    };

    writeJson(dataFile, docs);
    addLog('RESTORE_DOCUMENT', req.session.user, { title: docs[index].title }, req);

    res.json({ message: 'Doküman geri yüklendi.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Doküman geri yüklenemedi.' });
  }
});

app.delete('/api/deleted-documents/:id/permanent', requireAuth, requirePermission('doc:restore'), csrfProtection, (req, res) => {
  try {
    const docs = readJson(dataFile);
    const doc = docs.find(d => d.id === req.params.id);

    if (!doc) return res.status(404).json({ error: 'Doküman bulunamadı.' });

    writeJson(dataFile, docs.filter(d => d.id !== req.params.id));

    const fullPath = path.join(uploadRootDir, sanitizeFileName(doc.department), doc.fileName);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);

    addLog('PERMANENT_DELETE_DOCUMENT', req.session.user, { title: doc.title }, req);

    res.json({ message: 'Doküman kalıcı olarak silindi.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Doküman kalıcı silinemedi.' });
  }
});

app.get('/api/logs', requireAuth, requirePermission('logs:view'), (req, res) => {
  try {
    let logs = readJson(logsFile);
    const { q = '', action = '' } = req.query;

    if (req.session.user.role !== 'admin') {
      logs = logs.filter(log => log.username === req.session.user.username || log.department === req.session.user.department);
    }

    if (q) {
      const query = q.toLowerCase();
      logs = logs.filter(log =>
        log.action.toLowerCase().includes(query) ||
        log.user.toLowerCase().includes(query) ||
        log.username.toLowerCase().includes(query) ||
        log.department.toLowerCase().includes(query) ||
        (log.ip || '').toLowerCase().includes(query)
      );
    }

    if (action) logs = logs.filter(log => log.action === action);

    res.json(logs.slice(0, 300));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Loglar okunamadı.' });
  }
});

app.get('/api/notifications', requireAuth, requirePermission('notifications:view'), (req, res) => {
  try {
    const all = readJson(notificationsFile);
    const user = req.session.user;
    const filtered = all.filter(n =>
      (n.targetRole === 'all' || n.targetRole === user.role) &&
      (n.targetDepartment === 'all' || n.targetDepartment === user.department)
    );
    res.json(filtered.slice(0, 50));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Bildirimler okunamadı.' });
  }
});

app.get('/api/stats', requireAuth, requirePermission('stats:view'), (req, res) => {
  try {
    const docs = readJson(dataFile);
    const users = readJson(usersFile);
    const visibleDocs = docs.filter(doc => canAccessDocument(req.session.user, doc));

    const byStatus = {};
    const byDepartment = {};
    let totalViews = 0;
    let totalDownloads = 0;

    visibleDocs.forEach(doc => {
      byStatus[doc.status] = (byStatus[doc.status] || 0) + 1;
      byDepartment[doc.department] = (byDepartment[doc.department] || 0) + 1;
      totalViews += doc.viewCount || 0;
      totalDownloads += doc.downloadCount || 0;
    });

    res.json({
      totalDocs: visibleDocs.length,
      totalUsers: users.filter(u => u.isActive).length,
      deletedDocs: docs.filter(d => d.deleted).length,
      totalViews,
      totalDownloads,
      byStatus,
      byDepartment
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'İstatistikler alınamadı.' });
  }
});

app.post('/api/admin/backup', requireAuth, requirePermission('backup:create'), csrfProtection, (req, res) => {
  try {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const target = path.join(backupsDir, stamp);
    fs.mkdirSync(target, { recursive: true });

    [dataFile, usersFile, logsFile, departmentsFile, notificationsFile].forEach(file => {
      fs.copyFileSync(file, path.join(target, path.basename(file)));
    });

    addLog('CREATE_BACKUP', req.session.user, { folder: stamp }, req);
    res.json({ message: 'Yedek oluşturuldu.', folder: stamp });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Yedek oluşturulamadı.' });
  }
});

app.post('/api/export/zip', requireAuth, requirePermission('export:zip'), csrfProtection, (req, res) => {
  try {
    const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
    const docs = readJson(dataFile).filter(doc => ids.includes(doc.id) && canAccessDocument(req.session.user, doc));

    if (!docs.length) {
      return res.status(400).json({ error: 'ZIP için uygun doküman bulunamadı.' });
    }

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename=export-${Date.now()}.zip`);

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.on('error', err => { throw err; });
    archive.pipe(res);

    docs.forEach(doc => {
      const fullPath = path.join(uploadRootDir, sanitizeFileName(doc.department), doc.fileName);
      if (fs.existsSync(fullPath)) {
        archive.file(fullPath, { name: doc.originalName });
      }
    });

    archive.finalize();
    addLog('EXPORT_ZIP', req.session.user, { count: docs.length }, req);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'ZIP dışa aktarma başarısız.' });
  }
});

app.listen(PORT, () => {
  console.log(`Kurumsal Doküman Yönetim Sistemi çalışıyor: http://localhost:${PORT}`);
  console.log('Varsayılan kullanıcılar: admin / manager / editor / viewer | şifre: 1234');
});