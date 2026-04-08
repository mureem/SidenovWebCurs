require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.PGSSLMODE === 'require' || process.env.DATABASE_URL?.includes('sslmode=require')
      ? { rejectUnauthorized: false }
      : false,
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'pages'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.set('trust proxy', 1);

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function sign(payload) {
  const secret = process.env.SESSION_SECRET || 'dev-only-secret';
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function setAuthCookie(res, userId) {
  const payload = String(userId);
  const value = `${payload}.${sign(payload)}`;
  const maxAge = 7 * 24 * 60 * 60;
  res.setHeader(
    'Set-Cookie',
    `auth=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}` +
      (process.env.NODE_ENV === 'production' ? '; Secure' : '')
  );
}

function clearAuthCookie(res) {
  res.setHeader(
    'Set-Cookie',
    'auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' +
      (process.env.NODE_ENV === 'production' ? '; Secure' : '')
  );
}

async function loadUser(req, res, next) {
  res.locals.currentUser = null;

  const raw = parseCookies(req).auth;
  if (!raw) return next();

  const [idStr, sig] = raw.split('.', 2);
  const id = Number(idStr);
  if (!id || !sig) return next();

  const expected = sign(String(id));
  if (expected !== sig) {
    clearAuthCookie(res);
    return next();
  }

  try {
    const { rows } = await pool.query('SELECT id, username, role, is_blocked FROM users WHERE id = $1', [
      id,
    ]);
    const u = rows[0];
    if (!u || u.is_blocked) {
      clearAuthCookie(res);
      return next();
    }
    res.locals.currentUser = u;
    next();
  } catch (e) {
    next(e);
  }
}

function requireLogin(req, res, next) {
  if (!res.locals.currentUser) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    const u = res.locals.currentUser;
    if (!u || !roles.includes(u.role)) return res.status(403).send('Доступ запрещён');
    next();
  };
}

app.use(loadUser);

app.get('/', (req, res) => res.redirect('/chat'));

app.get('/chat', async (req, res, next) => {
  try {
    const { rows: messages } = await pool.query(
      `SELECT m.id, m.body, m.created_at, u.username
       FROM messages m
       JOIN users u ON u.id = m.user_id
       ORDER BY m.created_at DESC
       LIMIT 100`
    );
    messages.reverse();
    res.render('chat', {
      title: 'Чат',
      messages,
      chatRefreshSec: 8,
      error: req.query.error || null,
    });
  } catch (e) {
    next(e);
  }
});

app.post('/chat/message', requireLogin, async (req, res, next) => {
  const body = (req.body.body || '').trim();
  if (!body) return res.redirect('/chat?error=' + encodeURIComponent('Пустое сообщение'));
  try {
    await pool.query('INSERT INTO messages (user_id, body) VALUES ($1, $2)', [
      res.locals.currentUser.id,
      body,
    ]);
    res.redirect('/chat');
  } catch (e) {
    next(e);
  }
});

app.get('/register', (req, res) => {
  if (res.locals.currentUser) return res.redirect('/chat');
  res.render('register', { title: 'Регистрация', error: null });
});

app.post('/register', async (req, res, next) => {
  if (res.locals.currentUser) return res.redirect('/chat');
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  if (!username) return res.render('register', { title: 'Регистрация', error: 'Введите логин' });
  if (password.length < 4)
    return res.render('register', { title: 'Регистрация', error: 'Пароль должен быть длиннее 3 символов' });
  try {
    const { rows: cnt } = await pool.query('SELECT COUNT(*)::int AS n FROM users');
    const role = cnt[0].n === 0 ? 'admin' : 'user';
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3::user_role)', [
      username,
      hash,
      role,
    ]);
    res.redirect('/login?registered=1');
  } catch (e) {
    if (e.code === '23505') {
      return res.render('register', { title: 'Регистрация', error: 'Такой логин уже занят' });
    }
    next(e);
  }
});

app.get('/login', (req, res) => {
  if (res.locals.currentUser) return res.redirect('/chat');
  res.render('login', {
    title: 'Вход',
    error: null,
    registered: req.query.registered === '1',
    next: req.query.next || '/chat',
  });
});

app.post('/login', async (req, res, next) => {
  if (res.locals.currentUser) return res.redirect('/chat');
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  const nextUrl = req.body.next || '/chat';
  try {
    const { rows } = await pool.query(
      'SELECT id, password_hash, is_blocked FROM users WHERE username = $1',
      [username]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.render('login', {
        title: 'Вход',
        error: 'Неверный логин или пароль',
        registered: false,
        next: nextUrl,
      });
    }
    if (user.is_blocked) {
      return res.render('login', {
        title: 'Вход',
        error: 'Учётная запись заблокирована',
        registered: false,
        next: nextUrl,
      });
    }
    setAuthCookie(res, user.id);
    res.redirect(nextUrl.startsWith('/') ? nextUrl : '/chat');
  } catch (e) {
    next(e);
  }
});

app.post('/logout', (req, res) => {
  clearAuthCookie(res);
  res.redirect('/chat');
});

app.get('/mod/users', requireLogin, requireRole('moderator', 'admin'), async (req, res, next) => {
  try {
    const { rows: users } = await pool.query(
      'SELECT id, username, role, is_blocked, created_at FROM users ORDER BY id'
    );
    res.render('mod-users', { title: 'Модерация', users, message: req.query.message || null });
  } catch (e) {
    next(e);
  }
});

app.post('/mod/block/:id', requireLogin, requireRole('moderator', 'admin'), async (req, res, next) => {
  const targetId = Number(req.params.id);
  if (!targetId || targetId === res.locals.currentUser.id) {
    return res.redirect('/mod/users?message=' + encodeURIComponent('Нельзя заблокировать себя'));
  }
  try {
    const { rows } = await pool.query('SELECT role FROM users WHERE id = $1', [targetId]);
    if (!rows[0]) {
      return res.redirect('/mod/users?message=' + encodeURIComponent('Пользователь не найден'));
    }
    if (rows[0].role === 'admin') {
      return res.redirect('/mod/users?message=' + encodeURIComponent('Нельзя блокировать администратора'));
    }
    await pool.query('UPDATE users SET is_blocked = TRUE WHERE id = $1', [targetId]);
    res.redirect('/mod/users?message=' + encodeURIComponent('Пользователь заблокирован'));
  } catch (e) {
    next(e);
  }
});

app.post('/mod/unblock/:id', requireLogin, requireRole('moderator', 'admin'), async (req, res, next) => {
  const targetId = Number(req.params.id);
  if (!targetId) return res.redirect('/mod/users');
  try {
    await pool.query('UPDATE users SET is_blocked = FALSE WHERE id = $1 AND role <> $2', [
      targetId,
      'admin',
    ]);
    res.redirect('/mod/users?message=' + encodeURIComponent('Блокировка снята'));
  } catch (e) {
    next(e);
  }
});

app.get('/admin/users', requireLogin, requireRole('admin'), async (req, res, next) => {
  try {
    const { rows: users } = await pool.query(
      'SELECT id, username, role, is_blocked, created_at FROM users ORDER BY id'
    );
    res.render('admin-users', { title: 'Администрирование', users, message: req.query.message || null });
  } catch (e) {
    next(e);
  }
});

app.post('/admin/role', requireLogin, requireRole('admin'), async (req, res, next) => {
  const userId = Number(req.body.user_id);
  const role = req.body.role;
  if (!userId || !['user', 'moderator'].includes(role)) {
    return res.redirect('/admin/users?message=' + encodeURIComponent('Некорректные данные'));
  }
  if (userId === res.locals.currentUser.id) {
    return res.redirect('/admin/users?message=' + encodeURIComponent('Нельзя изменить свою роль'));
  }
  try {
    const { rows } = await pool.query('SELECT role FROM users WHERE id = $1', [userId]);
    if (!rows[0] || rows[0].role === 'admin') {
      return res.redirect('/admin/users?message=' + encodeURIComponent('Операция недоступна'));
    }
    await pool.query('UPDATE users SET role = $1::user_role WHERE id = $2', [role, userId]);
    res.redirect('/admin/users?message=' + encodeURIComponent('Роль обновлена'));
  } catch (e) {
    next(e);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Ошибка сервера');
});

app.listen(PORT, () => {
  console.log('http://localhost:' + PORT);
});
