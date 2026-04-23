require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');

const app = express();
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false
});

const upload = multer({ dest: uploadDir, limits: { fileSize: 100 * 1024 * 1024 } });

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

const OTP = new Map();

function signToken(user){
  return jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: '30d' });
}

function auth(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try{
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    next();
  }catch(e){
    return res.status(401).json({ error: 'unauthorized' });
  }
}

async function mailer(){
  if (!process.env.SMTP_HOST) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
}

app.get('/health', (_, res) => res.json({ ok: true }));

app.post('/api/auth/request-otp', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email required' });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  OTP.set(email.toLowerCase(), { code, expires: Date.now() + 10 * 60 * 1000 });

  const transport = await mailer();
  if (transport){
    await transport.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'Kode OTP MAR MUSIC',
      text: `Ini kode OTP kamu.\n\n${code}\n\nJangan bagikan kode ini kepada siapa pun.`,
      html: `
        <div style="font-family:Arial,sans-serif;background:#f7f9fc;padding:24px">
          <div style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #dbe7fb;border-radius:18px;padding:24px">
            <h2 style="margin:0 0 12px;color:#0b57d0">MAR MUSIC</h2>
            <p style="margin:0 0 16px;color:#111">Ini kode OTP kamu.</p>
            <div style="font-size:30px;font-weight:700;letter-spacing:6px;padding:14px 18px;background:#edf4ff;border-radius:14px;display:inline-block">${code}</div>
            <p style="margin:16px 0 0;color:#111">Jangan bagikan kode ini kepada siapa pun.</p>
          </div>
        </div>`
      });
  } else {
    console.log('OTP for', email, code);
  }

  res.json({ ok: true });
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body || {};
  const row = OTP.get(String(email || '').toLowerCase());
  if (!row || row.code !== String(otp) || Date.now() > row.expires) {
    return res.status(400).json({ error: 'invalid otp' });
  }
  OTP.delete(String(email).toLowerCase());

  const result = await pool.query(
    `INSERT INTO users (email, otp_verified_at)
     VALUES ($1, NOW())
     ON CONFLICT (email) DO UPDATE SET otp_verified_at = NOW()
     RETURNING id, email`,
    [email.toLowerCase()]
  );
  const user = result.rows[0];
  const token = signToken(user);
  res.json({ ok: true, token, user });
});

app.get('/api/me', auth, async (req, res) => {
  const user = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.user.sub]);
  res.json({ user: user.rows[0] || null });
});

app.get('/api/playlists', auth, async (req, res) => {
  const playlists = await pool.query('SELECT * FROM playlists WHERE user_id = $1 ORDER BY updated_at DESC', [req.user.sub]);
  res.json({ playlists: playlists.rows });
});

app.post('/api/playlists', auth, async (req, res) => {
  const { title, cover_url } = req.body || {};
  const q = await pool.query(
    `INSERT INTO playlists (user_id, title, cover_url)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [req.user.sub, title || 'My Playlist', cover_url || null]
  );
  res.json({ playlist: q.rows[0] });
});

app.patch('/api/playlists/:id', auth, async (req, res) => {
  const { title, cover_url } = req.body || {};
  const q = await pool.query(
    `UPDATE playlists
     SET title = COALESCE($1, title),
         cover_url = COALESCE($2, cover_url),
         updated_at = NOW()
     WHERE id = $3 AND user_id = $4
     RETURNING *`,
    [title || null, cover_url || null, req.params.id, req.user.sub]
  );
  res.json({ playlist: q.rows[0] || null });
});

app.delete('/api/playlists/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM playlists WHERE id = $1 AND user_id = $2', [req.params.id, req.user.sub]);
  res.json({ ok: true });
});

app.post('/api/tracks/upload', auth, upload.single('file'), async (req, res) => {
  const { title, artist, playlist_id } = req.body || {};
  if (!req.file) return res.status(400).json({ error: 'file required' });

  const q = await pool.query(
    `INSERT INTO tracks (user_id, title, artist, file_path, file_name, file_size, mime_type)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [req.user.sub, title || req.file.originalname.replace(/\.[^/.]+$/, ''), artist || 'Local file', req.file.path, req.file.originalname, req.file.size, req.file.mimetype]
  );

  if (playlist_id){
    await pool.query(
      `INSERT INTO playlist_tracks (playlist_id, track_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [playlist_id, q.rows[0].id]
    );
  }

  res.json({ track: q.rows[0] });
});

app.get('/api/tracks', auth, async (req, res) => {
  const q = await pool.query('SELECT * FROM tracks WHERE user_id = $1 ORDER BY created_at DESC', [req.user.sub]);
  res.json({ tracks: q.rows });
});

app.delete('/api/tracks/:id', auth, async (req, res) => {
  const t = await pool.query('SELECT * FROM tracks WHERE id = $1 AND user_id = $2', [req.params.id, req.user.sub]);
  if (t.rows[0]?.file_path && fs.existsSync(t.rows[0].file_path)) fs.unlinkSync(t.rows[0].file_path);
  await pool.query('DELETE FROM tracks WHERE id = $1 AND user_id = $2', [req.params.id, req.user.sub]);
  res.json({ ok: true });
});

app.post('/api/markers', auth, async (req, res) => {
  const { track_id, position, label } = req.body || {};
  const q = await pool.query(
    `INSERT INTO markers (user_id, track_id, position, label)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [req.user.sub, track_id, position || 0, label || 'flag']
  );
  res.json({ marker: q.rows[0] });
});

app.get('/api/storage', auth, async (req, res) => {
  const q = await pool.query(
    `SELECT COALESCE(SUM(file_size),0) AS used
     FROM tracks WHERE user_id = $1`,
    [req.user.sub]
  );
  res.json({ used: Number(q.rows[0].used || 0) });
});

app.post('/api/sync/push', auth, async (req, res) => {
  const payload = req.body || {};
  await pool.query(
    `INSERT INTO sync_states (user_id, payload, updated_at)
     VALUES ($1, $2::jsonb, NOW())
     ON CONFLICT (user_id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()`,
    [req.user.sub, JSON.stringify(payload)]
  );
  res.json({ ok: true });
});

app.get('/api/sync/pull', auth, async (req, res) => {
  const q = await pool.query('SELECT payload FROM sync_states WHERE user_id = $1', [req.user.sub]);
  res.json({ payload: q.rows[0]?.payload || null });
});

app.use('/uploads', express.static(uploadDir));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`MAR MUSIC backend on ${port}`));
