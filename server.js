require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('Defina JWT_SECRET (32+ caracteres) nas variáveis de ambiente.');
  process.exit(1);
}

const IS_VERCEL = Boolean(process.env.VERCEL);
const IS_PROD = process.env.NODE_ENV === 'production' || IS_VERCEL;
const COOKIE = 'winchester_token';

// Na Vercel, apenas /tmp permite escrita; localmente usa users.json na raiz
const DB_FILE = IS_VERCEL
  ? path.join(os.tmpdir(), 'users.json')
  : path.join(__dirname, 'users.json');

// Copia os utilizadores iniciais para /tmp na primeira execução na Vercel
if (IS_VERCEL && !fs.existsSync(DB_FILE)) {
  const seedFile = path.join(__dirname, 'users.json');
  if (fs.existsSync(seedFile)) {
    fs.copyFileSync(seedFile, DB_FILE);
  }
}

function readUsers() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return []; }
}
function writeUsers(users) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

const emailOk = v => typeof v === 'string' && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const publicUser = u => ({ name: u.name, email: u.email });
const DUMMY_HASH = bcrypt.hashSync('senha-falsa', 12);

function issueSession(res, user) {
  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    maxAge: 7 * 24 * 3600 * 1000,
  });
}

function currentUser(req) {
  try {
    const { sub } = jwt.verify(req.cookies[COOKIE] || '', JWT_SECRET);
    return readUsers().find(u => u.id === sub) || null;
  } catch { return null; }
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Muitas tentativas. Tente de novo em alguns minutos.' },
});

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'cadastros.html'));
});

// ==========================================
// ROTA DO CHAT (Integração com a API da Groq)
// ==========================================
app.post('/api/chat', limiter, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ message: 'Mensagem não informada.' });

  const apiKey = process.env.API_KEY_GROQ;
  if (!apiKey) return res.status(500).json({ message: 'API_KEY_GROQ não configurada no servidor.' });

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: 'Você é um assistente prestativo.' },
          { role: 'user', content: message }
        ],
        temperature: 0.7
      })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error?.message || 'Erro ao comunicar com a API da Groq.');
    }

    const reply = data.choices[0].message.content;
    res.json({ reply });
  } catch (error) {
    console.error('Erro no chat:', error);
    res.status(500).json({ message: error.message || 'Erro interno no servidor.' });
  }
});

// Rotas de Autenticação
app.post('/api/signup', limiter, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!name || name.length > 80) return res.status(400).json({ message: 'Informe um nome válido.' });
  if (!emailOk(email)) return res.status(400).json({ message: 'Informe um e-mail válido.' });
  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({ message: 'A senha deve ter de 8 a 72 caracteres.' });
  }

  const hash = await bcrypt.hash(password, 12);
  const users = readUsers();
  if (users.some(u => u.email === email)) {
    return res.status(409).json({ message: 'Este e-mail já está cadastrado.' });
  }
  const user = { id: crypto.randomUUID(), name, email, hash, createdAt: new Date().toISOString() };
  users.push(user);
  writeUsers(users);

  issueSession(res, user);
  res.status(201).json({ ok: true, user: publicUser(user) });
});

app.post('/api/login', limiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const user = readUsers().find(u => u.email === email);
  const ok = await bcrypt.compare(password, user ? user.hash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ message: 'E-mail ou senha incorretos.' });

  issueSession(res, user);
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE, { httpOnly: true, sameSite: 'lax', secure: IS_PROD });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ message: 'Não autenticado.' });
  res.json({ user: publicUser(user) });
});

if (!IS_VERCEL) {
  app.listen(PORT, () => console.log('Rodando em http://localhost:' + PORT));
}

module.exports = app;
