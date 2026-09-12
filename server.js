require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const Groq = require('groq-sdk');
const passport = require('./auth');
const db = require('./db');

const PORT = process.env.PORT || 3000;
const MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

if (!process.env.GROQ_API_KEY) {
  console.warn(
    '\n⚠  GROQ_API_KEY nahi mila. .env.example ko .env mein copy karke apni key daalo:\n' +
    '   copy .env.example .env\n' +
    '   Key yahan se milegi: https://console.groq.com/keys\n'
  );
}

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'samadhan-dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }, // 7 days
  })
);
app.use(passport.initialize());
app.use(passport.session());

const bcrypt = require('bcryptjs');

// ---------- LOGIN TOGGLE ----------
// Abhi ke liye login OFF hai (local testing ke liye).
// VPS pe deploy karte waqt isse true kar dena, taaki login wapas ON ho jaye.
const AUTH_ENABLED = false;

// Login OFF hone par isi guest user (asli DB row) se kaam chalega, taaki notes/xp save ho sakein
function getGuestUser() {
  return db.findOrCreateUser({ provider: 'guest', providerId: 'local', name: 'Guest' });
}

function ensureAuth(req, res, next) {
  if (!AUTH_ENABLED) {
    if (!req.user) req.user = getGuestUser(); // fake login taaki routes crash na karein
    return next();
  }
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Login required' });
}

// Serve static assets from root directory (login.html, public assets etc.)
app.use(express.static(path.join(__dirname), { index: false }));

// Also serve from public/ if it exists (for index.html and other app files)
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ---------- Routes ----------

// Login page — always accessible
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Root — redirect to login if not authenticated (agar AUTH_ENABLED true hai)
app.get('/', (req, res) => {
  if (AUTH_ENABLED && !req.isAuthenticated()) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------- Email + password auth ----------
app.post('/auth/register', async (req, res) => {
  try {
    const email = (req.body?.email || '').trim().toLowerCase();
    const password = req.body?.password || '';
    const name = (req.body?.name || '').trim();
    if (!email || !password) return res.status(400).json({ error: 'Email aur password dono chahiye.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password kam se kam 6 characters ka ho.' });
    if (db.getLocalUserByEmail(email)) {
      return res.status(400).json({ error: 'Is email se account pehle se hai. Login karo.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const user = db.createLocalUser({ email, name, passwordHash });
    req.login(user, err => {
      if (err) return res.status(500).json({ error: 'Account bana par login nahi hua. Dobara login try karo.' });
      res.json({ ok: true });
    });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ error: 'Account banate waqt error aaya.' });
  }
});

app.post('/auth/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.status(500).json({ error: 'Login karte waqt error aaya.' });
    if (!user) return res.status(401).json({ error: (info && info.message) || 'Login fail ho gaya.' });
    req.login(user, loginErr => {
      if (loginErr) return res.status(500).json({ error: 'Login fail ho gaya.' });
      res.json({ ok: true });
    });
  })(req, res, next);
});

// ---------- Google OAuth ----------
app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.redirect('/login.html?error=google_not_configured');
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});
app.get(
  '/auth/google/callback',
  (req, res, next) => passport.authenticate('google', { failureRedirect: '/login.html?error=google_failed' })(req, res, next),
  (req, res) => res.redirect('/')
);

// ---------- Twitter / X OAuth ----------
app.get('/auth/twitter', (req, res, next) => {
  if (!process.env.TWITTER_CONSUMER_KEY) {
    return res.redirect('/login.html?error=twitter_not_configured');
  }
  passport.authenticate('twitter')(req, res, next);
});
app.get(
  '/auth/twitter/callback',
  (req, res, next) => passport.authenticate('twitter', { failureRedirect: '/login.html?error=twitter_failed' })(req, res, next),
  (req, res) => res.redirect('/')
);

// ---------- Logout ----------
app.post('/auth/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.json({ ok: true });
  });
});

// ---------- User info ----------
app.get('/api/me', (req, res) => {
  if (!AUTH_ENABLED) {
    const g = getGuestUser();
    return res.json({ id: g.id, name: g.name, avatar: g.avatar, provider: g.provider, xp: g.xp });
  }
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Not logged in' });
  res.json({
    id: req.user.id,
    name: req.user.name,
    avatar: req.user.avatar,
    provider: req.user.provider,
    xp: req.user.xp,
  });
});

// ---------- Sticky notes ----------
app.get('/api/notes', ensureAuth, (req, res) => {
  const notes = db.getNotes(req.user.id).map(n => ({
    id: n.id,
    text: n.text,
    color: { bg: n.color_bg, tape: n.color_tape },
    rotation: n.rotation,
  }));
  res.json({ notes });
});

app.post('/api/notes', ensureAuth, (req, res) => {
  const notes = Array.isArray(req.body?.notes) ? req.body.notes : [];
  if (!notes.length) return res.status(400).json({ error: 'notes[] required' });
  const inserted = db.insertNotes(req.user.id, notes);
  res.json({ notes: inserted });
});

app.delete('/api/notes/:id', ensureAuth, (req, res) => {
  db.deleteNote(req.user.id, req.params.id);
  res.json({ ok: true });
});

// ---------- XP ----------
app.post('/api/xp', ensureAuth, (req, res) => {
  const gain = parseInt(req.body?.gain, 10) || 0;
  const xp = db.addXp(req.user.id, gain);
  res.json({ xp });
});

// ---------- Helpers ----------
function extractJson(text) {
  const cleaned = text.replace(/```json|```/g, '').trim();
  return JSON.parse(cleaned);
}

// ---------- POST /api/solve ----------
app.post('/api/solve', ensureAuth, async (req, res) => {
  try {
    const doubt = (req.body?.doubt || '').toString().trim();
    if (!doubt) return res.status(400).json({ error: 'Doubt khaali nahi ho sakta.' });
    if (!process.env.GROQ_API_KEY) {
      return res.status(500).json({ error: 'Server par GROQ_API_KEY set nahi hai.' });
    }

    const completion = await groq.chat.completions.create({
      model: MODEL,
      temperature: 0.4,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            'You are Samadhan, a patient tutor for students. Given a doubt/question, respond ONLY with a JSON object ' +
            'of this exact shape, no extra text: {"explanation": string, "shortNotes": string[]}. ' +
            'The explanation should walk through the concept step by step in simple language, using numbered steps ' +
            'separated by newlines. shortNotes should be 4-6 very short, revision-friendly bullet points (each under 12 words).',
        },
        { role: 'user', content: doubt },
      ],
    });

    const raw = completion.choices[0]?.message?.content || '{}';
    const data = extractJson(raw);
    if (!data.explanation || !Array.isArray(data.shortNotes)) {
      throw new Error('Model se malformed response mila.');
    }
    res.json(data);
  } catch (err) {
    console.error('solve error:', err);
    res.status(500).json({ error: 'Doubt solve karte waqt error aaya. Dobara try karo.' });
  }
});

// ---------- POST /api/quiz ----------
app.post('/api/quiz', ensureAuth, async (req, res) => {
  try {
    const topic = (req.body?.topic || '').toString().trim();
    const count = Math.min(Math.max(parseInt(req.body?.count, 10) || 5, 1), 10);
    if (!topic) return res.status(400).json({ error: 'Topic khaali nahi ho sakta.' });
    if (!process.env.GROQ_API_KEY) {
      return res.status(500).json({ error: 'Server par GROQ_API_KEY set nahi hai.' });
    }

    const completion = await groq.chat.completions.create({
      model: MODEL,
      temperature: 0.5,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            `You are a quiz generator for students. Given a topic, respond ONLY with a JSON object of this exact ` +
            `shape, no extra text: {"questions": [{"question": string, "options": string[4], "correctIndex": number (0-3), "explanation": string}]}. ` +
            `Generate exactly ${count} multiple-choice questions on the given topic, medium difficulty, options should ` +
            `be plausible and not obviously wrong, and each explanation should briefly justify the correct answer.`,
        },
        { role: 'user', content: topic },
      ],
    });

    const raw = completion.choices[0]?.message?.content || '{}';
    const data = extractJson(raw);
    if (!Array.isArray(data.questions) || !data.questions.length) {
      throw new Error('Model se malformed response mila.');
    }
    data.questions = data.questions
      .filter(q => q && Array.isArray(q.options) && q.options.length === 4)
      .map(q => ({
        question: String(q.question || ''),
        options: q.options.map(String),
        correctIndex: Number.isInteger(q.correctIndex) ? q.correctIndex : 0,
        explanation: String(q.explanation || ''),
      }));

    if (!data.questions.length) throw new Error('Koi valid question nahi bana.');
    res.json(data);
  } catch (err) {
    console.error('quiz error:', err);
    res.status(500).json({ error: 'Quiz banate waqt error aaya. Dobara try karo.' });
  }
});

app.listen(PORT, () => {
  console.log(`\nSamadhan server chal raha hai: http://localhost:${PORT}\n`);
});
