
const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const DATA_FILE = path.join(__dirname, 'data.json');
const JWT_SECRET = 'twoj-super-sekret'; // zmień na silny sekret!
const TOKEN_EXPIRE = '7d'; // token ważny 7 dni

// Wczytanie danych lub pustej struktury
let db = { users: [], games: [], comments: [] };
try {
  if (fs.existsSync(DATA_FILE)) {
    const jsonData = fs.readFileSync(DATA_FILE);
    db = JSON.parse(jsonData);
  }
} catch (e) {
  console.error('Błąd wczytywania danych:', e);
}

// Zapis danych do pliku (pamięć trwała)
function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}
// Middleware do sprawdzania tokena JWT i aktywności użytkownika
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Brak tokena' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Brak tokena' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Nieprawidłowy token' });

    // Sprawdzamy czy user istnieje i czy nie wygasł po roku
    const dbUser = db.users.find(u => u.id === user.id);
    if (!dbUser) return res.status(404).json({ error: 'Użytkownik nie znaleziony' });

    const yearMs = 365 * 24 * 60 * 60 * 1000;
    const now = Date.now();

    // Usuwanie nieaktywnych kont
    db.users = db.users.filter(u => now - u.lastActive < yearMs);

    // Aktualizacja lastActive dla zalogowanego usera
    dbUser.lastActive = now;

    saveData();

    req.user = dbUser;
    next();
  });
}
// Rejestracja użytkownika
app.post('/register', async (req, res) => {
  const { email, nickname, password } = req.body;
  if (!email || !nickname || !password)
    return res.status(400).json({ error: 'Wszystkie pola są wymagane' });

  if (db.users.find(u => u.email === email))
    return res.status(400).json({ error: 'Użytkownik już istnieje' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now(),
    email,
    nickname,
    password: hashedPassword,
    createdAt: Date.now(),
    lastActive: Date.now(),
    avatar: null
  };

  db.users.push(newUser);
  saveData();

  res.status(201).json({ message: 'Użytkownik zarejestrowany' });
});

// Logowanie użytkownika (zwraca token JWT)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email i hasło są wymagane' });

  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Nieprawidłowe dane' });

  const passMatch = await bcrypt.compare(password, user.password);
  if (!passMatch) return res.status(401).json({ error: 'Nieprawidłowe dane' });

  // Tworzymy token JWT
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: TOKEN_EXPIRE });

  res.json({ token, nickname: user.nickname, avatar: user.avatar });
});

// Proste wylogowanie — klient usuwa token, więc backend nic nie musi robić
// Pobierz listę gier
app.get('/games', (req, res) => {
  res.json(db.games);
});

// Dodaj nową grę (tylko zalogowany)
app.post('/games', authMiddleware, (req, res) => {
  const { title, description } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'Brak tytułu lub opisu' });

  const newGame = {
    id: Date.now(),
    ownerId: req.user.id,
    title,
    description,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  db.games.push(newGame);
  saveData();
  res.status(201).json(newGame);
});

// Aktualizuj grę (tylko właściciel)
app.put('/games/:id', authMiddleware, (req, res) => {
  const game = db.games.find(g => g.id == req.params.id);
  if (!game) return res.status(404).json({ error: 'Gra nie znaleziona' });
  if (game.ownerId !== req.user.id) return res.status(403).json({ error: 'Brak dostępu' });

  const { title, description } = req.body;
  if (title) game.title = title;
  if (description) game.description = description;
  game.updatedAt = Date.now();

  saveData();
  res.json(game);
});

// Dodaj komentarz do gry (zalogowany)
app.post('/games/:id/comments', authMiddleware, (req, res) => {
  const game = db.games.find(g => g.id == req.params.id);
  if (!game) return res.status(404).json({ error: 'Gra nie znaleziona' });

  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Komentarz jest wymagany' });

  const newComment = {
    id: Date.now(),
    gameId: game.id,
    userId: req.user.id,
    text,
    createdAt: Date.now(),
  };
  db.comments.push(newComment);
  saveData();

  res.status(201).json(newComment);
});

// Pobierz komentarze do gry
app.get('/games/:id/comments', (req, res) => {
  const comments = db.comments.filter(c => c.gameId == req.params.id);
  res.json(comments);
});

// Start serwera
app.listen(PORT, () => {
  console.log(`Backend działa na porcie ${PORT}`);
});