const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(bodyParser.json());

const db = new sqlite3.Database('hex.db');

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    guessedColors TEXT
  )
`);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
  
    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Insert user into the database
    db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      (err) => {
        if (err) {
          return res.status(500).json({ error: 'Registration failed' });
        }
        res.json({ message: 'Registration successful' });
      }
    );
  });
  
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    // Retrieve user from the database
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Compare the provided password with the hashed password in the database
      const passwordMatch = await bcrypt.compare(password, user.password);
  
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Generate a JWT for authentication
      const token = jwt.sign({ userId: user.id, username: user.username }, 'your-secret-key');
  
      res.json({ token });
    });
  });
  
  function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
  
    if (!token) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
  
    jwt.verify(token, 'your-secret-key', (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      req.user = user;
      next();
    });
  }
  
  app.get('/user', authenticateToken, (req, res) => {
    // Fetch user data based on the authenticated user
    const userId = req.user.userId;
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
      if (err || !user) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json(user);
    });
  });
  
  app.put('/user', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { guessedColors } = req.body;
  
    // Update user's guessedColors in the database
    db.run('UPDATE users SET guessedColors = ? WHERE id = ?', [guessedColors, userId], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to update user data' });
      }
      res.json({ message: 'User data updated successfully' });
    });
  });
  