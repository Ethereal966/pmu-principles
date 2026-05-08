const express = require('express');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();

const PORT = 3000;
const saltRounds = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); 

const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error("Database connection error:", err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

db.run(`CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    pmu_email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    password TEXT NOT NULL
)`);

app.get('/', (req, res) => {
    res.redirect('/login.html');
});

app.post('/register', async (req, res) => {
    const { fullName, pmuEmail, role, password } = req.body;
    
    if (role === 'student' && !pmuEmail.includes('@pmu.edu.sa')) {
        return res.send('<h2 style="color: red; text-align: center; margin-top: 50px;">Error: Invalid PMU email.</h2>');
    }

    try {
        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert the HASHED password into the database
        const sql = `INSERT INTO users (full_name, pmu_email, role, password) VALUES (?, ?, ?, ?)`;
        db.run(sql, [fullName, pmuEmail, role, hashedPassword], function(err) {
            if (err) {
                return res.send('<h2 style="color: red; text-align: center; margin-top: 50px;">Email is already registered.</h2>');
            }
            res.redirect('/login.html'); // Redirect to login on success
        });
    } catch (error) {
        res.status(500).send("Error hashing password");
    }
});

app.post('/login', (req, res) => {
    const { pmuEmail, password } = req.body;
    
    const sql = `SELECT * FROM users WHERE pmu_email = ?`;
    
    db.get(sql, [pmuEmail], async (err, user) => {
        if (err) {
            return res.send('<h2>Server Error</h2>');
        }
        
        // If user exists, securely compare the entered password with the stored hash
        if (user && await bcrypt.compare(password, user.password)) {
            res.send(`
                <div style="font-family: sans-serif; text-align: center; margin-top: 50px;">
                    <h2 style="color: #3b82f6;">Welcome back, ${user.full_name}!</h2>
                    <p>Logged in as: <strong>${user.role}</strong></p>
                </div>
            `);
        } else {
            res.send('<h2 style="color: red; text-align: center; margin-top: 50px;">Invalid email or password.</h2>');
        }
    });
});

app.listen(PORT, () => {
    console.log(`Bank of Clothes running on http://localhost:${PORT}`);
});