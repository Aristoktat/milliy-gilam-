const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.join(__dirname, 'milliy_gilam.db');
const db = new sqlite3.Database(dbPath);

console.log("Stories jadvalini qo'shish...");

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS stories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        image_url TEXT,
        media_type TEXT DEFAULT 'image',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error("Xato:", err.message);
        else console.log("Muvaffaqiyatli: stories jadvali yaratildi.");
    });
});

db.close();
