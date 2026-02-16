const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.join(__dirname, 'milliy_gilam.db');
const db = new sqlite3.Database(dbPath);

console.log("Tekshiruv boshlandi...");

db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='saved_posts'", (err, row) => {
    if (err) {
        console.error("Xato:", err.message);
    } else if (row) {
        console.log("Jadval mavjud: saved_posts");
    } else {
        console.log("Jadval YO'Q: saved_posts");
    }
});

db.all("PRAGMA table_info(posts)", (err, rows) => {
    if (err) console.error(err);
    else {
        const columns = rows.map(r => r.name);
        console.log("Posts jadvali ustunlari:", columns.join(', '));
    }
});

db.close();
