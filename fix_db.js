const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.join(__dirname, 'milliy_gilam.db');
const db = new sqlite3.Database(dbPath);

console.log("Bazani yangilash boshlandi...");

db.serialize(() => {
    db.run("ALTER TABLE messages ADD COLUMN image_url TEXT", (err) => {
        if (err) console.log("Info: " + err.message);
        else console.log("Muvaffaqiyatli: image_url ustuni qo'shildi.");
    });

    db.run("ALTER TABLE messages ADD COLUMN is_read BOOLEAN DEFAULT 0", (err) => {
        if (err) console.log("Info: " + err.message);
        else console.log("Muvaffaqiyatli: is_read ustuni qo'shildi.");
    });
});

db.close(() => {
    console.log("Baza yangilandi.");
});
