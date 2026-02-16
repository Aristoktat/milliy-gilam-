const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const http = require('http');
const https = require('https');
const selfsigned = require('selfsigned');
const { Server } = require('socket.io');

// Generate Self-Signed Certs for Local HTTPS (Needed for Camera access on mobile)
const attrs = [{ name: 'commonName', value: 'localhost' }];
const pems = selfsigned.generate(attrs, { days: 365 });

const server = http.createServer(app);
const httpsServer = https.createServer({ key: pems.private, cert: pems.cert }, app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
io.attach(httpsServer); // Attach socket to HTTPS too

app.use(cors());
app.use(express.json());

// Serve HTML files
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/profile.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/chat.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'chat.html')));
// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database connection (SQLite)
const dbPath = path.join(__dirname, 'milliy_gilam.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error("Baza ochishda xato:", err.message);
    else console.log("SQLite bazaga ulandi.");
});

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        profile_pic TEXT,
        bio TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        image_url TEXT,
        caption TEXT,
        media_type TEXT DEFAULT 'image',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        text TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(post_id, user_id),
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER,
        following_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(follower_id, following_id),
        FOREIGN KEY(follower_id) REFERENCES users(id),
        FOREIGN KEY(following_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        text TEXT,
        image_url TEXT,
        is_read BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS saved_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        post_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        actor_id INTEGER,
        type TEXT,
        message TEXT,
        post_id INTEGER,
        is_read BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(actor_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS stories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        image_url TEXT,
        media_type TEXT DEFAULT 'image',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

// Helper for notifications
const createNotification = (userId, actorId, type, message, postId = null) => {
    if (userId == actorId) return; // Don't notify self actions
    db.run(`INSERT INTO notifications(user_id, actor_id, type, message, post_id) VALUES(?, ?, ?, ?, ?)`,
        [userId, actorId, type, message, postId],
        (err) => {
            if (err) console.error("Notification Error:", err.message);
        }
    );
};

const JWT_SECRET = 'milliy-gilam-secret-key';

// Multer setup
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, `${Date.now()} - ${file.originalname}`)
});

const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Faqat rasm yoki video yuklash mumkin!'));
        }
    }
});

// Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// --- ROUTES ---

// Auth
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Ma\'lumotlar yetarli emas' });

    const hashedPassword = await bcryptjs.hash(password, 10);

    db.run(`INSERT INTO users(username, email, password, profile_pic) VALUES(?, ?, ?, ?)`,
        [username, email, hashedPassword, `https://ui-avatars.com/api/?name=${username}&background=random`],
        function (err) {
            if (err) return res.status(400).json({ error: 'Foydalanuvchi allaqachon mavjud' });

            const token = jwt.sign({ id: this.lastID, username, email }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ message: 'Muvaffaqiyatli ro\'yxatdan o\'tildi', user: { id: this.lastID, username, email }, token });
        });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Email yoki parol xato' });

        const validPassword = await bcryptjs.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Email yoki parol xato' });

        const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Kirish muvaffaqiyatli', user: { id: user.id, username: user.username, email: user.email, profile_pic: user.profile_pic }, token });
    });
});

app.get('/api/auth/me', verifyToken, (req, res) => {
    db.get(`
        SELECT u.id, u.username, u.email, u.profile_pic, u.bio,
        (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count,
        (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
        (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) as following_count
        FROM users u WHERE u.id = ?`,
        [req.user.id], (err, row) => {
            if (err || !row) return res.status(404).json({ error: 'User not found' });
            res.json(row);
        });
});

// Users
app.get('/api/users', (req, res) => {
    db.all(`
        SELECT u.id, u.username, u.email, u.profile_pic,
        (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count
        FROM users u LIMIT 50`,
        [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

app.get('/api/users/:id', (req, res) => {
    db.get(`
        SELECT u.id, u.username, u.email, u.profile_pic, u.bio,
        (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count,
        (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
        (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) as following_count
        FROM users u WHERE u.id = ?`,
        [req.params.id], (err, row) => {
            if (err || !row) return res.status(404).json({ error: 'User not found' });
            res.json(row);
        });
});

app.get('/api/users/:id/posts', (req, res) => {
    db.all(`
        SELECT p.*, 
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
        FROM posts p 
        WHERE user_id = ? 
        ORDER BY created_at DESC`,
        [req.params.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

app.get('/api/users/:id/followers', (req, res) => {
    db.all(`
        SELECT u.id, u.username, u.profile_pic 
        FROM follows f 
        JOIN users u ON f.follower_id = u.id 
        WHERE f.following_id = ?`,
        [req.params.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

app.get('/api/users/:id/following', (req, res) => {
    db.all(`
        SELECT u.id, u.username, u.profile_pic 
        FROM follows f 
        JOIN users u ON f.following_id = u.id 
        WHERE f.follower_id = ?`,
        [req.params.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

app.post('/api/users/:id/follow', verifyToken, (req, res) => {
    const targetUserId = req.params.id;
    const currentUserId = req.user.id;

    if (targetUserId == currentUserId) return res.status(400).json({ error: 'O\'zingizga obuna bo\'lolmaysiz' });

    db.get('SELECT * FROM follows WHERE follower_id = ? AND following_id = ?', [currentUserId, targetUserId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });

        if (row) {
            // Unfollow
            db.run('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [currentUserId, targetUserId], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'Obuna bekor qilindi', following: false });
            });
        } else {
            // Follow
            db.run('INSERT INTO follows (follower_id, following_id) VALUES (?, ?)', [currentUserId, targetUserId], (err) => {
                if (err) return res.status(500).json({ error: err.message });

                // Notification
                createNotification(targetUserId, currentUserId, 'follow', 'sizga obuna bo\'ldi');

                res.json({ message: 'Obuna bo\'ldingiz', following: true });
            });
        }
    });
});

// Posts & Feed
// Search
app.get('/api/search', (req, res) => {
    const q = req.query.q;
    if (!q) return res.json({ users: [], posts: [] });

    const searchQuery = `%${q}%`;

    const usersPromise = new Promise((resolve, reject) => {
        db.all("SELECT id, username, profile_pic FROM users WHERE username LIKE ? OR bio LIKE ? LIMIT 20",
            [searchQuery, searchQuery], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
    });

    const postsPromise = new Promise((resolve, reject) => {
        db.all(`
            SELECT p.*, u.username, u.profile_pic,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
            (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.caption LIKE ? OR u.username LIKE ?
            ORDER BY p.created_at DESC 
            LIMIT 50
        `, [searchQuery, searchQuery], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });

    Promise.all([usersPromise, postsPromise])
        .then(([users, posts]) => {
            res.json({ users, posts });
        })
        .catch(err => {
            res.status(500).json({ error: err.message });
        });
});

app.get('/api/feed', verifyToken, (req, res) => {
    const query = `
        SELECT p.*, u.username, u.profile_pic,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = ?) as is_liked,
        (SELECT COUNT(*) FROM saved_posts WHERE post_id = p.id AND user_id = ?) as is_saved
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC 
        LIMIT 50
    `;
    db.all(query, [req.user.id, req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Fayl tanlanmadi' });

    const fileUrl = `/uploads/${req.file.filename}`;
    const mediaType = req.file.mimetype.startsWith('video') ? 'video' : 'image';

    res.json({ message: 'Yuklandi', url: fileUrl, media_type: mediaType });
});

app.post('/api/posts', verifyToken, (req, res) => {
    const { image_url, caption, media_type } = req.body;
    if (!image_url) return res.status(400).json({ error: 'Media URL kiritilmadi' });

    db.run(
        `INSERT INTO posts (user_id, image_url, caption, media_type) VALUES (?, ?, ?, ?)`,
        [req.user.id, image_url, caption || '', media_type || 'image'],
        function (err) {
            if (err) return res.status(500).json({ error: 'Post yaratishda xato: ' + err.message });

            // Return created post structure manually or fetch it
            const newPost = {
                id: this.lastID,
                user_id: req.user.id,
                image_url,
                caption,
                media_type: media_type || 'image',
                created_at: new Date()
            };
            res.json({ message: 'Post yaratildi', post: newPost });
        }
    );
});

// Likes & Comments
app.get('/api/posts/:id/comments', (req, res) => {
    db.all(`
        SELECT c.*, u.username 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.post_id = ? 
        ORDER BY c.created_at DESC`,
        [req.params.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

app.post('/api/posts/:id/comments', verifyToken, (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Matn kiritilmadi' });

    db.run(`INSERT INTO comments (post_id, user_id, text) VALUES (?, ?, ?)`,
        [req.params.id, req.user.id, text],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });

            // Notification: We need post owner's ID.
            db.get("SELECT user_id FROM posts WHERE id = ?", [req.params.id], (err, post) => {
                if (post) createNotification(post.user_id, req.user.id, 'comment', 'postingizga izoh qoldirdi', req.params.id);
            });

            res.json({ message: 'Sharh qo\'shildi', comment: { id: this.lastID, text, user_id: req.user.id } });
        });
});

app.post('/api/posts/:id/like', verifyToken, (req, res) => {
    const post_id = req.params.id;
    const user_id = req.user.id;

    db.get(`SELECT * FROM likes WHERE post_id = ? AND user_id = ?`, [post_id, user_id], (err, row) => {
        if (row) {
            // Unlike
            db.run(`DELETE FROM likes WHERE post_id = ? AND user_id = ?`, [post_id, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'Like olib tashlandi', liked: false });
            });
        } else {
            // Like
            db.run(`INSERT INTO likes (post_id, user_id) VALUES (?, ?)`, [post_id, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });

                // Notification
                db.get("SELECT user_id FROM posts WHERE id = ?", [post_id], (err, post) => {
                    if (post) createNotification(post.user_id, user_id, 'like', 'postingizga like bosdi', post_id);
                });

                res.json({ message: 'Like bosildi', liked: true });
            });
        }
    });
});

app.delete('/api/posts/:id', verifyToken, (req, res) => {
    // TEMPORARY: Removed user_id check to allow editing seeded posts
    console.log(`[DELETE] Request for post ID: ${req.params.id}`);
    db.run(`DELETE FROM posts WHERE id = ?`, [req.params.id], function (err) {
        if (err) {
            console.error(`[DELETE] Error: ${err.message}`);
            return res.status(500).json({ error: err.message });
        }
        console.log(`[DELETE] Rows affected: ${this.changes}`);
        if (this.changes === 0) return res.status(403).json({ error: 'Post topilmadi (ID: ' + req.params.id + ')' });
        res.json({ message: 'Post o\'chirildi' });
    });
});

app.put('/api/posts/:id', verifyToken, (req, res) => {
    const { caption } = req.body;
    // TEMPORARY: Removed user_id check to allow editing seeded posts
    console.log(`[PUT] Request for post ID: ${req.params.id}, Caption: ${caption}`);
    db.run(`UPDATE posts SET caption = ? WHERE id = ?`, [caption, req.params.id], function (err) {
        if (err) {
            console.error(`[PUT] Error: ${err.message}`);
            return res.status(500).json({ error: err.message });
        }
        console.log(`[PUT] Rows affected: ${this.changes}`);
        if (this.changes === 0) return res.status(403).json({ error: 'Post topilmadi (ID: ' + req.params.id + ')' });
        res.json({ message: 'Post yangilandi' });
    });
});

app.put('/api/users/me', verifyToken, (req, res) => {
    const { profile_pic, bio } = req.body;
    db.run(`UPDATE users SET profile_pic = ?, bio = ? WHERE id = ?`, [profile_pic, bio, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Profil yangilandi' });
    });
});



// Messages
app.get('/api/conversations', verifyToken, (req, res) => {
    // Get list of unique users the current user has exchanged messages with
    const query = `
        SELECT DISTINCT u.id, u.username, u.profile_pic
        FROM users u
        JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = ?) OR (m.receiver_id = u.id AND m.sender_id = ?)
    `;
    db.all(query, [req.user.id, req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/messages/:userId', verifyToken, (req, res) => {
    const otherId = req.params.userId;
    const query = `
        SELECT m.*, u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC
    `;
    db.all(query, [req.user.id, otherId, otherId, req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/messages', verifyToken, upload.single('image'), (req, res) => {
    const { receiver_id, text } = req.body;
    let image_url = null;

    if (req.file) {
        image_url = `/uploads/${req.file.filename}`;
    }

    if (!receiver_id || (!text && !image_url)) return res.status(400).json({ error: 'Xabar bo\'sh bo\'lolmaydi' });

    db.run(`INSERT INTO messages (sender_id, receiver_id, text, image_url) VALUES (?, ?, ?, ?)`,
        [req.user.id, receiver_id, text || '', image_url],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });

            // Notification for new message
            createNotification(receiver_id, req.user.id, 'message', 'sizga xabar yubordi');

            res.json({ message: 'Xabar yuborildi', data: { id: this.lastID, sender_id: req.user.id, receiver_id, text, image_url, created_at: new Date() } });
        });
});

app.post('/api/messages/read/:senderId', verifyToken, (req, res) => {
    db.run(`UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?`,
        [req.params.senderId, req.user.id],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'O\'qildi' });
        });
});


// Stories
app.get('/api/stories', verifyToken, (req, res) => {
    // Get active stories (last 24 hours)
    db.all(`
        SELECT s.*, u.username, u.profile_pic 
        FROM stories s
        JOIN users u ON s.user_id = u.id
        WHERE s.created_at > datetime('now', '-24 hours')
        ORDER BY s.created_at DESC`,
        [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });

            // Group by user
            const grouped = {};
            rows.forEach(row => {
                if (!grouped[row.user_id]) {
                    grouped[row.user_id] = {
                        user_id: row.user_id,
                        username: row.username,
                        profile_pic: row.profile_pic,
                        stories: [],
                        has_unseen: true // Simplified logic
                    };
                }
                grouped[row.user_id].stories.push({
                    id: row.id,
                    image_url: row.image_url,
                    media_type: row.media_type,
                    created_at: row.created_at
                });
            });

            // Convert to array and reverse stories for chronological playback (Oldest -> Newest)
            const result = Object.values(grouped).map(group => {
                group.stories.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
                return group;
            });

            res.json(result);
        });
});

app.post('/api/stories', verifyToken, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Fayl tanlanmadi' });

    const image_url = `/uploads/${req.file.filename}`;
    const media_type = req.file.mimetype.startsWith('video') ? 'video' : 'image';

    db.run(`INSERT INTO stories (user_id, image_url, media_type) VALUES (?, ?, ?)`,
        [req.user.id, image_url, media_type],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Hikoya qo\'shildi', story: { id: this.lastID, image_url, media_type } });
        });
});

// Saved Posts
app.post('/api/posts/:id/save', verifyToken, (req, res) => {
    const post_id = req.params.id;
    const user_id = req.user.id;

    db.get(`SELECT * FROM saved_posts WHERE post_id = ? AND user_id = ?`, [post_id, user_id], (err, row) => {
        if (row) {
            // Unsave
            db.run(`DELETE FROM saved_posts WHERE post_id = ? AND user_id = ?`, [post_id, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'Saqlanganlardan olib tashlandi', saved: false });
            });
        } else {
            // Save
            db.run(`INSERT INTO saved_posts (post_id, user_id) VALUES (?, ?)`, [post_id, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'Saqlandi', saved: true });
            });
        }
    });
});

app.get('/api/saved', verifyToken, (req, res) => {
    db.all(`
        SELECT p.*, u.username, u.profile_pic,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
        FROM saved_posts s
        JOIN posts p ON s.post_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE s.user_id = ?
        ORDER BY s.created_at DESC`,
        [req.user.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

// Seed function (optional, run once)
const seed = async () => {
    // Check if users exist
    db.get("SELECT count(*) as count FROM users", [], async (err, row) => {
        if (row && row.count === 0) {
            console.log("Bazaga boshlang'ich ma'lumotlar qo'shilmoqda...");
            const hash = await bcryptjs.hash('123', 10);

            db.serialize(() => {
                db.run(`INSERT INTO users (username, email, password, profile_pic, bio) VALUES (?,?,?,?,?)`, ['AnvarXO', 'anvar@example.com', hash, 'https://ui-avatars.com/api/?name=Anvar&background=0D8ABC&color=fff', 'Milliy taomlar shaydosiman 🍲']);
                db.run(`INSERT INTO users (username, email, password, profile_pic, bio) VALUES (?,?,?,?,?)`, ['Malika_Art', 'malika@example.com', hash, 'https://ui-avatars.com/api/?name=Malika&background=EE82EE&color=fff', 'San\'at va sayohat 🎨✈️']);

                db.run(`INSERT INTO posts (user_id, image_url, caption, media_type) VALUES (?, ?, ?, ?)`, [1, 'https://images.unsplash.com/photo-1546069901-ba9599a7e63c', "Bugungi palovimiz juda o'xshabdi! Kelnglar mehmon bo'ling. #osh #palov #uzbekistan", 'image']);
                db.run(`INSERT INTO posts (user_id, image_url, caption, media_type) VALUES (?, ?, ?, ?)`, [2, 'https://images.unsplash.com/photo-1526772662003-753c2c2f6d0a', "Samarqandning moviy gumbazlari... Har safar ko'rganimda hayratlanaman.", 'image']);

                // Mock Chat Messages
                db.run(`INSERT INTO messages (sender_id, receiver_id, text) VALUES (?, ?, ?)`, [2, 1, "Assalomu alaykum! Palov zo'r chiqibdi, retseptini berasizmi? 😍"]);
                db.run(`INSERT INTO messages (sender_id, receiver_id, text) VALUES (?, ?, ?)`, [1, 2, "Va alaykum assalom! Albatta, hozir tashlab beraman."]);
            });
        }
    });
};
seed();

// Notifications
app.get('/api/notifications', verifyToken, (req, res) => {
    db.all(`
        SELECT n.*, u.username, u.profile_pic 
        FROM notifications n 
        JOIN users u ON n.actor_id = u.id 
        WHERE n.user_id = ? 
        ORDER BY n.created_at DESC 
        LIMIT 20`,
        [req.user.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

// --- Socket.io Logic for Video Call ---
const onlineUsers = new Map(); // userId -> socketId

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // Register user
    socket.on('register-user', (userId) => {
        onlineUsers.set(userId, socket.id);
        console.log(`User registered: ${userId} -> ${socket.id}`);
        // Notify others? Not needed for now
    });

    // Call User
    socket.on('call-user', (data) => {
        const { targetUserId, signalData, callerId, callerName, callerPic } = data;
        const targetSocketId = onlineUsers.get(Number(targetUserId)) || onlineUsers.get(String(targetUserId));

        if (targetSocketId) {
            io.to(targetSocketId).emit('incoming-call', {
                signal: signalData,
                from: callerId,
                name: callerName,
                pic: callerPic
            });
        } else {
            console.log(`User ${targetUserId} is offline`);
            // Optionally notify caller user is offline
        }
    });

    // Answer Call
    socket.on('answer-call', (data) => {
        const { targetUserId, signalData } = data; // targetUserId is the original caller
        const targetSocketId = onlineUsers.get(Number(targetUserId)) || onlineUsers.get(String(targetUserId));

        if (targetSocketId) {
            io.to(targetSocketId).emit('call-accepted', signalData);
        }
    });

    // ICE Candidate
    socket.on('ice-candidate', (data) => {
        const { targetUserId, candidate } = data;
        const targetSocketId = onlineUsers.get(Number(targetUserId)) || onlineUsers.get(String(targetUserId));

        if (targetSocketId) {
            io.to(targetSocketId).emit('ice-candidate', candidate);
        }
    });

    // End Call / Reject
    socket.on('end-call', (data) => {
        const { targetUserId } = data;
        const targetSocketId = onlineUsers.get(Number(targetUserId)) || onlineUsers.get(String(targetUserId));

        if (targetSocketId) {
            io.to(targetSocketId).emit('call-ended');
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        // Remove from onlineUsers
        for (const [uid, sid] of onlineUsers.entries()) {
            if (sid === socket.id) {
                onlineUsers.delete(uid);
                break;
            }
        }
    });
});

const PORT = process.env.PORT || 4001;
const HTTPS_PORT = 4002;

// Agar hostingda bo'lsa (PORT defined), faqat asosiy serverni ishlatamiz (SSLni Hosting o'zi qiladi)
if (process.env.PORT) {
    server.listen(PORT, () => {
        console.log(`Server Hostingda ishga tushdi (Port/Pipe: ${PORT})`);
        console.log(`Baza fayli: ${dbPath}`);
    });
} else {
    // Lokal kompyuterda (Uyda) ikkalasini ham ishlatamiz
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`Server HTTP (Oddiy) ishga tushdi: http://localhost:${PORT}`);
        console.log(`Baza fayli: ${dbPath}`);
    });

    try {
        httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
            console.log(`Server HTTPS (Xavfsiz) ishga tushdi: https://localhost:${HTTPS_PORT}`);
        });
    } catch (e) {
        console.log("HTTPS server ishga tushmadi (Muhim emas):", e.message);
    }
}
