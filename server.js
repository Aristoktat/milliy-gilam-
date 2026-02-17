const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
// const sqlite3 = require('sqlite3').verbose(); // Removed SQLite
const { Pool } = require('pg'); // PostgreSQL client

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

// Database connection (PostgreSQL)
// Use DATABASE_URL from environment variables (Render/Neon) or fallback to local
const isProduction = process.env.NODE_ENV === 'production';
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
    connectionString: connectionString,
    ssl: { rejectUnauthorized: false } // Force SSL for Render Postgres
});

// Helper to run queries (wraps pool.query)
const dbQuery = (text, params) => pool.query(text, params);

// Create tables (PostgreSQL Syntax)
const createTables = async () => {
    try {
        await dbQuery(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            profile_pic TEXT,
            bio TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            image_url TEXT,
            caption TEXT,
            media_type TEXT DEFAULT 'image',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            post_id INTEGER,
            user_id INTEGER,
            text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS likes (
            id SERIAL PRIMARY KEY,
            post_id INTEGER,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(post_id, user_id),
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS follows (
            id SERIAL PRIMARY KEY,
            follower_id INTEGER,
            following_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(follower_id, following_id),
            FOREIGN KEY(follower_id) REFERENCES users(id),
            FOREIGN KEY(following_id) REFERENCES users(id)
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender_id INTEGER,
            receiver_id INTEGER,
            text TEXT,
            image_url TEXT,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS saved_posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            post_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, post_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(post_id) REFERENCES posts(id)
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            actor_id INTEGER,
            type TEXT,
            message TEXT,
            post_id INTEGER,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(actor_id) REFERENCES users(id)
        )`);

        await dbQuery(`CREATE TABLE IF NOT EXISTS stories (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            image_url TEXT,
            media_type TEXT DEFAULT 'image',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
        console.log("PostgreSQL jadvallari yaratildi/tekshirildi.");
    } catch (err) {
        console.error("Jadvallarni yaratishda xato:", err);
    }
};

// Initialize DB
createTables();

// Helper for notifications
const createNotification = async (userId, actorId, type, message, postId = null) => {
    if (userId == actorId) return; // Don't notify self actions
    try {
        await dbQuery(`INSERT INTO notifications(user_id, actor_id, type, message, post_id) VALUES($1, $2, $3, $4, $5)`,
            [userId, actorId, type, message, postId]);
    } catch (err) {
        console.error("Notification Error:", err.message);
    }
};

const JWT_SECRET = 'milliy-gilam-secret-key';
const ADMIN_PASSWORD = 'admin'; // Oddiy parol (o'zgartirishingiz mumkin)


const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer Storage Setup (Switch between Local and Cloudinary based on Env)
let storage;

if (process.env.CLOUDINARY_CLOUD_NAME) {
    // Use Cloudinary Storage
    storage = new CloudinaryStorage({
        cloudinary: cloudinary,
        params: {
            folder: 'milliy_gilam_uploads',
            allowed_formats: ['jpg', 'png', 'jpeg', 'gif', 'mp4', 'mov'],
            resource_type: 'auto'
        }
    });
    console.log("Using Cloudinary Storage for uploads.");
} else {
    // Use Local Disk Storage (Fallback)
    const uploadsDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

    storage = multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadsDir),
        filename: (req, file, cb) => cb(null, `${Date.now()} - ${file.originalname}`)
    });
    console.log("Using Local Disk Storage for uploads (Warning: Files may be deleted on Render restart).");
}

const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
    fileFilter: (req, file, cb) => {
        // Simple check for image/video types
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

// Admin Middleware
const verifyAdmin = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
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

    try {
        const hashedPassword = await bcryptjs.hash(password, 10);
        const result = await dbQuery(
            `INSERT INTO users(username, email, password, profile_pic) VALUES($1, $2, $3, $4) RETURNING id, username, email`,
            [username, email, hashedPassword, `https://ui-avatars.com/api/?name=${username}&background=random`]
        );
        const newUser = result.rows[0];
        const token = jwt.sign({ id: newUser.id, username: newUser.username, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Muvaffaqiyatli ro\'yxatdan o\'tildi', user: newUser, token });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Foydalanuvchi allaqachon mavjud' });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    // Admin Login Check
    if (email === 'admin' && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ id: 0, username: 'Admin', role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ message: 'Admin kirish', token, isAdmin: true });
    }

    try {
        const result = await dbQuery(`SELECT * FROM users WHERE email = $1`, [email]);
        const user = result.rows[0];

        if (!user) return res.status(401).json({ error: 'Email yoki parol xato' });

        const validPassword = await bcryptjs.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Email yoki parol xato' });

        const token = jwt.sign({ id: user.id, username: user.username, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Kirish muvaffaqiyatli', user: { id: user.id, username: user.username, email: user.email, profile_pic: user.profile_pic }, token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT u.id, u.username, u.email, u.profile_pic, u.bio,
            (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count,
            (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
            (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) as following_count
            FROM users u WHERE u.id = $1`,
            [req.user.id]);

        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Users
app.get('/api/users', async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT u.id, u.username, u.email, u.profile_pic,
            (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count
            FROM users u LIMIT 50`);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users/:id', async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT u.id, u.username, u.email, u.profile_pic, u.bio,
            (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count,
            (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followers_count,
            (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) as following_count
            FROM users u WHERE u.id = $1`,
            [req.params.id]);

        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users/:id/posts', async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT p.*, 
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
            (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
            FROM posts p 
            WHERE user_id = $1 
            ORDER BY created_at DESC`,
            [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users/:id/followers', async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT u.id, u.username, u.profile_pic 
            FROM follows f 
            JOIN users u ON f.follower_id = u.id 
            WHERE f.following_id = $1`,
            [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users/:id/following', async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT u.id, u.username, u.profile_pic 
            FROM follows f 
            JOIN users u ON f.following_id = u.id 
            WHERE f.follower_id = $1`,
            [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users/:id/follow', verifyToken, async (req, res) => {
    const targetUserId = req.params.id;
    const currentUserId = req.user.id;

    if (targetUserId == currentUserId) return res.status(400).json({ error: 'O\'zingizga obuna bo\'lolmaysiz' });

    try {
        const check = await dbQuery('SELECT * FROM follows WHERE follower_id = $1 AND following_id = $2', [currentUserId, targetUserId]);
        if (check.rows.length > 0) {
            // Unfollow
            await dbQuery('DELETE FROM follows WHERE follower_id = $1 AND following_id = $2', [currentUserId, targetUserId]);
            res.json({ message: 'Obuna bekor qilindi', following: false });
        } else {
            // Follow
            await dbQuery('INSERT INTO follows (follower_id, following_id) VALUES ($1, $2)', [currentUserId, targetUserId]);
            createNotification(targetUserId, currentUserId, 'follow', 'sizga obuna bo\'ldi');
            res.json({ message: 'Obuna bo\'ldingiz', following: true });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Posts & Feed
// Search
app.get('/api/search', async (req, res) => {
    const q = req.query.q;
    if (!q) return res.json({ users: [], posts: [] });

    const searchQuery = `%${q}%`;
    try {
        const users = await dbQuery("SELECT id, username, profile_pic FROM users WHERE username ILIKE $1 OR bio ILIKE $1 LIMIT 20", [searchQuery]);
        const posts = await dbQuery(`
            SELECT p.*, u.username, u.profile_pic,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
            (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.caption ILIKE $1 OR u.username ILIKE $1
            ORDER BY p.created_at DESC 
            LIMIT 50`, [searchQuery]);

        res.json({ users: users.rows, posts: posts.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/feed', verifyToken, async (req, res) => {
    const query = `
        SELECT p.*, u.username, u.profile_pic,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = $1) as is_liked,
        (SELECT COUNT(*) FROM saved_posts WHERE post_id = p.id AND user_id = $2) as is_saved
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC 
        LIMIT 50
    `;
    try {
        const result = await dbQuery(query, [req.user.id, req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Fayl tanlanmadi' });

    const fileUrl = req.file.path || `/uploads/${req.file.filename}`;
    const mediaType = req.file.mimetype.startsWith('video') ? 'video' : 'image';

    res.json({ message: 'Yuklandi', url: fileUrl, media_type: mediaType });
});

app.post('/api/posts', verifyToken, async (req, res) => {
    const { image_url, caption, media_type } = req.body;
    if (!image_url) return res.status(400).json({ error: 'Media URL kiritilmadi' });

    try {
        const result = await dbQuery(
            `INSERT INTO posts (user_id, image_url, caption, media_type) VALUES ($1, $2, $3, $4) RETURNING *`,
            [req.user.id, image_url, caption || '', media_type || 'image']
        );
        res.json({ message: 'Post yaratildi', post: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Post yaratishda xato: ' + err.message });
    }
});

// Likes & Comments
app.get('/api/posts/:id/comments', async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT c.*, u.username 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.post_id = $1 
            ORDER BY c.created_at DESC`,
            [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/posts/:id/comments', verifyToken, async (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Matn kiritilmadi' });

    try {
        const result = await dbQuery(`INSERT INTO comments (post_id, user_id, text) VALUES ($1, $2, $3) RETURNING id`,
            [req.params.id, req.user.id, text]);

        // Notification
        const postRes = await dbQuery("SELECT user_id FROM posts WHERE id = $1", [req.params.id]);
        if (postRes.rows.length > 0) {
            createNotification(postRes.rows[0].user_id, req.user.id, 'comment', 'postingizga izoh qoldirdi', req.params.id);
        }

        res.json({ message: 'Sharh qo\'shildi', comment: { id: result.rows[0].id, text, user_id: req.user.id } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/posts/:id/like', verifyToken, async (req, res) => {
    const post_id = req.params.id;
    const user_id = req.user.id;

    try {
        const check = await dbQuery(`SELECT * FROM likes WHERE post_id = $1 AND user_id = $2`, [post_id, user_id]);

        if (check.rows.length > 0) {
            // Unlike
            await dbQuery(`DELETE FROM likes WHERE post_id = $1 AND user_id = $2`, [post_id, user_id]);
            res.json({ message: 'Like olib tashlandi', liked: false });
        } else {
            // Like
            await dbQuery(`INSERT INTO likes (post_id, user_id) VALUES ($1, $2)`, [post_id, user_id]);

            const postRes = await dbQuery("SELECT user_id FROM posts WHERE id = $1", [post_id]);
            if (postRes.rows.length > 0) {
                createNotification(postRes.rows[0].user_id, user_id, 'like', 'postingizga like bosdi', post_id);
            }
            res.json({ message: 'Like bosildi', liked: true });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/posts/:id', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(`DELETE FROM posts WHERE id = $1 RETURNING id`, [req.params.id]);
        if (result.rowCount === 0) return res.status(403).json({ error: 'Post topilmadi' });
        res.json({ message: 'Post o\'chirildi' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/posts/:id', verifyToken, async (req, res) => {
    const { caption } = req.body;
    try {
        const result = await dbQuery(`UPDATE posts SET caption = $1 WHERE id = $2 RETURNING id`, [caption, req.params.id]);
        if (result.rowCount === 0) return res.status(403).json({ error: 'Post topilmadi' });
        res.json({ message: 'Post yangilandi' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/users/me', verifyToken, async (req, res) => {
    const { profile_pic, bio } = req.body;
    try {
        await dbQuery(`UPDATE users SET profile_pic = $1, bio = $2 WHERE id = $3`, [profile_pic, bio, req.user.id]);
        res.json({ message: 'Profil yangilandi' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Messages
app.get('/api/conversations', verifyToken, async (req, res) => {
    const query = `
        SELECT DISTINCT u.id, u.username, u.profile_pic
        FROM users u
        JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = $1) OR (m.receiver_id = u.id AND m.sender_id = $2)
    `;
    try {
        const result = await dbQuery(query, [req.user.id, req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/messages/:userId', verifyToken, async (req, res) => {
    const otherId = req.params.userId;
    const query = `
        SELECT m.*, u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = $1 AND m.receiver_id = $2) OR (m.sender_id = $3 AND m.receiver_id = $4)
        ORDER BY m.created_at ASC
    `;
    try {
        const result = await dbQuery(query, [req.user.id, otherId, otherId, req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/messages', verifyToken, upload.single('image'), async (req, res) => {
    const { receiver_id, text } = req.body;
    let image_url = null;

    if (req.file) {
        image_url = req.file.path || `/uploads/${req.file.filename}`;
    }

    if (!receiver_id || (!text && !image_url)) return res.status(400).json({ error: 'Xabar bo\'sh bo\'lolmaydi' });

    try {
        const result = await dbQuery(`INSERT INTO messages (sender_id, receiver_id, text, image_url) VALUES ($1, $2, $3, $4) RETURNING *`,
            [req.user.id, receiver_id, text || '', image_url]);

        createNotification(receiver_id, req.user.id, 'message', 'sizga xabar yubordi');

        res.json({ message: 'Xabar yuborildi', data: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/messages/read/:senderId', verifyToken, async (req, res) => {
    try {
        await dbQuery(`UPDATE messages SET is_read = TRUE WHERE sender_id = $1 AND receiver_id = $2`,
            [req.params.senderId, req.user.id]);
        res.json({ message: 'O\'qildi' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Stories
app.get('/api/stories', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT s.*, u.username, u.profile_pic 
            FROM stories s
            JOIN users u ON s.user_id = u.id
            WHERE s.created_at > NOW() - INTERVAL '24 hours'
            ORDER BY s.created_at DESC`);

        // Group by user (Existing logic preserved)
        const grouped = {};
        result.rows.forEach(row => {
            if (!grouped[row.user_id]) {
                grouped[row.user_id] = {
                    user_id: row.user_id,
                    username: row.username,
                    profile_pic: row.profile_pic,
                    stories: [],
                    has_unseen: true
                };
            }
            grouped[row.user_id].stories.push({
                id: row.id,
                image_url: row.image_url,
                media_type: row.media_type,
                created_at: row.created_at
            });
        });

        const final = Object.values(grouped).map(group => {
            group.stories.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
            return group;
        });
        res.json(final);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/stories', verifyToken, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Fayl tanlanmadi' });

    const image_url = req.file.path || `/uploads/${req.file.filename}`;
    const media_type = req.file.mimetype.startsWith('video') ? 'video' : 'image';

    try {
        const result = await dbQuery(`INSERT INTO stories (user_id, image_url, media_type) VALUES ($1, $2, $3) RETURNING id`,
            [req.user.id, image_url, media_type]);
        res.json({ message: 'Hikoya qo\'shildi', story: { id: result.rows[0].id, image_url, media_type } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Saved Posts
app.post('/api/posts/:id/save', verifyToken, async (req, res) => {
    const post_id = req.params.id;
    const user_id = req.user.id;

    try {
        const check = await dbQuery(`SELECT * FROM saved_posts WHERE post_id = $1 AND user_id = $2`, [post_id, user_id]);
        if (check.rows.length > 0) {
            await dbQuery(`DELETE FROM saved_posts WHERE post_id = $1 AND user_id = $2`, [post_id, user_id]);
            res.json({ message: 'Saqlanganlardan olib tashlandi', saved: false });
        } else {
            await dbQuery(`INSERT INTO saved_posts (post_id, user_id) VALUES ($1, $2)`, [post_id, user_id]);
            res.json({ message: 'Saqlandi', saved: true });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/saved', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT p.*, u.username, u.profile_pic,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
            (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
            FROM saved_posts s
            JOIN posts p ON s.post_id = p.id
            JOIN users u ON p.user_id = u.id
            WHERE s.user_id = $1
            ORDER BY s.created_at DESC`,
            [req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Seed function (optional, run once)
// NOTE: For Postgres migration, seeding is simplified or disabled to avoid duplicates on every restart if not handled carefully.
// You can uncomment and adjust if needed, but for "Permanent" DB, better to seed once manually or via SQL script.

// Notifications
app.get('/api/notifications', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT n.*, u.username, u.profile_pic 
            FROM notifications n 
            JOIN users u ON n.actor_id = u.id 
            WHERE n.user_id = $1 
            ORDER BY n.created_at DESC 
            LIMIT 20`,
            [req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ADMIN API ---
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const users = await dbQuery("SELECT COUNT(*) as count FROM users");
        const posts = await dbQuery("SELECT COUNT(*) as count FROM posts");
        const messages = await dbQuery("SELECT COUNT(*) as count FROM messages");

        res.json({
            users: users.rows[0].count,
            posts: posts.rows[0].count,
            messages: messages.rows[0].count
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const result = await dbQuery("SELECT id, username, email, created_at FROM users ORDER BY created_at DESC");
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => {
    try {
        await dbQuery("DELETE FROM users WHERE id = $1", [req.params.id]);
        // Foreign key cascades should ideally handle related data, or delete manually:
        // await dbQuery("DELETE FROM posts WHERE user_id = $1", [req.params.id]);
        res.json({ message: 'Foydalanuvchi o\'chirildi' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/posts', verifyAdmin, async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT p.*, u.username 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC`);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/posts/:id', verifyAdmin, async (req, res) => {
    try {
        await dbQuery("DELETE FROM posts WHERE id = $1", [req.params.id]);
        res.json({ message: 'Post o\'chirildi' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
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

    });
} else {
    // Lokal kompyuterda (Uyda) ikkalasini ham ishlatamiz
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`Server HTTP (Oddiy) ishga tushdi: http://localhost:${PORT}`);
    });

    try {
        httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
            console.log(`Server HTTPS (Xavfsiz) ishga tushdi: https://localhost:${HTTPS_PORT}`);
        });
    } catch (e) {
        console.log("HTTPS server ishga tushmadi (Muhim emas):", e.message);
    }
}
