require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const QRCode = require('qrcode');

const app = express();
const port = Number(process.env.PORT || 3000);
const root = __dirname;
const uploads = path.join(root, 'uploads');
fs.mkdirSync(uploads, { recursive: true });
const db = new DatabaseSync(path.join(root, 'chennai-bakery.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL, price INTEGER NOT NULL CHECK(price >= 0), description TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', eggless INTEGER NOT NULL DEFAULT 0, ingredients TEXT NOT NULL DEFAULT '', allergens TEXT NOT NULL DEFAULT '', stock INTEGER NOT NULL DEFAULT 0, low_stock_threshold INTEGER NOT NULL DEFAULT 5, active INTEGER NOT NULL DEFAULT 1, featured INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER NOT NULL, action TEXT NOT NULL, affected_item TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(admin_id) REFERENCES users(id));
  CREATE TABLE IF NOT EXISTS custom_cake_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, customer TEXT NOT NULL, occasion TEXT, flavour TEXT, size TEXT, eggless TEXT, theme TEXT, message TEXT, budget TEXT, required_date TEXT, status TEXT NOT NULL DEFAULT 'New', internal_notes TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS website_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
  CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, order_number TEXT UNIQUE NOT NULL, customer_name TEXT NOT NULL, phone TEXT NOT NULL, pin TEXT NOT NULL, area TEXT NOT NULL, address TEXT NOT NULL, delivery_date TEXT NOT NULL, time_slot TEXT NOT NULL, items_json TEXT NOT NULL, subtotal INTEGER NOT NULL, delivery_fee INTEGER NOT NULL, total INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING_PAYMENT', payment_reference TEXT, paid_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`);
try { db.exec("ALTER TABLE orders ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'UPI'"); } catch (error) { if (!error.message.includes('duplicate column name')) throw error; }

const defaultStorySettings = {
  founderNames: 'Ajay & Neha', storyHeading: 'Our Story',
  storySubheading: 'Two People. One Dream. A Bakery Built With Love.',
  storyText: 'Chennai Bakery began with a simple dream shared by Ajay and his wife, Neha — to create a bakery where every product feels homemade, every celebration feels special, and every customer feels like part of the family.\n\nAjay always believed that good food has the power to bring people together. Neha shared the same passion for creating beautiful, delicious food and making people happy through it.\n\nWhat started as an idea between two people slowly became a shared vision: to build a bakery that combines traditional warmth with modern baking.\n\nTogether, Ajay and Neha began developing recipes, experimenting with flavours, learning what customers loved, and paying attention to every little detail — from the ingredients and freshness to presentation and service.\n\nFor them, Chennai Bakery is not simply about selling cakes, breads and pastries. It is about birthdays celebrated with a special cake. It is about families sharing a box of pastries. It is about a warm loaf of bread brought home after a long day. It is about the small moments that become beautiful memories.\n\nEvery product carries a little piece of their journey. Every order is prepared with care. And every customer who walks through the doors becomes part of the Chennai Bakery story.',
  founderImage: 'https://images.unsplash.com/photo-1509440159596-0249088772ff?auto=format&fit=crop&w=1000&q=85',
  closingQuote: 'From our family to yours — thank you for being part of our journey.', showStory: '1'
};
const saveSetting = db.prepare('INSERT INTO website_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO NOTHING');
Object.entries(defaultStorySettings).forEach(([key, value]) => saveSetting.run(key, value));
db.prepare('UPDATE website_settings SET value=? WHERE key=? AND value LIKE ?').run(defaultStorySettings.founderImage, 'founderImage', '%1556910103%');

const adminEmail = process.env.ADMIN_EMAIL;
const adminPassword = process.env.ADMIN_PASSWORD;
const upiVpa = process.env.UPI_VPA || 'chennaibakery@upi';
const upiPayeeName = process.env.UPI_PAYEE_NAME || 'Chennai Bakery';
if (!adminEmail || !adminPassword) console.warn('Set ADMIN_EMAIL and ADMIN_PASSWORD in .env before starting the server.');
else {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
  const passwordHash = bcrypt.hashSync(adminPassword, 12);
  if (!existing) db.prepare('INSERT INTO users (email,password_hash,name,role) VALUES (?,?,?,?)').run(adminEmail, passwordHash, process.env.ADMIN_NAME || 'Bakery Admin', 'admin');
  else db.prepare('UPDATE users SET password_hash=?, name=?, role=\'admin\' WHERE id=?').run(passwordHash, process.env.ADMIN_NAME || 'Bakery Admin', existing.id);
}

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({ secret: process.env.SESSION_SECRET || 'change-this-session-secret', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 } }));
app.use('/uploads', express.static(uploads));
app.use(express.static(root, { index: 'index.html', extensions: ['html'] }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
function requireAdmin(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'Authentication required' }); if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Access Denied' }); next(); }
function audit(req, action, item) { db.prepare('INSERT INTO audit_log (admin_id,action,affected_item) VALUES (?,?,?)').run(req.session.user.id, action, item); }

app.get('/admin/login', (req, res) => res.sendFile(path.join(root, 'admin.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(root, 'admin.html')));
app.get('/admin/:section', (req, res) => res.sendFile(path.join(root, 'admin.html')));
app.get('/api/products', (req, res) => res.json(db.prepare('SELECT * FROM products WHERE active = 1 ORDER BY featured DESC, id DESC').all()));
app.get('/api/website/story', (req, res) => { const rows = db.prepare('SELECT key,value FROM website_settings').all(); const story = { ...defaultStorySettings }; rows.forEach(row => { story[row.key] = row.value; }); res.json(story); });
app.post('/api/orders', async (req, res) => {
  const { customer, items, delivery, paymentMethod = 'UPI' } = req.body || {};
  if (!customer || !delivery || !Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Customer, delivery details and cart items are required' });
  const cleanItems = items.map(item => ({ name: String(item.name || '').trim(), price: Number(item.price), quantity: Number(item.quantity), detail: String(item.detail || '') })).filter(item => item.name && Number.isInteger(item.price) && item.price >= 0 && Number.isInteger(item.quantity) && item.quantity > 0 && item.quantity <= 10);
  if (cleanItems.length !== items.length) return res.status(400).json({ error: 'Invalid cart items' });
  const subtotal = cleanItems.reduce((sum, item) => sum + item.price * item.quantity, 0);
  const deliveryFee = 49;
  const total = subtotal + deliveryFee;
  if (!['UPI', 'COD'].includes(paymentMethod)) return res.status(400).json({ error: 'Choose UPI or cash on delivery' });
  if (!customer.name || !/^\d{10}$/.test(String(customer.phone || '')) || !/^6\d{5}$/.test(String(delivery.pin || '')) || !delivery.area || !delivery.address || !delivery.date || !delivery.slot) return res.status(400).json({ error: 'Please provide valid Chennai delivery details' });
  const orderNumber = `CB-${Date.now().toString().slice(-8)}`;
  const status = paymentMethod === 'COD' ? 'COD_PENDING' : 'PENDING_PAYMENT';
  const result = db.prepare('INSERT INTO orders (order_number,customer_name,phone,pin,area,address,delivery_date,time_slot,items_json,subtotal,delivery_fee,total,status,payment_method) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(orderNumber, customer.name.trim(), customer.phone, delivery.pin, delivery.area.trim(), delivery.address.trim(), delivery.date, delivery.slot, JSON.stringify(cleanItems), subtotal, deliveryFee, total, status, paymentMethod);
  if (paymentMethod === 'COD') return res.status(201).json({ orderId: Number(result.lastInsertRowid), orderNumber, subtotal, deliveryFee, total, status, paymentMethod, deliveryDate: delivery.date, timeSlot: delivery.slot });
  const upiUri = `upi://pay?pa=${encodeURIComponent(upiVpa)}&pn=${encodeURIComponent(upiPayeeName)}&am=${total.toFixed(2)}&cu=INR&tn=${encodeURIComponent(`Order ${orderNumber}`)}`;
  const qr = await QRCode.toDataURL(upiUri, { width: 280, margin: 1 });
  res.status(201).json({ orderId: Number(result.lastInsertRowid), orderNumber, subtotal, deliveryFee, total, status, paymentMethod, deliveryDate: delivery.date, timeSlot: delivery.slot, upiVpa, qr, expiresInMinutes: 15 });
});
app.post('/api/orders/:id/verify-payment', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id=?').get(Number(req.params.id));
  const reference = String(req.body?.reference || '').trim();
  const paidAmount = Number(req.body?.amount);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (order.payment_method !== 'UPI') return res.status(400).json({ error: 'This order is configured for cash on delivery' });
  if (order.status === 'PAID') return res.json({ ok: true, orderNumber: order.order_number, status: order.status, total: order.total });
  if (!reference || !Number.isFinite(paidAmount) || paidAmount !== order.total) return res.status(400).json({ error: `Payment verification requires the exact amount of ₹${order.total.toLocaleString('en-IN')} and a UPI reference` });
  db.prepare('UPDATE orders SET status=\'PAID\',payment_reference=?,paid_at=CURRENT_TIMESTAMP WHERE id=? AND status=\'PENDING_PAYMENT\'').run(reference, order.id);
  res.json({ ok: true, orderNumber: order.order_number, status: 'PAID', total: order.total });
});
app.post('/api/auth/login', loginLimiter, (req, res) => { const { email, password } = req.body; const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase()); if (!user || !bcrypt.compareSync(String(password || ''), user.password_hash)) return res.status(401).json({ error: 'Invalid admin credentials' }); if (user.role !== 'admin') return res.status(403).json({ error: 'Access Denied' }); req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role }; res.json({ user: req.session.user }); });
app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/auth/me', (req, res) => { if (!req.session.user) return res.status(401).json({ error: 'Unauthenticated' }); res.json({ user: req.session.user }); });

app.get('/api/admin/dashboard', requireAdmin, (req, res) => { const stats = { totalProducts: db.prepare('SELECT COUNT(*) count FROM products').get().count, activeProducts: db.prepare('SELECT COUNT(*) count FROM products WHERE active=1').get().count, outOfStock: db.prepare('SELECT COUNT(*) count FROM products WHERE stock=0').get().count, lowStock: db.prepare('SELECT COUNT(*) count FROM products WHERE stock>0 AND stock<=low_stock_threshold').get().count, customCakeRequests: db.prepare('SELECT COUNT(*) count FROM custom_cake_requests WHERE status NOT IN (\'Completed\',\'Cancelled\')').get().count, orders: db.prepare('SELECT COUNT(*) count FROM orders').get().count, paidOrders: db.prepare('SELECT COUNT(*) count FROM orders WHERE status=\'PAID\'').get().count }; res.json({ stats, recentOrders: db.prepare('SELECT order_number,customer_name,total,status,created_at FROM orders ORDER BY id DESC LIMIT 5').all(), recentRequests: db.prepare('SELECT * FROM custom_cake_requests ORDER BY id DESC LIMIT 5').all(), audit: db.prepare('SELECT audit_log.*, users.email FROM audit_log JOIN users ON users.id=audit_log.admin_id ORDER BY audit_log.id DESC LIMIT 8').all() }); });
app.get('/api/admin/orders', requireAdmin, (req, res) => res.json(db.prepare('SELECT id,order_number,customer_name,phone,area,total,status,payment_reference,created_at FROM orders ORDER BY id DESC').all()));
app.get('/api/admin/products', requireAdmin, (req, res) => res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.post('/api/admin/products', requireAdmin, (req, res) => { const p=req.body; if (!p.name || !p.category || !p.description || !Number.isFinite(Number(p.price))) return res.status(400).json({ error: 'Name, category, description and price are required' }); const result=db.prepare('INSERT INTO products (name,category,price,description,image,eggless,ingredients,allergens,stock,low_stock_threshold,active,featured) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').run(p.name,p.category,Number(p.price),p.description,p.image||'',p.eggless?1:0,p.ingredients||'',p.allergens||'',Number(p.stock||0),Number(p.low_stock_threshold||5),p.active===false?0:1,p.featured?1:0); audit(req,'Created product',p.name); res.status(201).json(db.prepare('SELECT * FROM products WHERE id=?').get(result.lastInsertRowid)); });
app.put('/api/admin/products/:id', requireAdmin, (req, res) => { const p=req.body; const id=Number(req.params.id); if (!p.name || !p.category || !p.description || !Number.isFinite(Number(p.price))) return res.status(400).json({ error: 'Name, category, description and price are required' }); const result=db.prepare('UPDATE products SET name=?,category=?,price=?,description=?,image=?,eggless=?,ingredients=?,allergens=?,stock=?,low_stock_threshold=?,active=?,featured=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(p.name,p.category,Number(p.price),p.description,p.image||'',p.eggless?1:0,p.ingredients||'',p.allergens||'',Number(p.stock||0),Number(p.low_stock_threshold||5),p.active?1:0,p.featured?1:0,id); if (!result.changes) return res.status(404).json({ error: 'Product not found' }); audit(req,'Updated product',p.name); res.json(db.prepare('SELECT * FROM products WHERE id=?').get(id)); });
app.delete('/api/admin/products/:id', requireAdmin, (req, res) => { const item=db.prepare('SELECT name FROM products WHERE id=?').get(Number(req.params.id)); if (!item) return res.status(404).json({ error: 'Product not found' }); db.prepare('UPDATE products SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(Number(req.params.id)); audit(req,'Archived product',item.name); res.json({ ok:true }); });
const upload = multer({ storage: multer.diskStorage({ destination: uploads, filename: (req,file,cb) => cb(null, `${Date.now()}-${file.originalname.replace(/[^a-z0-9.-]/gi,'-')}`) }), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req,file,cb) => cb(null, /image\/(jpeg|png|webp)/.test(file.mimetype)) });
app.post('/api/admin/uploads', requireAdmin, upload.single('image'), (req,res) => { if (!req.file) return res.status(400).json({ error:'Only JPG, PNG and WEBP images up to 5MB are accepted' }); res.json({ url:`/uploads/${req.file.filename}` }); });
app.get('/api/admin/audit', requireAdmin, (req,res) => res.json(db.prepare('SELECT audit_log.*,users.email FROM audit_log JOIN users ON users.id=audit_log.admin_id ORDER BY audit_log.id DESC').all()));
app.get('/api/admin/content/story', requireAdmin, (req, res) => { const rows = db.prepare('SELECT key,value FROM website_settings').all(); const settings = { ...defaultStorySettings }; rows.forEach(row => { settings[row.key] = row.value; }); res.json(settings); });
app.put('/api/admin/content/story', requireAdmin, (req, res) => { const allowed = ['founderNames','storyHeading','storySubheading','storyText','founderImage','closingQuote','showStory']; const update = db.transaction(() => allowed.forEach(key => { if (req.body[key] !== undefined) db.prepare('INSERT INTO website_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, String(req.body[key])); })); update(); audit(req, 'Updated story content', 'Our Story'); res.json({ ok: true }); });
app.delete('/api/admin/content/story/image', requireAdmin, (req, res) => { db.prepare('UPDATE website_settings SET value=? WHERE key=?').run(defaultStorySettings.founderImage, 'founderImage'); audit(req, 'Removed founder image', 'Our Story'); res.json({ ok: true, image: defaultStorySettings.founderImage }); });
app.listen(port, () => console.log(`Chennai Bakery running at http://localhost:${port}`));
