require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: false });
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenants (
      id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL,
      slug VARCHAR(100) UNIQUE NOT NULL, brand_color VARCHAR(20) DEFAULT '#8b5cf6',
      telegram_bot_token TEXT, telegram_chat_id TEXT, created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, tenant_id INTEGER REFERENCES tenants(id),
      username VARCHAR(100) NOT NULL, password TEXT NOT NULL, email TEXT,
      role VARCHAR(50) DEFAULT 'cashier', created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(tenant_id, username)
    );
    CREATE TABLE IF NOT EXISTS categories (
      id SERIAL PRIMARY KEY, tenant_id INTEGER REFERENCES tenants(id),
      name VARCHAR(255) NOT NULL, icon VARCHAR(50), color VARCHAR(20), created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY, tenant_id INTEGER REFERENCES tenants(id),
      category_id INTEGER REFERENCES categories(id), name VARCHAR(255) NOT NULL,
      barcode VARCHAR(100), price DECIMAL(12,2) DEFAULT 0, cost_price DECIMAL(12,2) DEFAULT 0,
      stock INTEGER DEFAULT 0, unit VARCHAR(50) DEFAULT 'dona', image_url TEXT,
      is_active BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY, tenant_id INTEGER REFERENCES tenants(id),
      user_id INTEGER REFERENCES users(id), customer_name VARCHAR(255), customer_phone VARCHAR(50),
      total DECIMAL(12,2) DEFAULT 0, profit DECIMAL(12,2) DEFAULT 0,
      payment_method VARCHAR(50) DEFAULT 'cash', status VARCHAR(50) DEFAULT 'completed',
      items JSONB, created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY, tenant_id INTEGER REFERENCES tenants(id),
      transaction_id INTEGER REFERENCES transactions(id),
      status VARCHAR(50) DEFAULT 'new', notes TEXT, created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY, tenant_id INTEGER REFERENCES tenants(id),
      name VARCHAR(255), phone VARCHAR(50) UNIQUE,
      total_spent DECIMAL(12,2) DEFAULT 0, order_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('DB tayyor');
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token kerak' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token yaroqsiz' }); }
}

app.post('/api/auth/register', async (req, res) => {
  const { storeName, slug, username, password, email } = req.body;
  if (!storeName || !slug || !username || !password)
    return res.status(400).json({ error: "Barcha maydonlarni to'ldiring" });
  const hash = await bcrypt.hash(password, 10);
  const t = await pool.query('INSERT INTO tenants (name,slug) VALUES ($1,$2) RETURNING *', [storeName, slug]).catch(() => null);
  if (!t) return res.status(400).json({ error: "Bu slug band, boshqa slug tanlang" });
  const u = await pool.query('INSERT INTO users (tenant_id,username,password,email,role) VALUES ($1,$2,$3,$4,$5) RETURNING *', [t.rows[0].id, username, hash, email||null, 'admin']);
  const token = jwt.sign({ id: u.rows[0].id, tenantId: t.rows[0].id, role: 'admin' }, JWT_SECRET);
  res.json({ token, user: { id: u.rows[0].id, username, role: 'admin', email }, tenant: t.rows[0] });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password, slug } = req.body;
  let tenantId = null;
  if (slug) {
    const t = await pool.query('SELECT id FROM tenants WHERE slug=$1', [slug]);
    if (!t.rows[0]) return res.status(400).json({ error: "Do'kon topilmadi" });
    tenantId = t.rows[0].id;
  }
  const q = tenantId
    ? 'SELECT u.*,t.name,t.slug,t.brand_color FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.username=$1 AND u.tenant_id=$2'
    : 'SELECT u.*,t.name,t.slug,t.brand_color FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.username=$1 LIMIT 1';
  const result = await pool.query(q, tenantId ? [username, tenantId] : [username]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: "Foydalanuvchi topilmadi" });
  if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: "Parol noto'g'ri" });
  const token = jwt.sign({ id: user.id, tenantId: user.tenant_id, role: user.role }, JWT_SECRET);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, email: user.email }, tenant: { id: user.tenant_id, name: user.name, slug: user.slug, brand_color: user.brand_color } });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const r = await pool.query('SELECT u.*,t.name,t.slug,t.brand_color FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.id=$1', [req.user.id]);
  const user = r.rows[0];
  res.json({ token: req.headers.authorization?.split(' ')[1], user: { id: user.id, username: user.username, role: user.role, email: user.email }, tenant: { id: user.tenant_id, name: user.name, slug: user.slug, brand_color: user.brand_color } });
});

app.get('/api/products', auth, async (req, res) => {
  const r = await pool.query('SELECT p.*,c.name as category_name FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.tenant_id=$1 AND p.is_active=true ORDER BY p.id DESC', [req.user.tenantId]);
  res.json(r.rows);
});
app.post('/api/products', auth, async (req, res) => {
  const { name, barcode, price, cost_price, stock, unit, image_url, category_id } = req.body;
  const r = await pool.query('INSERT INTO products (tenant_id,name,barcode,price,cost_price,stock,unit,image_url,category_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [req.user.tenantId,name,barcode,price||0,cost_price||0,stock||0,unit||'dona',image_url,category_id]);
  res.json(r.rows[0]);
});
app.put('/api/products/:id', auth, async (req, res) => {
  const { name, barcode, price, cost_price, stock, unit, image_url, category_id, is_active } = req.body;
  const r = await pool.query('UPDATE products SET name=$1,barcode=$2,price=$3,cost_price=$4,stock=$5,unit=$6,image_url=$7,category_id=$8,is_active=$9 WHERE id=$10 AND tenant_id=$11 RETURNING *', [name,barcode,price,cost_price,stock,unit,image_url,category_id,is_active!==false,req.params.id,req.user.tenantId]);
  res.json(r.rows[0]);
});
app.delete('/api/products/:id', auth, async (req, res) => {
  await pool.query('UPDATE products SET is_active=false WHERE id=$1 AND tenant_id=$2', [req.params.id,req.user.tenantId]);
  res.json({ ok: true });
});

app.get('/api/categories', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM categories WHERE tenant_id=$1 ORDER BY id', [req.user.tenantId]);
  res.json(r.rows);
});
app.post('/api/categories', auth, async (req, res) => {
  const { name, icon, color } = req.body;
  const r = await pool.query('INSERT INTO categories (tenant_id,name,icon,color) VALUES ($1,$2,$3,$4) RETURNING *', [req.user.tenantId,name,icon,color]);
  res.json(r.rows[0]);
});
app.put('/api/categories/:id', auth, async (req, res) => {
  const { name, icon, color } = req.body;
  const r = await pool.query('UPDATE categories SET name=$1,icon=$2,color=$3 WHERE id=$4 AND tenant_id=$5 RETURNING *', [name,icon,color,req.params.id,req.user.tenantId]);
  res.json(r.rows[0]);
});
app.delete('/api/categories/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM categories WHERE id=$1 AND tenant_id=$2', [req.params.id,req.user.tenantId]);
  res.json({ ok: true });
});

app.get('/api/transactions', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM transactions WHERE tenant_id=$1 ORDER BY created_at DESC', [req.user.tenantId]);
  res.json(r.rows);
});
app.post('/api/transactions', auth, async (req, res) => {
  const { customer_name, customer_phone, total, profit, payment_method, items } = req.body;
  const r = await pool.query('INSERT INTO transactions (tenant_id,user_id,customer_name,customer_phone,total,profit,payment_method,items) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
    [req.user.tenantId,req.user.id,customer_name,customer_phone,total,profit,payment_method||'cash',JSON.stringify(items)]);
  if (items) for (const item of items) await pool.query('UPDATE products SET stock=stock-$1 WHERE id=$2', [item.qty||item.quantity||1,item.id]);
  if (customer_phone) await pool.query(`INSERT INTO customers (tenant_id,name,phone,total_spent,order_count) VALUES ($1,$2,$3,$4,1) ON CONFLICT (phone) DO UPDATE SET total_spent=customers.total_spent+$4,order_count=customers.order_count+1,name=EXCLUDED.name`, [req.user.tenantId,customer_name,customer_phone,total]).catch(()=>{});
  res.json(r.rows[0]);
});

app.get('/api/orders', auth, async (req, res) => {
  const r = await pool.query('SELECT o.*,t.customer_name,t.customer_phone,t.total,t.payment_method,t.items FROM orders o JOIN transactions t ON t.id=o.transaction_id WHERE o.tenant_id=$1 ORDER BY o.created_at DESC', [req.user.tenantId]);
  res.json(r.rows);
});
app.put('/api/orders/:id', auth, async (req, res) => {
  const r = await pool.query('UPDATE orders SET status=$1 WHERE id=$2 AND tenant_id=$3 RETURNING *', [req.body.status,req.params.id,req.user.tenantId]);
  res.json(r.rows[0]);
});

app.get('/api/customers', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM customers WHERE tenant_id=$1 ORDER BY total_spent DESC', [req.user.tenantId]);
  res.json(r.rows);
});

app.put('/api/tenant', auth, async (req, res) => {
  const { name, brand_color, telegram_bot_token, telegram_chat_id } = req.body;
  const r = await pool.query('UPDATE tenants SET name=$1,brand_color=$2,telegram_bot_token=$3,telegram_chat_id=$4 WHERE id=$5 RETURNING *', [name,brand_color,telegram_bot_token,telegram_chat_id,req.user.tenantId]);
  res.json(r.rows[0]);
});
app.get('/api/tenants', auth, async (req, res) => {
  const r = await pool.query('SELECT id,name,slug FROM tenants ORDER BY id');
  res.json(r.rows);
});

app.get('/api/stats', auth, async (req, res) => {
  const [p, tr, o] = await Promise.all([
    pool.query('SELECT COUNT(*) as count FROM products WHERE tenant_id=$1 AND is_active=true', [req.user.tenantId]),
    pool.query('SELECT SUM(total) as revenue,SUM(profit) as profit,COUNT(*) as count FROM transactions WHERE tenant_id=$1', [req.user.tenantId]),
    pool.query("SELECT COUNT(*) as count FROM orders WHERE tenant_id=$1 AND status='new'", [req.user.tenantId]),
  ]);
  res.json({ products: p.rows[0].count, revenue: tr.rows[0].revenue||0, profit: tr.rows[0].profit||0, transactions: tr.rows[0].count, new_orders: o.rows[0].count });
});

app.get('/', (req, res) => res.json({ status: 'ok' }));
