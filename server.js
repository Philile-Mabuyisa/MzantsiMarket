require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// --- REDIRECT ROOT TO LOGIN PAGE ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- MONGOOSE SCHEMAS ---
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['customer', 'manager', 'Store Manager'], default: 'customer' }
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  qty: { type: Number, required: true },
  lowStockThreshold: { type: Number, default: 5 }
});

const OrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  customerName: String,
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    productName: String,
    quantity: Number,
    price: Number
  }],
  totalAmount: Number,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);

// --- AUTH MIDDLEWARE ---
const auth = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });
  try {
    const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET || 'mzansi_secret_key');
    req.user = decoded;
    next();
  } catch (e) {
    res.status(400).json({ msg: 'Token is not valid' });
  }
};

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({ name, email, password: hashedPassword, role: role || 'customer' });
    await user.save();

    res.status(201).json({ msg: 'Account created successfully' });
  } catch (err) {
    console.error('Register Error:', err);
    res.status(500).json({ msg: 'Server Error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, role: user.role, name: user.name }, 
      process.env.JWT_SECRET || 'mzansi_secret_key', 
      { expiresIn: '1d' }
    );
    res.json({ token, user: { id: user._id, name: user.name, role: user.role, email: user.email } });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ msg: 'Server Error during login' });
  }
});

// --- PRODUCT ROUTES ---
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    console.error('Get Products Error:', err);
    res.status(500).json({ msg: 'Failed to fetch products' });
  }
});

app.post('/api/products', auth, async (req, res) => {
  try {
    if (req.user.role !== 'manager' && req.user.role !== 'Store Manager') {
      return res.status(403).json({ msg: 'Access denied' });
    }
    const { name, price, qty } = req.body;
    const product = new Product({ name, price, qty });
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    console.error('Create Product Error:', err);
    res.status(500).json({ msg: 'Failed to create product' });
  }
});

app.put('/api/products/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'manager' && req.user.role !== 'Store Manager') {
      return res.status(403).json({ msg: 'Access denied' });
    }
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(product);
  } catch (err) {
    console.error('Update Product Error:', err);
    res.status(500).json({ msg: 'Failed to update product' });
  }
});

// --- ORDER ROUTES ---
app.post('/api/orders', auth, async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ msg: 'Product not found' });
    if (product.qty < quantity) return res.status(400).json({ msg: 'Insufficient stock available' });

    product.qty -= quantity;
    await product.save();

    const order = new Order({
      userId: req.user.id,
      customerName: req.user.name,
      items: [{ productId: product._id, productName: product.name, quantity, price: product.price }],
      totalAmount: product.price * quantity
    });
    await order.save();

    res.status(201).json({ msg: 'Order placed successfully', order });
  } catch (err) {
    console.error('Create Order Error:', err);
    res.status(500).json({ msg: 'Failed to place order' });
  }
});

app.get('/api/orders', auth, async (req, res) => {
  try {
    const isManager = req.user.role === 'manager' || req.user.role === 'Store Manager';
    const orders = isManager 
      ? await Order.find().sort({ createdAt: -1 })
      : await Order.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error('Get Orders Error:', err);
    res.status(500).json({ msg: 'Failed to fetch orders' });
  }
});

// --- DATABASE CONNECTION & SERVER LISTEN ---
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://amabuyisa_db_user:YGPdoBNUWx4a6sZA@dreamer.zukokqc.mongodb.net/M_Market?appName=Dreamer';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB Atlas connected successfully!');
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('MongoDB Connection Error:', err.message);
  });