// --- 1. Imports ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // For hashing passwords
const jwt = require('jsonwebtoken'); // For user sessions

// --- 2. Basic Setup ---
const app = express();
const PORT = 5000;
const JWT_SECRET = 'your-super-secret-key-change-this'; // Used to sign tokens

// --- 3. Middleware ---
app.use(cors());
app.use(express.json());

// --- 4. Database Connection ---
mongoose.connect('mongodb://localhost:27017/ecommerceDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected successfully!"))
.catch(err => console.error("MongoDB connection error:", err));

// --- 5. Mongoose Schemas ---

// Product Schema (Unchanged, but averageRating/reviewCount are still here)
const productSchema = new mongoose.Schema({
  productId: { type: String, unique: true, required: true },
  name: String,
  description: String,
  price: Number,
  category: String,
  stock_quantity: Number,
  imageUrl: String,
  averageRating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 }
});
const Product = mongoose.model('Product', productSchema, 'products');

// Review Schema (Updated to link to a user)
const reviewSchema = new mongoose.Schema({
  productId: { type: String, required: true },
  authorName: { type: String, required: true }, // Store the user's email/name
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Review = mongoose.model('Review', reviewSchema, 'reviews');

// NEW: User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema, 'users');

// NEW: Order Schema
const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    productId: { type: String, required: true },
    productName: { type: String, required: true },
    customerName: { type: String, required: true },
    shippingAddress: { type: String, required: true },
    orderDate: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema, 'orders');


// --- 6. Authentication Middleware ---

// This function checks if a user is logged in
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"
    
    if (token == null) return res.sendStatus(401); // No token, unauthorized

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) return res.sendStatus(403); // Token is invalid, forbidden
        req.user = userPayload; // Add user payload ( { userId, email, role } ) to the request
        next();
    });
};

// This function checks if the logged-in user is an admin
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required." });
    }
    next();
};


// --- 7. API Endpoints ---

// --- A. Auth Endpoints (NEW) ---

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required." });
        }
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already in use." });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
        
        const user = new User({
            email,
            password: hashedPassword
            // Role defaults to 'user'
        });
        
        await user.save();
        res.status(201).json({ message: "User registered successfully." });

    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Invalid credentials." });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials." });
        }
        
        // Create JWT
        const tokenPayload = {
            userId: user._id,
            email: user.email,
            role: user.role
        };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1d' }); // Token lasts for 1 day
        
        res.json({ 
            token, 
            user: { 
                email: user.email, 
                role: user.role,
                id: user._id
            } 
        });

    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// --- B. Product Endpoints (PUBLIC and ADMIN) ---

// GET (Public): Get all products
app.get('/api/products', async (req, res) => {
    const products = await Product.find({});
    res.json(products);
});

// GET (Public): Get one product
app.get('/api/products/:productId', async (req, res) => {
    const product = await Product.findOne({ productId: req.params.productId });
    if (!product) return res.status(404).json({ message: "Product not found" });
    res.json(product);
});

// POST (Admin): Add a new product
app.post('/api/products', authenticateToken, isAdmin, async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (err) {
        res.status(400).json({ message: "Error creating product: " + err.message });
    }
});

// PUT (Admin): Update stock
app.put('/api/products/:productId', authenticateToken, isAdmin, async (req, res) => {
    try {
      const { new_stock } = req.body; 
      const updatedProduct = await Product.findOneAndUpdate(
        { productId: req.params.productId },
        { stock_quantity: new_stock },
        { new: true }
      );
      if (!updatedProduct) return res.status(404).json({ message: "Product not found" });
      res.json(updatedProduct);
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
});

// DELETE (Admin): Delete a product
app.delete('/api/products/:productId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const deletedProduct = await Product.findOneAndDelete({ productId: req.params.productId });
        if (!deletedProduct) return res.status(404).json({ message: "Product not found" });
        
        // Also delete associated reviews
        await Review.deleteMany({ productId: req.params.productId });
        
        res.json({ message: "Product and associated reviews deleted." });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// --- C. Review Endpoints (PUBLIC and USER) ---

// GET (Public): Get reviews for a product
app.get('/api/reviews/:productId', async (req, res) => {
    const reviews = await Review.find({ productId: req.params.productId }).sort({ createdAt: -1 });
    res.json(reviews);
});

// POST (User): Add a new review
app.post('/api/reviews', authenticateToken, async (req, res) => {
    // Admins cannot post reviews
    if (req.user.role === 'admin') {
        return res.status(403).json({ message: "Admins cannot submit reviews." });
    }
    
    try {
        const { productId, rating, comment } = req.body;
        
        const newReview = new Review({
          productId,
          rating,
          comment,
          userId: req.user.userId, // From the authenticated token
          authorName: req.user.email // Use email as author name
        });
        await newReview.save();

        // Recalculate average rating
        const reviews = await Review.find({ productId: productId });
        const totalRating = reviews.reduce((acc, review) => acc + review.rating, 0);
        const newAverageRating = totalRating / reviews.length;
        
        await Product.findOneAndUpdate(
          { productId: productId },
          {
            averageRating: newAverageRating.toFixed(1),
            reviewCount: reviews.length
          }
        );
        
        res.status(201).json(newReview);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// --- D. Recommendation Endpoint (PUBLIC) ---
app.get('/api/recommendations/:productId', async (req, res) => {
    // This logic is unchanged, but now recommends based on top ratings
    const currentProduct = await Product.findOne({ productId: req.params.productId });
    if (!currentProduct) return res.status(404).json({ message: "Product not found" });
    
    const recommendations = await Product.find({
      category: currentProduct.category,
      productId: { $ne: req.params.productId }
    })
    .sort({ averageRating: -1 }) // Sort by top-rated
    .limit(4);
    
    res.json(recommendations);
});


// --- E. Order Endpoint (USER) ---
app.post('/api/orders', authenticateToken, async (req, res) => {
    // Admins cannot place orders
    if (req.user.role === 'admin') {
        return res.status(403).json({ message: "Admins cannot place orders." });
    }
    
    try {
        const { productId, customerName, shippingAddress } = req.body;
        
        // 1. Find the product being ordered
        const product = await Product.findOne({ productId: productId });
        if (!product) return res.status(404).json({ message: "Product not found." });
        
        // 2. Check stock
        if (product.stock_quantity < 1) {
            return res.status(400).json({ message: "Product is out of stock." });
        }
        
        // 3. Create the order
        const newOrder = new Order({
            userId: req.user.userId,
            productId: product.productId,
            productName: product.name,
            customerName,
            shippingAddress
        });
        await newOrder.save();
        
        // 4. Decrement the product's stock
        await Product.findOneAndUpdate(
            { productId: productId },
            { $inc: { stock_quantity: -1 } } // $inc is an atomic operator to increment/decrement
        );
        
        res.status(201).json({ message: "Order placed successfully!", order: newOrder });
        
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// --- 8. Start Server ---
app.listen(PORT, () => {
  console.log(`Backend server is running on http://localhost:${PORT}`);
});