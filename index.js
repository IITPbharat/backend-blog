require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const Post = require('./models/post');

//Middleware import
const auth = require('./middlewares/auth');
const authorizeUser = require('./middlewares/authorizeUser');


const app = express();
app.use(express.json());


//Connect MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log(" Connected to MongoDB"))
  .catch(err => console.error("MongoDB Error:", err));



//Regiser API
app.post('/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const user = new User({ name, email, password, role });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//Login API
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { _id: user._id, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//Post
app.post('/posts', auth, async (req, res) => {
  try {
    const { title, content } = req.body;
    const newPost = new Post({ title, content, author: req.user._id });
    await newPost.save();
    res.status(201).json(newPost);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//Get All Posts
app.get('/posts', async (req, res) => {
  try {
    const posts = await Post.find().populate('author', 'name email');
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//Update Post
app.put('/posts/:id', auth,authorizeUser, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) return res.status(404).json({ message: "Post not found" });

    // Allow if same author or admin
    if (post.author.toString() !== req.user._id && req.user.role !== 'admin') {
      return res.status(403).json({ message: "Access denied" });
    }

    const { title, content } = req.body;
    post.title = title;
    post.content = content;
    await post.save();

    res.json(post);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//Delete Post (only by same author or admin)
app.delete('/posts/:id', auth,authorizeUser, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) return res.status(404).json({ message: "Post not found" });

    if (post.author.toString() !== req.user._id && req.user.role !== 'admin') {
      return res.status(403).json({ message: "Access denied" });
    }

    await post.deleteOne();
    res.json({ message: "Post deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//Role-Based Dashboard
app.get('/dashboard', auth, async (req, res) => {
  try {
    let posts;
    if (req.user.role === 'admin') {
      posts = await Post.find().populate('author', 'name email');
    } else {
      posts = await Post.find({ author: req.user._id });
    }
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(` Server running on http://localhost:${PORT}`);
});