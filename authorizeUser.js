const Post = require('../models/post');

const authorizeUser = async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    if (post.author.toString() === req.user._id || req.user.role === "admin") {
      next(); 
    } else {
      return res.status(403).json({ message: "Unauthorized access" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports = authorizeUser;
