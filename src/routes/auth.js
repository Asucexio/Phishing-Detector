const express = require('express');
const jwt     = require('jsonwebtoken');
const router  = express.Router();

// POST /api/auth/token
// Generates a test token — in production replace with real API key check
router.post('/token', (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Name is required' });
  }

  const token = jwt.sign(
    { name, createdAt: new Date().toISOString() },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({
    token,
    expiresIn: '30 days',
    usage: 'Add to requests as: Authorization: Bearer <token>'
  });
});

module.exports = router;