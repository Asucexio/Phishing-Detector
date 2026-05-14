const express    = require('express');
const router     = express.Router();
const { supabase } = require('../config/db');
const { authMiddleware } = require('../middleware/auth');

// GET /api/history
router.get('/', authMiddleware, async (req, res) => {
  const { verdict, limit = 20, page = 1 } = req.query;

  try {
    let query = supabase
      .from('scan_results')
      .select('*')
      .order('checked_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);

    if (verdict) {
      query = query.eq('verdict', verdict.toUpperCase());
    }

    const { data, error } = await query;
    if (error) throw error;

    res.json({
      page:    parseInt(page),
      limit:   parseInt(limit),
      results: data
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;