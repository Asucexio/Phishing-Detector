const express      = require('express');
const router       = express.Router();
const { supabase } = require('../config/db');
const { authMiddleware } = require('../middleware/auth');

// GET /api/history - Retrieve scan history (paginated)
router.get('/', authMiddleware, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    // Fetch recent scan results
    const { data, error, count } = await supabase
      .from('scan_results')
      .select('*', { count: 'exact' })
      .order('checked_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      return res.status(500).json({
        error: 'Failed to retrieve history',
        message: error.message
      });
    }

    res.json({
      results: data || [],
      total: count || 0,
      limit,
      offset,
      user: req.user.name
    });

  } catch (error) {
    console.error('History retrieval error:', error.message);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// GET /api/history/:urlHash - Get specific scan result
router.get('/:urlHash', authMiddleware, async (req, res) => {
  try {
    const { urlHash } = req.params;

    const { data, error } = await supabase
      .from('scan_results')
      .select('*')
      .eq('url_hash', urlHash)
      .single();

    if (error || !data) {
      return res.status(404).json({
        error: 'Scan result not found',
        urlHash
      });
    }

    res.json(data);

  } catch (error) {
    console.error('History retrieval error:', error.message);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

module.exports = router;