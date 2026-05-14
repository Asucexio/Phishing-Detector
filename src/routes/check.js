const express        = require('express');
const router         = express.Router();
const { analyzeURL } = require('../services/scorer');
const { supabase }   = require('../config/db');
const { cacheGet, cacheSet } = require('../config/redis');
const { authMiddleware }     = require('../middleware/auth');
const { validateURL }        = require('../middleware/validator');
const { hashUrl }            = require('../utils/hashUrl');

// POST /api/check
router.post('/', authMiddleware, validateURL, async (req, res) => {
  const { url } = req.body;
  const urlHash = hashUrl(url);

  try {
    // Step 1 — Check Redis cache first
    const cached = await cacheGet(urlHash);
    if (cached) {
      return res.json({ ...cached, cached: true });
    }

    // Step 2 — Check Supabase for recent result (last 24 hours)
    const { data: existing } = await supabase
      .from('scan_results')
      .select('*')
      .eq('url_hash', urlHash)
      .gte('checked_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
      .single();

    if (existing) {
      // Save to Redis for next time
      await cacheSet(urlHash, existing);
      return res.json({ ...existing, cached: true });
    }

    // Step 3 — Run full analysis
    const result = await analyzeURL(url);

    // Step 4 — Save to Supabase
    const { error: saveError } = await supabase
      .from('scan_results')
      .upsert({
        url_hash:   urlHash,
        url:        result.url,
        verdict:    result.verdict,
        risk_score: result.risk_score,
        confidence: result.confidence,
        signals:    result.signals,
        cached:     false,
        checked_at: result.checked_at
      });

    if (saveError) {
      console.error('Supabase save error:', saveError.message);
    }

    // Step 5 — Save to Redis
    await cacheSet(urlHash, result);

    // Step 6 — Return result
    return res.json({ ...result, cached: false });

  } catch (error) {
    console.error('Analysis error:', error.message);
    return res.status(500).json({
      error: 'Analysis failed',
      message: error.message
    });
  }
});

module.exports = router;