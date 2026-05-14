const express        = require('express');
const router         = express.Router();
const { analyzeURL } = require('../services/scorer');
const { supabase }   = require('../config/db');
const { cacheGet, cacheSet } = require('../config/redis');
const { authMiddleware }     = require('../middleware/auth');
const { validateURL }        = require('../middleware/validator');
const { hashUrl }            = require('../utils/hashUrl');
const urlParserModule        = require('../services/urlParser');
const logger                 = require('../utils/logger');
const RESULT_TIME_COLUMNS = [
  process.env.RESULT_TIME_COLUMN,
  'checked_at',
  'created_at'
].filter((v, i, arr) => v && arr.indexOf(v) === i);

function shouldBypassCache(url) {
  try {
    if (typeof urlParserModule.parseURL !== 'function') return false;
    const parsed = urlParserModule.parseURL(url);
    const hasCredentialLure = parsed.suspiciousKeywords?.some(k =>
      ['verify', 'login', 'account', 'secure', 'password'].includes(k)
    );
    return Boolean(parsed.brandImpersonation && hasCredentialLure);
  } catch {
    return false;
  }
}

// POST /api/check
router.post('/', authMiddleware, validateURL, async (req, res) => {
  const { url } = req.body;
  const urlHash = hashUrl(url);
  const bypassCache = shouldBypassCache(url);
  logger.info(`Scanning URL: ${url}`);

  try {
    // Step 1 — Check Redis cache first
    const cached = bypassCache ? null : await cacheGet(urlHash);
    if (cached) {
      return res.json({ ...cached, cached: true });
    }

    // Step 2 — Check Supabase for recent result (last 24 hours)
    let existing = null;
    let timeColumnMatched = false;
    for (const timeColumn of RESULT_TIME_COLUMNS) {
      const response = await supabase
        .from('scan_results')
        .select('*')
        .eq('url_hash', urlHash)
        .gte(timeColumn, new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
        .single();

      if (!response.error || !/column .* does not exist/i.test(response.error.message || '')) {
        existing = response.data || null;
        timeColumnMatched = !response.error;
        break;
      }
    }

    if (!timeColumnMatched && !existing) {
      const fallbackResponse = await supabase
        .from('scan_results')
        .select('*')
        .eq('url_hash', urlHash)
        .single();
      if (!fallbackResponse.error) {
        existing = fallbackResponse.data || null;
      }
    }

    if (existing && !bypassCache) {
      // Save to Redis for next time
      await cacheSet(urlHash, existing);
      return res.json({ ...existing, cached: true });
    }

    // Step 3 — Run full analysis
    const result = await analyzeURL(url);

    // Step 4 — Save to Supabase
    let saveError = null;
    let savedWithTimeColumn = false;
    for (const timeColumn of RESULT_TIME_COLUMNS) {
      const payload = {
        url_hash:   urlHash,
        url:        result.url,
        verdict:    result.verdict,
        risk_score: result.risk_score,
        confidence: result.confidence,
        signals:    result.signals,
        cached:     false,
        [timeColumn]: result.checked_at
      };
      const response = await supabase.from('scan_results').upsert(payload);
      if (!response.error || !/column .* does not exist/i.test(response.error.message || '')) {
        saveError = response.error;
        savedWithTimeColumn = !response.error;
        break;
      }
      saveError = response.error;
    }

    if (!savedWithTimeColumn) {
      const fallbackPayload = {
        url_hash:   urlHash,
        url:        result.url,
        verdict:    result.verdict,
        risk_score: result.risk_score,
        confidence: result.confidence,
        signals:    result.signals,
        cached:     false
      };
      const fallbackSave = await supabase.from('scan_results').upsert(fallbackPayload);
      saveError = fallbackSave.error;
    }

    if (saveError) {
      console.error('Supabase save error:', saveError.message);
    }

    // Step 5 — Save to Redis
    await cacheSet(urlHash, result);

    // Step 6 — Return result
    logger.info(`Result: ${result.verdict} - Score: ${result.risk_score}`);
    return res.json({ ...result, cached: false });

  } catch (error) {
    logger.error(`Analysis error: ${error.message}`);
    return res.status(500).json({
      error: 'Analysis failed',
      message: error.message
    });
  }
});

module.exports = router;