# Phishing Detector API

A Node.js/Express backend API that analyzes URLs and classifies them as **SAFE**, **SUSPICIOUS**, **PHISHING**, or **UNKNOWN** using layered signals (URL heuristics + threat intelligence providers).

## Features

- URL analysis endpoint with JWT auth.
- Multi-signal scoring engine:
  - URL lexical/structural heuristics
  - WHOIS/domain-age checks
  - Google Safe Browsing
  - VirusTotal
  - AbuseIPDB
- Brand impersonation detection (global + Ethiopian brands).
- Localized phishing keyword detection (including Amharic keywords).
- Redis + Supabase result caching with high-risk cache bypass rules.
- History endpoint with schema-tolerant timestamp fallback.
- Clear API error responses for malformed JSON and runtime failures.

## Tech Stack

- Node.js (CommonJS)
- Express
- Supabase (`@supabase/supabase-js`)
- Redis (`ioredis`)
- Axios
- JWT (`jsonwebtoken`)

## Project Structure

```text
src/
  app.js
  config/
    db.js
    redis.js
  routes/
    auth.js
    check.js
    history.js
  services/
    scorer.js
    urlParser.js
    safeBrowsing.js
    virusTotal.js
    whois.js
    abuseIPDB.js
  middleware/
    auth.js
    validator.js
    rateLimit.js
  utils/
    logger.js
```

## API Endpoints

### Health
- `GET /`

### Auth
- `POST /api/auth/token`
- Alias: `POST /auth/token`

Body:
```json
{ "name": "your-name" }
```

### Check URL
- `POST /api/check`
- Alias: `POST /check`
- Requires `Authorization: Bearer <token>`

Body:
```json
{ "url": "https://example.com/login" }
```

Response includes:
- `verdict`
- `risk_score`
- `confidence`
- `uncertainty_reason` (when applicable)
- detailed `signals`

### History
- `GET /api/history`
- Alias: `GET /history`
- Requires `Authorization: Bearer <token>`

Query params:
- `verdict` (optional)
- `limit` (default `20`)
- `page` (default `1`)

## Environment Variables

Create `.env` with:

```bash
PORT=3001
JWT_SECRET=change-me

SUPABASE_URL=...
SUPABASE_KEY=...

REDIS_URL=...

GOOGLE_SAFE_BROWSING_KEY=...
VIRUSTOTAL_KEY=...
ABUSEIPDB_KEY=...

# Optional schema override
RESULT_TIME_COLUMN=checked_at
```

> If your `scan_results` table uses a different timestamp column, set `RESULT_TIME_COLUMN`.

## Installation & Run

```bash
npm install
npm run start
```

Dev mode:
```bash
npm run dev
```

## Verdict Logic (High-Level)

- Weighted score normalized to 0–100.
- Default thresholds:
  - `>= 70` → `PHISHING`
  - `40–69` → `SUSPICIOUS`
  - `< 40` → `SAFE`
- Certain high-confidence signals can hard-override to phishing.
- If critical external providers are unavailable, verdict can become `UNKNOWN`.

## Notes

- This is a risk-scoring system, not an absolute-truth detector.
- Keep API keys and threat feeds active for best results.
- Cache bypass is enabled for high-risk brand-impersonation credential-lure URLs.

## License

ISC (as declared in `package.json`).
