const whois = require('whois');
const { URL } = require('url');

const HIGH_RISK_TLDS = ['.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq'];
const HIGH_RISK_REGISTRARS = ['namesilo', 'namecheap', 'publicdomainregistry', 'resellerclub'];

function lookupWhois(domain) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), 8000);
    whois.lookup(domain, { timeout: 7000 }, (err, data) => {
      clearTimeout(timer);
      if (err || !data || data.includes('DOMAIN NOT FOUND')) resolve(null);
      else resolve(data);
    });
  });
}

function extractField(raw, patterns) {
  for (const pattern of patterns) {
    const match = raw.match(pattern);
    if (match?.[1]) return match[1].trim();
  }
  return null;
}

function extractDate(raw, patterns) {
  const val = extractField(raw, patterns);
  if (!val) return null;
  const d = new Date(val);
  return isNaN(d.getTime()) ? null : d;
}

async function checkWhois(rawUrl) {
  const result = {
    domain: null,
    domainAgeDays: null,
    registrar: null,
    registrantCountry: null,
    privacyProtected: false,
    expiresInDays: null,
    highRiskRegistrar: false,
    whoisAvailable: false,
    score: 0,
    error: null
  };

  let hostname;
  try {
    const parsed = new URL(rawUrl);
    hostname = parsed.hostname.replace(/^www\./, '');
    result.domain = hostname;
  } catch {
    result.error = 'Invalid URL';
    result.score = 20;
    return result;
  }

  // TLD-based pre-score (works even without WHOIS data)
  const tld = '.' + hostname.split('.').pop();
  const tldIsHighRisk = HIGH_RISK_TLDS.includes(tld);

  const raw = await lookupWhois(hostname);

  // WHOIS unavailable — use TLD signal only
  if (!raw) {
    result.error = 'WHOIS unavailable';
    result.score = tldIsHighRisk ? 20 : 10;
    return result;
  }

  result.whoisAvailable = true;

  // Parse dates
  const createdDate = extractDate(raw, [
    /Creation Date:\s*(.+)/i,
    /Created:\s*(.+)/i,
    /Registration Date:\s*(.+)/i,
    /Domain Registration Date:\s*(.+)/i,
    /created:\s*(.+)/i
  ]);

  const expiresDate = extractDate(raw, [
    /Registry Expiry Date:\s*(.+)/i,
    /Expiration Date:\s*(.+)/i,
    /Expires:\s*(.+)/i,
    /paid-till:\s*(.+)/i
  ]);

  const registrar = extractField(raw, [
    /Registrar:\s*(.+)/i,
    /Sponsoring Registrar:\s*(.+)/i,
    /registrar:\s*(.+)/i
  ]);

  const country = extractField(raw, [
    /Registrant Country:\s*(.+)/i,
    /Country:\s*(.+)/i,
    /country:\s*(.+)/i
  ]);

  const now = new Date();

  if (createdDate) {
    result.domainAgeDays = Math.floor(
      (now - createdDate) / (1000 * 60 * 60 * 24)
    );
  }

  if (expiresDate) {
    result.expiresInDays = Math.floor(
      (expiresDate - now) / (1000 * 60 * 60 * 24)
    );
  }

  result.registrar         = registrar || null;
  result.registrantCountry = country   || null;
  result.privacyProtected  = /REDACTED|privacy|protected|proxy/i.test(raw);

  if (registrar) {
    result.highRiskRegistrar = HIGH_RISK_REGISTRARS.some(r =>
      registrar.toLowerCase().includes(r)
    );
  }

  // --- SCORING ---
  let score = 0;

  if (result.domainAgeDays !== null) {
    if      (result.domainAgeDays < 7)   score += 35;
    else if (result.domainAgeDays < 30)  score += 25;
    else if (result.domainAgeDays < 90)  score += 15;
    else if (result.domainAgeDays < 365) score += 5;
  } else {
    score += 10; // unknown age = mild penalty
  }

  if (tldIsHighRisk)                                   score += 15;
  if (result.highRiskRegistrar)                        score += 10;
  if (result.privacyProtected)                         score += 5;
  if (result.expiresInDays !== null
      && result.expiresInDays < 365)                   score += 5;

  result.score = Math.min(score, 100);
  return result;
}

module.exports = { checkWhois };