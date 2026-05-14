const { URL } = require('url');

// Known URL shorteners
const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
  'ow.ly', 'short.link', 'buff.ly', 'rebrand.ly'
];

// High risk TLDs
const HIGH_RISK_TLDS = [
  '.xyz', '.top', '.click', '.tk', '.ml',
  '.ga', '.cf', '.gq', '.buzz', '.monster'
];

// Suspicious keywords (includes Ethiopian brands attackers spoof)
const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'account', 'update',
  'confirm', 'banking', 'password', 'suspended', 'alert',
  'ebbirr', 'telebirr', 'cbe', 'awash', 'dashen',
  'ethiotelecom', 'insa', 'ethswitch'
];

function calculateEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((e, count) => {
    const p = count / str.length;
    return e - p * Math.log2(p);
  }, 0);
}

function parseURL(rawUrl) {
  const signals = {
    urlLength: 0,
    subdomainDepth: 0,
    hasAtSymbol: false,
    hasDoubleSlash: false,
    hasIPAddress: false,
    isShortened: false,
    suspiciousKeywords: [],
    tldRisk: 'low',
    entropy: 0,
    excessiveHyphens: false,
    score: 0
  };

  // Basic checks before parsing
  signals.urlLength = rawUrl.length;
  signals.hasAtSymbol = rawUrl.includes('@');
  signals.hasDoubleSlash = (rawUrl.match(/\/\//g) || []).length > 1;

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    // If URL can't be parsed it is itself suspicious
    signals.score = 40;
    return signals;
  }

  const hostname = parsed.hostname;

  // IP address check
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  signals.hasIPAddress = ipPattern.test(hostname);

  // Subdomain depth
  const parts = hostname.split('.');
  signals.subdomainDepth = parts.length - 2;

  // URL shortener check
  signals.isShortened = SHORTENERS.some(s => hostname.includes(s));

  // TLD risk
  const tld = '.' + parts[parts.length - 1];
  signals.tldRisk = HIGH_RISK_TLDS.includes(tld) ? 'high' : 'low';

  // Suspicious keywords
  const fullLower = rawUrl.toLowerCase();
  signals.suspiciousKeywords = SUSPICIOUS_KEYWORDS.filter(k =>
    fullLower.includes(k)
  );

  // Excessive hyphens in domain
  signals.excessiveHyphens = (hostname.match(/-/g) || []).length >= 3;

  // Entropy on hostname
  signals.entropy = parseFloat(calculateEntropy(hostname).toFixed(2));

  // --- SCORING ---
  let score = 0;

  if (signals.urlLength > 75)        score += 20;
  else if (signals.urlLength > 54)   score += 10;

  if (signals.subdomainDepth > 3)    score += 20;
  else if (signals.subdomainDepth > 2) score += 10;

  if (signals.hasAtSymbol)           score += 20;
  if (signals.hasDoubleSlash)        score += 10;
  if (signals.hasIPAddress)          score += 20;
  if (signals.isShortened)           score += 10;
  if (signals.tldRisk === 'high')    score += 15;
  if (signals.excessiveHyphens)      score += 10;
  if (signals.entropy > 4.5)         score += 10;
  if (signals.suspiciousKeywords.length > 0) score += 10;

  signals.score = Math.min(score, 100);
  return signals;
}

module.exports = { parseURL };