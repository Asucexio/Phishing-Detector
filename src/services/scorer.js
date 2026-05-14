const { parseURL }          = require('./urlParser');
const { checkWhois }        = require('./whois');
const { checkSafeBrowsing } = require('./safeBrowsing');
const { checkVirusTotal }   = require('./virusTotal');
const { checkAbuseIPDB }    = require('./abuseIPDB');

// How many services responded successfully
function calcConfidence(results) {
  const total   = 5;
  const working = [
    results.safeBrowsing.error === null,
    results.virusTotal.error   === null,
    results.abuseIPDB.error    === null,
    results.whois.error        === null,
    true // urlParser never fails
  ].filter(Boolean).length;

  if (working >= 4) return 'HIGH';
  if (working >= 3) return 'MEDIUM';
  return 'LOW';
}

// Instant override — these signals alone confirm phishing
function checkHardOverride(results) {
  const sb = results.safeBrowsing;
  const vt = results.virusTotal;

  if (sb.threatTypes?.includes('SOCIAL_ENGINEERING')) return true;
  if (sb.threatTypes?.includes('MALWARE'))             return true;
  if (vt.malicious > 15)                               return true;

  return false;
}

function getVerdict(score) {
  if (score >= 70) return 'PHISHING';
  if (score >= 40) return 'SUSPICIOUS';
  return 'SAFE';
}

async function analyzeURL(rawUrl) {
  // Run all services in parallel for speed
  const [urlResult, whoisResult, sbResult, vtResult, abuseResult] =
    await Promise.all([
      Promise.resolve(parseURL(rawUrl)),
      checkWhois(rawUrl),
      checkSafeBrowsing(rawUrl),
      checkVirusTotal(rawUrl),
      checkAbuseIPDB(rawUrl)
    ]);

  const results = {
    urlParser:    urlResult,
    whois:        whoisResult,
    safeBrowsing: sbResult,
    virusTotal:   vtResult,
    abuseIPDB:    abuseResult
  };

  // Add up all service scores with weights
 const weights = {
    safeBrowsing: 1.0,
    virusTotal:   1.0,
    abuseIPDB:    0.8,
    whois:        0.7,
    urlParser:    1.0  // ← was 0.6, now equal weight
  };

  let rawScore = 0;
  rawScore += sbResult.score    * weights.safeBrowsing;
  rawScore += vtResult.score    * weights.virusTotal;
  rawScore += abuseResult.score * weights.abuseIPDB;
  rawScore += whoisResult.score * weights.whois;
  rawScore += urlResult.score   * weights.urlParser;

  // Normalize to 0-100
  const maxPossible = 100 * (
    weights.safeBrowsing +
    weights.virusTotal   +
    weights.abuseIPDB    +
    weights.whois        +
    weights.urlParser
  );

  let finalScore = Math.round((rawScore / maxPossible) * 100);
  finalScore = Math.min(finalScore, 100);

    // Hard override — confirmed phishing regardless of score
  const isHardOverride = checkHardOverride(results);
  if (isHardOverride) finalScore = Math.max(finalScore, 85);

  // IP address override — raw IP as host is always high risk
  if (urlResult.hasIPAddress) finalScore = Math.max(finalScore, 70);

  const verdict    = getVerdict(finalScore);
  const confidence = calcConfidence(results);

  return {
    url:        rawUrl,
    verdict,
    risk_score: finalScore,
    confidence,
    signals: {
      // URL Parser
      url_length:           urlResult.urlLength,
      subdomain_depth:      urlResult.subdomainDepth,
      has_at_symbol:        urlResult.hasAtSymbol,
      has_ip_address:       urlResult.hasIPAddress,
      is_shortened:         urlResult.isShortened,
      tld_risk:             urlResult.tldRisk,
      suspicious_keywords:  urlResult.suspiciousKeywords,
      entropy:              urlResult.entropy,
      url_score:            urlResult.score,

      // WHOIS
      domain_age_days:      whoisResult.domainAgeDays,
      registrar:            whoisResult.registrar,
      registrant_country:   whoisResult.registrantCountry,
      privacy_protected:    whoisResult.privacyProtected,
      high_risk_registrar:  whoisResult.highRiskRegistrar,
      whois_score:          whoisResult.score,

      // Google Safe Browsing
      google_threats:       sbResult.threatTypes,
      safe_browsing_score:  sbResult.score,

      // VirusTotal
      vt_malicious:         vtResult.malicious,
      vt_suspicious:        vtResult.suspicious,
      vt_total_engines:     vtResult.totalEngines,
      vt_permalink:         vtResult.permalink,
      virustotal_score:     vtResult.score,

      // AbuseIPDB
      ip_address:           abuseResult.ip,
      abuse_confidence:     abuseResult.abuseScore,
      ip_country:           abuseResult.countryCode,
      isp:                  abuseResult.isp,
      abuseipdb_score:      abuseResult.score
    },
    checked_at: new Date().toISOString()
  };
}

module.exports = { analyzeURL };