const axios = require('axios');
const dns = require('dns').promises;
const { URL } = require('url');

async function resolveIP(hostname) {
  try {
    const addresses = await dns.lookup(hostname);
    return addresses.address;
  } catch {
    return null;
  }
}

async function checkAbuseIPDB(rawUrl) {
  const result = {
    ip: null,
    abuseScore: 0,
    totalReports: 0,
    countryCode: null,
    isp: null,
    usageType: null,
    isWhitelisted: false,
    score: 0,
    error: null
  };

  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.replace(/^www\./, '');

    // Resolve domain to IP
    const ip = await resolveIP(hostname);
    if (!ip) {
      result.error = 'Could not resolve IP';
      return result;
    }

    result.ip = ip;

    const response = await axios.get(
      'https://api.abuseipdb.com/api/v2/check',
      {
        params: {
          ipAddress: ip,
          maxAgeInDays: 90,
          verbose: false
        },
        headers: {
          Key: process.env.ABUSEIPDB_KEY,
          Accept: 'application/json'
        },
        timeout: 8000
      }
    );

    const data = response.data?.data;
    if (!data) throw new Error('No data returned');

    result.abuseScore   = data.abuseConfidenceScore || 0;
    result.totalReports = data.totalReports         || 0;
    result.countryCode  = data.countryCode          || null;
    result.isp          = data.isp                  || null;
    result.usageType    = data.usageType            || null;
    result.isWhitelisted = data.isWhitelisted       || false;

    // --- SCORING ---
    if      (result.abuseScore > 80) result.score = 30;
    else if (result.abuseScore > 50) result.score = 20;
    else if (result.abuseScore > 20) result.score = 10;

    // Hosting type red flags
    if (['Data Center/Web Hosting/Transit', 'bulletproof hosting']
        .includes(result.usageType)) {
      result.score = Math.min(result.score + 10, 100);
    }

  } catch (error) {
    result.error = error.message;
    result.score = 0;
  }

  return result;
}

module.exports = { checkAbuseIPDB };