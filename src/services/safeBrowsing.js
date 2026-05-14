const axios = require('axios');

const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION'
];

// Points per threat type
const THREAT_SCORES = {
  MALWARE: 45,
  SOCIAL_ENGINEERING: 40,
  UNWANTED_SOFTWARE: 30,
  POTENTIALLY_HARMFUL_APPLICATION: 25
};

async function checkSafeBrowsing(url) {
  const result = {
    threats: [],
    threatTypes: [],
    score: 0,
    error: null
  };

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
      {
        client: {
          clientId: 'insa-phishing-detector',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: THREAT_TYPES,
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      },
      { timeout: 8000 }
    );

    const matches = response.data?.matches || [];

    if (matches.length === 0) {
      // Clean — no threats found
      return result;
    }

    // Extract unique threat types
    result.threatTypes = [...new Set(matches.map(m => m.threatType))];
    result.threats = matches.map(m => ({
      threatType: m.threatType,
      platformType: m.platformType
    }));

    // Score based on worst threat found
    let score = 0;
    for (const threatType of result.threatTypes) {
      const points = THREAT_SCORES[threatType] || 20;
      if (points > score) score = points;
    }

    result.score = score;

  } catch (error) {
    result.error = error.message;
    result.score = 0;
  }

  return result;
}

module.exports= { checkSafeBrowsing };