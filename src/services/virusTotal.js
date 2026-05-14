const axios = require('axios');

async function checkVirusTotal(url) {
  const result = {
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    totalEngines: 0,
    permalink: null,
    score: 0,
    error: null
  };

  try {
    // Step 1 — Submit URL for analysis
    const submitResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      {
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 10000
      }
    );

    const analysisId = submitResponse.data?.data?.id;
    if (!analysisId) throw new Error('No analysis ID returned');

    // Step 2 — Wait briefly then fetch results
    await new Promise(resolve => setTimeout(resolve, 3000));

    const reportResponse = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_KEY },
        timeout: 10000
      }
    );

    const stats = reportResponse.data?.data?.attributes?.stats;
    if (!stats) throw new Error('No stats in response');

    result.malicious  = stats.malicious  || 0;
    result.suspicious = stats.suspicious || 0;
    result.harmless   = stats.harmless   || 0;
    result.undetected = stats.undetected || 0;
    result.totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
    result.permalink  = `https://www.virustotal.com/gui/url/${analysisId}`;

    // --- SCORING ---
    const flagged = result.malicious + result.suspicious;

    if      (flagged > 10) result.score = 45;
    else if (flagged > 4)  result.score = 30;
    else if (flagged > 1)  result.score = 15;
    else if (flagged > 0)  result.score = 10;

  } catch (error) {
    result.error = error.message;
    result.score = 0;
  }

  return result;
}

module.exports = { checkVirusTotal };