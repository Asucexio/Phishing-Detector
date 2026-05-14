require('dotenv').config();
const { analyzeURL } = require('../services/scorer');

async function test() {
  const urls = [
    'https://google.com',
    'http://testsafebrowsing.appspot.com/s/phishing.html'
  ];

  for (const url of urls) {
    console.log('\n=============================');
    console.log('Analyzing:', url);
    console.log('Please wait...\n');

    const result = await analyzeURL(url);

    console.log('VERDICT:   ', result.verdict);
    console.log('SCORE:     ', result.risk_score);
    console.log('CONFIDENCE:', result.confidence);
    console.log('\nSIGNALS:');
    console.log('  Google threats:    ', result.signals.google_threats);
    console.log('  VT malicious:      ', result.signals.vt_malicious);
    console.log('  Abuse confidence:  ', result.signals.abuse_confidence);
    console.log('  Domain age (days): ', result.signals.domain_age_days);
    console.log('  TLD risk:          ', result.signals.tld_risk);
    console.log('  Keywords:          ', result.signals.suspicious_keywords);
  }
}

test();