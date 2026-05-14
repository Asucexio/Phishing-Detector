require('dotenv').config();
const { parseURL } = require('../services/urlParser');
const { checkWhois } = require('../services/whois');

async function test() {
  const testUrls = [
    'https://google.com',
    'https://facebook.com/login/verify',
    'http://cbe-verify-account.xyz/login'
  ];

  for (const url of testUrls) {
    console.log('\n=============================');
    console.log('URL:', url);

    const urlResult = parseURL(url);
    console.log('URL Score:', urlResult.score, '| TLD:', urlResult.tldRisk, '| Keywords:', urlResult.suspiciousKeywords);

    const whoisResult = await checkWhois(url);
    console.log('WHOIS Score:', whoisResult.score, '| Age:', whoisResult.domainAgeDays, 'days | Available:', whoisResult.whoisAvailable);
  }
}

test();