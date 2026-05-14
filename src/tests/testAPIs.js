require('dotenv').config();

const { checkSafeBrowsing } = require('../services/safeBrowsing');
const { checkVirusTotal }   = require('../services/virusTotal');
const { checkAbuseIPDB }    = require('../services/abuseIPDB');

async function test() {
  const testUrl = 'http://testsafebrowsing.appspot.com/s/phishing.html';

  console.log('Testing URL:', testUrl);
  console.log('This is Google\'s own test phishing URL — safe to use\n');

  console.log('--- GOOGLE SAFE BROWSING ---');
  try {
    const sbResult = await checkSafeBrowsing(testUrl);
    console.log(JSON.stringify(sbResult, null, 2));
  } catch (e) {
    console.error('Safe Browsing error:', e.message);
  }

  console.log('\n--- VIRUSTOTAL ---');
  try {
    const vtResult = await checkVirusTotal(testUrl);
    console.log(JSON.stringify(vtResult, null, 2));
  } catch (e) {
    console.error('VirusTotal error:', e.message);
  }

  console.log('\n--- ABUSEIPDB ---');
  try {
    const abuseResult = await checkAbuseIPDB(testUrl);
    console.log(JSON.stringify(abuseResult, null, 2));
  } catch (e) {
    console.error('AbuseIPDB error:', e.message);
  }
}

test();