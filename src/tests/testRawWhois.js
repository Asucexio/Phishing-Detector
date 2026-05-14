require('dotenv').config();
const whois = require('whois');

whois.lookup('paypal-secure-login.xyz', { timeout: 10000 }, (err, data) => {
  if (err) {
    console.error('Error:', err.message);
  } else {
    console.log('RAW WHOIS RESPONSE:');
    console.log(data);
  }
});