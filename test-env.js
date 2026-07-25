require('dotenv').config();
console.log('Key:', process.env.BREVO_API_KEY);
console.log('Length:', (process.env.BREVO_API_KEY || '').length);
