/**
 * Reset Rate Limit for a specific user/email
 * 
 * Usage: npx ts-node scripts/reset-ratelimit.ts hasan.aker@clinisyn.com clinisyn
 */

import { resetRateLimit, RateLimitEndpoint } from '../src/services/ratelimit.service';

async function main() {
  const email = process.argv[2] || 'hasan.aker@clinisyn.com';
  const realmId = process.argv[3] || 'clinisyn';

  console.log(`\n🔓 Rate Limit Reset`);
  console.log(`==================`);
  console.log(`Email: ${email}`);
  console.log(`Realm: ${realmId}`);
  console.log('');

  // Reset all endpoint types for this email
  const endpoints = [
    RateLimitEndpoint.LOGIN,
    RateLimitEndpoint.REGISTER,
    RateLimitEndpoint.PASSWORD_RESET,
    RateLimitEndpoint.MFA_VERIFY,
    RateLimitEndpoint.EMAIL_VERIFY,
    RateLimitEndpoint.API_GENERAL,
    RateLimitEndpoint.SOCIAL_AUTH,
    RateLimitEndpoint.WEBAUTHN,
    RateLimitEndpoint.DEVICE_TRUST,
    RateLimitEndpoint.ACCOUNT_LINK
  ];

  for (const endpoint of endpoints) {
    try {
      await resetRateLimit(realmId, endpoint, email);
      console.log(`✅ ${endpoint} - reset`);
    } catch (error) {
      console.log(`⚠️  ${endpoint} - ${error}`);
    }
  }

  console.log('\n✅ Rate limit reset tamamlandı!');
  console.log('Artık tekrar giriş deneyebilirsin.\n');
}

main().catch(console.error);
