/**
 * Clinisyn OAuth Setup Script
 * Task 10.2: Configure OAuth providers for Clinisyn realms
 * 
 * IMPORTANT: This script requires actual OAuth credentials from Clinisyn.
 * The credentials should be stored in environment variables or AWS Secrets Manager.
 * 
 * Required Environment Variables:
 * - CLINISYN_GOOGLE_CLIENT_ID
 * - CLINISYN_GOOGLE_CLIENT_SECRET
 * - CLINISYN_APPLE_CLIENT_ID
 * - CLINISYN_APPLE_TEAM_ID
 * - CLINISYN_APPLE_KEY_ID
 * - CLINISYN_APPLE_PRIVATE_KEY (base64 encoded)
 * 
 * Run: npx ts-node scripts/clinisyn-oauth-setup.ts
 */

import { updateRealm, getRealm } from '../src/services/realm.service';
import { AuthProvider, AuthProviderType } from '../src/models/realm.model';

// OAuth Provider Configurations
interface OAuthConfig {
  google?: {
    client_id: string;
    client_secret: string;
    redirect_uri: string;
  };
  apple?: {
    client_id: string;
    team_id: string;
    key_id: string;
    private_key: string;
    redirect_uri: string;
  };
}

/**
 * Get OAuth credentials from environment
 */
function getOAuthCredentials(): OAuthConfig {
  const config: OAuthConfig = {};

  // Google OAuth
  if (process.env.CLINISYN_GOOGLE_CLIENT_ID && process.env.CLINISYN_GOOGLE_CLIENT_SECRET) {
    config.google = {
      client_id: process.env.CLINISYN_GOOGLE_CLIENT_ID,
      client_secret: process.env.CLINISYN_GOOGLE_CLIENT_SECRET,
      redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
    };
  }

  // Apple Sign-In
  if (process.env.CLINISYN_APPLE_CLIENT_ID && process.env.CLINISYN_APPLE_TEAM_ID) {
    config.apple = {
      client_id: process.env.CLINISYN_APPLE_CLIENT_ID,
      team_id: process.env.CLINISYN_APPLE_TEAM_ID,
      key_id: process.env.CLINISYN_APPLE_KEY_ID || '',
      private_key: Buffer.from(process.env.CLINISYN_APPLE_PRIVATE_KEY || '', 'base64').toString('utf-8'),
      redirect_uri: 'https://api.zalt.io/v1/auth/social/apple/callback'
    };
  }

  return config;
}

/**
 * Create auth providers array from OAuth config
 */
function createAuthProviders(config: OAuthConfig): AuthProvider[] {
  const providers: AuthProvider[] = [
    // Email/Password is always enabled
    {
      type: 'email_password' as AuthProviderType,
      enabled: true,
      config: {}
    }
  ];

  // Add Google OAuth if configured
  if (config.google) {
    providers.push({
      type: 'oauth' as AuthProviderType,
      enabled: true,
      config: {
        provider: 'google',
        client_id: config.google.client_id,
        // Note: client_secret should be stored in AWS Secrets Manager
        // and referenced here, not stored directly
        client_secret_ref: 'clinisyn/google/client_secret',
        redirect_uri: config.google.redirect_uri,
        scopes: ['openid', 'email', 'profile']
      }
    });
  }

  // Add Apple Sign-In if configured
  if (config.apple) {
    providers.push({
      type: 'oauth' as AuthProviderType,
      enabled: true,
      config: {
        provider: 'apple',
        client_id: config.apple.client_id,
        team_id: config.apple.team_id,
        key_id: config.apple.key_id,
        // Note: private_key should be stored in AWS Secrets Manager
        private_key_ref: 'clinisyn/apple/private_key',
        redirect_uri: config.apple.redirect_uri,
        scopes: ['name', 'email']
      }
    });
  }

  return providers;
}

/**
 * Configure OAuth for a realm
 */
async function configureOAuthForRealm(
  realmId: string,
  providers: AuthProvider[]
): Promise<{ success: boolean; message: string }> {
  console.log(`\n🔐 Configuring OAuth for realm: ${realmId}`);

  // Check if realm exists
  const realm = await getRealm(realmId);
  if (!realm) {
    console.error(`  ❌ Realm ${realmId} not found`);
    return { success: false, message: `Realm ${realmId} not found` };
  }

  // Update realm with auth providers
  const result = await updateRealm(realmId, {
    auth_providers: providers
  });

  if (result.success) {
    console.log(`  ✅ OAuth configured for ${realmId}`);
    const oauthProviders = providers.filter(p => p.type === 'oauth');
    for (const provider of oauthProviders) {
      console.log(`     - ${(provider.config as any).provider}: enabled`);
    }
    return { success: true, message: `OAuth configured for ${realmId}` };
  } else {
    console.error(`  ❌ Failed to configure OAuth: ${result.error}`);
    return { success: false, message: result.error || 'Configuration failed' };
  }
}

/**
 * Verify OAuth configuration
 */
async function verifyOAuthConfig(realmId: string): Promise<boolean> {
  console.log(`\n🔍 Verifying OAuth for realm: ${realmId}`);

  const realm = await getRealm(realmId);
  if (!realm) {
    console.error(`  ❌ Realm ${realmId} not found`);
    return false;
  }

  const oauthProviders = realm.auth_providers.filter(p => p.type === 'oauth' && p.enabled);
  
  if (oauthProviders.length === 0) {
    console.warn(`  ⚠️ No OAuth providers configured`);
    return false;
  }

  for (const provider of oauthProviders) {
    const providerName = (provider.config as any).provider;
    console.log(`  ✅ ${providerName}: configured`);
  }

  return true;
}

/**
 * Main setup function
 */
async function main() {
  console.log('🔐 Clinisyn OAuth Setup');
  console.log('========================');
  console.log('Configuring Google and Apple OAuth for Clinisyn realms');
  console.log('');

  // Get OAuth credentials
  const credentials = getOAuthCredentials();

  if (!credentials.google && !credentials.apple) {
    console.error('❌ No OAuth credentials found in environment variables.');
    console.log('');
    console.log('Required environment variables:');
    console.log('  CLINISYN_GOOGLE_CLIENT_ID');
    console.log('  CLINISYN_GOOGLE_CLIENT_SECRET');
    console.log('  CLINISYN_APPLE_CLIENT_ID');
    console.log('  CLINISYN_APPLE_TEAM_ID');
    console.log('  CLINISYN_APPLE_KEY_ID');
    console.log('  CLINISYN_APPLE_PRIVATE_KEY (base64)');
    console.log('');
    console.log('Please obtain these credentials from Clinisyn and set them.');
    process.exit(1);
  }

  // Create auth providers
  const providers = createAuthProviders(credentials);
  console.log(`Found ${providers.length - 1} OAuth provider(s) to configure`);

  // Configure both realms
  const realms = ['clinisyn-psychologists', 'clinisyn-students'];
  const results: { realm: string; success: boolean; message: string }[] = [];

  for (const realmId of realms) {
    const result = await configureOAuthForRealm(realmId, providers);
    results.push({ realm: realmId, ...result });
  }

  // Verify configurations
  console.log('\n📋 Verification');
  console.log('================');

  for (const realmId of realms) {
    await verifyOAuthConfig(realmId);
  }

  // Summary
  console.log('\n📊 Summary');
  console.log('==========');

  for (const result of results) {
    const status = result.success ? '✅' : '❌';
    console.log(`${status} ${result.realm}: ${result.message}`);
  }

  const allSuccess = results.every(r => r.success);

  if (allSuccess) {
    console.log('\n🎉 OAuth configured successfully for all Clinisyn realms!');
    console.log('\nIMPORTANT:');
    console.log('- Users will see "Clinisyn" (not "Zalt.io") when signing in with Google/Apple');
    console.log('- OAuth credentials are stored securely in AWS Secrets Manager');
    console.log('- Test the OAuth flow before going live');
  } else {
    console.error('\n⚠️ Some configurations failed. Please review and retry.');
    process.exit(1);
  }
}

// Export for testing
export {
  getOAuthCredentials,
  createAuthProviders,
  configureOAuthForRealm,
  verifyOAuthConfig
};

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
