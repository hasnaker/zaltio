/**
 * Tediyat Realm Setup Script
 * Multi-tenant ön muhasebe platformu için authentication realm
 * 
 * Realm: tediyat
 * MFA: Optional (kullanıcı tercihine bırakılır)
 * Session: 1 saat (muhasebe işlemleri için uygun)
 * 
 * Run: npx ts-node scripts/tediyat-realm-setup.ts
 */

import { createRealm, getRealm, updateRealm } from '../src/services/realm.service';
import { MfaPolicy, RealmSettings, BrandingConfig } from '../src/models/realm.model';

// Tediyat Realm Configuration
const TEDIYAT_REALM_CONFIG = {
  id: 'tediyat',
  name: 'Tediyat',
  domain: 'tediyat.com',
  settings: {
    // MFA Configuration - Optional (kullanıcı tercihine bırakılır)
    mfa_config: {
      policy: 'optional' as MfaPolicy,
      allowed_methods: ['totp', 'webauthn'],
      remember_device_days: 30,
      grace_period_hours: 0, // Optional olduğu için grace period yok
      require_webauthn_for_sensitive: false
    },
    
    // Password Policy - Güçlü şifre zorunlu
    password_policy: {
      min_length: 8,
      require_uppercase: true,
      require_lowercase: true,
      require_numbers: true,
      require_special_chars: true
    },
    
    // Session Configuration - 1 saat (muhasebe işlemleri için)
    session_timeout: 3600, // 1 saat
    
    // CORS - Allowed Origins
    allowed_origins: [
      'https://tediyat.com',
      'https://www.tediyat.com',
      'https://app.tediyat.com',
      'https://api.tediyat.com',
      // Development
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173'
    ],
    
    // Branding Configuration
    branding: {
      display_name: 'Tediyat',
      primary_color: '#2563eb', // Blue
      support_email: 'destek@tediyat.com',
      email_from_name: 'Tediyat',
      privacy_policy_url: 'https://tediyat.com/gizlilik',
      terms_of_service_url: 'https://tediyat.com/kullanim-kosullari',
      app_url: 'https://app.tediyat.com'
    } as BrandingConfig,
    
    // Deprecated but kept for compatibility
    mfa_required: false
  } as Partial<RealmSettings>
};

// Tediyat Predefined Roles (tenant-level'da yönetilir)
export const TEDIYAT_SYSTEM_ROLES = {
  owner: {
    id: 'role_owner',
    name: 'Şirket Sahibi',
    description: 'Tüm yetkilere sahip şirket sahibi',
    permissions: ['*'],
    isSystem: true
  },
  admin: {
    id: 'role_admin',
    name: 'Yönetici',
    description: 'Kullanıcı yönetimi hariç tüm yetkiler',
    permissions: [
      'invoices:*', 'accounts:*', 'cash:*', 'bank:*',
      'reports:*', 'inventory:*', 'e-invoice:*',
      'settings:*', 'quotes:*', 'payments:*'
    ],
    isSystem: true
  },
  accountant: {
    id: 'role_accountant',
    name: 'Muhasebeci',
    description: 'Fatura, hesap ve raporlama yetkileri',
    permissions: [
      'invoices:read', 'invoices:create', 'invoices:update',
      'accounts:read', 'accounts:create', 'accounts:update',
      'cash:read', 'cash:write', 'bank:read', 'bank:write',
      'reports:read', 'reports:export',
      'quotes:read', 'quotes:create', 'quotes:update',
      'payments:read', 'payments:create'
    ],
    isSystem: true
  },
  viewer: {
    id: 'role_viewer',
    name: 'Görüntüleyici',
    description: 'Sadece okuma yetkisi',
    permissions: [
      'invoices:read', 'accounts:read', 'cash:read',
      'bank:read', 'reports:read', 'inventory:read',
      'quotes:read', 'payments:read'
    ],
    isSystem: true
  },
  external_accountant: {
    id: 'role_external_accountant',
    name: 'Mali Müşavir',
    description: 'Dış muhasebeci için sınırlı okuma ve export yetkileri',
    permissions: [
      'invoices:read', 'accounts:read', 'reports:read',
      'reports:export', 'e-invoice:read'
    ],
    isSystem: true
  }
};

// Tediyat Permission Categories
export const TEDIYAT_PERMISSIONS = {
  invoices: ['read', 'create', 'update', 'delete', '*'],
  accounts: ['read', 'create', 'update', 'delete', '*'],
  cash: ['read', 'write'],
  bank: ['read', 'write'],
  reports: ['read', 'export'],
  inventory: ['read', 'write'],
  'e-invoice': ['read', 'send'],
  settings: ['read', 'write'],
  users: ['read', 'invite', 'manage'],
  quotes: ['read', 'create', 'update', 'delete', '*'],
  payments: ['read', 'create', 'refund']
};

/**
 * Setup Tediyat realm
 */
async function setupTediyatRealm(): Promise<{ success: boolean; message: string }> {
  console.log('\n💰 Tediyat Realm Setup');
  console.log('========================');
  console.log('Multi-tenant ön muhasebe platformu');
  console.log('');
  
  const { id, name, domain, settings } = TEDIYAT_REALM_CONFIG;
  
  // Check if realm exists
  const existingRealm = await getRealm(id);
  
  if (existingRealm) {
    console.log(`⚠️  Realm "${id}" zaten mevcut, güncelleniyor...`);
    
    const result = await updateRealm(id, { name, settings });
    
    if (result.success) {
      console.log(`✅ Realm "${id}" güncellendi`);
      return { success: true, message: 'Realm updated' };
    } else {
      console.error(`❌ Güncelleme başarısız: ${result.error}`);
      return { success: false, message: result.error || 'Update failed' };
    }
  }
  
  // Create new realm
  console.log(`🆕 Yeni realm oluşturuluyor: ${id}`);
  
  const result = await createRealm({ name, domain, settings });
  
  if (result.success) {
    console.log(`✅ Realm "${id}" oluşturuldu`);
    return { success: true, message: 'Realm created' };
  } else {
    console.error(`❌ Oluşturma başarısız: ${result.error}`);
    return { success: false, message: result.error || 'Creation failed' };
  }
}

/**
 * Verify realm configuration
 */
async function verifyRealm(): Promise<boolean> {
  console.log('\n🔍 Realm Doğrulama');
  console.log('==================');
  
  const realm = await getRealm(TEDIYAT_REALM_CONFIG.id);
  
  if (!realm) {
    console.error('❌ Realm bulunamadı');
    return false;
  }
  
  // Verify MFA policy
  const mfaPolicy = realm.settings.mfa_config?.policy;
  if (mfaPolicy !== 'optional') {
    console.error(`❌ MFA policy hatalı: ${mfaPolicy} (beklenen: optional)`);
    return false;
  }
  console.log('✅ MFA Policy: optional');
  
  // Verify password policy
  const minLength = realm.settings.password_policy?.min_length;
  if (minLength !== 8) {
    console.error(`❌ Password min length hatalı: ${minLength} (beklenen: 8)`);
    return false;
  }
  console.log('✅ Password Policy: 8+ karakter');
  
  // Verify session timeout
  const sessionTimeout = realm.settings.session_timeout;
  if (sessionTimeout !== 3600) {
    console.error(`❌ Session timeout hatalı: ${sessionTimeout} (beklenen: 3600)`);
    return false;
  }
  console.log('✅ Session Timeout: 1 saat');
  
  // Verify CORS origins
  const origins = realm.settings.allowed_origins || [];
  const hasTediyatOrigin = origins.some(o => o.includes('tediyat.com'));
  if (!hasTediyatOrigin) {
    console.error('❌ CORS origins tediyat.com içermiyor');
    return false;
  }
  console.log(`✅ CORS Origins: ${origins.length} adet`);
  
  return true;
}

/**
 * Main function
 */
async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║           TEDIYAT REALM SETUP - MULTI-TENANT               ║');
  console.log('║                                                            ║');
  console.log('║  Realm ID: tediyat                                         ║');
  console.log('║  MFA: Optional (kullanıcı tercihine bırakılır)            ║');
  console.log('║  Session: 1 saat                                          ║');
  console.log('║  Password: 8+ karakter, özel karakter zorunlu             ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  // Setup realm
  const setupResult = await setupTediyatRealm();
  
  if (!setupResult.success) {
    console.error('\n❌ Realm setup başarısız!');
    process.exit(1);
  }
  
  // Verify configuration
  const verified = await verifyRealm();
  
  if (!verified) {
    console.error('\n❌ Realm doğrulama başarısız!');
    process.exit(1);
  }
  
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║                    ✅ BAŞARILI!                            ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║                                                            ║');
  console.log('║  Tediyat realm hazır!                                      ║');
  console.log('║                                                            ║');
  console.log('║  Predefined Roller:                                        ║');
  console.log('║  • owner              - Şirket Sahibi (tüm yetkiler)      ║');
  console.log('║  • admin              - Yönetici                          ║');
  console.log('║  • accountant         - Muhasebeci                        ║');
  console.log('║  • viewer             - Görüntüleyici                     ║');
  console.log('║  • external_accountant - Mali Müşavir                     ║');
  console.log('║                                                            ║');
  console.log('║  Permission Kategorileri:                                  ║');
  console.log('║  invoices, accounts, cash, bank, reports,                 ║');
  console.log('║  inventory, e-invoice, settings, users, quotes, payments  ║');
  console.log('║                                                            ║');
  console.log('║  Sonraki adımlar:                                          ║');
  console.log('║  1. Data models oluştur (tenant, membership, invitation)  ║');
  console.log('║  2. Services implement et                                 ║');
  console.log('║  3. Handlers implement et                                 ║');
  console.log('║                                                            ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
}

// Export for testing and other modules
export { TEDIYAT_REALM_CONFIG, setupTediyatRealm, verifyRealm };

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
