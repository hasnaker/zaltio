/**
 * Clinisyn Realm Setup Script
 * TEK REALM YAKLAŞIMI - Profesyonel standart (Auth0, Okta, Clerk gibi)
 * 
 * Realm: clinisyn
 * Roller: user.profile.metadata.clinisyn_role ile yönetilir
 * 
 * ⚠️ MFA ZORUNLU - Tüm kullanıcılar için! (Siberci kararı)
 * 
 * Run: npx ts-node scripts/clinisyn-realm-setup.ts
 */

import { createRealm, getRealm, updateRealm } from '../src/services/realm.service';
import { MfaPolicy, RealmSettings } from '../src/models/realm.model';

// Clinisyn Tek Realm Configuration
const CLINISYN_REALM_CONFIG = {
  id: 'clinisyn',
  name: 'Clinisyn Healthcare Platform',
  domain: 'clinisyn.com',
  settings: {
    // MFA Configuration - ZORUNLU
    mfa_config: {
      policy: 'required' as MfaPolicy,
      allowed_methods: ['totp', 'webauthn'],
      remember_device_days: 7,
      grace_period_hours: 72, // 3 gün MFA kurulum süresi
      require_webauthn_for_sensitive: true // Healthcare: WebAuthn önerilir
    },
    
    // Password Policy - HIPAA uyumlu
    password_policy: {
      min_length: 12,
      require_uppercase: true,
      require_lowercase: true,
      require_numbers: true,
      require_special_chars: true
    },
    
    // Session Configuration
    session_timeout: 1800, // 30 dakika idle timeout (HIPAA)
    
    // CORS - Allowed Origins
    allowed_origins: [
      // Production
      'https://clinisyn.com',
      'https://www.clinisyn.com',
      'https://app.clinisyn.com',
      'https://portal.clinisyn.com',
      'https://admin.clinisyn.com',
      'https://student.clinisyn.com',
      // Staging
      'https://staging.clinisyn.com',
      'https://staging-app.clinisyn.com',
      'https://staging-portal.clinisyn.com',
      'https://staging-admin.clinisyn.com',
      // Development (production'da kaldırılacak)
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173'
    ],
    
    // Rate Limiting - Ayrı middleware'de yönetilir
    
    // Account Lockout - Ayrı service'de yönetilir
    // Deprecated but kept for compatibility
    mfa_required: true
  } as Partial<RealmSettings>
};

// NOT: Audit logging ve OAuth providers ayrı tablolarda yönetilir
// - Audit: AuditLog tablosu (otomatik)
// - OAuth: AWS Secrets Manager (clinisyn/oauth/*)

/**
 * Setup Clinisyn realm
 */
async function setupClinsynRealm(): Promise<{ success: boolean; message: string }> {
  console.log('\n🏥 Clinisyn Realm Setup');
  console.log('========================');
  console.log('TEK REALM YAKLAŞIMI - Profesyonel standart');
  console.log('');
  
  const { id, name, domain, settings } = CLINISYN_REALM_CONFIG;
  
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
  
  const realm = await getRealm(CLINISYN_REALM_CONFIG.id);
  
  if (!realm) {
    console.error('❌ Realm bulunamadı');
    return false;
  }
  
  // Verify MFA policy
  const mfaPolicy = realm.settings.mfa_config?.policy;
  if (mfaPolicy !== 'required') {
    console.error(`❌ MFA policy hatalı: ${mfaPolicy} (beklenen: required)`);
    return false;
  }
  console.log('✅ MFA Policy: required');
  
  // Verify password policy
  const minLength = realm.settings.password_policy?.min_length;
  if (minLength !== 12) {
    console.error(`❌ Password min length hatalı: ${minLength} (beklenen: 12)`);
    return false;
  }
  console.log('✅ Password Policy: 12+ karakter');
  
  // Verify session timeout
  const sessionTimeout = realm.settings.session_timeout;
  if (sessionTimeout !== 1800) {
    console.error(`❌ Session timeout hatalı: ${sessionTimeout} (beklenen: 1800)`);
    return false;
  }
  console.log('✅ Session Timeout: 30 dakika');
  
  // Verify CORS origins
  const origins = realm.settings.allowed_origins || [];
  console.log(`✅ CORS Origins: ${origins.length} adet`);
  
  return true;
}

/**
 * Main function
 */
async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║           CLINISYN REALM SETUP - TEK REALM                 ║');
  console.log('║                                                            ║');
  console.log('║  Realm ID: clinisyn                                        ║');
  console.log('║  MFA: ZORUNLU (TOTP + WebAuthn)                           ║');
  console.log('║  Session: 30 dk idle, 8 saat max                          ║');
  console.log('║  Audit: HIPAA/KVKK uyumlu                                 ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  // Setup realm
  const setupResult = await setupClinsynRealm();
  
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
  console.log('║  Clinisyn realm hazır!                                     ║');
  console.log('║                                                            ║');
  console.log('║  Kullanıcı Rolleri (metadata.clinisyn_role):              ║');
  console.log('║  • root_admin     - Tam yetki                             ║');
  console.log('║  • admin          - Content, Ads, Manager                 ║');
  console.log('║  • seo_admin      - SEO yönetimi                          ║');
  console.log('║  • psychologist   - Psikolog/Danışman                     ║');
  console.log('║  • student        - Öğrenci                               ║');
  console.log('║  • client         - Danışan/Hasta                         ║');
  console.log('║  • clinic_owner   - Klinik sahibi                         ║');
  console.log('║  • clinic_manager - Şube yöneticisi                       ║');
  console.log('║  • clinic_staff   - Asistan, muhasebe                     ║');
  console.log('║                                                            ║');
  console.log('║  Sonraki adımlar:                                          ║');
  console.log('║  1. OAuth credentials kontrol et                          ║');
  console.log('║  2. Clerk migration çalıştır                              ║');
  console.log('║  3. SDK entegrasyonu test et                              ║');
  console.log('║                                                            ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
}

// Export for testing
export { CLINISYN_REALM_CONFIG, setupClinsynRealm, verifyRealm };

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
