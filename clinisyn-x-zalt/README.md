# Clinisyn x Zalt.io Integration Guide

**Healthcare Authentication Platform**
**4000+ Psikolog | 11 Ülke | HIPAA/GDPR Uyumlu**

## 🎯 Hızlı Başlangıç

```bash
# API Endpoint
https://api.zalt.io

# Realm ID
clinisyn
```

## 📋 Test Sonuçları (27 Ocak 2026)

| Test | Durum | Açıklama |
|------|-------|----------|
| Health Check | ✅ PASS | API sağlıklı, eu-central-1 |
| Login | ✅ PASS | Argon2id + KMS RS256 |
| Token Refresh | ✅ PASS | 30s grace period |
| Logout | ✅ PASS | Session sonlandırma |
| TOTP MFA Setup | ✅ PASS | QR kod + secret |
| WebAuthn Register | ✅ PASS | Passkey desteği |
| WebAuthn List | ✅ PASS | Credential listesi |
| SMS MFA Warning | ✅ PASS | Türkçe uyarı |
| Password Reset | ✅ PASS | Email gönderimi |
| JWKS Endpoint | ✅ PASS | RS256 public key |
| OpenID Config | ✅ PASS | OIDC discovery |
| Rate Limiting | ✅ PASS | 5 deneme/15dk |
| Email Enumeration | ✅ PASS | Korumalı |

## 📁 Klasör Yapısı

```
clinisyn-x-zalt/
├── README.md                 # Bu dosya
├── tests/                    # Test scriptleri
│   ├── run-all-tests.sh     # Tüm testleri çalıştır
│   └── test-results.json    # Son test sonuçları
├── examples/                 # Kod örnekleri
│   ├── nextjs/              # Next.js entegrasyonu
│   ├── react/               # React entegrasyonu
│   └── node/                # Node.js backend
└── troubleshooting/         # Sorun giderme
    ├── common-errors.md     # Sık karşılaşılan hatalar
    └── debug-guide.md       # Debug rehberi
```

## 🔐 Güvenlik Özellikleri

### Şifre Güvenliği
- **Algoritma:** Argon2id (OWASP önerisi)
- **Memory:** 32MB
- **Iterations:** 5
- **Parallelism:** 2

### Token Güvenliği
- **JWT Algoritması:** RS256 (FIPS-140-2 uyumlu)
- **Access Token:** 15 dakika
- **Refresh Token:** 7 gün
- **Grace Period:** 30 saniye (network retry)

### MFA Seçenekleri
1. **WebAuthn/Passkeys** (Önerilen - Phishing-proof)
2. **TOTP** (Google Authenticator)
3. **SMS** (Risk kabul gerekli)

## 🚀 Entegrasyon

Detaylı örnekler için `examples/` klasörüne bakın.

### Hızlı Login Örneği

```typescript
const response = await fetch('https://api.zalt.io/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    realm_id: 'clinisyn',
    email: 'user@clinisyn.com',
    password: 'SecurePass123!'
  })
});

const { tokens, user } = await response.json();
// tokens.access_token - API istekleri için
// tokens.refresh_token - Token yenileme için
```

## 📞 Destek

- **Teknik Destek:** support@zalt.io
- **Dokümantasyon:** https://docs.zalt.io
- **Status Page:** https://status.zalt.io
