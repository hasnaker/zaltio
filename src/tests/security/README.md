# 🔒 HSD Auth Platform - Security Testing Suite

Kapsamlı güvenlik test altyapısı ve dokümantasyonu.

## 📁 Klasör Yapısı

```
src/tests/security/
├── owasp/                    # OWASP Top 10 testleri
│   ├── injection.test.ts     # SQL, NoSQL, Command Injection
│   ├── xss.test.ts           # Cross-Site Scripting
│   ├── authentication.test.ts # Authentication failures
│   ├── access-control.test.ts # Broken Access Control
│   ├── cryptographic.test.ts  # Cryptographic failures
│   ├── csrf.test.ts          # Cross-Site Request Forgery
│   └── ssrf.test.ts          # Server-Side Request Forgery
├── penetration/              # Penetration testleri
│   └── api-security.test.ts  # API güvenlik testleri
├── vulnerability/            # Zafiyet taramaları
│   ├── session-hijacking.test.ts  # Session security tests
│   ├── business-logic.test.ts     # Business logic vulnerabilities
│   ├── timing-attacks.test.ts     # Timing side-channel attacks
│   ├── file-upload.test.ts        # File upload security
│   ├── jwt-security.test.ts       # JWT vulnerabilities
│   └── rate-limiting.test.ts      # Rate limiting & DDoS protection
├── compliance/               # Uyumluluk testleri
│   └── gdpr-checklist.test.ts # GDPR uyumluluk
└── reports/                  # Güvenlik raporları
    ├── SECURITY_ASSESSMENT_REPORT.md
    └── VULNERABILITY_TRACKER.md
```

## 🚀 Testleri Çalıştırma

### Tüm Güvenlik Testleri
```bash
npm run test:security
```

### OWASP Testleri
```bash
npm run test -- --testPathPattern=security/owasp
```

### Penetration Testleri
```bash
npm run test -- --testPathPattern=security/penetration
```

### Compliance Testleri
```bash
npm run test -- --testPathPattern=security/compliance
```

## 📊 Test Kategorileri

### OWASP Top 10 2021

| Kategori | Test Dosyası | Kapsam |
|----------|--------------|--------|
| A01 Broken Access Control | `access-control.test.ts`, `csrf.test.ts` | IDOR, Privilege Escalation, CSRF |
| A02 Cryptographic Failures | `cryptographic.test.ts`, `timing-attacks.test.ts` | Encryption, Key Management, Timing Attacks |
| A03 Injection | `injection.test.ts`, `xss.test.ts` | SQLi, XSS, Command Injection |
| A04 Insecure Design | `business-logic.test.ts`, `file-upload.test.ts` | Business Logic, File Upload |
| A07 Auth Failures | `authentication.test.ts`, `jwt-security.test.ts`, `session-hijacking.test.ts` | Brute Force, JWT, Session Security |
| A10 SSRF | `ssrf.test.ts` | Server-Side Request Forgery |

### Vulnerability Testing

| Test | Açıklama |
|------|----------|
| Session Hijacking | Session fixation, cookie security, fingerprinting |
| Business Logic | State machine, privilege escalation, race conditions |
| Timing Attacks | Constant-time comparison, enumeration prevention |
| File Upload | Extension validation, MIME type, path traversal |
| JWT Security | Algorithm confusion, token replay, claim injection |
| Rate Limiting | Token bucket, sliding window, DDoS protection |

### Penetration Testing

| Test | Açıklama |
|------|----------|
| API Security | Header, JWT, Rate Limiting |
| Input Validation | Payload testing |
| Error Handling | Information leakage |

### Compliance

| Standard | Test Dosyası |
|----------|--------------|
| GDPR | `gdpr-checklist.test.ts` |

## 🔧 Araçlar

### Otomatik Tarama
- **OWASP ZAP**: Otomatik vulnerability scanning
- **npm audit**: Dependency vulnerabilities
- **Snyk**: Security scanning

### Manuel Test
- **Burp Suite**: Proxy-based testing
- **Postman**: API testing
- **curl**: Command-line testing

## 📝 Rapor Oluşturma

```bash
# Test sonuçlarını JSON olarak kaydet
npm run test:security -- --json --outputFile=security-results.json

# Coverage raporu
npm run test:security -- --coverage
```

## ⚠️ Önemli Notlar

1. **Production'da çalıştırmayın** - Bu testler sadece development/staging ortamında çalıştırılmalıdır
2. **Sonuçları paylaşmayın** - Güvenlik test sonuçları gizli tutulmalıdır
3. **Düzenli çalıştırın** - Her release öncesi güvenlik testleri çalıştırılmalıdır

## 📞 İletişim

Güvenlik açığı bildirimi: security@hsdcore.com
