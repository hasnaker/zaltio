# HSD Finans Platform - Zalt İhtiyaç Raporu (CTO Düzeyi)

**Tarih:** 28 Ocak 2026  
**Hazırlayan:** HSD Finans Platform CTO  
**Proje:** Multi-tenant Finans/Ön Muhasebe Platformu  
**Durum:** Production-Ready (20/20 modül tamamlandı)

---

## 📊 Executive Summary

HSD Finans Platform, Türkiye pazarı için geliştirilmiş enterprise-grade bir multi-tenant finans ve ön muhasebe platformudur. Zalt entegrasyonu tamamlanmış durumda, ancak **production deployment için Zalt tarafından sağlanması gereken kritik öğeler** bulunmaktadır.

| Metrik | Değer |
|--------|-------|
| Platform Durumu | ✅ Production-Ready |
| Zalt Entegrasyonu | ✅ Kod tamamlandı |
| E2E Testler | 232/234 geçiyor |
| Beklenen Kullanıcı | 10,000+ |
| Beklenen Tenant | 1,000+ |

---

## 🔴 KRİTİK İHTİYAÇLAR (Production Blocker)

### 1. Zalt Realm Oluşturma

**İhtiyaç:** `finans-platform` veya `tediyat` adında bir realm oluşturulması

**Detaylar:**
```yaml
Realm Adı: finans-platform (veya tediyat)
Tip: Multi-tenant SaaS
Bölge: EU (Frankfurt) - KVKK/GDPR uyumu için
```

**Neden Kritik:** Realm olmadan hiçbir auth işlemi çalışmaz.

---

### 2. OAuth Credentials

**İhtiyaç:** Backend ve frontend için OAuth client credentials

**Backend Client:**
```env
ZALT_CLIENT_ID=finans-platform-backend
ZALT_CLIENT_SECRET=xxx (güvenli şekilde iletilmeli)
```

**Frontend Client:**
```env
NEXT_PUBLIC_ZALT_CLIENT_ID=finans-platform-web
# Client secret frontend'de kullanılmaz
```

**Neden Kritik:** API çağrıları için zorunlu.

---

### 3. JWKS Endpoint Erişimi

**İhtiyaç:** JWT doğrulama için public key endpoint'i

**Beklenen URL:**
```
https://api.zalt.io/.well-known/jwks.json
```

**Veya realm-specific:**
```
https://api.zalt.io/realms/finans-platform/.well-known/jwks.json
```

**Neden Kritik:** Backend JWT verification için zorunlu.

---

### 4. Webhook Secret

**İhtiyaç:** Webhook imza doğrulama için secret key

```env
ZALT_WEBHOOK_SECRET=xxx
```

**Neden Kritik:** User/tenant sync için webhook'lar kullanılacak.

---

## 🟡 YÜKSEK ÖNCELİKLİ İHTİYAÇLAR

### 5. API Base URL Onayı

**Soru:** Production API URL'i nedir?

**Mevcut Varsayım:**
```
https://api.zalt.io/v1/tediyat
```

**Alternatif:**
```
https://api.zalt.io/v1/finans-platform
https://api.zalt.io/realms/finans-platform/api/v1
```

---

### 6. JWT Token Payload Yapısı

**Mevcut Implementasyonumuz:**
```typescript
interface ZaltJwtPayload {
  sub: string;           // User ID
  email: string;
  realm_id: string;      // finans-platform
  tenant_id: string;     // Aktif tenant
  tenant_ids: string[];  // Tüm tenant'lar
  roles: string[];       // Tenant-specific roller
  permissions: string[]; // Flatten yetkiler
  session_id: string;
  iat: number;
  exp: number;
}
```

**Soru:** Bu yapı Zalt'ın döndüreceği JWT ile uyumlu mu?

---

### 7. Token Süreleri

**Beklentimiz:**
| Token Tipi | Süre |
|------------|------|
| Access Token | 1 saat (3600s) |
| Refresh Token | 30 gün |
| 2FA Temp Token | 5 dakika |
| Password Reset | 1 saat |
| Email Verification | 24 saat |

**Soru:** Bu süreler konfigüre edilebilir mi?

---

### 8. Rate Limiting Bilgisi

**Beklentimiz:**
| Endpoint | Limit |
|----------|-------|
| Login | 5/dakika/IP |
| Register | 3/dakika/IP |
| Password Reset | 3/saat/email |
| API Genel | 100/dakika/user |

**Soru:** Gerçek limitler nedir? Header'larda dönüyor mu?

---

## 🟢 ORTA ÖNCELİKLİ İHTİYAÇLAR

### 9. Webhook Event Listesi

**İhtiyacımız olan event'ler:**

| Event | Kullanım |
|-------|----------|
| `user.created` | DB'de user kaydı oluşturma |
| `user.updated` | User bilgilerini sync |
| `user.deleted` | User soft-delete |
| `tenant.created` | Tenant kaydı oluşturma |
| `member.joined` | Tenant-user ilişkisi |
| `member.removed` | İlişki kaldırma |
| `session.created` | Audit log |
| `session.revoked` | Audit log |

**Soru:** Bu event'ler destekleniyor mu? Payload formatı nedir?

---

### 10. User Migration Desteği

**Mevcut Durum:**
- ~100 test kullanıcısı var
- bcrypt ile hash'lenmiş şifreler
- Tenant-user ilişkileri mevcut

**İhtiyaç:**
1. bcrypt hash'leri Zalt'a import edebilme
2. Veya lazy migration (ilk login'de hash upgrade)

**Soru:** Hangi yöntem destekleniyor?

---

### 11. Custom Role Desteği

**İhtiyaç:** Tenant bazında özel rol oluşturabilme

**Örnek:**
```json
{
  "name": "Satış Müdürü",
  "slug": "sales-manager",
  "permissions": ["invoices:read", "invoices:create", "reports:read"]
}
```

**Soru:** Custom role API'si mevcut mu?

---

### 12. Permission Listesi Onayı

**Bizim tanımladığımız permission'lar:**

```
# Fatura
invoices:read, invoices:create, invoices:update, invoices:delete, invoices:*

# Cari Hesap
accounts:read, accounts:create, accounts:update, accounts:delete, accounts:*

# Kasa/Banka
cash:read, cash:write
bank:read, bank:write, bank:connect, bank:transfer

# Raporlar
reports:read, reports:export

# Stok
inventory:read, inventory:write

# e-Dönüşüm
e-invoice:read, e-invoice:send

# Ayarlar
settings:read, settings:write

# Kullanıcı Yönetimi
users:read, users:invite, users:manage

# Audit
audit:read, audit:export
```

**Soru:** Bu permission'lar Zalt'ta tanımlanmalı mı, yoksa JWT'de custom claim olarak mı geçecek?

---

## 📋 ENTEGRASYON CHECKLIST

### Zalt Tarafından Sağlanacaklar

| # | Öğe | Durum | Öncelik |
|---|-----|-------|---------|
| 1 | Realm oluşturma | ⏳ Bekleniyor | P0 |
| 2 | Backend client credentials | ⏳ Bekleniyor | P0 |
| 3 | Frontend client ID | ⏳ Bekleniyor | P0 |
| 4 | JWKS endpoint URL | ⏳ Bekleniyor | P0 |
| 5 | Webhook secret | ⏳ Bekleniyor | P0 |
| 6 | API base URL onayı | ⏳ Bekleniyor | P1 |
| 7 | JWT payload yapısı onayı | ⏳ Bekleniyor | P1 |
| 8 | Token süreleri bilgisi | ⏳ Bekleniyor | P1 |
| 9 | Rate limit bilgisi | ⏳ Bekleniyor | P2 |
| 10 | Webhook event listesi | ⏳ Bekleniyor | P2 |
| 11 | User migration yöntemi | ⏳ Bekleniyor | P2 |
| 12 | Custom role API | ⏳ Bekleniyor | P2 |

### Bizim Tarafımızda Hazır Olanlar

| # | Öğe | Durum |
|---|-----|-------|
| 1 | ZaltClientService | ✅ Tamamlandı |
| 2 | JwtVerificationService | ✅ Tamamlandı |
| 3 | ZaltAuthGuard | ✅ Tamamlandı |
| 4 | PermissionGuard | ✅ Tamamlandı |
| 5 | Auth Controller (proxy) | ✅ Tamamlandı |
| 6 | Frontend auth service | ✅ Tamamlandı |
| 7 | Tenant switching | ✅ Tamamlandı |
| 8 | Session management | ✅ Tamamlandı |
| 9 | 2FA support | ✅ Tamamlandı |
| 10 | Migration service | ✅ Tamamlandı |

---

## 🔧 TEKNİK DETAYLAR

### Mevcut Environment Variables

```env
# Backend (.env)
ZALT_BASE_URL=https://api.zalt.io/v1/tediyat
ZALT_REALM=finans-platform
ZALT_CLIENT_ID=finans-platform-backend
ZALT_CLIENT_SECRET=xxx  # Bekleniyor
ZALT_JWKS_URL=https://api.zalt.io/.well-known/jwks.json
ZALT_WEBHOOK_SECRET=xxx  # Bekleniyor

# Frontend (.env.local)
NEXT_PUBLIC_ZALT_BASE_URL=https://api.zalt.io/v1/tediyat
NEXT_PUBLIC_ZALT_REALM=finans-platform
NEXT_PUBLIC_ZALT_CLIENT_ID=finans-platform-web
```

### Development Mode

Şu an `ZALT_CLIENT_SECRET` boş olduğunda development mode aktif:
- Mock JWT token üretiliyor
- Mock user/tenant data dönüyor
- Tüm auth flow'lar simüle ediliyor

**Production'a geçiş için sadece credentials gerekli.**

---

## 📞 İLETİŞİM

### Teknik Sorular İçin

Zalt ekibine iletilecek sorular:

1. **Realm Setup:** Realm oluşturma süreci nasıl işliyor?
2. **Credentials:** Client ID/Secret nasıl iletilecek? (Güvenli kanal)
3. **Documentation:** Güncel API dokümantasyonu var mı?
4. **Sandbox:** Test ortamı mevcut mu?
5. **SLA:** Uptime garantisi nedir?
6. **Support:** Teknik destek kanalı nedir?

### Proje Bilgileri

- **Proje:** HSD Finans Platform
- **Stack:** NestJS + Next.js + PostgreSQL
- **Deployment:** AWS (eu-central-1)
- **Timeline:** Production-ready, credentials bekleniyor

---

## 📎 EKLER

### İlgili Dokümanlar

1. `docs/ZALT-API-DOCUMENTATION.md` - API kullanım örnekleri
2. `docs/ZALT-INTEGRATION-REQUIREMENTS.md` - Detaylı gereksinimler
3. `docs/ZALT-OZELLIK-LISTESI.md` - Özellik listesi
4. `.kiro/specs/zalt-integration/` - Spec dosyaları

### Kod Referansları

1. `finans-platform/src/modules/core-platform/zalt/` - Zalt modülü
2. `finans-platform-web/src/services/auth.service.ts` - Frontend auth
3. `finans-platform-web/src/contexts/TenantContext.tsx` - Tenant yönetimi

---

*Bu rapor Zalt ekibi ile paylaşılmak üzere hazırlanmıştır.*
*Son Güncelleme: 28 Ocak 2026*
