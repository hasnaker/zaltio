# Implementation Plan: Zalt SaaS Platform

## Overview

Zalt.io'yu Clinisyn'in (ve diğer müşterilerin) kullanabileceği tam çalışan SaaS platformuna dönüştürme.

## Priority Order

1. **P0 - Kritik**: SDK çalışsın, müşteri register olsun, end-user login olsun
2. **P1 - Önemli**: Usage tracking, billing
3. **P2 - Nice to have**: Advanced analytics, webhooks

## Tasks

### Phase 1: Customer Account System (P0)

- [x] 1. DynamoDB: Customer & API Key Tables
  - [x] 1.1 zalt-customers tablosu oluştur
    - PK: CUSTOMER#{customer_id}
    - Attributes: email, password_hash, company_name, plan, stripe_customer_id
    - GSI: email-index (email → customer_id)
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Customers
    - _Requirements: 1.2, 1.5_
  - [x] 1.2 zalt-api-keys tablosu oluştur
    - PK: KEY#{key_id}
    - SK: CUSTOMER#{customer_id}
    - Attributes: type, key_prefix, key_hash, name, status, realm_id
    - GSI: customer-index (customer_id → keys)
    - GSI: key-prefix-index (key_prefix → key details)
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - API Keys
    - _Requirements: 4.1, 4.2_

- [x] 2. Backend: Customer Auth Handlers
  - [x] 2.1 customer-register handler
    - POST /platform/register
    - Create customer, hash password, create default realm
    - Generate pk_live_xxx and sk_live_xxx
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Platform register
    - _Requirements: 1.2, 1.3, 1.4_
  - [x] 2.2 customer-login handler
    - POST /platform/login
    - Verify credentials, return JWT for dashboard
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Platform login
    - _Requirements: 2.1_
  - [x] 2.3 customer-me handler
    - GET /platform/me
    - Return customer info, realms, usage
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Platform me
    - _Requirements: 2.2_

- [x] 3. Backend: API Key Handlers
  - [x] 3.1 api-keys CRUD handler
    - GET /platform/api-keys - list keys
    - POST /platform/api-keys - create key
    - DELETE /platform/api-keys/{id} - revoke key
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - API Keys CRUD
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - [x] 3.2 API key validation middleware
    - Validate pk_live_xxx for SDK requests
    - Validate sk_live_xxx for backend requests
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - API Key validation
    - _Requirements: 5.2_

### Phase 2: SDK ↔ Backend Connection (P0)

- [x] 4. @zalt.io/core: Real API Connection
  - [x] 4.1 ZaltClient - publishableKey ile initialize
    - api.zalt.io endpoint'lerine bağlan
    - Publishable key header'da gönder
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md`
    - _Requirements: 5.1, 5.2_
  - [x] 4.2 Auth methods - gerçek API çağrıları
    - login() → POST /login
    - register() → POST /register
    - logout() → POST /logout
    - getUser() → GET /me
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Auth methods
    - _Requirements: 5.3, 5.4, 5.5_
  - [x] 4.3 Token management
    - Access token storage
    - Refresh token rotation
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Token management
    - _Requirements: 5.4_

- [x] 5. @zalt.io/react: Working Components
  - [x] 5.1 ZaltProvider - real connection
    - publishableKey prop
    - API client initialization
    - Auth state management
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md`
    - _Requirements: 5.2_
  - [x] 5.2 useUser hook - real data
    - Fetch user from API
    - Cache and update
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useUser
    - _Requirements: 5.6_
  - [x] 5.3 useAuth hook - real state
    - isSignedIn, isLoaded
    - signIn, signOut methods
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useAuth
    - _Requirements: 5.7_
  - [x] 5.4 SignInButton - working login
    - Open login modal or redirect
    - Handle OAuth flow
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - SignInButton
    - _Requirements: 5.3_
  - [x] 5.5 UserButton - working profile
    - Show user info
    - Logout functionality
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - UserButton
    - _Requirements: 5.5_

- [x] 6. Checkpoint: End-to-End Test
  - [x] 6.1 Customer signup test
    - zalt.io/signup → account created
    - Realm + API keys generated
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
  - [x] 6.2 SDK integration test
    - npm install @zalt.io/react
    - ZaltProvider with publishableKey
    - SignInButton → login works
    - useUser → returns real user
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
  - [x] 6.3 End-user flow test
    - End-user registers in customer's realm
    - End-user logs in
    - Session created in Zalt
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki phase'e geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

### Phase 3: Dashboard API Integration (P0)

- [x] 7. Dashboard: Real API Calls
  - [x] 7.1 /api/auth/* - customer auth
    - signup → POST /platform/register ✅
    - login → POST /platform/login ✅
    - me → GET /platform/me ✅
    - logout → POST /platform/logout ✅
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Auth API
    - _Requirements: 1.2, 2.1_
  - [x] 7.2 /api/dashboard/* - real data
    - realms → GET /platform/realms ✅
    - users → Uses admin API (realm-scoped)
    - sessions → Uses admin API (realm-scoped)
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Dashboard API
    - _Requirements: 2.2, 2.3_
  - [x] 7.3 /api/settings/* - real settings
    - api-keys → /platform/api-keys ✅
    - billing → /platform/billing ✅
    - profile → /platform/me ✅
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki phase'e geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Settings API
    - _Requirements: 4.1_

### Phase 4: Usage Tracking (P1)

- [x] 8. Usage Tracking System
  - [x] 8.1 zalt-usage tablosu
    - PK: CUSTOMER#{customer_id}
    - SK: MONTH#{yyyy-mm} or DAY#{yyyy-mm-dd}
    - Attributes: mau, api_calls, realms
    - Model: `src/models/usage.model.ts` ✅
    - Repository: `src/repositories/usage.repository.ts` ✅
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Usage
    - _Requirements: 7.1, 7.2, 7.3_
  - [x] 8.2 MAU calculation
    - Track unique user logins per month
    - Aggregate daily → monthly
    - Service: `src/services/usage.service.ts` ✅
    - Handler: `src/handlers/platform/usage.handler.ts` ✅
    - Tests: 22 passing ✅
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - MAU
    - _Requirements: 7.1_
  - [x] 8.3 Usage limits enforcement
    - Check limits on register/login
    - Warn when approaching limit (80%)
    - Block when exceeded (110% with grace)
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki phase'e geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Usage limits
    - _Requirements: 7.4, 7.5_

### Phase 5: Billing (P1)

- [x] 9. Stripe Integration
  - [x] 9.1 Stripe account setup
    - Products: Free, Pro ($49), Enterprise ($299)
    - Prices: monthly recurring
    - Dashboard config: `dashboard/src/lib/stripe.ts` ✅
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
  - [x] 9.2 Checkout endpoint
    - POST /platform/billing/checkout
    - Create Stripe checkout session
    - Handler: `src/handlers/platform/billing.handler.ts` ✅
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Billing checkout
    - _Requirements: 8.3_
  - [x] 9.3 Webhook handler
    - checkout.session.completed → upgrade plan
    - invoice.paid → record payment
    - customer.subscription.deleted → downgrade
    - Handler: `src/handlers/platform/billing-webhook.handler.ts` ✅
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Billing webhooks
    - _Requirements: 8.4, 8.5_
  - [x] 9.4 Customer portal
    - POST /platform/billing/portal
    - Redirect to Stripe portal
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki phase'e geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Billing portal
    - _Requirements: 8.2_

### Phase 6: Analytics (P2)

- [x] 10. Analytics Dashboard
  - [x] 10.1 Daily active users chart
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Analytics
    - _Requirements: 9.1_
  - [x] 10.2 Login success/failure rates
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Analytics
    - _Requirements: 9.2_
  - [x] 10.3 MFA adoption rate
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Final checkpoint'e geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Analytics
    - _Requirements: 9.3_

- [x] 11. Final Checkpoint
  - Ensure all tests pass, ask the user if questions arise.
  - Verify Clinisyn onboarding works
  - Ready for production
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Production deploy'a geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

## Clinisyn Onboarding Checklist

When Clinisyn signs up:
- [ ] Account created with company name "Clinisyn"
- [ ] Default realm "clinisyn" created
- [ ] API keys generated
- [ ] Plan set to Enterprise (manual)
- [ ] MFA policy set to webauthn_only (HIPAA)
- [ ] SDK integration guide sent

## API Endpoints Summary

### Platform (Customer) APIs
```
POST /platform/register     - Customer signup
POST /platform/login        - Customer login
GET  /platform/me           - Customer profile
GET  /platform/realms       - List realms
POST /platform/realms       - Create realm
GET  /platform/api-keys     - List API keys
POST /platform/api-keys     - Create API key
DELETE /platform/api-keys/{id} - Revoke key
GET  /platform/usage        - Usage stats
POST /platform/billing/checkout - Stripe checkout
POST /platform/billing/portal   - Stripe portal
```

### End-User APIs (existing)
```
POST /register              - End-user signup
POST /login                 - End-user login
POST /logout                - End-user logout
GET  /me                    - End-user profile
POST /refresh               - Token refresh
```

## Notes

- Phase 1-3 kritik, Clinisyn için bunlar lazım
- Phase 4-5 billing için, başta manual takip edilebilir
- Phase 6 nice to have, sonra eklenebilir
- All property-based tests are REQUIRED (not optional)
- Each task references specific requirements for traceability