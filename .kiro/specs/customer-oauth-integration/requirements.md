# Requirements Document

## Introduction

Clerk benzeri self-service müşteri deneyimi. Müşteri zalt.io'ya gelir, hesap oluşturur, dashboard'dan realm/app oluşturur, API key alır, SDK kurar ve kullanmaya başlar.

## Glossary

- **Zalt_Dashboard**: zalt.io web dashboard (mevcut: dashboard/)
- **Customer**: Zalt'ı kullanan geliştirici/şirket
- **End_User**: Müşterinin uygulamasını kullanan son kullanıcı
- **Realm**: Müşteriye ait izole authentication alanı
- **Publishable_Key**: Frontend'de kullanılan public key (pk_live_xxx)
- **Secret_Key**: Backend'de kullanılan gizli key (sk_live_xxx)

## Müşteri Akışı (Clerk Benzeri)

```
1. zalt.io'ya git
2. "Get Started" → Signup
3. Email doğrula
4. Onboarding wizard:
   - Realm oluştur (otomatik)
   - API keys al
   - SDK kurulum kodu kopyala
5. Dashboard'a git
6. Kendi uygulamasına SDK'yı entegre et
7. End-user'lar login olmaya başlar
```

## Requirements

### Requirement 1: Self-Service Signup

**User Story:** As a developer, I want to sign up for Zalt without talking to sales, so that I can start integrating immediately.

#### Acceptance Criteria

1. WHEN a developer visits zalt.io, THE Landing_Page SHALL display a prominent "Get Started" button
2. WHEN a developer clicks signup, THE System SHALL create an account with email/password
3. WHEN signup completes, THE System SHALL automatically create a default realm
4. WHEN signup completes, THE System SHALL generate publishable and secret API keys
5. WHEN signup completes, THE System SHALL redirect to onboarding wizard

### Requirement 2: Onboarding Wizard

**User Story:** As a new user, I want a guided setup, so that I can integrate Zalt quickly.

#### Acceptance Criteria

1. THE Onboarding_Wizard SHALL show 4 steps: Welcome, API Keys, Integrate, Done
2. WHEN showing API Keys step, THE Wizard SHALL display realm_id, publishable_key, and masked secret_key
3. WHEN showing Integrate step, THE Wizard SHALL show copy-paste code for @zalt.io/react
4. THE Wizard SHALL allow copying each code snippet with one click

### Requirement 3: Dashboard Realm Management

**User Story:** As a customer, I want to manage my realms, so that I can organize my applications.

#### Acceptance Criteria

1. THE Dashboard SHALL display all customer's realms with user count and session count
2. WHEN creating a new realm, THE System SHALL generate unique realm_id
3. THE Dashboard SHALL allow configuring MFA policy per realm (optional/required/webauthn_only)
4. THE Dashboard SHALL show realm status (active/suspended)

### Requirement 4: API Key Management

**User Story:** As a developer, I want to manage my API keys, so that I can rotate them securely.

#### Acceptance Criteria

1. THE Settings_Page SHALL display all API keys with name, type (live/test), and creation date
2. WHEN creating a new key, THE System SHALL generate a secure random key
3. THE System SHALL only show the full secret key once (at creation)
4. THE Dashboard SHALL allow deleting/revoking API keys

### Requirement 5: SDK Integration

**User Story:** As a developer, I want to use Zalt SDK in my app, so that I can add authentication easily.

#### Acceptance Criteria

1. THE SDK SHALL be installable via npm: `npm install @zalt.io/react`
2. THE SDK SHALL provide ZaltProvider component for wrapping the app
3. THE SDK SHALL provide SignInButton, SignUpButton, UserButton components
4. THE SDK SHALL provide useUser, useAuth hooks for accessing user state
5. WHEN user logs in via SDK, THE System SHALL create session in Zalt backend

### Requirement 6: Billing & Plans

**User Story:** As a customer, I want to see my usage and upgrade my plan, so that I can scale my application.

#### Acceptance Criteria

1. THE Billing_Page SHALL show current plan (Free/Pro/Enterprise)
2. THE Billing_Page SHALL show usage metrics (MAU, realms)
3. WHEN clicking upgrade, THE System SHALL redirect to Stripe checkout
4. THE System SHALL enforce plan limits (MAU, realm count)

## Mevcut Durum

| Bileşen | Durum | Notlar |
|---------|-------|--------|
| Landing Page | ✅ Var | dashboard/src/app/page.tsx |
| Signup | ✅ Var | dashboard/src/app/signup/page.tsx |
| Login | ✅ Var | dashboard/src/app/login/page.tsx |
| Onboarding | ✅ Var | dashboard/src/app/onboarding/page.tsx (güncellendi) |
| Realms | ✅ Var | dashboard/src/app/dashboard/realms/page.tsx |
| Settings/API Keys | ✅ Var | dashboard/src/app/dashboard/settings/page.tsx |
| Billing | ✅ Var | Settings içinde |
| SDK @zalt.io/react | ✅ npm'de | packages/react/ |
| SDK @zalt.io/next | ✅ npm'de | packages/next/ |
| SDK @zalt.io/core | ✅ npm'de | packages/core/ |
| Backend API | ✅ Var | api.zalt.io |

## Eksikler

1. **Signup → Realm Otomatik Oluşturma**: Signup sonrası otomatik realm oluşturulmuyor
2. **API Key Generation**: Gerçek API key generation backend'de yok
3. **SDK ↔ Backend Bağlantısı**: SDK'lar henüz gerçek API'ye bağlı değil
4. **Email Verification**: Signup sonrası email doğrulama akışı
5. **Stripe Integration**: Billing için Stripe entegrasyonu
