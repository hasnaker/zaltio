# Requirements Document: Zalt SaaS Platform

## Introduction

Zalt.io'yu tam çalışan bir SaaS platformuna dönüştürme. Clinisyn (ilk müşteri) dahil tüm müşteriler:
1. zalt.io'ya gelip register olacak
2. Dashboard'dan realm oluşturacak
3. API key alacak
4. SDK'yı kurup kullanacak
5. Kullanım ve ödeme takip edilecek

## Glossary

- **Platform_Admin**: Zalt.io'yu yöneten biz (HSD)
- **Customer**: Zalt'ı kullanan şirket (örn: Clinisyn)
- **End_User**: Müşterinin uygulamasındaki kullanıcı (örn: Clinisyn'in psikologları)
- **Realm**: Müşteriye ait izole auth alanı
- **MAU**: Monthly Active Users (aylık aktif kullanıcı)

## Requirements

### Requirement 1: Customer Registration

**User Story:** As Clinisyn, I want to register on zalt.io, so that I can use Zalt for my application's authentication.

#### Acceptance Criteria

1. WHEN a customer visits zalt.io, THE System SHALL display signup option
2. WHEN a customer signs up, THE System SHALL create a customer account (email, password, company name)
3. WHEN signup completes, THE System SHALL automatically create a default realm
4. WHEN signup completes, THE System SHALL generate publishable_key (pk_live_xxx) and secret_key (sk_live_xxx)
5. WHEN signup completes, THE System SHALL assign Free plan by default
6. THE System SHALL send email verification

### Requirement 2: Customer Dashboard

**User Story:** As Clinisyn, I want a dashboard to manage my authentication setup, so that I can configure and monitor my users.

#### Acceptance Criteria

1. THE Dashboard SHALL require customer login
2. THE Dashboard SHALL show overview: total users, active sessions, API calls
3. THE Dashboard SHALL allow creating/managing multiple realms
4. THE Dashboard SHALL show API keys with copy functionality
5. THE Dashboard SHALL show usage metrics (MAU, API calls)
6. THE Dashboard SHALL show billing status and plan

### Requirement 3: Realm Management

**User Story:** As Clinisyn, I want to create separate realms for different apps, so that I can isolate users.

#### Acceptance Criteria

1. WHEN creating a realm, THE System SHALL generate unique realm_id
2. THE Customer SHALL be able to configure MFA policy per realm (optional/required/webauthn_only)
3. THE Customer SHALL be able to set session timeout per realm
4. THE Customer SHALL be able to configure allowed domains (CORS)
5. THE Dashboard SHALL show user count and session count per realm

### Requirement 4: API Key Management

**User Story:** As Clinisyn, I want to manage my API keys, so that I can integrate securely and rotate keys when needed.

#### Acceptance Criteria

1. THE System SHALL provide two key types: publishable (frontend) and secret (backend)
2. WHEN generating a new key, THE System SHALL show the full key only once
3. THE Customer SHALL be able to create multiple keys with names
4. THE Customer SHALL be able to revoke/delete keys
5. THE System SHALL track last used timestamp per key

### Requirement 5: SDK Integration (Working!)

**User Story:** As Clinisyn developer, I want to install SDK and have it work immediately, so that I can add auth to my app.

#### Acceptance Criteria

1. WHEN developer runs `npm install @zalt.io/react`, THE SDK SHALL install successfully
2. WHEN developer wraps app with ZaltProvider, THE SDK SHALL connect to api.zalt.io
3. WHEN end-user clicks SignInButton, THE SDK SHALL show login modal/redirect
4. WHEN end-user logs in, THE SDK SHALL create session in Zalt backend
5. WHEN end-user logs out, THE SDK SHALL invalidate session
6. THE useUser hook SHALL return real user data from Zalt
7. THE useAuth hook SHALL return real auth state

### Requirement 6: End-User Authentication

**User Story:** As Clinisyn's end-user (psychologist), I want to login to Clinisyn app, so that I can access my account.

#### Acceptance Criteria

1. WHEN end-user registers, THE System SHALL create user in customer's realm
2. WHEN end-user logs in, THE System SHALL verify credentials and create session
3. WHEN MFA is required, THE System SHALL enforce MFA before completing login
4. WHEN end-user logs out, THE System SHALL invalidate session
5. THE System SHALL track user activity for MAU calculation

### Requirement 7: Usage Tracking

**User Story:** As Zalt platform, I want to track customer usage, so that I can bill correctly and enforce limits.

#### Acceptance Criteria

1. THE System SHALL track MAU per customer per month
2. THE System SHALL track API calls per customer
3. THE System SHALL track realm count per customer
4. WHEN customer exceeds plan limits, THE System SHALL show warning
5. WHEN customer exceeds plan limits significantly, THE System SHALL block new registrations

### Requirement 8: Billing & Subscription

**User Story:** As Clinisyn, I want to see my usage and pay for the service, so that I can continue using Zalt.

#### Acceptance Criteria

1. THE System SHALL offer plans: Free (1K MAU), Pro ($49/mo, 10K MAU), Enterprise (custom)
2. THE Dashboard SHALL show current plan and usage
3. WHEN customer clicks upgrade, THE System SHALL redirect to Stripe checkout
4. WHEN payment succeeds, THE System SHALL upgrade plan immediately
5. THE System SHALL send invoice emails via Stripe
6. WHEN subscription fails, THE System SHALL notify customer and give grace period

### Requirement 9: Analytics

**User Story:** As Clinisyn, I want to see analytics, so that I can understand my users' behavior.

#### Acceptance Criteria

1. THE Dashboard SHALL show daily/weekly/monthly active users chart
2. THE Dashboard SHALL show login success/failure rates
3. THE Dashboard SHALL show MFA adoption rate
4. THE Dashboard SHALL show geographic distribution (optional)
5. THE Dashboard SHALL show device/browser breakdown (optional)

## Data Model

### Customer (Platform User)
```
customer_id: string (cust_xxx)
email: string
password_hash: string
company_name: string
plan: 'free' | 'pro' | 'enterprise'
stripe_customer_id: string
created_at: timestamp
```

### API Key
```
key_id: string (key_xxx)
customer_id: string
realm_id: string (optional, null = all realms)
type: 'publishable' | 'secret'
key_prefix: string (pk_live_xxx... or sk_live_xxx...)
key_hash: string (for secret keys)
name: string
status: 'active' | 'revoked'
last_used_at: timestamp
created_at: timestamp
```

### Usage Record
```
customer_id: string
month: string (2026-01)
mau: number
api_calls: number
realms: number
```

## Clinisyn Specific

- Company: Clinisyn
- Use case: 4000 Psychologists, 11 Countries
- Requirements: HIPAA compliant, WebAuthn mandatory
- Expected plan: Enterprise
- Realms: clinisyn-psychologists, clinisyn-students (maybe)
