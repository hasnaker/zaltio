# ZALT.IO Authentication Platform - Design Document

## Overview

Zalt.io is an enterprise-grade Authentication-as-a-Service platform designed to surpass Clerk in security, reliability, and developer experience. Built with healthcare compliance (HIPAA/GDPR) as the baseline, the system is architected to withstand sophisticated attacks including credential stuffing, phishing proxies (Evilginx2), and nation-state level threats.

**Security Philosophy:** Assume breach. Defense in depth. Zero trust.

---

## THREAT MODEL

### Primary Threat Actors

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           THREAT ACTOR MATRIX                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  ACTOR              CAPABILITY        MOTIVATION       ATTACK VECTORS       │
├─────────────────────────────────────────────────────────────────────────────┤
│  Script Kiddies     Low               Fame/Fun         Credential stuffing  │
│                                                        Default passwords    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Cybercriminals     Medium-High       Financial        Phishing (Evilginx2) │
│                                                        Account takeover     │
│                                                        Ransomware           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Hacktivists        Medium            Ideological      DDoS, Data leaks     │
│                                                        Defacement           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Insiders           High (access)     Various          Data exfiltration    │
│                                                        Privilege abuse      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Nation-State       Very High         Espionage        APT, Zero-days       │
│  (APT Groups)                         Disruption       Supply chain         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Attack Vectors & Mitigations

```
CREDENTIAL STUFFING:
├── Attack: Automated login attempts using leaked password databases
├── Scale: Millions of attempts per hour
├── Mitigation:
│   ├── HaveIBeenPwned integration (block known breached passwords)
│   ├── Rate limiting (5 attempts/15 min/IP)
│   ├── Progressive delays (1s, 2s, 4s, 8s, 16s)
│   ├── Account lockout (5 failures = 15 min lock)
│   ├── CAPTCHA after 3 failures
│   └── Credential stuffing pattern detection

PHISHING (Evilginx2):
├── Attack: Real-time proxy captures credentials AND session tokens
├── Bypasses: Traditional MFA (TOTP, SMS, Email codes)
├── Mitigation:
│   ├── WebAuthn/Passkeys (origin-bound, phishing-proof)
│   ├── Device fingerprinting (new device = extra verification)
│   ├── IP geolocation anomaly detection
│   └── User education (but don't rely on it!)

SESSION HIJACKING:
├── Attack: Steal session tokens via XSS, network sniffing, malware
├── Mitigation:
│   ├── Short-lived access tokens (15 min)
│   ├── Refresh token rotation (every use)
│   ├── Device binding (token tied to fingerprint)
│   ├── Secure cookie flags (HttpOnly, Secure, SameSite=Strict)
│   └── Token blacklisting on logout

BRUTE FORCE:
├── Attack: Systematic password guessing
├── Mitigation:
│   ├── Argon2id (computationally expensive)
│   ├── Rate limiting per IP and per account
│   ├── Account lockout with exponential backoff
│   └── No username enumeration

INSIDER THREAT:
├── Attack: Malicious employee with database access
├── Mitigation:
│   ├── Password hashing (Argon2id - irreversible)
│   ├── Encryption at rest (AES-256-GCM)
│   ├── Audit logging (all access logged)
│   ├── Principle of least privilege
│   └── Key rotation (30 days)
```

---

## ARCHITECTURE

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │  Clinisyn   │  │   Voczo     │  │  HSD Apps   │  │  Future     │       │
│  │  (Next.js)  │  │  (React)    │  │  (Various)  │  │  Customers  │       │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │
│         │                │                │                │               │
│         └────────────────┴────────────────┴────────────────┘               │
│                                   │                                         │
│                          @zalt/auth-sdk                                    │
│                          @zalt/auth-react                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTPS/TLS 1.3
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              EDGE LAYER                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        AWS CloudFront                                │   │
│  │                    (CDN + DDoS Protection)                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          AWS WAF                                     │   │
│  │  ├── Rate limiting rules                                            │   │
│  │  ├── SQL injection protection                                       │   │
│  │  ├── XSS protection                                                 │   │
│  │  ├── Known bad IP blocking                                          │   │
│  │  └── Geo-blocking (if needed)                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      API Gateway (api.zalt.io)                       │   │
│  │  ├── Request validation                                             │   │
│  │  ├── JWT authorizer                                                 │   │
│  │  ├── Request/response transformation                                │   │
│  │  └── Throttling (per API key)                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Lambda Functions                                │   │
│  │                                                                      │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │ Register │ │  Login   │ │ Refresh  │ │  Logout  │ │   MFA    │  │   │
│  │  │ Handler  │ │ Handler  │ │ Handler  │ │ Handler  │ │ Handler  │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │   │
│  │                                                                      │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │ WebAuthn │ │  Social  │ │  Email   │ │ Password │ │  Admin   │  │   │
│  │  │ Handler  │ │ Handler  │ │ Verify   │ │  Reset   │ │ Handler  │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            SERVICE LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│  │     JWT      │ │   Password   │ │    Email     │ │    Device    │       │
│  │   Service    │ │   Service    │ │   Service    │ │   Service    │       │
│  │              │ │              │ │              │ │              │       │
│  │ - Sign       │ │ - Hash       │ │ - Send       │ │ - Fingerprint│       │
│  │ - Verify     │ │ - Verify     │ │ - Templates  │ │ - Trust score│       │
│  │ - Rotate     │ │ - HIBP check │ │ - Rate limit │ │ - Management │       │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘       │
│                                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│  │     MFA      │ │   WebAuthn   │ │    Social    │ │  Rate Limit  │       │
│  │   Service    │ │   Service    │ │   Service    │ │   Service    │       │
│  │              │ │              │ │              │ │              │       │
│  │ - TOTP       │ │ - Register   │ │ - Google     │ │ - Sliding    │       │
│  │ - Backup     │ │ - Verify     │ │ - Apple      │ │   window     │       │
│  │ - Enforce    │ │ - Manage     │ │ - Link       │ │ - Per IP/user│       │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘       │
│                                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│  │  Encryption  │ │   Audit      │ │   Security   │ │    Realm     │       │
│  │   Service    │ │   Service    │ │   Service    │ │   Service    │       │
│  │              │ │              │ │              │ │              │       │
│  │ - AES-256    │ │ - Log events │ │ - Alerts     │ │ - Isolation  │       │
│  │ - Key mgmt   │ │ - Retention  │ │ - Detection  │ │ - Config     │       │
│  │ - Rotation   │ │ - Export     │ │ - Response   │ │ - Policies   │       │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             DATA LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         DynamoDB                                      │  │
│  │                                                                       │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │  │
│  │  │   Users     │  │  Sessions   │  │   Tokens    │  │   Realms    │ │  │
│  │  │   Table     │  │   Table     │  │   Table     │  │   Table     │ │  │
│  │  │             │  │             │  │             │  │             │ │  │
│  │  │ PK: realm   │  │ PK: session │  │ PK: token   │  │ PK: realm   │ │  │
│  │  │ SK: user    │  │ TTL: 7 days │  │ TTL: varies │  │ SK: config  │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │  │
│  │                                                                       │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │  │
│  │  │   Devices   │  │  MFA Data   │  │  Audit Log  │  │  Blacklist  │ │  │
│  │  │   Table     │  │   Table     │  │   Table     │  │   Table     │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │  │
│  │                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────┐   │
│  │     AWS KMS          │  │      AWS SES         │  │   AWS S3        │   │
│  │  (Key Management)    │  │  (Email Service)     │  │  (Documents)    │   │
│  │                      │  │                      │  │                 │   │
│  │  - JWT signing keys  │  │  - Verification      │  │  - User docs    │   │
│  │  - Encryption keys   │  │  - Password reset    │  │  - Audit logs   │   │
│  │  - Key rotation      │  │  - Security alerts   │  │  - Backups      │   │
│  └──────────────────────┘  └──────────────────────┘  └─────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## DATA MODELS

### User Model

```typescript
interface User {
  // Primary Key
  pk: string;                    // "REALM#clinisyn-psychologists"
  sk: string;                    // "USER#user_abc123"
  
  // Core Identity
  id: string;                    // "user_abc123"
  realm_id: string;              // "clinisyn-psychologists"
  email: string;                 // "dr.ayse@clinisyn.com"
  email_verified: boolean;       // true
  email_verified_at?: number;    // Unix timestamp
  
  // Authentication
  password_hash: string;         // Argon2id hash
  password_changed_at: number;   // Unix timestamp
  
  // Profile
  profile: {
    first_name?: string;
    last_name?: string;
    avatar_url?: string;
    phone?: string;
    metadata: Record<string, any>;  // Custom fields (role, clinic_id, etc.)
  };
  
  // MFA
  mfa: {
    enabled: boolean;
    methods: ('totp' | 'webauthn' | 'backup_codes')[];
    totp_secret?: string;           // Encrypted
    backup_codes_hash?: string[];   // Hashed
    backup_codes_remaining: number;
    webauthn_credentials?: WebAuthnCredential[];
  };
  
  // Social Login
  social_providers?: {
    google?: { sub: string; email: string; linked_at: number };
    apple?: { sub: string; email: string; linked_at: number };
  };
  
  // Security
  status: 'active' | 'suspended' | 'pending_verification' | 'locked';
  failed_login_attempts: number;
  locked_until?: number;
  last_login_at?: number;
  last_login_ip?: string;
  last_login_device?: string;
  
  // Timestamps
  created_at: number;
  updated_at: number;
  
  // GSI
  gsi1pk: string;                // "EMAIL#dr.ayse@clinisyn.com"
  gsi1sk: string;                // "REALM#clinisyn-psychologists"
}
```

### Session Model

```typescript
interface Session {
  // Primary Key
  pk: string;                    // "SESSION#sess_xyz789"
  sk: string;                    // "USER#user_abc123"
  
  // Core
  id: string;                    // "sess_xyz789"
  user_id: string;               // "user_abc123"
  realm_id: string;              // "clinisyn-psychologists"
  
  // Tokens
  refresh_token_hash: string;    // SHA-256 hash
  old_refresh_token_hash?: string;  // For grace period
  rotated_at?: number;           // When last rotated
  
  // Device Binding
  device_id: string;             // "dev_abc123"
  device_fingerprint: string;    // Hashed fingerprint
  device_name?: string;          // "Chrome on MacOS"
  
  // Context
  ip_address: string;
  user_agent: string;
  geolocation?: {
    country: string;
    city: string;
    lat: number;
    lon: number;
  };
  
  // Timestamps
  created_at: number;
  last_activity_at: number;
  expires_at: number;            // TTL
  
  // TTL for DynamoDB
  ttl: number;                   // Unix timestamp for auto-deletion
}
```

### Device Model

```typescript
interface Device {
  // Primary Key
  pk: string;                    // "USER#user_abc123"
  sk: string;                    // "DEVICE#dev_xyz789"
  
  // Core
  id: string;                    // "dev_xyz789"
  user_id: string;
  realm_id: string;
  
  // Fingerprint
  fingerprint_hash: string;
  fingerprint_components: {
    user_agent: string;
    screen_resolution: string;
    timezone: string;
    language: string;
    platform: string;
  };
  
  // Trust
  trust_score: number;           // 0-100
  is_trusted: boolean;
  trusted_at?: number;
  
  // Metadata
  name?: string;                 // "My MacBook Pro"
  last_seen_at: number;
  last_ip: string;
  ip_history: string[];          // Last 5 IPs
  
  // Timestamps
  created_at: number;
  updated_at: number;
}
```

### WebAuthn Credential Model

```typescript
interface WebAuthnCredential {
  // Primary Key
  pk: string;                    // "USER#user_abc123"
  sk: string;                    // "WEBAUTHN#cred_abc123"
  
  // Core
  id: string;                    // "cred_abc123"
  user_id: string;
  realm_id: string;
  
  // WebAuthn Data
  credential_id: string;         // Base64URL encoded
  public_key: string;            // Base64URL encoded
  counter: number;               // For replay prevention
  transports?: ('usb' | 'nfc' | 'ble' | 'internal')[];
  
  // Metadata
  name: string;                  // "MacBook Touch ID"
  aaguid?: string;               // Authenticator identifier
  
  // Timestamps
  created_at: number;
  last_used_at?: number;
}
```

### Realm Model

```typescript
interface Realm {
  // Primary Key
  pk: string;                    // "REALM#clinisyn-psychologists"
  sk: string;                    // "CONFIG"
  
  // Core
  id: string;                    // "clinisyn-psychologists"
  name: string;                  // "Clinisyn Psikolog Portalı"
  
  // Settings
  settings: {
    // MFA Policy
    mfa_policy: 'disabled' | 'optional' | 'required';
    mfa_methods_allowed: ('totp' | 'webauthn' | 'backup_codes')[];
    webauthn_required: boolean;  // For healthcare
    
    // Session
    session_timeout_days: number;  // Default 7
    max_concurrent_sessions: number;  // Default 5
    
    // Password Policy
    password_min_length: number;  // Default 12
    password_require_uppercase: boolean;
    password_require_lowercase: boolean;
    password_require_number: boolean;
    password_require_special: boolean;
    password_check_hibp: boolean;  // Default true
    
    // Rate Limiting
    login_rate_limit: number;     // Per 15 min
    register_rate_limit: number;  // Per hour
    
    // CORS
    allowed_origins: string[];
    
    // Callbacks
    webhook_url?: string;
    webhook_events: string[];
  };
  
  // OAuth Providers (Customer's credentials!)
  oauth_providers?: {
    google?: {
      enabled: boolean;
      client_id: string;
      client_secret: string;      // Encrypted
      scopes: string[];
    };
    apple?: {
      enabled: boolean;
      client_id: string;
      team_id: string;
      key_id: string;
      private_key: string;        // Encrypted
    };
  };
  
  // Branding
  branding?: {
    logo_url?: string;
    primary_color?: string;
    app_name: string;             // Shown in OAuth consent
  };
  
  // Timestamps
  created_at: number;
  updated_at: number;
}
```

### Audit Log Model

```typescript
interface AuditLog {
  // Primary Key
  pk: string;                    // "AUDIT#2026-01-15"
  sk: string;                    // "1705312800000#evt_abc123"
  
  // Core
  id: string;                    // "evt_abc123"
  realm_id: string;
  user_id?: string;              // May be null for failed logins
  
  // Event
  event_type: 
    | 'login_success' | 'login_failure'
    | 'register' | 'logout'
    | 'password_change' | 'password_reset'
    | 'mfa_enable' | 'mfa_disable'
    | 'webauthn_register' | 'webauthn_remove'
    | 'device_trust' | 'device_revoke'
    | 'session_create' | 'session_revoke'
    | 'account_lock' | 'account_unlock'
    | 'social_link' | 'social_unlink'
    | 'config_change' | 'admin_action';
  
  // Context
  ip_address: string;
  user_agent: string;
  device_id?: string;
  
  // Details
  details: Record<string, any>;  // Event-specific data
  result: 'success' | 'failure';
  failure_reason?: string;
  
  // Timestamp
  timestamp: number;
  
  // TTL (90 days for regular, 6 years for HIPAA)
  ttl?: number;
  
  // GSI for user-specific queries
  gsi1pk?: string;               // "USER#user_abc123"
  gsi1sk?: string;               // Timestamp
}
```

---

## AUTHENTICATION FLOWS

### 1. Registration Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REGISTRATION FLOW                                   │
└─────────────────────────────────────────────────────────────────────────────┘

Client                          Zalt.io API                         External
  │                                 │                                   │
  │  POST /v1/auth/register         │                                   │
  │  {email, password, realm_id}    │                                   │
  │────────────────────────────────>│                                   │
  │                                 │                                   │
  │                                 │  1. Validate email format         │
  │                                 │  2. Check disposable email        │
  │                                 │  3. Check rate limit (3/hr/IP)    │
  │                                 │                                   │
  │                                 │  4. Check HaveIBeenPwned          │
  │                                 │─────────────────────────────────>│
  │                                 │<─────────────────────────────────│
  │                                 │                                   │
  │                                 │  5. Hash password (Argon2id)      │
  │                                 │     32MB, timeCost 5, parallel 2  │
  │                                 │                                   │
  │                                 │  6. Create user (status: pending) │
  │                                 │  7. Generate verification code    │
  │                                 │                                   │
  │                                 │  8. Send verification email       │
  │                                 │─────────────────────────────────>│
  │                                 │                                   │  AWS SES
  │                                 │                                   │
  │  201 Created                    │                                   │
  │  {user_id, email_sent: true}    │                                   │
  │<────────────────────────────────│                                   │
  │                                 │                                   │

SECURITY CHECKS:
├── Email format validation (RFC 5322)
├── Disposable email provider blocking (1000+ domains)
├── Rate limiting: 3 registrations per hour per IP
├── Password strength: min 12 chars, complexity rules
├── HaveIBeenPwned: k-anonymity check (first 5 chars of SHA-1)
├── Argon2id: 32MB memory, 5 iterations, 2 parallelism
└── Audit log: registration attempt with IP, user-agent
```

### 2. Login Flow (with MFA)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LOGIN FLOW (MFA)                                  │
└─────────────────────────────────────────────────────────────────────────────┘

Client                          Zalt.io API                         Database
  │                                 │                                   │
  │  POST /v1/auth/login            │                                   │
  │  {email, password, realm_id,    │                                   │
  │   device_fingerprint}           │                                   │
  │────────────────────────────────>│                                   │
  │                                 │                                   │
  │                                 │  1. Check rate limit (5/15min/IP) │
  │                                 │  2. Apply progressive delay       │
  │                                 │                                   │
  │                                 │  3. Lookup user by email+realm    │
  │                                 │─────────────────────────────────>│
  │                                 │<─────────────────────────────────│
  │                                 │                                   │
  │                                 │  4. Check account status          │
  │                                 │     (locked? suspended?)          │
  │                                 │                                   │
  │                                 │  5. Verify password (Argon2id)    │
  │                                 │                                   │
  │                                 │  6. Calculate device trust score  │
  │                                 │                                   │
  │                                 │  7. Check MFA requirement         │
  │                                 │     - Realm policy                │
  │                                 │     - User MFA enabled            │
  │                                 │     - Device trust < 80           │
  │                                 │                                   │
  │  IF MFA REQUIRED:               │                                   │
  │  200 OK                         │                                   │
  │  {mfa_required: true,           │                                   │
  │   mfa_session_id: "...",        │                                   │
  │   mfa_methods: ["totp","webauthn"]}                                 │
  │<────────────────────────────────│                                   │
  │                                 │                                   │
  │  POST /v1/auth/mfa/verify       │                                   │
  │  {mfa_session_id, method,       │                                   │
  │   code/credential}              │                                   │
  │────────────────────────────────>│                                   │
  │                                 │                                   │
  │                                 │  8. Verify MFA                    │
  │                                 │  9. Create session                │
  │                                 │  10. Generate tokens (RS256)      │
  │                                 │  11. Log successful login         │
  │                                 │                                   │
  │  200 OK                         │                                   │
  │  {access_token, refresh_token,  │                                   │
  │   user, device_trusted}         │                                   │
  │<────────────────────────────────│                                   │
  │                                 │                                   │

SECURITY CHECKS:
├── Rate limiting: 5 attempts per 15 min per IP
├── Progressive delay: 1s, 2s, 4s, 8s, 16s after failures
├── Account lockout: 5 failures = 15 min lock
├── No email enumeration: same response for invalid email/password
├── Device trust scoring: fingerprint, IP, time pattern
├── MFA enforcement: realm policy + user setting + device trust
├── Credential stuffing detection: pattern analysis
└── Audit log: every attempt with full context
```

### 3. Token Refresh Flow (with Grace Period)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TOKEN REFRESH FLOW (GRACE PERIOD)                      │
└─────────────────────────────────────────────────────────────────────────────┘

Client                          Zalt.io API                         Database
  │                                 │                                   │
  │  POST /v1/auth/refresh          │                                   │
  │  {refresh_token}                │                                   │
  │────────────────────────────────>│                                   │
  │                                 │                                   │
  │                                 │  1. Hash refresh token            │
  │                                 │  2. Lookup session by hash        │
  │                                 │─────────────────────────────────>│
  │                                 │<─────────────────────────────────│
  │                                 │                                   │
  │  CASE A: Token found (normal)   │                                   │
  │                                 │  3. Generate new refresh token    │
  │                                 │  4. Store old hash + rotated_at   │
  │                                 │  5. Generate new access token     │
  │                                 │                                   │
  │  200 OK                         │                                   │
  │  {access_token, refresh_token}  │                                   │
  │<────────────────────────────────│                                   │
  │                                 │                                   │
  │  CASE B: Token not found        │                                   │
  │                                 │  3. Check old_refresh_token_hash  │
  │                                 │  4. Check rotated_at < 30 seconds │
  │                                 │                                   │
  │  IF within grace period:        │                                   │
  │  200 OK (same tokens as before) │  5. Return SAME new tokens        │
  │<────────────────────────────────│     (idempotent!)                 │
  │                                 │                                   │
  │  IF after grace period:         │                                   │
  │  401 Unauthorized               │                                   │
  │  {error: "token_expired"}       │                                   │
  │<────────────────────────────────│                                   │
  │                                 │                                   │

GRACE PERIOD LOGIC:
├── Normal refresh: rotate token, store old hash with timestamp
├── Retry within 30s: return same new tokens (idempotent)
├── Retry after 30s: reject, require re-login
├── Purpose: Handle network failures, mobile connectivity issues
└── Security: 30s window is short enough to minimize attack surface
```

### 4. WebAuthn Registration Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       WEBAUTHN REGISTRATION FLOW                            │
└─────────────────────────────────────────────────────────────────────────────┘

Client                          Zalt.io API                      Authenticator
  │                                 │                                   │
  │  POST /v1/auth/webauthn/        │                                   │
  │       register/options          │                                   │
  │────────────────────────────────>│                                   │
  │                                 │                                   │
  │                                 │  1. Generate challenge (32 bytes) │
  │                                 │  2. Create registration options   │
  │                                 │                                   │
  │  200 OK                         │                                   │
  │  {challenge, rp, user,          │                                   │
  │   pubKeyCredParams,             │                                   │
  │   authenticatorSelection}       │                                   │
  │<────────────────────────────────│                                   │
  │                                 │                                   │
  │  navigator.credentials.create() │                                   │
  │─────────────────────────────────────────────────────────────────────>│
  │                                 │                                   │
  │                                 │                    User verifies  │
  │                                 │                    (Face ID, etc) │
  │                                 │                                   │
  │  Credential response            │                                   │
  │<─────────────────────────────────────────────────────────────────────│
  │                                 │                                   │
  │  POST /v1/auth/webauthn/        │                                   │
  │       register/verify           │                                   │
  │  {credential}                   │                                   │
  │────────────────────────────────>│                                   │
  │                                 │                                   │
  │                                 │  3. Verify challenge              │
  │                                 │  4. Verify origin (phishing!)     │
  │                                 │  5. Extract public key            │
  │                                 │  6. Store credential              │
  │                                 │                                   │
  │  201 Created                    │                                   │
  │  {credential_id, name}          │                                   │
  │<────────────────────────────────│                                   │
  │                                 │                                   │

SECURITY FEATURES:
├── Origin binding: Credential only works on registered origin
├── Challenge: Prevents replay attacks
├── Counter: Increments on each use, detects cloned keys
├── Attestation: Optional, verifies authenticator type
└── Phishing-proof: Attacker cannot use credential on fake site
```

---

## API ENDPOINTS

### Authentication Endpoints

```yaml
# Registration
POST /v1/auth/register
  Request:
    realm_id: string (required)
    email: string (required)
    password: string (required, min 12 chars)
    profile?: { first_name?, last_name?, metadata? }
  Response:
    201: { user_id, email, email_verification_sent: true }
    400: { error: "weak_password" | "invalid_email" | "email_exists" }
    429: { error: "rate_limited", retry_after: number }

# Login
POST /v1/auth/login
  Request:
    realm_id: string (required)
    email: string (required)
    password: string (required)
    device_fingerprint?: object
  Response:
    200 (no MFA): { access_token, refresh_token, user }
    200 (MFA required): { mfa_required: true, mfa_session_id, mfa_methods }
    401: { error: "invalid_credentials" }
    423: { error: "account_locked", locked_until: number }
    429: { error: "rate_limited", retry_after: number }

# MFA Verification
POST /v1/auth/mfa/verify
  Request:
    mfa_session_id: string (required)
    method: "totp" | "webauthn" | "backup_code" (required)
    code?: string (for TOTP/backup)
    credential?: object (for WebAuthn)
  Response:
    200: { access_token, refresh_token, user }
    401: { error: "invalid_mfa_code" }
    429: { error: "too_many_attempts" }

# Token Refresh
POST /v1/auth/refresh
  Request:
    refresh_token: string (required)
  Response:
    200: { access_token, refresh_token }
    401: { error: "invalid_token" | "token_expired" }

# Logout
POST /v1/auth/logout
  Headers:
    Authorization: Bearer <access_token>
  Request:
    all_devices?: boolean (default false)
  Response:
    200: { success: true }

# Get Current User
GET /v1/auth/me
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { user }
    401: { error: "unauthorized" }
```

### Email Verification Endpoints

```yaml
# Send Verification Email
POST /v1/auth/verify-email/send
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { sent: true }
    429: { error: "rate_limited" }

# Verify Email
POST /v1/auth/verify-email/confirm
  Request:
    code: string (6 digits)
    user_id: string
  Response:
    200: { verified: true }
    400: { error: "invalid_code" | "code_expired" }
```

### Password Reset Endpoints

```yaml
# Request Password Reset
POST /v1/auth/password-reset/request
  Request:
    realm_id: string (required)
    email: string (required)
  Response:
    200: { sent: true }  # Always returns success (no enumeration!)
    429: { error: "rate_limited" }

# Confirm Password Reset
POST /v1/auth/password-reset/confirm
  Request:
    token: string (required)
    new_password: string (required)
  Response:
    200: { success: true, sessions_invalidated: number }
    400: { error: "invalid_token" | "weak_password" }
```

### MFA Management Endpoints

```yaml
# Setup TOTP
POST /v1/auth/mfa/totp/setup
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { secret, qr_code_url, backup_codes }

# Verify TOTP Setup
POST /v1/auth/mfa/totp/verify
  Headers:
    Authorization: Bearer <access_token>
  Request:
    code: string (6 digits)
  Response:
    200: { enabled: true }
    400: { error: "invalid_code" }

# Disable TOTP
DELETE /v1/auth/mfa/totp
  Headers:
    Authorization: Bearer <access_token>
  Request:
    password: string (required for security)
  Response:
    200: { disabled: true }

# Regenerate Backup Codes
POST /v1/auth/mfa/backup-codes/regenerate
  Headers:
    Authorization: Bearer <access_token>
  Request:
    password: string (required)
  Response:
    200: { backup_codes: string[] }
```

### WebAuthn Endpoints

```yaml
# Get Registration Options
POST /v1/auth/webauthn/register/options
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { challenge, rp, user, pubKeyCredParams, ... }

# Verify Registration
POST /v1/auth/webauthn/register/verify
  Headers:
    Authorization: Bearer <access_token>
  Request:
    credential: object (from navigator.credentials.create)
    name?: string (credential name)
  Response:
    201: { credential_id, name }
    400: { error: "verification_failed" }

# Get Authentication Options
POST /v1/auth/webauthn/authenticate/options
  Request:
    realm_id: string
    email: string
  Response:
    200: { challenge, allowCredentials, ... }

# Verify Authentication
POST /v1/auth/webauthn/authenticate/verify
  Request:
    mfa_session_id: string
    credential: object (from navigator.credentials.get)
  Response:
    200: { access_token, refresh_token, user }

# List Credentials
GET /v1/auth/webauthn/credentials
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { credentials: [{ id, name, created_at, last_used_at }] }

# Delete Credential
DELETE /v1/auth/webauthn/credentials/:id
  Headers:
    Authorization: Bearer <access_token>
  Request:
    password: string (required)
  Response:
    200: { deleted: true }
```

### Device Management Endpoints

```yaml
# List Devices
GET /v1/auth/devices
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { devices: [{ id, name, last_seen, is_current, trust_score }] }

# Revoke Device
DELETE /v1/auth/devices/:id
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { revoked: true, sessions_terminated: number }

# Trust Current Device
POST /v1/auth/devices/trust
  Headers:
    Authorization: Bearer <access_token>
  Response:
    200: { trusted: true, device_id }
```

### Social Login Endpoints

```yaml
# Get OAuth Authorization URL
GET /v1/auth/social/:provider/authorize
  Query:
    realm_id: string (required)
    redirect_uri: string (required)
    state?: string
  Response:
    302: Redirect to OAuth provider

# OAuth Callback
GET /v1/auth/social/:provider/callback  # Google
POST /v1/auth/social/:provider/callback # Apple
  Query/Body:
    code: string
    state: string
  Response:
    302: Redirect to client with tokens
    OR
    200: { access_token, refresh_token, user, is_new_user }
```

---

## SECURITY IMPLEMENTATION DETAILS

### 1. Password Hashing (Argon2id)

```typescript
// src/utils/password.ts
import argon2 from 'argon2';

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 32768,      // 32 MB (Lambda-optimized)
  timeCost: 5,            // 5 iterations
  parallelism: 2,         // 2 threads
  hashLength: 32,         // 256 bits
  saltLength: 16          // 128 bits
};

// Why these parameters?
// - 32MB: Fits in Lambda memory, allows ~90 concurrent hashes
// - timeCost 5: Compensates for lower memory
// - parallelism 2: Lambda typically has 2 vCPUs
// - Result: ~500-800ms per hash (acceptable for auth)
```

### 2. JWT Configuration (RS256)

```typescript
// src/utils/jwt.ts
const JWT_CONFIG = {
  algorithm: 'RS256',           // FIPS-compliant for HIPAA
  accessTokenExpiry: '15m',     // 15 minutes
  refreshTokenExpiry: '7d',     // 7 days
  issuer: 'zalt.io',
  audience: 'zalt.io'
};

// JWT Payload Structure
interface JWTPayload {
  sub: string;          // user_id
  realm_id: string;     // tenant isolation
  email: string;
  type: 'access' | 'refresh';
  iat: number;          // issued at
  exp: number;          // expiry
  jti: string;          // unique token ID (for blacklisting)
}

// JWT Header (with key rotation support)
interface JWTHeader {
  alg: 'RS256';
  typ: 'JWT';
  kid: string;          // Key ID for rotation
}
```

### 3. Rate Limiting (Sliding Window)

```typescript
// src/services/ratelimit.service.ts
interface RateLimitConfig {
  login: { limit: 5, window: 900 };        // 5 per 15 min
  register: { limit: 3, window: 3600 };    // 3 per hour
  passwordReset: { limit: 3, window: 3600 };
  mfaVerify: { limit: 5, window: 60 };     // 5 per minute
  apiGeneral: { limit: 100, window: 60 };  // 100 per minute
}

// Sliding window algorithm using DynamoDB
// Key: RATELIMIT#{ip}#{endpoint}
// Value: { count, window_start }
// TTL: window duration
```

### 4. Device Fingerprinting

```typescript
// src/services/device.service.ts
interface FingerprintComponents {
  userAgent: string;        // Weight: 30%
  screenResolution: string; // Weight: 20%
  timezone: string;         // Weight: 20%
  language: string;         // Weight: 15%
  platform: string;         // Weight: 15%
}

function calculateTrustScore(current: Fingerprint, stored: Fingerprint): number {
  let score = 0;
  
  // Fingerprint similarity (50% of total)
  const fpSimilarity = calculateFingerprintSimilarity(current, stored);
  score += fpSimilarity * 50;
  
  // IP geolocation (20% of total)
  const geoScore = calculateGeoScore(current.ip, stored.lastIp);
  score += geoScore * 20;
  
  // User-Agent consistency (15% of total)
  const uaScore = calculateUAScore(current.userAgent, stored.userAgent);
  score += uaScore * 15;
  
  // Time pattern (15% of total)
  const timeScore = calculateTimeScore(current.hour, stored.typicalHours);
  score += timeScore * 15;
  
  return Math.round(score);
}

// Trust thresholds:
// >= 80: Trusted (no additional MFA)
// 50-79: Familiar (require MFA)
// < 50: Suspicious (require MFA + email verification)
```

### 5. Credential Stuffing Detection

```typescript
// src/services/security.service.ts
interface StuffingPattern {
  samePasswordDifferentEmails: boolean;  // Same password tried on multiple accounts
  sameIPManyFailures: boolean;           // Single IP, many failed logins
  distributedAttack: boolean;            // Many IPs, same target account
  velocityAnomaly: boolean;              // Unusual request rate
}

async function detectCredentialStuffing(
  ip: string,
  email: string,
  passwordHash: string
): Promise<StuffingPattern> {
  // Check recent login attempts from this IP
  const ipAttempts = await getRecentAttempts({ ip, window: 3600 });
  
  // Check if same password hash used for different emails
  const passwordReuse = await checkPasswordReuse(passwordHash, 3600);
  
  // Check distributed attack pattern
  const targetAttempts = await getRecentAttempts({ email, window: 3600 });
  
  return {
    samePasswordDifferentEmails: passwordReuse.count > 3,
    sameIPManyFailures: ipAttempts.failures > 10,
    distributedAttack: targetAttempts.uniqueIPs > 5,
    velocityAnomaly: ipAttempts.requestsPerSecond > 1
  };
}
```

### 6. Audit Logging

```typescript
// src/services/audit.service.ts
interface AuditEvent {
  event_type: string;
  realm_id: string;
  user_id?: string;
  ip_address: string;
  user_agent: string;
  device_id?: string;
  result: 'success' | 'failure';
  failure_reason?: string;
  details: Record<string, any>;
  timestamp: number;
}

// All events logged:
// - login_success, login_failure
// - register, logout
// - password_change, password_reset
// - mfa_enable, mfa_disable
// - webauthn_register, webauthn_remove
// - device_trust, device_revoke
// - session_create, session_revoke
// - account_lock, account_unlock
// - config_change, admin_action

// Retention:
// - Regular logs: 90 days
// - HIPAA compliance: 6 years
```

---

## ERROR HANDLING

### Error Response Format

```typescript
interface ErrorResponse {
  error: {
    code: string;           // Machine-readable code
    message: string;        // Human-readable message
    details?: object;       // Additional context (never sensitive!)
    request_id: string;     // For debugging
    timestamp: string;      // ISO 8601
  };
}

// Example:
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "request_id": "req_abc123xyz",
    "timestamp": "2026-01-15T10:30:00Z"
  }
}
```

### Error Codes

```typescript
// Authentication Errors (401)
INVALID_CREDENTIALS       // Wrong email or password (no enumeration!)
TOKEN_EXPIRED            // Access/refresh token expired
TOKEN_INVALID            // Malformed or tampered token
MFA_REQUIRED             // MFA verification needed
MFA_INVALID              // Wrong MFA code

// Authorization Errors (403)
INSUFFICIENT_PERMISSIONS // User lacks required permissions
REALM_MISMATCH          // Token realm doesn't match request

// Validation Errors (400)
INVALID_EMAIL           // Email format invalid
WEAK_PASSWORD           // Password doesn't meet policy
BREACHED_PASSWORD       // Password found in breach database
INVALID_CODE            // Verification code invalid/expired
MISSING_FIELD           // Required field not provided

// Rate Limiting (429)
RATE_LIMITED            // Too many requests
ACCOUNT_LOCKED          // Too many failed attempts

// Server Errors (500)
INTERNAL_ERROR          // Generic server error (log details internally!)
SERVICE_UNAVAILABLE     // Dependency failure
```

### Security Principles for Errors

```
1. NO ENUMERATION:
   ├── "Invalid email or password" (not "email not found")
   ├── Password reset always says "email sent" (even if email doesn't exist)
   └── Same response time for valid/invalid emails

2. NO INFORMATION LEAKAGE:
   ├── Never expose stack traces
   ├── Never expose internal IDs in errors
   ├── Never expose database details
   └── Log details internally, return generic message

3. CONSISTENT TIMING:
   ├── Add artificial delay for invalid emails (prevent timing attacks)
   └── Same response structure for all error types
```

---

## TESTING STRATEGY

### Property-Based Testing (Critical Security Properties)

```typescript
// Using fast-check for property-based testing

// Property 1: Password hashing is irreversible
fc.assert(
  fc.property(fc.string(), async (password) => {
    const hash = await hashPassword(password);
    // Cannot derive password from hash
    expect(hash).not.toContain(password);
    expect(hash.length).toBeGreaterThan(50);
  })
);

// Property 2: JWT tokens are tamper-proof
fc.assert(
  fc.property(fc.record({...}), async (payload) => {
    const token = signJWT(payload);
    const tampered = token.slice(0, -1) + 'X';
    await expect(verifyJWT(tampered)).rejects.toThrow();
  })
);

// Property 3: Rate limiting is enforced
fc.assert(
  fc.property(fc.integer({min: 1, max: 100}), async (attempts) => {
    const results = await Promise.all(
      Array(attempts).fill(null).map(() => loginAttempt())
    );
    const blocked = results.filter(r => r.status === 429).length;
    expect(blocked).toBeGreaterThanOrEqual(Math.max(0, attempts - 5));
  })
);

// Property 4: Realm isolation is maintained
fc.assert(
  fc.property(fc.tuple(fc.string(), fc.string()), async ([realm1, realm2]) => {
    const user1 = await createUser({ realm_id: realm1 });
    const user2 = await getUser({ realm_id: realm2, user_id: user1.id });
    expect(user2).toBeNull(); // Cannot access across realms
  })
);
```

### Integration Tests

```typescript
// Full authentication flow
describe('Authentication Flow', () => {
  it('should complete registration → verification → login → MFA → logout', async () => {
    // 1. Register
    const registerRes = await api.post('/auth/register', {...});
    expect(registerRes.status).toBe(201);
    
    // 2. Verify email
    const code = await getVerificationCode(email);
    const verifyRes = await api.post('/auth/verify-email/confirm', { code });
    expect(verifyRes.status).toBe(200);
    
    // 3. Setup MFA
    const mfaSetup = await api.post('/auth/mfa/totp/setup');
    const totpCode = generateTOTP(mfaSetup.secret);
    await api.post('/auth/mfa/totp/verify', { code: totpCode });
    
    // 4. Login with MFA
    const loginRes = await api.post('/auth/login', {...});
    expect(loginRes.body.mfa_required).toBe(true);
    
    const mfaRes = await api.post('/auth/mfa/verify', {
      mfa_session_id: loginRes.body.mfa_session_id,
      method: 'totp',
      code: generateTOTP(mfaSetup.secret)
    });
    expect(mfaRes.body.access_token).toBeDefined();
    
    // 5. Logout
    const logoutRes = await api.post('/auth/logout');
    expect(logoutRes.status).toBe(200);
  });
});
```

---

## MONITORING & ALERTING

### Key Metrics

```yaml
Authentication:
  - login_success_rate: Target > 99%
  - login_latency_p95: Target < 500ms
  - mfa_success_rate: Target > 95%
  - token_refresh_latency_p95: Target < 200ms

Security:
  - failed_login_rate: Alert if > 10/min for single user
  - account_lockout_rate: Alert if > 5/hour
  - credential_stuffing_detected: Alert immediately
  - new_device_login_rate: Monitor for anomalies

Infrastructure:
  - lambda_error_rate: Alert if > 1%
  - dynamodb_throttle_rate: Alert if > 0
  - api_gateway_5xx_rate: Alert if > 0.1%
```

### Alert Thresholds

```yaml
Critical (Page immediately):
  - Authentication service down
  - Database unreachable
  - Credential stuffing attack detected
  - Mass account lockouts (> 100/hour)

High (Alert within 5 min):
  - Error rate > 5%
  - Latency p95 > 2s
  - Failed login spike (> 50/min)

Medium (Alert within 1 hour):
  - Error rate > 1%
  - Unusual geographic login patterns
  - MFA failure rate > 10%

Low (Daily digest):
  - New device logins
  - Password resets
  - MFA changes
```
