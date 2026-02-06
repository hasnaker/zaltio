# HSD Auth Platform - Security Guide

This document outlines security best practices and configurations for the HSD Auth Platform.

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Layers                              │
├─────────────────────────────────────────────────────────────────┤
│  Transport Security                                             │
│  ├── TLS 1.3 encryption                                        │
│  ├── HTTPS enforcement                                          │
│  └── Certificate management (ACM)                               │
├─────────────────────────────────────────────────────────────────┤
│  API Security                                                   │
│  ├── Rate limiting                                              │
│  ├── CORS configuration                                         │
│  ├── Input validation                                           │
│  └── Request signing                                            │
├─────────────────────────────────────────────────────────────────┤
│  Authentication                                                 │
│  ├── JWT tokens (RS256)                                         │
│  ├── Refresh token rotation                                     │
│  ├── Session management                                         │
│  └── MFA support                                                │
├─────────────────────────────────────────────────────────────────┤
│  Data Security                                                  │
│  ├── Encryption at rest (AES-256)                              │
│  ├── Password hashing (bcrypt)                                  │
│  ├── PII protection                                             │
│  └── Audit logging                                              │
└─────────────────────────────────────────────────────────────────┘
```

## Authentication Security

### Password Requirements

Default password policy (configurable per realm):

| Requirement | Default | Min | Max |
|-------------|---------|-----|-----|
| Minimum length | 8 | 6 | 128 |
| Uppercase required | Yes | - | - |
| Lowercase required | Yes | - | - |
| Numbers required | Yes | - | - |
| Special characters | No | - | - |

### Password Hashing

Passwords are hashed using bcrypt with a cost factor of 12:

```typescript
import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 12;

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

### JWT Token Security

**Access Token Configuration:**
- Algorithm: RS256 (asymmetric)
- Expiration: 1 hour (configurable)
- Contains: user_id, realm_id, email, roles

**Refresh Token Configuration:**
- Algorithm: RS256
- Expiration: 7 days (configurable)
- Single-use with rotation
- Stored in database for revocation

**Token Structure:**
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user-abc123",
    "email": "user@example.com",
    "realm_id": "realm-123",
    "roles": ["user"],
    "iat": 1705315800,
    "exp": 1705319400,
    "jti": "token-unique-id"
  }
}
```

### Session Management

- Sessions are stored in DynamoDB with TTL
- Maximum concurrent sessions: 5 (configurable)
- Session includes: IP address, user agent, location
- Automatic session cleanup on logout

### Multi-Factor Authentication (MFA)

Supported MFA methods:
1. **TOTP** - Time-based One-Time Password (Google Authenticator, Authy)
2. **SMS** - SMS verification codes (backup method)

MFA enrollment flow:
```
1. User enables MFA in settings
2. System generates TOTP secret
3. User scans QR code with authenticator app
4. User enters verification code
5. MFA is activated
```

## API Security

### Rate Limiting

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Login attempts | 5 | 15 minutes |
| Registration | 3 | 1 hour |
| Password reset | 3 | 1 hour |
| API calls (authenticated) | 1000 | 1 minute |
| Admin API calls | 100 | 1 minute |

Rate limiting implementation:
```typescript
interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyGenerator: (req: Request) => string;
}

// Per-IP rate limiting for login
const loginRateLimit: RateLimitConfig = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5,
  keyGenerator: (req) => `login:${req.ip}`
};
```

### CORS Configuration

Allowed origins (production):
```typescript
const ALLOWED_ORIGINS = [
  'https://dashboard.auth.hsdcore.com',
  'https://portal.hsdcore.com',
  'https://chat.hsdcore.com',
  'https://tasks.hsdcore.com',
  'https://docs.hsdcore.com',
  'https://crm.hsdcore.com'
];

const corsConfig = {
  origin: ALLOWED_ORIGINS,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  credentials: true,
  maxAge: 86400
};
```

### Input Validation

All inputs are validated using schema validation:

```typescript
const registerSchema = {
  email: {
    type: 'string',
    format: 'email',
    maxLength: 255
  },
  password: {
    type: 'string',
    minLength: 8,
    maxLength: 128
  },
  realm_id: {
    type: 'string',
    pattern: '^realm-[a-z0-9]+$'
  }
};
```

### Security Headers

All responses include security headers:

```typescript
const securityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Content-Security-Policy': "default-src 'self'",
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};
```

## Data Security

### Encryption at Rest

All sensitive data in DynamoDB is encrypted:
- DynamoDB encryption: AWS managed keys (SSE-S3)
- Sensitive fields: Additional application-level encryption (AES-256-GCM)

```typescript
import { EncryptionService } from './services/encryption.service';

// Encrypt sensitive data before storage
const encryptedData = await encryptionService.encrypt(sensitiveData);

// Decrypt when reading
const decryptedData = await encryptionService.decrypt(encryptedData);
```

### Encryption in Transit

- All API traffic uses TLS 1.3
- Certificate managed by AWS ACM
- HTTPS enforced via redirect

### PII Protection

Personal Identifiable Information (PII) handling:

| Data Type | Storage | Access | Retention |
|-----------|---------|--------|-----------|
| Email | Encrypted | Auth only | Account lifetime |
| Password | Hashed (bcrypt) | Never readable | Account lifetime |
| IP Address | Encrypted | Audit only | 90 days |
| Name | Encrypted | User/Admin | Account lifetime |

### Data Retention

| Data Type | Retention Period | Deletion Method |
|-----------|------------------|-----------------|
| User accounts | Until deletion request | Hard delete |
| Sessions | 7 days after expiry | TTL auto-delete |
| Audit logs | 1 year | Archive then delete |
| Failed logins | 90 days | Auto-delete |

## Audit Logging

### Logged Events

All security-relevant events are logged:

```typescript
interface SecurityEvent {
  event_type: string;
  timestamp: string;
  user_id?: string;
  realm_id: string;
  ip_address: string;
  user_agent: string;
  details: Record<string, unknown>;
  outcome: 'success' | 'failure';
}
```

Event types:
- `auth.login` - Login attempt
- `auth.logout` - Logout
- `auth.register` - Registration
- `auth.password_change` - Password change
- `auth.mfa_enable` - MFA enabled
- `auth.mfa_disable` - MFA disabled
- `admin.user_suspend` - User suspended
- `admin.user_delete` - User deleted
- `admin.realm_create` - Realm created
- `admin.realm_delete` - Realm deleted

### Log Storage

- CloudWatch Logs for real-time monitoring
- S3 for long-term archival
- Encrypted at rest
- Access restricted to security team

## Incident Response

### Security Incident Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Data breach, system compromise | Immediate |
| High | Unauthorized access attempt | 1 hour |
| Medium | Suspicious activity | 4 hours |
| Low | Policy violation | 24 hours |

### Response Procedures

1. **Detection** - Automated alerts or manual report
2. **Containment** - Isolate affected systems
3. **Investigation** - Analyze logs and impact
4. **Remediation** - Fix vulnerability
5. **Recovery** - Restore normal operations
6. **Post-mortem** - Document and improve

### Emergency Contacts

- Security Team: security@hsdcore.com
- On-call: +49-xxx-xxx-xxxx
- AWS Support: Enterprise support ticket

## Compliance

### GDPR Compliance

- Data minimization: Only collect necessary data
- Right to access: Users can export their data
- Right to deletion: Users can delete their account
- Data portability: Export in standard format
- Consent management: Explicit consent for data processing

### Security Certifications

- SOC 2 Type II (planned)
- ISO 27001 (planned)

## Security Checklist

### Development

- [ ] Input validation on all endpoints
- [ ] Parameterized queries (no SQL injection)
- [ ] Secure password hashing
- [ ] JWT token validation
- [ ] Rate limiting implemented
- [ ] CORS properly configured
- [ ] Security headers set
- [ ] Sensitive data encrypted
- [ ] Audit logging enabled

### Deployment

- [ ] HTTPS enforced
- [ ] TLS 1.3 configured
- [ ] Secrets in Secrets Manager
- [ ] IAM least privilege
- [ ] VPC security groups configured
- [ ] CloudWatch alarms set
- [ ] Backup enabled
- [ ] Disaster recovery tested

### Operations

- [ ] Regular security audits
- [ ] Penetration testing (annual)
- [ ] Dependency updates
- [ ] Log monitoring
- [ ] Incident response plan
- [ ] Security training for team
