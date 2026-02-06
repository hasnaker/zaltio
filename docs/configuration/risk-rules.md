# Custom Risk Rules Configuration

This guide explains how to configure custom risk rules for AI-powered risk assessment in Zalt.io.

## Overview

Custom risk rules allow you to fine-tune the AI risk assessment behavior for your realm. You can:

- **IP Whitelist**: Bypass or reduce risk assessment for trusted IP addresses
- **Trusted Devices**: Reduce risk scores for pre-approved devices
- **Custom Thresholds**: Override default MFA and block thresholds

## Configuration

Custom risk rules are configured in your realm settings:

```typescript
import { ZaltAdmin } from '@zalt/admin-sdk';

const admin = new ZaltAdmin({ apiKey: 'your-api-key' });

await admin.realms.update('realm_xxx', {
  settings: {
    custom_risk_rules: {
      enabled: true,
      ip_whitelist: ['192.168.1.0/24', '10.0.0.1'],
      trusted_devices: [
        {
          fingerprint_hash: 'sha256-hash-of-device-fingerprint',
          name: 'Corporate Laptop #1',
          added_at: '2025-01-01T00:00:00Z',
          added_by: 'admin_xxx',
          active: true
        }
      ],
      thresholds: {
        mfa_threshold: 50,
        block_threshold: 80,
        alert_threshold: 60
      },
      ip_whitelist_score_reduction: 100,
      trusted_device_score_reduction: 30,
      audit_enabled: true
    }
  }
});
```

## IP Whitelist

The IP whitelist allows you to specify IP addresses or CIDR ranges that should bypass or have reduced risk assessment.

### Supported Formats

- **Single IPv4**: `192.168.1.1`
- **IPv4 CIDR**: `192.168.1.0/24`, `10.0.0.0/8`
- **Single IPv6**: `2001:db8::1`
- **IPv6 CIDR**: `2001:db8::/32`

### Use Cases

1. **Corporate VPN**: Whitelist your company's VPN exit IPs
2. **Office Networks**: Whitelist office IP ranges
3. **Partner Networks**: Whitelist trusted partner IPs

### Score Reduction

The `ip_whitelist_score_reduction` setting controls how much the risk score is reduced:

- **100** (default): Complete bypass - risk score set to 0
- **50**: Reduce risk score by 50 points
- **0**: No reduction (whitelist has no effect)

### Example

```typescript
{
  ip_whitelist: [
    '203.0.113.0/24',    // Corporate office
    '198.51.100.1',      // VPN exit node
    '2001:db8::/32'      // IPv6 range
  ],
  ip_whitelist_score_reduction: 100  // Complete bypass
}
```

## Trusted Devices

Trusted devices are pre-approved device fingerprints that receive a reduced risk score.

### Device Entry Structure

```typescript
interface TrustedDevice {
  fingerprint_hash: string;  // SHA-256 hash of device fingerprint
  name: string;              // Human-readable name (max 100 chars)
  added_at: string;          // ISO 8601 timestamp
  added_by: string;          // Admin user ID who added this device
  expires_at?: string;       // Optional expiration date
  active: boolean;           // Whether device is currently active
}
```

### Getting Device Fingerprint Hash

Device fingerprints are collected during login. To get the hash:

```typescript
import { createHash } from 'crypto';

// Device fingerprint from login context
const fingerprint = {
  userAgent: 'Mozilla/5.0...',
  screenResolution: '1920x1080',
  timezone: 'America/New_York',
  // ... other fingerprint data
};

const hash = createHash('sha256')
  .update(JSON.stringify(fingerprint))
  .digest('hex');
```

### Score Reduction

The `trusted_device_score_reduction` setting controls how much the risk score is reduced:

- **30** (default): Reduce risk score by 30 points
- **50**: Reduce risk score by 50 points
- **0**: No reduction

### Example

```typescript
{
  trusted_devices: [
    {
      fingerprint_hash: 'a1b2c3d4e5f6...',  // 64-char SHA-256
      name: 'CEO MacBook Pro',
      added_at: '2025-01-15T10:00:00Z',
      added_by: 'admin_security_team',
      expires_at: '2026-01-15T10:00:00Z',  // 1 year validity
      active: true
    },
    {
      fingerprint_hash: 'f6e5d4c3b2a1...',
      name: 'IT Support Workstation',
      added_at: '2025-01-10T08:00:00Z',
      added_by: 'admin_it_manager',
      active: true  // No expiration
    }
  ],
  trusted_device_score_reduction: 30
}
```

## Custom Thresholds

Override the default risk thresholds for your realm.

### Default Thresholds

| Threshold | Default | Description |
|-----------|---------|-------------|
| `mfa_threshold` | 70 | Score above which MFA is required |
| `block_threshold` | 90 | Score above which login is blocked |
| `alert_threshold` | 75 | Score above which admin is alerted |

### Healthcare Realms

For healthcare realms (HIPAA compliance), we recommend stricter thresholds:

```typescript
{
  thresholds: {
    mfa_threshold: 50,     // Require MFA earlier
    block_threshold: 80,   // Block suspicious logins sooner
    alert_threshold: 60    // Alert security team earlier
  }
}
```

### Enterprise Realms

For enterprise realms with trusted networks:

```typescript
{
  thresholds: {
    mfa_threshold: 60,
    block_threshold: 85,
    alert_threshold: 70
  }
}
```

## Audit Logging

When `audit_enabled` is true (default), all custom rule applications are logged:

```json
{
  "event_type": "custom_risk_rule_applied",
  "realm_id": "realm_xxx",
  "timestamp": "2025-01-25T10:30:00Z",
  "details": {
    "rule_type": "ip_whitelist",
    "ip": "192.168.1.50",
    "matched_entry": "192.168.1.0/24",
    "original_score": 75,
    "adjusted_score": 0,
    "bypassed": true
  }
}
```

## Security Considerations

### IP Whitelist Security

⚠️ **Warning**: IP whitelisting reduces security. Use with caution.

- Only whitelist IPs you fully control
- Regularly audit whitelisted IPs
- Consider using partial reduction instead of full bypass
- Monitor for IP spoofing attempts

### Trusted Device Security

- Device fingerprints can be spoofed by sophisticated attackers
- Use in combination with other security measures (MFA, WebAuthn)
- Set expiration dates for trusted devices
- Regularly review and remove unused devices

### Threshold Security

- Lower thresholds increase security but may impact user experience
- Higher thresholds reduce friction but increase risk
- Healthcare realms should use stricter thresholds
- Monitor false positive rates and adjust accordingly

## API Reference

### Get Custom Risk Rules

```http
GET /api/v1/realms/{realmId}/settings/custom-risk-rules
Authorization: Bearer {admin-token}
```

### Update Custom Risk Rules

```http
PATCH /api/v1/realms/{realmId}/settings/custom-risk-rules
Authorization: Bearer {admin-token}
Content-Type: application/json

{
  "enabled": true,
  "ip_whitelist": ["192.168.1.0/24"],
  "thresholds": {
    "mfa_threshold": 50
  }
}
```

### Add Trusted Device

```http
POST /api/v1/realms/{realmId}/settings/custom-risk-rules/trusted-devices
Authorization: Bearer {admin-token}
Content-Type: application/json

{
  "fingerprint_hash": "a1b2c3d4...",
  "name": "New Corporate Device",
  "expires_at": "2026-01-01T00:00:00Z"
}
```

### Remove Trusted Device

```http
DELETE /api/v1/realms/{realmId}/settings/custom-risk-rules/trusted-devices/{fingerprintHash}
Authorization: Bearer {admin-token}
```

## Validation Rules

### IP Whitelist Validation

- Must be valid IPv4, IPv6, or CIDR notation
- CIDR mask must be valid (0-32 for IPv4, 0-128 for IPv6)
- Maximum 100 entries per realm

### Trusted Device Validation

- `fingerprint_hash` must be 64-character SHA-256 hex string
- `name` is required, max 100 characters
- `added_at` must be valid ISO 8601 date
- `added_by` is required
- Maximum 500 trusted devices per realm

### Threshold Validation

- All thresholds must be 0-100
- `mfa_threshold` must be less than `block_threshold`

## Best Practices

1. **Start Conservative**: Begin with default thresholds and adjust based on data
2. **Monitor Metrics**: Track false positive/negative rates
3. **Regular Audits**: Review whitelists and trusted devices quarterly
4. **Document Changes**: Keep records of why rules were added
5. **Test Changes**: Test rule changes in staging before production
6. **Use Expiration**: Set expiration dates for trusted devices
7. **Combine with MFA**: Don't rely solely on custom rules for security

## Troubleshooting

### Rule Not Applied

1. Check if `enabled` is `true`
2. Verify IP format is correct
3. Check device fingerprint hash is exact match
4. Review audit logs for rule application

### Unexpected Blocks

1. Check if thresholds are too low
2. Review risk factors in audit log
3. Consider adding IP to whitelist
4. Add device to trusted list

### Performance Issues

1. Reduce number of whitelist entries
2. Use CIDR ranges instead of individual IPs
3. Remove expired trusted devices
