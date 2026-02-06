# Zalt.io Documentation

**Internal Auth Platform for HSD Projects**

API: `https://api.zalt.io`

---

## Quick Links

| Need | Go To |
|------|-------|
| 5 dakikada entegrasyon | [Quickstart](./quickstart.md) |
| Nasıl çalışıyor? | [How it Works](./how-it-works.md) |
| Next.js projesi | [Next.js Guide](./guides/nextjs-integration.md) |
| React SPA | [React Guide](./guides/react-integration.md) |
| Node.js backend | [Node/Express Guide](./guides/node-express.md) |
| MFA kurulumu | [MFA Setup](./guides/mfa-setup.md) |
| Passkeys/WebAuthn | [WebAuthn Guide](./guides/webauthn.md) |
| API endpoint'leri | [API Reference](./api-reference.md) |
| JWT doğrulama | [JWT Claims](./reference/jwt-claims.md) |
| Hata kodları | [Error Codes](./reference/error-codes.md) |

---

## Docs Structure

```
docs/
├── quickstart.md          # 5 dakikada entegrasyon
├── how-it-works.md        # Mimari ve akış diyagramları
├── api-reference.md       # Tüm endpoint'ler
├── security.md            # Güvenlik özellikleri
├── ZALT-API-VERIFIED.md   # Kaynak koddan doğrulanmış referans
│
├── guides/                # Framework & feature rehberleri
│   ├── nextjs-integration.md
│   ├── react-integration.md
│   ├── node-express.md
│   ├── mobile-apps.md
│   ├── mfa-setup.md       # TOTP kurulumu
│   └── webauthn.md        # Passkeys kurulumu
│
├── reference/             # Teknik referans
│   ├── jwt-claims.md
│   ├── error-codes.md
│   └── rate-limits.md
│
└── configuration/         # Ayarlar
    ├── realm-settings.md
    └── email-templates.md
```

---

## Key Info

| Config | Value |
|--------|-------|
| API URL | `https://api.zalt.io` |
| JWT Issuer | `https://api.zalt.io` |
| JWT Audience | `https://api.zalt.io` |
| Algorithm | RS256 (KMS) |
| Access Token | 15 dakika |
| Refresh Token | 7 gün |

---

## Support

- Slack: #zalt-auth
- Auth Kiro: Kiro workspace
