# Zalt Authentication - VS Code Extension

Official VS Code and Cursor extension for Zalt.io authentication SDK.

## Features

### Commands

- **Zalt: Add Authentication** - Scaffold authentication setup for your framework
- **Zalt: Add MFA Setup** - Add MFA setup component
- **Zalt: Add Protected Route** - Add Next.js middleware for route protection
- **Zalt: Security Check** - Scan current file for security issues

### Code Snippets

| Prefix | Description |
|--------|-------------|
| `zalt-provider` | ZaltProvider setup |
| `zalt-useauth` | useAuth hook usage |
| `zalt-signed` | SignedIn/SignedOut components |
| `zalt-login-form` | Complete login form |
| `zalt-mfa-component` | MFA setup component |
| `zalt-middleware` | Next.js middleware |
| `zalt-server-auth` | Server-side auth |
| `zalt-client` | ZaltClient instance |
| `zalt-login` | Login with MFA handling |
| `zalt-register` | User registration |
| `zalt-error` | Error handling pattern |

### Sidebar Panel

- **Status** - API connection status
- **Realms** - Your configured realms
- **Documentation** - Quick links to docs

## Installation

1. Install from VS Code Marketplace
2. Or install from Open VSX (for Cursor)

## Configuration

```json
{
  "zalt.apiUrl": "https://api.zalt.io",
  "zalt.adminKey": "your-admin-key"
}
```

## Quick Start

1. Open Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
2. Run "Zalt: Add Authentication"
3. Select your framework
4. Enter your Realm ID
5. Install packages: `npm install @zalt/core @zalt/react @zalt/next`

## Security

This extension helps you follow security best practices:

- ✅ httpOnly cookies for token storage
- ✅ TOTP/WebAuthn for MFA (not SMS)
- ✅ Rate limiting awareness
- ✅ No sensitive data logging

## Links

- [Documentation](https://zalt.io/docs)
- [Dashboard](https://zalt.io)
- [GitHub](https://github.com/zalt-io/zalt-sdk)
