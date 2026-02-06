# Zalt Next.js Example

Complete authentication example with Zalt SDK.

## Features

- ✅ Email/password authentication
- ✅ User registration with onboarding
- ✅ Two-factor authentication (TOTP)
- ✅ WebAuthn/Passkeys
- ✅ Session management
- ✅ Protected routes with middleware
- ✅ Server-side authentication

## Getting Started

1. Install dependencies:
```bash
npm install
```

2. Copy environment file:
```bash
cp .env.example .env.local
```

3. Add your Zalt realm ID to `.env.local`:
```
NEXT_PUBLIC_ZALT_REALM_ID=your-realm-id
```

4. Run the development server:
```bash
npm run dev
```

5. Open [http://localhost:3000](http://localhost:3000)

## Project Structure

```
src/
├── app/
│   ├── layout.tsx          # ZaltProvider setup
│   ├── page.tsx            # Home page
│   ├── sign-in/
│   │   └── page.tsx        # Login with MFA
│   ├── sign-up/
│   │   └── page.tsx        # Registration
│   ├── onboarding/
│   │   └── page.tsx        # MFA setup flow
│   └── dashboard/
│       ├── page.tsx        # Protected dashboard
│       ├── mfa/
│       │   └── page.tsx    # MFA settings
│       ├── passkeys/
│       │   └── page.tsx    # WebAuthn management
│       └── sessions/
│           └── page.tsx    # Session management
└── middleware.ts           # Route protection
```

## Learn More

- [Zalt Documentation](https://zalt.io/docs)
- [@zalt/react README](../react/README.md)
- [@zalt/next README](../next/README.md)
