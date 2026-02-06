# Implementation Plan: Clerk-Style Customer Experience

## Overview

Müşterilerin self-service olarak Zalt'a kaydolup, SDK'yı kurarak authentication eklemesini sağlayan tam akış.

## Mevcut Durum

✅ Dashboard UI hazır (onboarding, realms, settings, billing)
✅ SDK'lar npm'de yayınlandı (@zalt.io/core, @zalt.io/react, @zalt.io/next)
✅ Backend API çalışıyor (api.zalt.io)

## Eksik Parçalar

1. Signup → Otomatik Realm + API Key oluşturma
2. SDK'ların gerçek API'ye bağlanması
3. Dashboard'un gerçek API'yi kullanması

## Tasks

- [x] 1. Backend: Customer Account & Auto-Provisioning
  - [x] 1.1 Customer tablosu oluştur (DynamoDB)
    - customer_id, email, name, company
    - created_at, subscription_plan
    - _Requirements: 1.1, 1.2_
  - [x] 1.2 Signup handler'ı güncelle - otomatik realm oluştur
    - Signup sonrası default realm oluştur
    - Publishable key (pk_live_xxx) generate et
    - Secret key (sk_live_xxx) generate et
    - _Requirements: 1.3, 1.4, 1.5_
  - [x] 1.3 API Key tablosu oluştur
    - key_id, customer_id, realm_id
    - key_hash (secret key için), key_prefix (gösterim için)
    - type (publishable/secret), status (active/revoked)
    - _Requirements: 4.1, 4.2, 4.3_

- [x] 2. Dashboard API Routes
  - [x] 2.1 /api/auth/signup - Gerçek signup endpoint
    - Zalt API'ye register çağrısı
    - Customer kaydı oluştur
    - Otomatik realm + keys oluştur
    - _Requirements: 1.2, 1.3, 1.4_
  - [x] 2.2 /api/dashboard/realms - Realm CRUD
    - GET: Müşterinin realm'lerini listele
    - POST: Yeni realm oluştur
    - _Requirements: 3.1, 3.2_
  - [x] 2.3 /api/settings/api-keys - API Key CRUD
    - GET: Müşterinin key'lerini listele
    - POST: Yeni key oluştur
    - DELETE: Key revoke et
    - _Requirements: 4.1, 4.2, 4.4_

- [x] 3. SDK: API Bağlantısı
  - [x] 3.1 @zalt.io/core - API client güncelle
    - Publishable key ile initialize
    - api.zalt.io endpoint'lerine bağlan
    - _Requirements: 5.1, 5.2_
  - [x] 3.2 @zalt.io/react - Provider güncelle
    - ZaltProvider publishableKey prop'u
    - Gerçek login/register/logout
    - _Requirements: 5.2, 5.3, 5.4_
  - [x] 3.3 @zalt.io/react - Hooks güncelle
    - useUser: Gerçek user data
    - useAuth: Gerçek auth state
    - _Requirements: 5.4, 5.5_

- [x] 4. Checkpoint - End-to-End Test
  - [x] 4.1 Signup flow test
    - zalt.io/signup → account oluştur
    - Otomatik realm + keys oluşturuldu mu?
    - _Requirements: 1.2, 1.3, 1.4_
    - ✅ 11 tests passing (customer-signup.e2e.test.ts)
  - [x] 4.2 SDK integration test
    - npm install @zalt.io/react
    - ZaltProvider ile wrap
    - SignInButton çalışıyor mu?
    - _Requirements: 5.1, 5.2, 5.3_
    - ✅ 81 tests passing (sdk-integration.e2e.test.ts)

- [ ] 5. Billing: Stripe Integration (Optional)
  - [ ] 5.1 Stripe account setup
  - [ ] 5.2 Checkout session endpoint
  - [ ] 5.3 Webhook handler (subscription events)
  - [ ] 5.4 Plan limits enforcement
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

## Müşteri Deneyimi (Hedef)

```
1. Geliştirici zalt.io'ya gelir
2. "Get Started Free" tıklar
3. Email + password ile signup
4. Onboarding wizard:
   - "Welcome to Zalt! 🎉"
   - API Keys gösterilir (pk_live_xxx, sk_live_xxx)
   - SDK kurulum kodu:
     npm install @zalt.io/react
     
     <ZaltProvider publishableKey="pk_live_xxx">
       <App />
     </ZaltProvider>
5. Dashboard'a yönlendirilir
6. Kendi uygulamasına SDK'yı ekler
7. End-user'lar login olmaya başlar
8. Dashboard'dan analytics görür
```

## SDK Kullanım Örneği (Hedef)

```tsx
// 1. Install
npm install @zalt.io/react

// 2. Wrap app
import { ZaltProvider } from '@zalt.io/react';

function App() {
  return (
    <ZaltProvider publishableKey="pk_live_xxx">
      <MyApp />
    </ZaltProvider>
  );
}

// 3. Use components
import { SignInButton, UserButton, useUser } from '@zalt.io/react';

function Header() {
  const { user, isLoaded } = useUser();
  
  if (!isLoaded) return <div>Loading...</div>;
  
  return (
    <header>
      {user ? (
        <UserButton />
      ) : (
        <SignInButton />
      )}
    </header>
  );
}

// 4. Protect routes
import { useAuth } from '@zalt.io/react';

function ProtectedPage() {
  const { isSignedIn } = useAuth();
  
  if (!isSignedIn) {
    return <RedirectToSignIn />;
  }
  
  return <Dashboard />;
}
```

## Notes

- Dashboard UI zaten hazır, sadece gerçek API'ye bağlanması gerekiyor
- SDK'lar npm'de, sadece API bağlantısı eksik
- Backend API çalışıyor, customer/api-key tabloları eklenmeli
