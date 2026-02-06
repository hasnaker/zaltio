# Zalt.io React SDK

React hooks ve components for Zalt.io Authentication Platform.

## Kurulum

```bash
npm install @zalt/auth-sdk react react-dom
```

## Hızlı Başlangıç

### 1. AuthProvider ile Uygulamayı Sar

```tsx
// app/layout.tsx veya _app.tsx
import { AuthProvider } from '@zalt/auth-sdk/react';

export default function RootLayout({ children }) {
  return (
    <AuthProvider
      baseUrl="https://api.zalt.io/v1"
      realmId="clinisyn-psychologists"
      onLogin={(user) => console.log('Giriş yapıldı:', user.email)}
      onLogout={() => console.log('Çıkış yapıldı')}
      onMFARequired={(sessionId) => router.push('/mfa')}
    >
      {children}
    </AuthProvider>
  );
}
```

### 2. useAuth Hook'u Kullan

```tsx
import { useAuth } from '@zalt/auth-sdk/react';

function LoginPage() {
  const { login, isLoading, error, mfaSessionId } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await login({ email, password });
      router.push('/dashboard');
    } catch (err) {
      // Error is also available in error state
    }
  };

  // MFA gerekiyorsa yönlendir
  if (mfaSessionId) {
    return <MFAVerification />;
  }

  return (
    <form onSubmit={handleSubmit}>
      <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      {error && <p className="error">{error.message}</p>}
      <button disabled={isLoading}>
        {isLoading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
      </button>
    </form>
  );
}
```

### 3. useUser Hook'u Kullan

```tsx
import { useUser } from '@zalt/auth-sdk/react';

function ProfilePage() {
  const { user, isLoading, updateProfile, isEmailVerified } = useUser();

  if (isLoading) return <Spinner />;
  if (!user) return <Navigate to="/login" />;

  return (
    <div>
      <h1>Merhaba, {user.profile.first_name}!</h1>
      <p>Email: {user.email} {isEmailVerified ? '✅' : '❌'}</p>
    </div>
  );
}
```

## Hooks

### Core Hooks

| Hook | Açıklama |
|------|----------|
| `useAuth()` | Login, logout, register, MFA verification |
| `useUser()` | User data, profile update, password change |

### MFA Hooks

| Hook | Açıklama |
|------|----------|
| `useMFA()` | MFA login verification |
| `useMFASetup()` | TOTP setup, backup codes |
| `useWebAuthn()` | Passkey registration/authentication |

### Other Hooks

| Hook | Açıklama |
|------|----------|
| `useDevices()` | Device management |
| `useSocialLogin()` | Google/Apple OAuth |
| `useEmailVerification()` | Email verification flow |
| `usePasswordReset()` | Password reset flow |

## MFA Akışı

```tsx
import { useMFA } from '@zalt/auth-sdk/react';

function MFAPage() {
  const { mfaRequired, verifyMFA, isLoading, error } = useMFA();
  const [code, setCode] = useState('');

  if (!mfaRequired) {
    return <Navigate to="/dashboard" />;
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); verifyMFA(code); }}>
      <input 
        value={code} 
        onChange={(e) => setCode(e.target.value)}
        placeholder="6 haneli kod"
        maxLength={6}
      />
      {error && <p className="error">{error.message}</p>}
      <button disabled={isLoading}>Doğrula</button>
    </form>
  );
}
```

## WebAuthn (Passkey)

```tsx
import { useWebAuthn } from '@zalt/auth-sdk/react';

function PasskeySetup() {
  const { registerPasskey, listCredentials } = useWebAuthn();

  const handleRegister = async () => {
    // 1. Server'dan options al
    const options = await registerPasskey.getOptions();
    
    // 2. Browser API ile credential oluştur
    const credential = await navigator.credentials.create({ 
      publicKey: options 
    });
    
    // 3. Server'a gönder
    await registerPasskey.verify(credential, 'MacBook Pro');
  };

  return <button onClick={handleRegister}>Passkey Ekle</button>;
}
```

## Social Login

```tsx
import { useSocialLogin } from '@zalt/auth-sdk/react';

function SocialButtons() {
  const { loginWithGoogle, loginWithApple } = useSocialLogin();

  return (
    <div>
      <button onClick={async () => {
        const { auth_url } = await loginWithGoogle();
        window.location.href = auth_url;
      }}>
        Google ile Giriş
      </button>
      <button onClick={async () => {
        const { auth_url } = await loginWithApple();
        window.location.href = auth_url;
      }}>
        Apple ile Giriş
      </button>
    </div>
  );
}
```

## SSR Desteği (Next.js)

React SDK otomatik olarak SSR'ı destekler:
- Server'da MemoryStorage kullanılır
- Client'ta BrowserStorage kullanılır
- Hydration uyumlu

## TypeScript

Tüm tipler export edilir:

```tsx
import type { 
  User, 
  LoginCredentials, 
  AuthState,
  MFASetupResult 
} from '@zalt/auth-sdk/react';
```

## Peer Dependencies

```json
{
  "peerDependencies": {
    "react": ">=17.0.0",
    "react-dom": ">=17.0.0"
  }
}
```
