# React Integration Guide

Complete guide for integrating Zalt.io with React applications.

## Installation

```bash
npm install @zalt/auth-sdk
```

## Quick Setup

### 1. Create Auth Context

```tsx
// src/contexts/AuthContext.tsx
import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { ZaltAuth, User, LoginResult } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: process.env.REACT_APP_ZALT_REALM_ID!,
  autoRefresh: true
});

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<LoginResult>;
  register: (email: string, password: string, profile?: any) => Promise<void>;
  logout: () => Promise<void>;
  verifyMFA: (sessionId: string, code: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing session on mount
    auth.getCurrentUser()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));

    // Listen for auth state changes
    const unsubscribe = auth.onAuthStateChange((user) => {
      setUser(user);
    });

    return unsubscribe;
  }, []);

  const login = async (email: string, password: string) => {
    const result = await auth.login({ email, password });
    if (!result.mfa_required) {
      setUser(result.user);
    }
    return result;
  };

  const register = async (email: string, password: string, profile?: any) => {
    await auth.register({ email, password, profile });
  };

  const logout = async () => {
    await auth.logout();
    setUser(null);
  };

  const verifyMFA = async (sessionId: string, code: string) => {
    const result = await auth.verifyMFA({ mfa_session_id: sessionId, code });
    setUser(result.user);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, verifyMFA }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

### 2. Wrap Your App

```tsx
// src/App.tsx
import { AuthProvider } from './contexts/AuthContext';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/mfa" element={<MFAPage />} />
          <Route path="/dashboard" element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          } />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
```

### 3. Protected Route Component

```tsx
// src/components/ProtectedRoute.tsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <LoadingSpinner />;
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
```

## Page Components

### Login Page

```tsx
// src/pages/LoginPage.tsx
import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  
  const from = location.state?.from?.pathname || '/dashboard';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await login(email, password);
      
      if (result.mfa_required) {
        // Store MFA session and redirect
        sessionStorage.setItem('mfa_session_id', result.mfa_session_id);
        navigate('/mfa');
      } else {
        navigate(from, { replace: true });
      }
    } catch (err: any) {
      switch (err.code) {
        case 'INVALID_CREDENTIALS':
          setError('Invalid email or password');
          break;
        case 'ACCOUNT_LOCKED':
          setError('Account locked. Please try again later.');
          break;
        case 'RATE_LIMITED':
          setError('Too many attempts. Please wait a few minutes.');
          break;
        default:
          setError('An error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <h1>Sign In</h1>
      
      {error && <div className="error-message">{error}</div>}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
        </div>
        
        <button type="submit" disabled={loading}>
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>
      
      <p>
        <a href="/forgot-password">Forgot password?</a>
      </p>
      <p>
        Don't have an account? <a href="/register">Sign up</a>
      </p>
    </div>
  );
}
```

### Register Page

```tsx
// src/pages/RegisterPage.tsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function RegisterPage() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      await register(formData.email, formData.password, {
        first_name: formData.firstName,
        last_name: formData.lastName
      });
      
      navigate('/login', { 
        state: { message: 'Registration successful! Please check your email to verify your account.' }
      });
    } catch (err: any) {
      switch (err.code) {
        case 'PASSWORD_COMPROMISED':
          setError('This password was found in a data breach. Please choose a different password.');
          break;
        case 'VALIDATION_ERROR':
          setError(err.message);
          break;
        default:
          setError('Registration failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="register-container">
      <h1>Create Account</h1>
      
      {error && <div className="error-message">{error}</div>}
      
      <form onSubmit={handleSubmit}>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="firstName">First Name</label>
            <input
              id="firstName"
              type="text"
              value={formData.firstName}
              onChange={(e) => setFormData({...formData, firstName: e.target.value})}
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="lastName">Last Name</label>
            <input
              id="lastName"
              type="text"
              value={formData.lastName}
              onChange={(e) => setFormData({...formData, lastName: e.target.value})}
              required
            />
          </div>
        </div>
        
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={formData.email}
            onChange={(e) => setFormData({...formData, email: e.target.value})}
            required
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={formData.password}
            onChange={(e) => setFormData({...formData, password: e.target.value})}
            required
            minLength={12}
          />
          <PasswordStrength password={formData.password} />
        </div>
        
        <div className="form-group">
          <label htmlFor="confirmPassword">Confirm Password</label>
          <input
            id="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={(e) => setFormData({...formData, confirmPassword: e.target.value})}
            required
          />
        </div>
        
        <button type="submit" disabled={loading}>
          {loading ? 'Creating account...' : 'Create Account'}
        </button>
      </form>
    </div>
  );
}
```

### MFA Page

```tsx
// src/pages/MFAPage.tsx
import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function MFAPage() {
  const [code, setCode] = useState(['', '', '', '', '', '']);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);
  
  const { verifyMFA } = useAuth();
  const navigate = useNavigate();
  
  const sessionId = sessionStorage.getItem('mfa_session_id');

  useEffect(() => {
    if (!sessionId) {
      navigate('/login');
    }
    inputRefs.current[0]?.focus();
  }, [sessionId, navigate]);

  const handleChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return;
    
    const newCode = [...code];
    newCode[index] = value;
    setCode(newCode);
    
    // Auto-focus next input
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
    
    // Auto-submit when complete
    if (newCode.every(c => c) && newCode.join('').length === 6) {
      handleSubmit(newCode.join(''));
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handleSubmit = async (fullCode?: string) => {
    const codeToSubmit = fullCode || code.join('');
    if (codeToSubmit.length !== 6) return;
    
    setError('');
    setLoading(true);

    try {
      await verifyMFA(sessionId!, codeToSubmit);
      sessionStorage.removeItem('mfa_session_id');
      navigate('/dashboard');
    } catch (err: any) {
      setError('Invalid code. Please try again.');
      setCode(['', '', '', '', '', '']);
      inputRefs.current[0]?.focus();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mfa-container">
      <h1>Two-Factor Authentication</h1>
      <p>Enter the 6-digit code from your authenticator app</p>
      
      {error && <div className="error-message">{error}</div>}
      
      <div className="code-inputs">
        {code.map((digit, index) => (
          <input
            key={index}
            ref={(el) => inputRefs.current[index] = el}
            type="text"
            inputMode="numeric"
            maxLength={1}
            value={digit}
            onChange={(e) => handleChange(index, e.target.value)}
            onKeyDown={(e) => handleKeyDown(index, e)}
            disabled={loading}
          />
        ))}
      </div>
      
      <button 
        onClick={() => handleSubmit()} 
        disabled={loading || code.join('').length !== 6}
      >
        {loading ? 'Verifying...' : 'Verify'}
      </button>
      
      <p className="help-text">
        Lost access to your authenticator? <a href="/recovery">Use a backup code</a>
      </p>
    </div>
  );
}
```

## MFA Setup Component

```tsx
// src/components/MFASetup.tsx
import { useState } from 'react';
import QRCode from 'qrcode.react';
import { ZaltAuth } from '@zalt/auth-sdk';

export function MFASetup({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState<'intro' | 'qr' | 'verify' | 'backup'>('intro');
  const [setupData, setSetupData] = useState<any>(null);
  const [code, setCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState('');

  const startSetup = async () => {
    const data = await auth.setupMFA();
    setSetupData(data);
    setStep('qr');
  };

  const verifySetup = async () => {
    try {
      const result = await auth.verifyMFASetup({
        code,
        secret: setupData.secret
      });
      setBackupCodes(result.backup_codes);
      setStep('backup');
    } catch (err) {
      setError('Invalid code. Please try again.');
    }
  };

  return (
    <div className="mfa-setup">
      {step === 'intro' && (
        <>
          <h2>Enable Two-Factor Authentication</h2>
          <p>Add an extra layer of security to your account.</p>
          <button onClick={startSetup}>Get Started</button>
        </>
      )}

      {step === 'qr' && (
        <>
          <h2>Scan QR Code</h2>
          <p>Scan this code with your authenticator app (Google Authenticator, Authy, etc.)</p>
          <QRCode value={setupData.otpauth_url} size={200} />
          <p className="manual-entry">
            Can't scan? Enter this code manually: <code>{setupData.secret}</code>
          </p>
          <button onClick={() => setStep('verify')}>Next</button>
        </>
      )}

      {step === 'verify' && (
        <>
          <h2>Verify Setup</h2>
          <p>Enter the 6-digit code from your authenticator app</p>
          {error && <div className="error">{error}</div>}
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            maxLength={6}
            placeholder="000000"
          />
          <button onClick={verifySetup}>Verify</button>
        </>
      )}

      {step === 'backup' && (
        <>
          <h2>Save Backup Codes</h2>
          <p>Save these codes in a safe place. You can use them if you lose access to your authenticator.</p>
          <div className="backup-codes">
            {backupCodes.map((code, i) => (
              <code key={i}>{code}</code>
            ))}
          </div>
          <button onClick={() => navigator.clipboard.writeText(backupCodes.join('\n'))}>
            Copy Codes
          </button>
          <button onClick={onComplete}>Done</button>
        </>
      )}
    </div>
  );
}
```

## WebAuthn Component

```tsx
// src/components/WebAuthnSetup.tsx
import { useState } from 'react';

export function WebAuthnSetup() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const registerPasskey = async () => {
    setLoading(true);
    setError('');

    try {
      // Get registration options from Zalt.io
      const options = await auth.webauthn.getRegistrationOptions();

      // Create credential using browser API
      const credential = await navigator.credentials.create({
        publicKey: options
      });

      // Register with Zalt.io
      await auth.webauthn.register(credential, 'My Device');
      
      setSuccess(true);
    } catch (err: any) {
      if (err.name === 'NotAllowedError') {
        setError('Passkey registration was cancelled.');
      } else {
        setError('Failed to register passkey. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  if (!window.PublicKeyCredential) {
    return <p>Your browser doesn't support passkeys.</p>;
  }

  return (
    <div className="webauthn-setup">
      <h3>Add a Passkey</h3>
      <p>Use Face ID, Touch ID, or your device's security key for faster, phishing-resistant login.</p>
      
      {error && <div className="error">{error}</div>}
      {success && <div className="success">Passkey registered successfully!</div>}
      
      <button onClick={registerPasskey} disabled={loading}>
        {loading ? 'Registering...' : 'Add Passkey'}
      </button>
    </div>
  );
}
```

## Hooks

### useRequireAuth

```tsx
// src/hooks/useRequireAuth.ts
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function useRequireAuth(redirectTo = '/login') {
  const { user, loading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !user) {
      navigate(redirectTo);
    }
  }, [user, loading, navigate, redirectTo]);

  return { user, loading };
}
```

### useRequireMFA

```tsx
// src/hooks/useRequireMFA.ts
export function useRequireMFA() {
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (user && !user.mfa_enabled) {
      navigate('/settings/security', { 
        state: { message: 'Please enable MFA to continue.' }
      });
    }
  }, [user, navigate]);
}
```

## Environment Variables

```env
# .env
REACT_APP_ZALT_REALM_ID=your-realm-id
REACT_APP_ZALT_API_URL=https://api.zalt.io
```

## TypeScript Types

```typescript
// src/types/auth.ts
export interface User {
  id: string;
  email: string;
  email_verified: boolean;
  profile: {
    first_name?: string;
    last_name?: string;
    metadata?: Record<string, any>;
  };
  mfa_enabled: boolean;
  created_at: string;
}

export interface LoginResult {
  user?: User;
  tokens?: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  };
  mfa_required?: boolean;
  mfa_session_id?: string;
}
```
