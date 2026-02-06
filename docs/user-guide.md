# Zalt.io User Guide

Real-world implementation scenarios and best practices.

## Common Use Cases

### 1. Basic Web Application

Standard login/register flow for a web app.

```typescript
// Initialize
const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id'
});

// Registration page
async function handleRegister(form) {
  try {
    const result = await auth.register({
      email: form.email,
      password: form.password,
      profile: {
        first_name: form.firstName,
        last_name: form.lastName
      }
    });
    
    showMessage('Check your email to verify your account');
    redirect('/login');
  } catch (error) {
    if (error.code === 'PASSWORD_COMPROMISED') {
      showError('This password was found in a data breach. Choose another.');
    } else {
      showError(error.message);
    }
  }
}

// Login page
async function handleLogin(form) {
  const result = await auth.login({
    email: form.email,
    password: form.password
  });
  
  if (result.mfa_required) {
    // Store session for MFA page
    sessionStorage.setItem('mfa_session', result.mfa_session_id);
    redirect('/mfa');
  } else {
    redirect('/dashboard');
  }
}
```

### 2. Healthcare Application (HIPAA)

Required: MFA + WebAuthn for all users.

```typescript
const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'healthcare-realm' // MFA enforced at realm level
});

// After login, check security requirements
async function enforceSecurityPolicy(user) {
  // Email must be verified
  if (!user.email_verified) {
    await auth.sendVerificationEmail();
    redirect('/verify-email-required');
    return;
  }
  
  // MFA must be enabled
  if (!user.mfa_enabled) {
    redirect('/setup-mfa-required');
    return;
  }
  
  // WebAuthn recommended for sensitive operations
  const credentials = await auth.webauthn.listCredentials();
  if (credentials.length === 0) {
    showBanner('Add a passkey for phishing-resistant login');
  }
}

// Sensitive operation - require re-authentication
async function performSensitiveAction() {
  const lastAuth = getLastAuthTime();
  const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
  
  if (lastAuth < fiveMinutesAgo) {
    // Require fresh authentication
    const code = await promptForMFACode();
    await auth.verifyMFA({ code });
    setLastAuthTime(Date.now());
  }
  
  // Proceed with sensitive action
}
```

### 3. Mobile Application

Token storage and biometric authentication.

```typescript
import { ZaltAuth } from '@zalt/auth-sdk';
import * as SecureStore from 'expo-secure-store';

// Custom secure storage for mobile
const secureStorage = {
  async getItem(key) {
    return SecureStore.getItemAsync(key);
  },
  async setItem(key, value) {
    return SecureStore.setItemAsync(key, value);
  },
  async removeItem(key) {
    return SecureStore.deleteItemAsync(key);
  }
};

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  storage: secureStorage
});

// Biometric login with WebAuthn
async function biometricLogin() {
  try {
    const options = await auth.webauthn.getAuthenticationOptions({
      email: savedEmail
    });
    
    // This triggers Face ID / Touch ID
    const credential = await navigator.credentials.get({
      publicKey: options
    });
    
    const result = await auth.webauthn.authenticate(credential);
    return result.user;
  } catch (error) {
    // Fall back to password login
    redirect('/login');
  }
}
```

### 4. Multi-Tenant SaaS

Different realms for different customers.

```typescript
// Determine realm from subdomain
function getRealmFromHost() {
  const host = window.location.host;
  const subdomain = host.split('.')[0];
  
  // Map subdomains to realms
  const realmMap = {
    'acme': 'acme-corp-prod',
    'globex': 'globex-prod',
    'app': 'default-realm'
  };
  
  return realmMap[subdomain] || 'default-realm';
}

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: getRealmFromHost()
});

// Each realm has its own:
// - User database
// - MFA policies
// - Branding settings
// - Allowed origins
```

### 5. Admin Dashboard

Managing users and sessions.

```typescript
// Admin endpoints require admin role in JWT
const adminToken = await auth.getAccessToken();

// List users
const users = await fetch('https://api.zalt.io/v1/admin/users', {
  headers: { 'Authorization': `Bearer ${adminToken}` }
}).then(r => r.json());

// Suspend a user
await fetch(`https://api.zalt.io/v1/admin/users/${userId}/suspend`, {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${adminToken}` }
});

// Force logout all sessions
await fetch(`https://api.zalt.io/v1/admin/users/${userId}/sessions`, {
  method: 'DELETE',
  headers: { 'Authorization': `Bearer ${adminToken}` }
});

// Reset user's MFA
await fetch(`https://api.zalt.io/v1/admin/users/${userId}/mfa`, {
  method: 'DELETE',
  headers: { 'Authorization': `Bearer ${adminToken}` }
});
```

## Implementation Patterns

### Protected Routes (React)

```tsx
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  
  if (loading) {
    return <LoadingSpinner />;
  }
  
  if (!user) {
    return <Navigate to="/login" />;
  }
  
  return children;
}

// Usage
<Route path="/dashboard" element={
  <ProtectedRoute>
    <Dashboard />
  </ProtectedRoute>
} />
```

### API Middleware (Express)

```typescript
import { verify } from 'jsonwebtoken';

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    // Verify with Zalt.io public key
    const decoded = verify(token, ZALT_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'zalt.io'
    });
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
```

### Session Timeout Handling

```typescript
// Client-side session monitoring
let sessionTimer;

function resetSessionTimer() {
  clearTimeout(sessionTimer);
  sessionTimer = setTimeout(async () => {
    const isValid = await auth.isAuthenticated();
    if (!isValid) {
      showModal('Your session has expired. Please log in again.');
      await auth.logout();
      redirect('/login');
    }
  }, 14 * 60 * 1000); // Check 1 min before 15-min expiry
}

// Reset on user activity
document.addEventListener('click', resetSessionTimer);
document.addEventListener('keypress', resetSessionTimer);
```

### Error Handling

```typescript
async function safeApiCall(fn) {
  try {
    return await fn();
  } catch (error) {
    switch (error.code) {
      case 'TOKEN_EXPIRED':
        // SDK handles refresh automatically
        // This means refresh also failed
        await auth.logout();
        redirect('/login?reason=session_expired');
        break;
        
      case 'ACCOUNT_LOCKED':
        showError('Account locked due to too many failed attempts. Try again in 15 minutes.');
        break;
        
      case 'MFA_REQUIRED':
        redirect('/mfa');
        break;
        
      case 'RATE_LIMITED':
        showError('Too many requests. Please wait a moment.');
        break;
        
      default:
        showError('An error occurred. Please try again.');
        console.error(error);
    }
  }
}
```

## Security Recommendations

### Password Requirements

Display clear requirements to users:

```tsx
function PasswordRequirements({ password }) {
  const checks = [
    { label: 'At least 12 characters', valid: password.length >= 12 },
    { label: 'Uppercase letter', valid: /[A-Z]/.test(password) },
    { label: 'Lowercase letter', valid: /[a-z]/.test(password) },
    { label: 'Number', valid: /\d/.test(password) },
    { label: 'Special character', valid: /[!@#$%^&*]/.test(password) }
  ];
  
  return (
    <ul>
      {checks.map(({ label, valid }) => (
        <li className={valid ? 'valid' : 'invalid'}>
          {valid ? '✓' : '○'} {label}
        </li>
      ))}
    </ul>
  );
}
```

### MFA Setup Flow

Guide users through MFA setup:

```tsx
function MFASetupWizard() {
  const [step, setStep] = useState(1);
  const [setupData, setSetupData] = useState(null);
  
  // Step 1: Generate secret
  async function startSetup() {
    const data = await auth.setupMFA();
    setSetupData(data);
    setStep(2);
  }
  
  // Step 2: Show QR code
  // Step 3: Verify code
  // Step 4: Save backup codes
  
  return (
    <div>
      {step === 1 && <Button onClick={startSetup}>Enable MFA</Button>}
      {step === 2 && <QRCode value={setupData.otpauth_url} />}
      {step === 3 && <CodeInput onSubmit={verifyCode} />}
      {step === 4 && <BackupCodes codes={backupCodes} />}
    </div>
  );
}
```

## Troubleshooting

### Common Issues

**"Invalid credentials" but password is correct**
- Check realm_id is correct
- Verify email is not case-sensitive issue
- Account may be locked - wait 15 minutes

**Token refresh failing**
- Refresh token may have expired (7 days)
- User may have been logged out by admin
- Check network connectivity

**MFA code not working**
- Ensure device time is synchronized
- Code expires after 30 seconds
- Try the next code if timing is close

**WebAuthn not working**
- Requires HTTPS (except localhost)
- Browser must support WebAuthn
- Check if credential was deleted

### Debug Mode

```typescript
const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  debug: true // Logs all API calls
});
```

## Support

- Documentation: https://docs.zalt.io
- Email: support@zalt.io
- Status: https://status.zalt.io
