# HSD Auth Platform - SDK Integration Guide

This guide covers integrating the HSD Auth SDKs into your applications.

## Available SDKs

| SDK | Package | Documentation |
|-----|---------|---------------|
| JavaScript/TypeScript | `@hsd/auth-sdk` | [README](../sdk/README.md) |
| Python | `zalt` | [README](../sdk/python/README.md) |

## JavaScript/TypeScript SDK

### Installation

```bash
npm install @hsd/auth-sdk
# or
yarn add @hsd/auth-sdk
```

### Quick Start

```typescript
import { HSDAuthClient } from '@hsd/auth-sdk';

// Initialize the client
const auth = new HSDAuthClient({
  realmId: 'your-realm-id',
  apiUrl: 'https://api.auth.hsdcore.com'
});

// Register a new user
const { user, tokens } = await auth.register({
  email: 'user@example.com',
  password: 'SecurePassword123!'
});

// Login
const { user, tokens } = await auth.login({
  email: 'user@example.com',
  password: 'SecurePassword123!'
});

// Get current user
const currentUser = await auth.getCurrentUser();

// Logout
await auth.logout();
```

### Configuration Options

```typescript
interface HSDAuthConfig {
  realmId: string;           // Required: Your realm ID
  apiUrl: string;            // Required: API base URL
  storage?: Storage;         // Optional: Custom storage (default: localStorage)
  autoRefresh?: boolean;     // Optional: Auto-refresh tokens (default: true)
  refreshThreshold?: number; // Optional: Seconds before expiry to refresh (default: 300)
}
```

### Token Management

The SDK automatically handles token refresh:

```typescript
// Tokens are automatically refreshed when:
// 1. A request fails with 401
// 2. Token is about to expire (within refreshThreshold)

// Manual token access
const accessToken = auth.getAccessToken();
const refreshToken = auth.getRefreshToken();

// Check if authenticated
const isAuthenticated = auth.isAuthenticated();

// Manual refresh
await auth.refreshToken();
```

### Error Handling

```typescript
import { HSDAuthClient, AuthError, AuthErrorCode } from '@hsd/auth-sdk';

try {
  await auth.login({ email, password });
} catch (error) {
  if (error instanceof AuthError) {
    switch (error.code) {
      case AuthErrorCode.INVALID_CREDENTIALS:
        console.log('Invalid email or password');
        break;
      case AuthErrorCode.ACCOUNT_LOCKED:
        console.log('Account is locked');
        break;
      case AuthErrorCode.RATE_LIMITED:
        console.log('Too many attempts, try again later');
        break;
      default:
        console.log('Authentication error:', error.message);
    }
  }
}
```

### React Integration

```tsx
// AuthContext.tsx
import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { HSDAuthClient, User } from '@hsd/auth-sdk';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

const auth = new HSDAuthClient({
  realmId: process.env.NEXT_PUBLIC_REALM_ID!,
  apiUrl: process.env.NEXT_PUBLIC_API_URL!
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    auth.getCurrentUser()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const result = await auth.login({ email, password });
    setUser(result.user);
  };

  const logout = async () => {
    await auth.logout();
    setUser(null);
  };

  const register = async (email: string, password: string) => {
    const result = await auth.register({ email, password });
    setUser(result.user);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
```

### Next.js Integration

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  
  if (!token && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*']
};
```

## Python SDK

### Installation

```bash
pip install zalt
```

### Quick Start

```python
from hsd_auth import HSDAuthClient

# Initialize the client
auth = HSDAuthClient(
    realm_id='your-realm-id',
    api_url='https://api.auth.hsdcore.com'
)

# Register a new user
result = auth.register(
    email='user@example.com',
    password='SecurePassword123!'
)
user = result.user
tokens = result.tokens

# Login
result = auth.login(
    email='user@example.com',
    password='SecurePassword123!'
)

# Get current user
user = auth.get_current_user()

# Logout
auth.logout()
```

### Configuration Options

```python
from hsd_auth import HSDAuthClient, FileStorage

auth = HSDAuthClient(
    realm_id='your-realm-id',
    api_url='https://api.auth.hsdcore.com',
    storage=FileStorage('/path/to/tokens.json'),  # Custom storage
    auto_refresh=True,  # Auto-refresh tokens
    refresh_threshold=300  # Seconds before expiry to refresh
)
```

### Error Handling

```python
from hsd_auth import HSDAuthClient, AuthError, AuthErrorCode

try:
    auth.login(email=email, password=password)
except AuthError as e:
    if e.code == AuthErrorCode.INVALID_CREDENTIALS:
        print('Invalid email or password')
    elif e.code == AuthErrorCode.ACCOUNT_LOCKED:
        print('Account is locked')
    elif e.code == AuthErrorCode.RATE_LIMITED:
        print('Too many attempts, try again later')
    else:
        print(f'Authentication error: {e.message}')
```

### Django Integration

```python
# settings.py
HSD_AUTH = {
    'REALM_ID': 'your-realm-id',
    'API_URL': 'https://api.auth.hsdcore.com',
}

# middleware.py
from django.conf import settings
from django.http import HttpResponseRedirect
from hsd_auth import HSDAuthClient

class HSDAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth = HSDAuthClient(**settings.HSD_AUTH)
    
    def __call__(self, request):
        token = request.COOKIES.get('auth_token')
        
        if token:
            try:
                request.user = self.auth.validate_token(token)
            except:
                request.user = None
        else:
            request.user = None
        
        return self.get_response(request)

# views.py
from django.http import JsonResponse
from hsd_auth import HSDAuthClient

auth = HSDAuthClient(**settings.HSD_AUTH)

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            result = auth.login(email=email, password=password)
            response = JsonResponse({'user': result.user.to_dict()})
            response.set_cookie('auth_token', result.tokens.access_token)
            return response
        except AuthError as e:
            return JsonResponse({'error': e.message}, status=401)
```

### Flask Integration

```python
from flask import Flask, request, jsonify, make_response
from hsd_auth import HSDAuthClient, AuthError

app = Flask(__name__)
auth = HSDAuthClient(
    realm_id='your-realm-id',
    api_url='https://api.auth.hsdcore.com'
)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    try:
        result = auth.login(
            email=data['email'],
            password=data['password']
        )
        
        response = make_response(jsonify({
            'user': result.user.to_dict()
        }))
        response.set_cookie('auth_token', result.tokens.access_token)
        return response
    except AuthError as e:
        return jsonify({'error': e.message}), 401

@app.route('/me')
def get_current_user():
    token = request.cookies.get('auth_token')
    
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user = auth.get_current_user()
        return jsonify({'user': user.to_dict()})
    except AuthError:
        return jsonify({'error': 'Invalid token'}), 401
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException, Cookie
from hsd_auth import HSDAuthClient, AuthError

app = FastAPI()
auth = HSDAuthClient(
    realm_id='your-realm-id',
    api_url='https://api.auth.hsdcore.com'
)

async def get_current_user(auth_token: str = Cookie(None)):
    if not auth_token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    
    try:
        return auth.validate_token(auth_token)
    except AuthError:
        raise HTTPException(status_code=401, detail='Invalid token')

@app.post('/login')
async def login(email: str, password: str):
    try:
        result = auth.login(email=email, password=password)
        return {
            'user': result.user.to_dict(),
            'access_token': result.tokens.access_token
        }
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)

@app.get('/me')
async def me(user = Depends(get_current_user)):
    return {'user': user.to_dict()}
```

## Common Patterns

### Protected Routes

```typescript
// TypeScript/React
function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login');
    }
  }, [user, loading, router]);

  if (loading) return <LoadingSpinner />;
  if (!user) return null;
  
  return <>{children}</>;
}
```

```python
# Python/Flask
from functools import wraps
from flask import request, jsonify

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        try:
            request.user = auth.validate_token(token)
        except AuthError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated
```

### Token Storage

```typescript
// Custom storage for React Native
import AsyncStorage from '@react-native-async-storage/async-storage';

const auth = new HSDAuthClient({
  realmId: 'your-realm-id',
  apiUrl: 'https://api.auth.hsdcore.com',
  storage: {
    getItem: (key) => AsyncStorage.getItem(key),
    setItem: (key, value) => AsyncStorage.setItem(key, value),
    removeItem: (key) => AsyncStorage.removeItem(key)
  }
});
```

### Handling Token Expiry

```typescript
// Listen for token expiry events
auth.on('tokenExpired', async () => {
  try {
    await auth.refreshToken();
  } catch {
    // Redirect to login
    window.location.href = '/login';
  }
});

auth.on('sessionEnded', () => {
  // User was logged out (session revoked)
  window.location.href = '/login?reason=session_ended';
});
```

## Best Practices

1. **Never store tokens in localStorage for sensitive apps** - Use httpOnly cookies
2. **Always use HTTPS** - Never send tokens over HTTP
3. **Implement token refresh** - Don't let users get logged out unexpectedly
4. **Handle errors gracefully** - Show user-friendly error messages
5. **Use environment variables** - Don't hardcode realm IDs or API URLs
6. **Implement logout on all tabs** - Use BroadcastChannel or storage events
