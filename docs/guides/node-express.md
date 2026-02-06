# Node.js / Express Integration Guide

Protect your Express.js API with Zalt.io authentication.

## Installation

```bash
npm install jsonwebtoken jwks-rsa express-rate-limit
```

## Basic Setup

### JWT Verification Middleware

```typescript
// middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

// JWKS client for fetching Zalt.io public keys
const client = jwksClient({
  jwksUri: 'https://api.zalt.io/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 86400000, // 24 hours
  rateLimit: true
});

function getKey(header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key?.getPublicKey();
    callback(null, signingKey);
  });
}

export interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    realmId: string;
    roles?: string[];
  };
}

export function authenticate(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.substring(7);
  
  jwt.verify(token, getKey, {
    algorithms: ['RS256'],
    issuer: 'zalt.io',
    audience: 'zalt.io'
  }, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired' });
      }
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    const payload = decoded as jwt.JwtPayload;
    req.user = {
      id: payload.sub!,
      email: payload.email,
      realmId: payload.realm_id,
      roles: payload.roles || []
    };
    
    next();
  });
}

// Optional: Require specific roles
export function requireRole(...roles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const hasRole = roles.some(role => req.user!.roles?.includes(role));
    if (!hasRole) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// Optional: Require email verification
export function requireVerifiedEmail(req: AuthRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  // Check email_verified claim in token
  // Or fetch user from Zalt.io API
  next();
}
```

### Express App Setup

```typescript
// app.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { authenticate, requireRole, AuthRequest } from './middleware/auth';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});
app.use(limiter);

// Public routes
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Protected routes
app.get('/api/profile', authenticate, (req: AuthRequest, res) => {
  res.json({
    userId: req.user!.id,
    email: req.user!.email
  });
});

app.get('/api/admin/users', authenticate, requireRole('admin'), (req: AuthRequest, res) => {
  // Admin-only endpoint
  res.json({ users: [] });
});

// Error handler
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

export default app;
```

## Advanced Patterns

### Session Validation

```typescript
// middleware/session.ts
import { AuthRequest } from './auth';
import { Response, NextFunction } from 'express';

const ZALT_API = 'https://api.zalt.io';

// Validate session is still active (not revoked)
export async function validateSession(req: AuthRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const response = await fetch(`${ZALT_API}/me`, {
      headers: {
        'Authorization': req.headers.authorization!
      }
    });
    
    if (!response.ok) {
      return res.status(401).json({ error: 'Session invalid' });
    }
    
    next();
  } catch (error) {
    next(error);
  }
}
```

### Realm Validation

```typescript
// middleware/realm.ts
import { AuthRequest } from './auth';
import { Response, NextFunction } from 'express';

const ALLOWED_REALMS = process.env.ALLOWED_REALMS?.split(',') || [];

export function requireRealm(...realms: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (!realms.includes(req.user.realmId)) {
      return res.status(403).json({ error: 'Access denied for this realm' });
    }
    
    next();
  };
}
```

### Audit Logging

```typescript
// middleware/audit.ts
import { AuthRequest } from './auth';
import { Response, NextFunction } from 'express';

export function auditLog(action: string) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const originalSend = res.send;
    
    res.send = function(body) {
      // Log after response
      console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        action,
        userId: req.user?.id,
        email: req.user?.email,
        ip: req.ip,
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        userAgent: req.headers['user-agent']
      }));
      
      return originalSend.call(this, body);
    };
    
    next();
  };
}

// Usage
app.post('/api/sensitive-action', 
  authenticate, 
  auditLog('SENSITIVE_ACTION'),
  (req, res) => {
    // ...
  }
);
```

### Token Refresh Proxy

```typescript
// routes/auth.ts
import { Router } from 'express';

const router = Router();
const ZALT_API = 'https://api.zalt.io';

router.post('/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  
  if (!refresh_token) {
    return res.status(400).json({ error: 'Refresh token required' });
  }
  
  try {
    const response = await fetch(`${ZALT_API}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      return res.status(response.status).json(data);
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

export default router;
```

## Multi-Tenant API

```typescript
// middleware/tenant.ts
import { AuthRequest } from './auth';
import { Response, NextFunction } from 'express';

// Extract tenant from subdomain or header
export function extractTenant(req: AuthRequest, res: Response, next: NextFunction) {
  // From subdomain: acme.api.yourapp.com
  const host = req.hostname;
  const subdomain = host.split('.')[0];
  
  // Or from header
  const tenantHeader = req.headers['x-tenant-id'] as string;
  
  // Or from authenticated user's realm
  const userRealm = req.user?.realmId;
  
  req.tenantId = tenantHeader || subdomain || userRealm;
  
  next();
}

// Ensure user belongs to requested tenant
export function validateTenant(req: AuthRequest, res: Response, next: NextFunction) {
  if (req.user && req.tenantId && req.user.realmId !== req.tenantId) {
    return res.status(403).json({ error: 'Access denied to this tenant' });
  }
  next();
}

declare global {
  namespace Express {
    interface Request {
      tenantId?: string;
    }
  }
}
```

## WebSocket Authentication

```typescript
// websocket/auth.ts
import { WebSocket, WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';
import { IncomingMessage } from 'http';

export function authenticateWebSocket(wss: WebSocketServer) {
  wss.on('connection', async (ws: WebSocket, req: IncomingMessage) => {
    // Get token from query string or header
    const url = new URL(req.url!, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    
    if (!token) {
      ws.close(4001, 'Authentication required');
      return;
    }
    
    try {
      const decoded = jwt.verify(token, ZALT_PUBLIC_KEY, {
        algorithms: ['RS256']
      }) as jwt.JwtPayload;
      
      // Attach user to WebSocket
      (ws as any).user = {
        id: decoded.sub,
        email: decoded.email,
        realmId: decoded.realm_id
      };
      
      ws.on('message', (message) => {
        // Handle authenticated messages
      });
      
    } catch (error) {
      ws.close(4001, 'Invalid token');
    }
  });
}
```

## Testing

```typescript
// tests/auth.test.ts
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../app';

// Generate test token
function generateTestToken(payload: any) {
  return jwt.sign(payload, TEST_PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: '1h',
    issuer: 'zalt.io',
    audience: 'zalt.io'
  });
}

describe('Protected Routes', () => {
  it('should reject requests without token', async () => {
    const res = await request(app).get('/api/profile');
    expect(res.status).toBe(401);
  });
  
  it('should accept valid token', async () => {
    const token = generateTestToken({
      sub: 'user-123',
      email: 'test@example.com',
      realm_id: 'test-realm'
    });
    
    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${token}`);
    
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe('user-123');
  });
  
  it('should reject expired token', async () => {
    const token = jwt.sign(
      { sub: 'user-123' },
      TEST_PRIVATE_KEY,
      { algorithm: 'RS256', expiresIn: '-1h' }
    );
    
    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${token}`);
    
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Token expired');
  });
});
```

## Environment Variables

```env
# .env
ZALT_REALM_ID=your-realm-id
ALLOWED_ORIGINS=http://localhost:3000,https://yourapp.com
ALLOWED_REALMS=realm-1,realm-2
```
