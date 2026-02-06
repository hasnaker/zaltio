/**
 * Clinisyn x Zalt.io - Express.js Authentication Middleware
 * 
 * KURULUM:
 * npm install express jsonwebtoken jwks-rsa
 * npm install -D @types/express @types/jsonwebtoken
 * 
 * Kullanım:
 * import { requireAuth, requireMfa } from './express-middleware';
 * 
 * app.use('/api', requireAuth);
 * app.get('/api/sensitive', requireMfa, handler);
 */

// Types (inline to avoid import errors in example)
interface Request {
  headers: { authorization?: string };
  ip?: string;
  user?: ZaltUser;
}

interface Response {
  status: (code: number) => Response;
  json: (data: unknown) => Response;
  setHeader: (name: string, value: string) => Response;
}

type NextFunction = () => void;

interface ZaltUser {
  id: string;
  email: string;
  realmId: string;
  mfaVerified?: boolean;
  sessionId?: string;
}

interface JwtPayload {
  sub: string;
  email: string;
  realm_id: string;
  mfa_verified?: boolean;
  session_id?: string;
  exp: number;
  iat: number;
}

// Configuration
const ZALT_CONFIG = {
  apiUrl: process.env.ZALT_API_URL || 'https://api.zalt.io',
  realmId: process.env.ZALT_REALM_ID || 'clinisyn',
  jwksUri: process.env.ZALT_JWKS_URI || 'https://api.zalt.io/.well-known/jwks.json',
};

// ============================================================
// IMPLEMENTATION (requires: express, jsonwebtoken, jwks-rsa)
// ============================================================

/*
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

// JWKS Client for RS256 verification
const jwks = jwksClient({
  jwksUri: ZALT_CONFIG.jwksUri,
  cache: true,
  cacheMaxAge: 600000, // 10 minutes
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

// Get signing key from JWKS
function getKey(header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) {
  if (!header.kid) {
    callback(new Error('No kid in token header'));
    return;
  }
  
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key?.getPublicKey();
    callback(null, signingKey);
  });
}
*/

/**
 * Verify JWT token and attach user to request
 * 
 * @example
 * app.use('/api', requireAuth);
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): Response | void {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Missing or invalid authorization header',
      },
    });
  }
  
  const token = authHeader.substring(7);
  
  // JWT verification with JWKS
  // Uncomment and use with actual jwt library:
  /*
  jwt.verify(token, getKey, {
    algorithms: ['RS256'],
    issuer: 'https://api.zalt.io',
  }, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          error: { code: 'TOKEN_EXPIRED', message: 'Access token has expired' },
        });
      }
      return res.status(401).json({
        error: { code: 'INVALID_TOKEN', message: 'Invalid access token' },
      });
    }
    
    const payload = decoded as JwtPayload;
    
    if (payload.realm_id !== ZALT_CONFIG.realmId) {
      return res.status(403).json({
        error: { code: 'INVALID_REALM', message: 'Token realm does not match' },
      });
    }
    
    req.user = {
      id: payload.sub,
      email: payload.email,
      realmId: payload.realm_id,
      mfaVerified: payload.mfa_verified,
      sessionId: payload.session_id,
    };
    
    next();
  });
  */
  
  // Simplified sync verification for example
  try {
    const payload = decodeToken(token);
    
    if (!payload || isTokenExpired(payload)) {
      return res.status(401).json({
        error: { code: 'TOKEN_EXPIRED', message: 'Access token has expired' },
      });
    }
    
    if (payload.realm_id !== ZALT_CONFIG.realmId) {
      return res.status(403).json({
        error: { code: 'INVALID_REALM', message: 'Token realm does not match' },
      });
    }
    
    req.user = {
      id: payload.sub,
      email: payload.email,
      realmId: payload.realm_id,
      mfaVerified: payload.mfa_verified,
      sessionId: payload.session_id,
    };
    
    next();
  } catch {
    return res.status(401).json({
      error: { code: 'INVALID_TOKEN', message: 'Invalid access token' },
    });
  }
}

/**
 * Require MFA verification for sensitive operations
 * 
 * @example
 * app.post('/api/patients/:id/records', requireMfa, handler);
 */
export function requireMfa(req: Request, res: Response, next: NextFunction): Response | void {
  if (!req.user) {
    return res.status(401).json({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
  }
  
  if (!req.user.mfaVerified) {
    return res.status(403).json({
      error: { code: 'MFA_REQUIRED', message: 'MFA verification required for this operation' },
    });
  }
  
  next();
}

/**
 * Optional auth - attach user if token present, but don't require it
 */
export function optionalAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    next();
    return;
  }
  
  const token = authHeader.substring(7);
  
  try {
    const payload = decodeToken(token);
    if (payload && !isTokenExpired(payload)) {
      req.user = {
        id: payload.sub,
        email: payload.email,
        realmId: payload.realm_id,
        mfaVerified: payload.mfa_verified,
        sessionId: payload.session_id,
      };
    }
  } catch {
    // Ignore invalid tokens for optional auth
  }
  
  next();
}

/**
 * Rate limiting middleware
 */
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(options: { max: number; windowMs: number }) {
  return (req: Request, res: Response, next: NextFunction): Response | void => {
    const key = req.ip || 'unknown';
    const now = Date.now();
    
    let record = rateLimitStore.get(key);
    
    if (!record || now > record.resetAt) {
      record = { count: 0, resetAt: now + options.windowMs };
      rateLimitStore.set(key, record);
    }
    
    record.count++;
    
    if (record.count > options.max) {
      const retryAfter = Math.ceil((record.resetAt - now) / 1000);
      res.setHeader('Retry-After', retryAfter.toString());
      return res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many requests',
          details: { retry_after: retryAfter },
        },
      });
    }
    
    next();
  };
}

// Helper functions
function decodeToken(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    return payload as JwtPayload;
  } catch {
    return null;
  }
}

function isTokenExpired(payload: JwtPayload): boolean {
  return Date.now() >= payload.exp * 1000;
}

// Export config for reference
export { ZALT_CONFIG };
export type { ZaltUser, JwtPayload };
