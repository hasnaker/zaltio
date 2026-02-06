'use client';

import { motion } from 'framer-motion';
import { Key, Copy, Check } from 'lucide-react';
import { useState } from 'react';

function CodeBlock({ code, language = 'json' }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative bg-neutral-950 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-emerald-500/10">
        <span className="text-xs text-neutral-500 font-mono">{language}</span>
        <button onClick={handleCopy} className="text-neutral-500 hover:text-white">
          {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
        </button>
      </div>
      <pre className="p-4 text-sm font-mono text-neutral-300 overflow-x-auto">{code}</pre>
    </div>
  );
}

function Endpoint({ method, path, description, request, response, rateLimit }: {
  method: 'POST' | 'GET' | 'DELETE' | 'PUT';
  path: string;
  description: string;
  request?: string;
  response: string;
  rateLimit?: string;
}) {
  const methodColors = {
    POST: 'bg-emerald-500/20 text-emerald-400',
    GET: 'bg-blue-500/20 text-blue-400',
    DELETE: 'bg-red-500/20 text-red-400',
    PUT: 'bg-yellow-500/20 text-yellow-400',
  };

  return (
    <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
      <div className="p-4 border-b border-emerald-500/10">
        <div className="flex items-center gap-3 mb-2">
          <span className={`px-2 py-1 text-xs font-mono font-semibold rounded ${methodColors[method]}`}>
            {method}
          </span>
          <code className="text-sm text-white font-mono">{path}</code>
        </div>
        <p className="text-sm text-neutral-400">{description}</p>
        {rateLimit && (
          <p className="text-xs text-neutral-500 mt-2">Rate limit: {rateLimit}</p>
        )}
      </div>
      <div className="p-4 space-y-4">
        {request && (
          <div>
            <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-2">Request Body</h4>
            <CodeBlock code={request} />
          </div>
        )}
        <div>
          <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-2">Response</h4>
          <CodeBlock code={response} />
        </div>
      </div>
    </div>
  );
}

export default function AuthAPIPage() {
  return (
    <div className="space-y-12">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Key size={14} />
          API REFERENCE
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Authentication API</h1>
        <p className="text-neutral-400">Core authentication endpoints for login, registration, and token management.</p>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">Endpoints</h2>

        <Endpoint
          method="POST"
          path="/api/v1/auth/login"
          description="Authenticate a user with email and password. Returns access and refresh tokens."
          rateLimit="5 attempts / 15 min / IP"
          request={`{
  "email": "user@example.com",
  "password": "secure-password",
  "deviceFingerprint": "optional-device-id"
}`}
          response={`{
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "emailVerified": true,
    "mfaEnabled": true
  },
  "tokens": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "rt_xyz789...",
    "expiresIn": 900
  },
  "requiresMfa": false
}`}
        />

        <Endpoint
          method="POST"
          path="/api/v1/auth/register"
          description="Create a new user account. Sends verification email."
          rateLimit="3 attempts / hour / IP"
          request={`{
  "email": "newuser@example.com",
  "password": "SecureP@ss123!",
  "name": "John Doe"
}`}
          response={`{
  "user": {
    "id": "usr_def456",
    "email": "newuser@example.com",
    "emailVerified": false
  },
  "message": "Verification email sent"
}`}
        />

        <Endpoint
          method="POST"
          path="/api/v1/auth/refresh"
          description="Exchange a refresh token for new access and refresh tokens."
          rateLimit="10 requests / min / user"
          request={`{
  "refreshToken": "rt_xyz789..."
}`}
          response={`{
  "tokens": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "rt_new123...",
    "expiresIn": 900
  }
}`}
        />

        <Endpoint
          method="POST"
          path="/api/v1/auth/logout"
          description="Invalidate the current session and refresh token."
          request={`{
  "refreshToken": "rt_xyz789..."
}`}
          response={`{
  "success": true
}`}
        />

        <Endpoint
          method="POST"
          path="/api/v1/auth/mfa/verify"
          description="Verify MFA code (TOTP or WebAuthn) to complete authentication."
          rateLimit="5 attempts / min / user"
          request={`{
  "mfaToken": "mfa_pending_abc...",
  "code": "123456",
  "type": "totp"
}`}
          response={`{
  "user": { ... },
  "tokens": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "rt_xyz789...",
    "expiresIn": 900
  }
}`}
        />
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
        <h2 className="font-outfit text-lg font-semibold text-white mb-4">Error Responses</h2>
        <CodeBlock code={`{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "status": 401
  }
}

// Common error codes:
// INVALID_CREDENTIALS - Wrong email/password
// RATE_LIMITED - Too many attempts
// MFA_REQUIRED - MFA verification needed
// TOKEN_EXPIRED - Access token expired
// INVALID_TOKEN - Malformed or invalid token`} />
      </motion.div>
    </div>
  );
}
