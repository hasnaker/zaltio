'use client';

import { motion } from 'framer-motion';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';

function Endpoint({ method, path, description }: { method: string; path: string; description: string }) {
  const methodColors: Record<string, string> = {
    GET: 'bg-blue-500/20 text-blue-400',
    POST: 'bg-emerald-500/20 text-emerald-400',
    PATCH: 'bg-yellow-500/20 text-yellow-400',
    DELETE: 'bg-red-500/20 text-red-400',
  };

  return (
    <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
      <div className="flex items-center gap-3 mb-2">
        <span className={`px-2 py-1 rounded text-xs font-mono font-medium ${methodColors[method]}`}>{method}</span>
        <code className="text-sm text-white font-mono">{path}</code>
      </div>
      <p className="text-sm text-neutral-400">{description}</p>
    </div>
  );
}

export default function UsersAPIPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Users API</h1>
        <p className="text-neutral-400">Manage users in your Zalt realm.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Endpoints</h2>
        <div className="space-y-3">
          <Endpoint method="GET" path="/v1/admin/users" description="List all users in the realm" />
          <Endpoint method="GET" path="/v1/admin/users/:id" description="Get a specific user by ID" />
          <Endpoint method="DELETE" path="/v1/admin/users/:id" description="Delete a user" />
          <Endpoint method="POST" path="/v1/admin/users/:id/suspend" description="Suspend a user account" />
          <Endpoint method="POST" path="/v1/admin/users/:id/activate" description="Activate a suspended user" />
          <Endpoint method="POST" path="/v1/admin/users/:id/unlock" description="Unlock a locked account" />
          <Endpoint method="POST" path="/v1/admin/users/:id/reset-password" description="Admin password reset" />
          <Endpoint method="POST" path="/v1/admin/users/:id/mfa/reset" description="Reset user's MFA" />
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">User Object</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "id": "user_abc123",
  "email": "user@example.com",
  "emailVerified": true,
  "profile": {
    "firstName": "John",
    "lastName": "Doe",
    "avatar": "https://..."
  },
  "mfa": {
    "enabled": true,
    "methods": ["totp", "webauthn"]
  },
  "status": "active",
  "createdAt": "2026-01-25T10:00:00Z",
  "lastLoginAt": "2026-01-25T12:00:00Z"
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Example: List Users</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`curl -X GET https://api.zalt.io/v1/admin/users \\
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
  -H "X-Realm-Id: your-realm-id"

// Response
{
  "users": [...],
  "pagination": {
    "total": 150,
    "page": 1,
    "limit": 20
  }
}`}
          </pre>
        </div>
      </section>
    </div>
  );
}
