'use client';

import { motion } from 'framer-motion';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';

function Endpoint({ method, path, description }: { method: string; path: string; description: string }) {
  const methodColors: Record<string, string> = {
    GET: 'bg-blue-500/20 text-blue-400',
    POST: 'bg-emerald-500/20 text-emerald-400',
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

export default function SessionsAPIPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Sessions API</h1>
        <p className="text-neutral-400">Manage user sessions and devices.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Endpoints</h2>
        <div className="space-y-3">
          <Endpoint method="GET" path="/v1/admin/sessions" description="List all active sessions" />
          <Endpoint method="DELETE" path="/v1/admin/sessions/:id" description="Revoke a specific session" />
          <Endpoint method="GET" path="/v1/admin/users/:id/sessions" description="List sessions for a user" />
          <Endpoint method="DELETE" path="/v1/admin/users/:id/sessions" description="Revoke all sessions for a user" />
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Session Object</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "id": "sess_abc123",
  "userId": "user_xyz789",
  "device": {
    "id": "dev_123",
    "name": "Chrome on MacOS",
    "type": "browser",
    "fingerprint": "abc..."
  },
  "ip": "192.168.1.1",
  "location": {
    "country": "US",
    "city": "San Francisco"
  },
  "createdAt": "2026-01-25T10:00:00Z",
  "lastActiveAt": "2026-01-25T12:00:00Z",
  "expiresAt": "2026-02-01T10:00:00Z"
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Device Fingerprinting</h2>
        <p className="text-neutral-400">Zalt uses device fingerprinting with 70% fuzzy matching to detect session hijacking attempts.</p>
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4">
          <p className="text-sm text-neutral-300">
            When a session is used from a device that doesn't match the original fingerprint, 
            the session is flagged and the user may be required to re-authenticate.
          </p>
        </div>
      </section>
    </div>
  );
}
