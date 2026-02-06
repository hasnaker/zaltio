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

export default function RealmsAPIPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Realms API</h1>
        <p className="text-neutral-400">Manage multi-tenant realms for your organization.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">What is a Realm?</h2>
        <p className="text-neutral-400">
          A realm is an isolated tenant in Zalt. Each realm has its own users, sessions, and configuration.
          Perfect for SaaS applications with multiple customers.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Endpoints</h2>
        <div className="space-y-3">
          <Endpoint method="GET" path="/v1/admin/realms" description="List all realms" />
          <Endpoint method="POST" path="/v1/admin/realms" description="Create a new realm" />
          <Endpoint method="GET" path="/v1/admin/realms/:id" description="Get realm details" />
          <Endpoint method="PATCH" path="/v1/admin/realms/:id" description="Update realm settings" />
          <Endpoint method="DELETE" path="/v1/admin/realms/:id" description="Delete a realm" />
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Realm Object</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "id": "realm_abc123",
  "name": "Clinisyn Psychologists",
  "domain": "clinisyn.com",
  "settings": {
    "mfa": {
      "required": true,
      "methods": ["totp", "webauthn"]
    },
    "session": {
      "maxConcurrent": 5,
      "timeout": 3600
    },
    "branding": {
      "logo": "https://...",
      "primaryColor": "#10B981"
    }
  },
  "dataResidency": "eu",
  "createdAt": "2026-01-01T00:00:00Z"
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Create Realm</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`curl -X POST https://api.zalt.io/v1/admin/realms \\
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "My App",
    "domain": "myapp.com",
    "settings": {
      "mfa": { "required": false }
    }
  }'`}
          </pre>
        </div>
      </section>
    </div>
  );
}
