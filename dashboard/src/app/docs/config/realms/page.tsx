'use client';

import { motion } from 'framer-motion';
import { ArrowLeft, Settings } from 'lucide-react';
import Link from 'next/link';

export default function RealmConfigPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Realm Settings</h1>
        <p className="text-neutral-400">Configure your realm's authentication policies and branding.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">MFA Policy</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "mfa": {
    "required": true,           // Force MFA for all users
    "methods": ["totp", "webauthn"],  // Allowed methods
    "gracePeriod": 7,           // Days before MFA is enforced
    "rememberDevice": true,     // Skip MFA on trusted devices
    "rememberDuration": 30      // Days to remember device
  }
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Session Policy</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "session": {
    "maxConcurrent": 5,         // Max sessions per user
    "timeout": 3600,            // Idle timeout in seconds
    "absoluteTimeout": 86400,   // Max session duration
    "deviceBinding": true,      // Bind session to device
    "fuzzyMatchThreshold": 0.7  // Device fingerprint tolerance
  }
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Password Policy</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "password": {
    "minLength": 8,
    "requireUppercase": true,
    "requireLowercase": true,
    "requireNumber": true,
    "requireSpecial": false,
    "checkBreached": true,      // Check HaveIBeenPwned
    "maxAge": 90,               // Days before password expires
    "preventReuse": 5           // Remember last N passwords
  }
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Branding</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "branding": {
    "name": "My Company",
    "logo": "https://...",
    "favicon": "https://...",
    "primaryColor": "#10B981",
    "backgroundColor": "#0A0A0A"
  }
}`}
          </pre>
        </div>
        <p className="text-sm text-neutral-400">
          Branding settings are used in OAuth consent screens and email templates.
        </p>
      </section>
    </div>
  );
}
