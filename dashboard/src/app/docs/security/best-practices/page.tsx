'use client';

import { motion } from 'framer-motion';
import { ArrowLeft, Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import Link from 'next/link';

export default function BestPracticesPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Security Best Practices</h1>
        <p className="text-neutral-400">Follow these guidelines to keep your Zalt implementation secure.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white flex items-center gap-2">
          <Shield className="text-emerald-500" size={20} /> Token Storage
        </h2>
        <div className="grid gap-4">
          <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <CheckCircle className="text-emerald-500 mt-0.5" size={18} />
              <div>
                <h4 className="font-medium text-white">DO: Use httpOnly Cookies</h4>
                <p className="text-sm text-neutral-400 mt-1">Zalt's Next.js SDK automatically stores tokens in secure httpOnly cookies.</p>
              </div>
            </div>
          </div>
          <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <XCircle className="text-red-500 mt-0.5" size={18} />
              <div>
                <h4 className="font-medium text-white">DON'T: Store in localStorage</h4>
                <p className="text-sm text-neutral-400 mt-1">localStorage is vulnerable to XSS attacks. Never store tokens there in production.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white flex items-center gap-2">
          <AlertTriangle className="text-yellow-500" size={20} /> MFA Selection
        </h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-neutral-950">
              <tr>
                <th className="text-left p-4 text-neutral-400 font-medium">Method</th>
                <th className="text-left p-4 text-neutral-400 font-medium">Security</th>
                <th className="text-left p-4 text-neutral-400 font-medium">Recommendation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-emerald-500/10">
              <tr>
                <td className="p-4 text-white">WebAuthn/Passkeys</td>
                <td className="p-4"><span className="text-emerald-400">★★★★★</span></td>
                <td className="p-4 text-emerald-400">Highly Recommended</td>
              </tr>
              <tr>
                <td className="p-4 text-white">TOTP (Authenticator)</td>
                <td className="p-4"><span className="text-emerald-400">★★★★☆</span></td>
                <td className="p-4 text-emerald-400">Recommended</td>
              </tr>
              <tr>
                <td className="p-4 text-white">SMS</td>
                <td className="p-4"><span className="text-yellow-400">★★☆☆☆</span></td>
                <td className="p-4 text-yellow-400">Use with caution (SS7 vulnerable)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Error Handling</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`// ❌ Bad: Reveals information
throw new Error('User not found');
throw new Error('Invalid password');

// ✅ Good: Generic message
throw new AuthenticationError('Invalid credentials');

// Zalt SDK handles this automatically
try {
  await zalt.login(email, password);
} catch (error) {
  if (error instanceof AuthenticationError) {
    // Same message for all auth failures
    showError('Invalid email or password');
  }
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Checklist</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-3">
          {[
            'Use httpOnly cookies for token storage',
            'Enable MFA for all users (TOTP or WebAuthn)',
            'Never log passwords or tokens',
            'Use HTTPS everywhere',
            'Implement rate limiting',
            'Enable audit logging',
            'Use generic error messages',
            'Validate all user inputs',
          ].map((item) => (
            <label key={item} className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" className="w-4 h-4 rounded border-emerald-500/30 bg-neutral-950 text-emerald-500 focus:ring-emerald-500" />
              <span className="text-neutral-300 text-sm">{item}</span>
            </label>
          ))}
        </div>
      </section>
    </div>
  );
}
