'use client';

import { motion } from 'framer-motion';
import { ArrowLeft, Webhook, CheckCircle } from 'lucide-react';
import Link from 'next/link';

export default function WebhooksConfigPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Webhooks</h1>
        <p className="text-neutral-400">Receive real-time notifications for authentication events.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Available Events</h2>
        <div className="grid gap-2">
          {[
            { event: 'user.created', desc: 'New user registered' },
            { event: 'user.updated', desc: 'User profile updated' },
            { event: 'user.deleted', desc: 'User account deleted' },
            { event: 'session.created', desc: 'User logged in' },
            { event: 'session.revoked', desc: 'Session terminated' },
            { event: 'mfa.enabled', desc: 'MFA enabled for user' },
            { event: 'mfa.disabled', desc: 'MFA disabled for user' },
            { event: 'password.changed', desc: 'Password changed' },
            { event: 'password.reset', desc: 'Password reset requested' },
          ].map(({ event, desc }) => (
            <div key={event} className="flex items-center justify-between bg-neutral-900 border border-emerald-500/10 rounded-lg p-3">
              <code className="text-sm text-emerald-400 font-mono">{event}</code>
              <span className="text-sm text-neutral-400">{desc}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Webhook Payload</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "id": "evt_abc123",
  "type": "user.created",
  "timestamp": "2026-01-25T10:00:00Z",
  "realmId": "realm_xyz",
  "data": {
    "userId": "user_123",
    "email": "user@example.com",
    "profile": {
      "firstName": "John",
      "lastName": "Doe"
    }
  }
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Signature Verification</h2>
        <p className="text-neutral-400">All webhooks are signed with HMAC-SHA256. Verify the signature to ensure authenticity:</p>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`import crypto from 'crypto';

function verifyWebhook(payload: string, signature: string, secret: string) {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

// In your webhook handler
app.post('/webhooks/zalt', (req, res) => {
  const signature = req.headers['x-zalt-signature'];
  
  if (!verifyWebhook(req.rawBody, signature, WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  
  // Process webhook...
});`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Retry Policy</h2>
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4">
          <ul className="text-sm text-neutral-300 space-y-2">
            <li className="flex items-center gap-2"><CheckCircle size={14} className="text-emerald-500" /> Webhooks are retried up to 5 times</li>
            <li className="flex items-center gap-2"><CheckCircle size={14} className="text-emerald-500" /> Exponential backoff: 1min, 5min, 30min, 2hr, 24hr</li>
            <li className="flex items-center gap-2"><CheckCircle size={14} className="text-emerald-500" /> Respond with 2xx within 30 seconds</li>
          </ul>
        </div>
      </section>
    </div>
  );
}
