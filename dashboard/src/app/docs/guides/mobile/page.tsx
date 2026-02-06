'use client';

import { motion } from 'framer-motion';
import { ArrowLeft, Smartphone, Apple, Play } from 'lucide-react';
import Link from 'next/link';

export default function MobileGuidePage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Mobile Apps Integration</h1>
        <p className="text-neutral-400">Add Zalt authentication to iOS and Android apps.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Platform Support</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
            <div className="flex items-center gap-3 mb-4">
              <Apple className="text-emerald-500" size={24} />
              <h3 className="font-semibold text-white">iOS / Swift</h3>
            </div>
            <p className="text-sm text-neutral-400 mb-4">Native Swift SDK with Keychain storage and biometric support.</p>
            <code className="text-xs text-emerald-400 bg-neutral-950 px-2 py-1 rounded">Coming Soon</code>
          </div>
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
            <div className="flex items-center gap-3 mb-4">
              <Play className="text-emerald-500" size={24} />
              <h3 className="font-semibold text-white">Android / Kotlin</h3>
            </div>
            <p className="text-sm text-neutral-400 mb-4">Native Kotlin SDK with encrypted SharedPreferences.</p>
            <code className="text-xs text-emerald-400 bg-neutral-950 px-2 py-1 rounded">Coming Soon</code>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">React Native</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <p className="text-neutral-400 mb-4">Use our React SDK with React Native. Works with Expo and bare React Native projects.</p>
          <pre className="bg-neutral-950 p-4 rounded text-sm font-mono text-neutral-300 overflow-x-auto">
{`npm install @zalt/core @zalt/react-native

import { ZaltProvider, useAuth } from '@zalt/react-native';

function App() {
  return (
    <ZaltProvider 
      realmId="your-realm-id"
      storage="secureStore" // Uses expo-secure-store
    >
      <YourApp />
    </ZaltProvider>
  );
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">REST API</h2>
        <p className="text-neutral-400">For any platform, you can use our REST API directly:</p>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="bg-neutral-950 p-4 rounded text-sm font-mono text-neutral-300 overflow-x-auto">
{`POST https://api.zalt.io/login
Content-Type: application/json

{
  "realm_id": "your-realm-id",
  "email": "user@example.com",
  "password": "secure-password"
}`}
          </pre>
        </div>
      </section>

      <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-6">
        <h3 className="font-semibold text-white mb-2">Need a Native SDK?</h3>
        <p className="text-sm text-neutral-400">Contact us for early access to native iOS and Android SDKs.</p>
        <a href="mailto:sdk@zalt.io" className="inline-block mt-4 px-4 py-2 bg-emerald-500 text-neutral-950 text-sm font-medium rounded">
          Request Access
        </a>
      </div>
    </div>
  );
}
