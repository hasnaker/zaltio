'use client';

import { motion } from 'framer-motion';
import { ArrowLeft, Fingerprint, Shield, Key, CheckCircle } from 'lucide-react';
import Link from 'next/link';

export default function WebAuthnPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">WebAuthn / Passkeys</h1>
        <p className="text-neutral-400">Phishing-proof authentication with biometrics and security keys.</p>
      </motion.div>

      <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-6">
        <div className="flex items-start gap-4">
          <Shield className="text-emerald-500 mt-1" size={24} />
          <div>
            <h3 className="font-semibold text-white mb-2">Why WebAuthn?</h3>
            <ul className="text-sm text-neutral-400 space-y-2">
              <li className="flex items-center gap-2"><CheckCircle size={14} className="text-emerald-500" /> Phishing-proof - credentials are bound to origin</li>
              <li className="flex items-center gap-2"><CheckCircle size={14} className="text-emerald-500" /> No shared secrets - private key never leaves device</li>
              <li className="flex items-center gap-2"><CheckCircle size={14} className="text-emerald-500" /> User-friendly - Face ID, Touch ID, Windows Hello</li>
              <li className="flex items-center gap-2"><CheckCircle size={14} className="text-emerald-500" /> HIPAA compliant - mandatory for healthcare realms</li>
            </ul>
          </div>
        </div>
      </div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Register a Passkey</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="bg-neutral-950 p-4 rounded text-sm font-mono text-neutral-300 overflow-x-auto">
{`import { useAuth } from '@zalt/react';

function PasskeySetup() {
  const { webauthn } = useAuth();

  const registerPasskey = async () => {
    try {
      const result = await webauthn.register({
        name: 'My MacBook', // Optional friendly name
      });
      console.log('Passkey registered:', result.credentialId);
    } catch (error) {
      console.error('Registration failed:', error);
    }
  };

  return (
    <button onClick={registerPasskey}>
      <Fingerprint /> Add Passkey
    </button>
  );
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Authenticate with Passkey</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="bg-neutral-950 p-4 rounded text-sm font-mono text-neutral-300 overflow-x-auto">
{`import { useAuth } from '@zalt/react';

function PasskeyLogin() {
  const { webauthn } = useAuth();

  const loginWithPasskey = async () => {
    try {
      const { user, tokens } = await webauthn.authenticate();
      console.log('Logged in as:', user.email);
    } catch (error) {
      console.error('Authentication failed:', error);
    }
  };

  return (
    <button onClick={loginWithPasskey}>
      Sign in with Passkey
    </button>
  );
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Manage Credentials</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="bg-neutral-950 p-4 rounded text-sm font-mono text-neutral-300 overflow-x-auto">
{`// List all passkeys
const credentials = await webauthn.listCredentials();

// Remove a passkey
await webauthn.removeCredential(credentialId);`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Supported Authenticators</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {['Face ID', 'Touch ID', 'Windows Hello', 'YubiKey'].map((auth) => (
            <div key={auth} className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4 text-center">
              <Key className="text-emerald-500 mx-auto mb-2" size={24} />
              <span className="text-sm text-white">{auth}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
