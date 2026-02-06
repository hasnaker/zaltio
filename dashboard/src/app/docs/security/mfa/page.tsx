'use client';

import { motion } from 'framer-motion';
import { Shield, Smartphone, Key, AlertTriangle, Check, Copy } from 'lucide-react';
import { useState } from 'react';

function CodeBlock({ code, language = 'typescript' }: { code: string; language?: string }) {
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

export default function MFAGuidePage() {
  return (
    <div className="space-y-12">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Shield size={14} />
          SECURITY
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Multi-Factor Authentication</h1>
        <p className="text-neutral-400">Implement TOTP and WebAuthn MFA for enhanced security.</p>
      </motion.div>

      {/* Warning */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4 flex items-start gap-3">
        <AlertTriangle size={18} className="text-yellow-400 flex-shrink-0 mt-0.5" />
        <div>
          <h3 className="font-semibold text-yellow-400 mb-1">No SMS Authentication</h3>
          <p className="text-sm text-neutral-400">
            Zalt does not support SMS-based MFA due to SS7 vulnerabilities. 
            We only support TOTP (authenticator apps) and WebAuthn (passkeys/security keys).
          </p>
        </div>
      </motion.div>

      {/* MFA Types */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
        <h2 className="font-outfit text-xl font-semibold text-white mb-6">Supported MFA Types</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5">
            <div className="w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center mb-4">
              <Smartphone size={18} className="text-emerald-500" />
            </div>
            <h3 className="font-semibold text-white mb-2">TOTP (Authenticator Apps)</h3>
            <p className="text-sm text-neutral-400 mb-3">
              Time-based one-time passwords. Works with Google Authenticator, Authy, 1Password, etc.
            </p>
            <ul className="space-y-1 text-xs text-neutral-500">
              <li className="flex items-center gap-2"><Check size={12} className="text-emerald-500" /> 6-digit codes</li>
              <li className="flex items-center gap-2"><Check size={12} className="text-emerald-500" /> 30-second validity</li>
              <li className="flex items-center gap-2"><Check size={12} className="text-emerald-500" /> Offline capable</li>
            </ul>
          </div>
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5">
            <div className="w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center mb-4">
              <Key size={18} className="text-emerald-500" />
            </div>
            <h3 className="font-semibold text-white mb-2">WebAuthn (Passkeys)</h3>
            <p className="text-sm text-neutral-400 mb-3">
              Phishing-proof authentication using biometrics or security keys.
            </p>
            <ul className="space-y-1 text-xs text-neutral-500">
              <li className="flex items-center gap-2"><Check size={12} className="text-emerald-500" /> Phishing resistant</li>
              <li className="flex items-center gap-2"><Check size={12} className="text-emerald-500" /> Biometric support</li>
              <li className="flex items-center gap-2"><Check size={12} className="text-emerald-500" /> Hardware keys (YubiKey)</li>
            </ul>
          </div>
        </div>
      </motion.div>

      {/* TOTP Setup */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">TOTP Setup Flow</h2>
        <CodeBlock code={`import { useZalt } from '@zalt/react';

function EnableTOTP() {
  const { setupTOTP, verifyTOTP } = useZalt();
  const [secret, setSecret] = useState<string | null>(null);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [code, setCode] = useState('');

  // Step 1: Generate TOTP secret
  const handleSetup = async () => {
    const result = await setupTOTP();
    setSecret(result.secret);
    setQrCode(result.qrCodeUrl);
  };

  // Step 2: Verify and enable
  const handleVerify = async () => {
    const result = await verifyTOTP({
      code,
      secret: secret!,
    });
    
    if (result.success) {
      // TOTP is now enabled
      // Store backup codes securely
      console.log('Backup codes:', result.backupCodes);
    }
  };

  return (
    <div>
      {!qrCode ? (
        <button onClick={handleSetup}>Enable TOTP</button>
      ) : (
        <>
          <img src={qrCode} alt="Scan with authenticator app" />
          <p>Manual entry: {secret}</p>
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Enter 6-digit code"
            maxLength={6}
          />
          <button onClick={handleVerify}>Verify & Enable</button>
        </>
      )}
    </div>
  );
}`} />
      </motion.div>

      {/* MFA Verification */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">MFA Verification During Login</h2>
        <CodeBlock code={`import { useZalt } from '@zalt/react';

function MFAVerification({ mfaToken }: { mfaToken: string }) {
  const { verifyMfa } = useZalt();
  const [code, setCode] = useState('');

  const handleVerify = async () => {
    const result = await verifyMfa({
      mfaToken,
      code,
      type: 'totp', // or 'webauthn'
    });

    if (result.success) {
      // User is now fully authenticated
      router.push('/dashboard');
    }
  };

  return (
    <div>
      <h2>Enter your authentication code</h2>
      <input
        type="text"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder="000000"
        maxLength={6}
        autoFocus
      />
      <button onClick={handleVerify}>Verify</button>
    </div>
  );
}`} />
      </motion.div>

      {/* Realm Policy */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }} className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
        <h2 className="font-outfit text-lg font-semibold text-white mb-4">Realm MFA Policy</h2>
        <p className="text-sm text-neutral-400 mb-4">
          Configure MFA requirements at the realm level in your dashboard settings.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-3 bg-neutral-800/50 rounded-lg">
            <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-1">Optional</h4>
            <p className="text-sm text-white">Users can enable MFA</p>
          </div>
          <div className="p-3 bg-neutral-800/50 rounded-lg">
            <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-1">Required</h4>
            <p className="text-sm text-white">All users must enable MFA</p>
          </div>
          <div className="p-3 bg-neutral-800/50 rounded-lg">
            <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-1">WebAuthn Only</h4>
            <p className="text-sm text-white">Healthcare compliance mode</p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
