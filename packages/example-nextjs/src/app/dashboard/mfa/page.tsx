'use client';

import { useState } from 'react';
import { useMFA } from '@zalt/react';
import Link from 'next/link';

export default function MFASetupPage() {
  const { setup, verify, disable, status, isLoading } = useMFA();
  const [step, setStep] = useState<'initial' | 'setup' | 'verify'>('initial');
  const [qrCode, setQrCode] = useState('');
  const [secret, setSecret] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');

  const handleSetup = async () => {
    try {
      const result = await setup('totp');
      setQrCode(result.qrCode);
      setSecret(result.secret);
      setStep('setup');
    } catch (err: any) {
      setError(err.message || 'Failed to setup MFA');
    }
  };

  const handleVerify = async () => {
    try {
      const result = await verify(code);
      setBackupCodes(result.backupCodes || []);
      setStep('verify');
    } catch (err) {
      setError('Invalid code. Please try again.');
    }
  };

  const handleDisable = async () => {
    if (!confirm('Are you sure you want to disable 2FA?')) return;
    
    const disableCode = prompt('Enter your 2FA code to confirm:');
    if (!disableCode) return;

    try {
      await disable(disableCode);
      setStep('initial');
      setQrCode('');
      setSecret('');
      setBackupCodes([]);
    } catch (err) {
      setError('Failed to disable MFA');
    }
  };

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-2xl mx-auto">
        <Link href="/dashboard" className="text-indigo-600 hover:underline mb-4 inline-block">
          ← Back to Dashboard
        </Link>
        
        <h1 className="text-3xl font-bold mb-8">Two-Factor Authentication</h1>

        {error && (
          <div className="p-3 bg-red-100 text-red-700 rounded-lg mb-4">
            {error}
          </div>
        )}

        {step === 'initial' && (
          <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow">
            {status?.enabled ? (
              <>
                <div className="flex items-center gap-2 mb-4">
                  <span className="w-3 h-3 bg-green-500 rounded-full"></span>
                  <span className="font-medium text-green-600">2FA is enabled</span>
                </div>
                <p className="text-gray-600 mb-4">
                  Your account is protected with two-factor authentication.
                </p>
                <button
                  onClick={handleDisable}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
                >
                  Disable 2FA
                </button>
              </>
            ) : (
              <>
                <p className="text-gray-600 mb-4">
                  Add an extra layer of security to your account by enabling two-factor authentication.
                </p>
                <button
                  onClick={handleSetup}
                  disabled={isLoading}
                  className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
                >
                  {isLoading ? 'Setting up...' : 'Enable 2FA'}
                </button>
              </>
            )}
          </div>
        )}

        {step === 'setup' && (
          <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow">
            <h2 className="text-xl font-semibold mb-4">Scan QR Code</h2>
            <p className="text-gray-600 mb-4">
              Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
            </p>
            
            <div className="flex justify-center mb-4">
              <img src={qrCode} alt="QR Code" className="w-48 h-48" />
            </div>
            
            <details className="mb-6">
              <summary className="cursor-pointer text-sm text-gray-500">
                Can't scan? Enter code manually
              </summary>
              <code className="block mt-2 p-2 bg-gray-100 rounded text-sm break-all">
                {secret}
              </code>
            </details>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">
                  Enter the 6-digit code from your app
                </label>
                <input
                  type="text"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>
              
              <button
                onClick={handleVerify}
                disabled={isLoading || code.length !== 6}
                className="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
              >
                {isLoading ? 'Verifying...' : 'Verify & Enable'}
              </button>
            </div>
          </div>
        )}

        {step === 'verify' && backupCodes.length > 0 && (
          <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow">
            <div className="flex items-center gap-2 mb-4">
              <span className="text-2xl">✅</span>
              <h2 className="text-xl font-semibold text-green-600">2FA Enabled!</h2>
            </div>
            
            <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg mb-4">
              <h3 className="font-semibold text-yellow-800 mb-2">⚠️ Save Your Backup Codes</h3>
              <p className="text-sm text-yellow-700 mb-3">
                Store these codes in a safe place. You can use them to access your account if you lose your authenticator.
              </p>
              <div className="grid grid-cols-2 gap-2">
                {backupCodes.map((code, i) => (
                  <code key={i} className="p-2 bg-white rounded text-center font-mono">
                    {code}
                  </code>
                ))}
              </div>
            </div>
            
            <Link
              href="/dashboard"
              className="block w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-center"
            >
              Done
            </Link>
          </div>
        )}
      </div>
    </main>
  );
}
