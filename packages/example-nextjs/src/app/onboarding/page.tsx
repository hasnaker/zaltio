'use client';

import { useState } from 'react';
import { useAuth, useMFA } from '@zalt/react';
import { useRouter } from 'next/navigation';

export default function OnboardingPage() {
  const { user } = useAuth();
  const { setup, verify } = useMFA();
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [qrCode, setQrCode] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');

  const handleSetupMFA = async () => {
    try {
      const result = await setup('totp');
      setQrCode(result.qrCode);
      setStep(2);
    } catch (err) {
      setError('Failed to setup MFA');
    }
  };

  const handleVerifyMFA = async () => {
    try {
      await verify(code);
      setStep(3);
    } catch (err) {
      setError('Invalid code');
    }
  };

  const handleSkip = () => {
    router.push('/dashboard');
  };

  const handleComplete = () => {
    router.push('/dashboard');
  };

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Progress */}
        <div className="flex justify-center gap-2 mb-8">
          {[1, 2, 3].map((s) => (
            <div
              key={s}
              className={`w-3 h-3 rounded-full ${
                s <= step ? 'bg-indigo-600' : 'bg-gray-200'
              }`}
            />
          ))}
        </div>

        {step === 1 && (
          <div className="text-center">
            <h1 className="text-3xl font-bold mb-4">Welcome, {user?.profile?.firstName || 'there'}!</h1>
            <p className="text-gray-600 mb-8">
              Let's secure your account with two-factor authentication.
            </p>
            
            <div className="space-y-4">
              <button
                onClick={handleSetupMFA}
                className="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
              >
                Enable 2FA (Recommended)
              </button>
              <button
                onClick={handleSkip}
                className="w-full py-3 text-gray-600 hover:text-gray-800"
              >
                Skip for now
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="text-center">
            <h1 className="text-2xl font-bold mb-4">Scan QR Code</h1>
            <p className="text-gray-600 mb-4">
              Use your authenticator app to scan this code
            </p>
            
            {error && (
              <div className="p-3 bg-red-100 text-red-700 rounded-lg mb-4">
                {error}
              </div>
            )}
            
            <div className="flex justify-center mb-6">
              <img src={qrCode} alt="QR Code" className="w-48 h-48" />
            </div>
            
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="w-full px-4 py-3 text-center text-2xl tracking-widest border rounded-lg mb-4"
              placeholder="000000"
              maxLength={6}
            />
            
            <button
              onClick={handleVerifyMFA}
              disabled={code.length !== 6}
              className="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
            >
              Verify
            </button>
          </div>
        )}

        {step === 3 && (
          <div className="text-center">
            <div className="text-6xl mb-4">🎉</div>
            <h1 className="text-3xl font-bold mb-4">You're all set!</h1>
            <p className="text-gray-600 mb-8">
              Your account is now protected with two-factor authentication.
            </p>
            
            <button
              onClick={handleComplete}
              className="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
            >
              Go to Dashboard
            </button>
          </div>
        )}
      </div>
    </main>
  );
}
