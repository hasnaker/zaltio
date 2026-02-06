/**
 * Clinisyn x Zalt.io - MFA Verification Component
 * 
 * Kullanım:
 * <MfaVerifyForm 
 *   sessionId={mfaSessionId} 
 *   methods={['totp', 'webauthn']}
 *   onSuccess={() => router.push('/dashboard')} 
 * />
 */

'use client';

import { useState } from 'react';
import { zaltAuth } from './auth-client';
import { ZALT_ERROR_CODES } from './auth-config';

interface MfaVerifyFormProps {
  sessionId: string;
  methods: string[];
  onSuccess?: () => void;
  onCancel?: () => void;
}

export function MfaVerifyForm({ sessionId, methods, onSuccess, onCancel }: MfaVerifyFormProps) {
  const [code, setCode] = useState('');
  const [selectedMethod, setSelectedMethod] = useState(methods[0] || 'totp');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await zaltAuth.mfa.loginVerify(sessionId, code, selectedMethod);
      onSuccess?.();
    } catch (err: unknown) {
      const error = err as { error?: { code?: string } };
      
      if (error?.error?.code === ZALT_ERROR_CODES.RATE_LIMITED) {
        setError('Çok fazla deneme. Lütfen bekleyin.');
      } else if (error?.error?.code === ZALT_ERROR_CODES.INVALID_TOKEN) {
        setError('Geçersiz kod. Lütfen tekrar deneyin.');
      } else {
        setError('Doğrulama başarısız. Lütfen tekrar deneyin.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleWebAuthn = async () => {
    if (!zaltAuth.webauthn.isSupported()) {
      setError('Bu cihaz WebAuthn desteklemiyor.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      // WebAuthn authentication flow would go here
      // This requires browser credential API integration
      setError('WebAuthn entegrasyonu için tam implementasyon gerekli.');
    } catch {
      setError('WebAuthn doğrulama başarısız.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-gray-900">İki Faktörlü Doğrulama</h2>
        <p className="mt-2 text-sm text-gray-600">
          Hesabınızı doğrulamak için güvenlik kodunuzu girin.
        </p>
      </div>

      {methods.length > 1 && (
        <div className="flex gap-2 justify-center">
          {methods.includes('totp') && (
            <button
              type="button"
              onClick={() => setSelectedMethod('totp')}
              className={`px-4 py-2 rounded-md text-sm font-medium ${
                selectedMethod === 'totp'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              Authenticator
            </button>
          )}
          {methods.includes('webauthn') && (
            <button
              type="button"
              onClick={() => setSelectedMethod('webauthn')}
              className={`px-4 py-2 rounded-md text-sm font-medium ${
                selectedMethod === 'webauthn'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              Passkey
            </button>
          )}
        </div>
      )}

      {selectedMethod === 'totp' ? (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="code" className="block text-sm font-medium text-gray-700">
              6 Haneli Kod
            </label>
            <input
              id="code"
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              required
              autoComplete="one-time-code"
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-center text-2xl tracking-widest shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              placeholder="000000"
            />
          </div>

          {error && (
            <div className="rounded-md bg-red-50 p-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || code.length !== 6}
            className="w-full rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Doğrulanıyor...' : 'Doğrula'}
          </button>
        </form>
      ) : (
        <div className="space-y-4">
          {error && (
            <div className="rounded-md bg-red-50 p-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          <button
            type="button"
            onClick={handleWebAuthn}
            disabled={loading}
            className="w-full rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
            </svg>
            {loading ? 'Bekleniyor...' : 'Passkey ile Doğrula'}
          </button>
        </div>
      )}

      {onCancel && (
        <div className="text-center">
          <button
            type="button"
            onClick={onCancel}
            className="text-sm text-gray-600 hover:text-gray-500"
          >
            İptal
          </button>
        </div>
      )}
    </div>
  );
}

export default MfaVerifyForm;
