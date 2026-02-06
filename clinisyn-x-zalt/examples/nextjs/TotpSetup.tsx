/**
 * Clinisyn x Zalt.io - TOTP MFA Setup Component
 * 
 * Kullanım:
 * <TotpSetup onSuccess={() => toast.success('MFA aktif!')} />
 */

'use client';

import { useState } from 'react';
import { zaltAuth } from './auth-client';

interface TotpSetupProps {
  onSuccess?: (backupCodes: string[]) => void;
}

type Step = 'init' | 'scan' | 'verify' | 'backup';

export function TotpSetup({ onSuccess }: TotpSetupProps) {
  const [step, setStep] = useState<Step>('init');
  const [secret, setSecret] = useState<string>('');
  const [qrCode, setQrCode] = useState<string>('');
  const [code, setCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSetup = async () => {
    setError(null);
    setLoading(true);

    try {
      const result = await zaltAuth.mfa.setupTOTP();
      setSecret(result.secret);
      if (result.qr_code) {
        setQrCode(result.qr_code);
      }
      setStep('scan');
    } catch {
      setError('MFA kurulumu başlatılamadı. Lütfen tekrar deneyin.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const result = await zaltAuth.mfa.verifyTOTP(code);
      setBackupCodes(result.backup_codes);
      setStep('backup');
    } catch {
      setError('Geçersiz kod. Lütfen tekrar deneyin.');
    } finally {
      setLoading(false);
    }
  };

  const handleComplete = () => {
    onSuccess?.(backupCodes);
  };

  // Step 1: Initial
  if (step === 'init') {
    return (
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-medium text-gray-900">Authenticator Uygulaması</h3>
          <p className="mt-1 text-sm text-gray-500">
            Google Authenticator, Authy veya benzeri bir uygulama ile 
            hesabınızı koruyun.
          </p>
        </div>

        {error && (
          <div className="rounded-md bg-red-50 p-3">
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}

        <button
          type="button"
          onClick={handleSetup}
          disabled={loading}
          className="w-full rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50"
        >
          {loading ? 'Hazırlanıyor...' : 'Kurulumu Başlat'}
        </button>
      </div>
    );
  }

  // Step 2: Scan QR Code
  if (step === 'scan') {
    return (
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-medium text-gray-900">QR Kodu Tarayın</h3>
          <p className="mt-1 text-sm text-gray-500">
            Authenticator uygulamanızla aşağıdaki QR kodu tarayın.
          </p>
        </div>

        <div className="flex justify-center">
          {qrCode ? (
            <img src={qrCode} alt="QR Code" className="w-48 h-48" />
          ) : (
            <div className="w-48 h-48 bg-gray-100 flex items-center justify-center rounded-lg">
              <span className="text-gray-400 text-sm">QR Kod</span>
            </div>
          )}
        </div>

        <div className="bg-gray-50 rounded-md p-4">
          <p className="text-xs text-gray-500 mb-2">Manuel giriş için:</p>
          <code className="text-sm font-mono bg-white px-2 py-1 rounded border break-all">
            {secret}
          </code>
        </div>

        <button
          type="button"
          onClick={() => setStep('verify')}
          className="w-full rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700"
        >
          Devam Et
        </button>
      </div>
    );
  }

  // Step 3: Verify Code
  if (step === 'verify') {
    return (
      <form onSubmit={handleVerify} className="space-y-6">
        <div>
          <h3 className="text-lg font-medium text-gray-900">Kodu Doğrulayın</h3>
          <p className="mt-1 text-sm text-gray-500">
            Authenticator uygulamanızdaki 6 haneli kodu girin.
          </p>
        </div>

        <div>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            required
            autoComplete="one-time-code"
            className="block w-full rounded-md border border-gray-300 px-3 py-2 text-center text-2xl tracking-widest shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            placeholder="000000"
          />
        </div>

        {error && (
          <div className="rounded-md bg-red-50 p-3">
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}

        <div className="flex gap-3">
          <button
            type="button"
            onClick={() => setStep('scan')}
            className="flex-1 rounded-md bg-gray-100 px-4 py-2 text-gray-700 font-medium hover:bg-gray-200"
          >
            Geri
          </button>
          <button
            type="submit"
            disabled={loading || code.length !== 6}
            className="flex-1 rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? 'Doğrulanıyor...' : 'Doğrula'}
          </button>
        </div>
      </form>
    );
  }

  // Step 4: Backup Codes
  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium text-gray-900">Yedek Kodlar</h3>
        <p className="mt-1 text-sm text-gray-500">
          Bu kodları güvenli bir yere kaydedin. Authenticator uygulamanıza 
          erişemezseniz bu kodları kullanabilirsiniz.
        </p>
      </div>

      <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
        <div className="flex">
          <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          <p className="ml-3 text-sm text-yellow-700">
            Her kod sadece bir kez kullanılabilir!
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {backupCodes.map((backupCode, index) => (
          <code
            key={index}
            className="bg-gray-100 px-3 py-2 rounded text-center font-mono text-sm"
          >
            {backupCode}
          </code>
        ))}
      </div>

      <button
        type="button"
        onClick={() => {
          const text = backupCodes.join('\n');
          navigator.clipboard.writeText(text);
        }}
        className="w-full rounded-md bg-gray-100 px-4 py-2 text-gray-700 font-medium hover:bg-gray-200 flex items-center justify-center gap-2"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
        Kodları Kopyala
      </button>

      <button
        type="button"
        onClick={handleComplete}
        className="w-full rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700"
      >
        Tamamla
      </button>
    </div>
  );
}

export default TotpSetup;
