/**
 * Clinisyn x Zalt.io - Login Form Component
 * 
 * Kullanım:
 * <LoginForm onSuccess={() => router.push('/dashboard')} />
 */

'use client';

import { useState } from 'react';
import { zaltAuth } from './auth-client';
import { ZALT_ERROR_CODES } from './auth-config';

interface LoginFormProps {
  onSuccess?: () => void;
  onMfaRequired?: (sessionId: string, methods: string[]) => void;
}

export function LoginForm({ onSuccess, onMfaRequired }: LoginFormProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const result = await zaltAuth.login(email, password);

      // MFA gerekli
      if ('mfa_required' in result && result.mfa_required) {
        onMfaRequired?.(result.mfa_session_id, result.available_methods);
        return;
      }

      // Başarılı login
      if ('tokens' in result) {
        onSuccess?.();
      }
    } catch (err: unknown) {
      const error = err as { error?: { code?: string; details?: { retry_after?: number } } };
      
      if (error?.error?.code === ZALT_ERROR_CODES.RATE_LIMITED) {
        const retryAfter = error.error.details?.retry_after || 900;
        setError(`Çok fazla deneme. ${Math.ceil(retryAfter / 60)} dakika sonra tekrar deneyin.`);
      } else if (error?.error?.code === ZALT_ERROR_CODES.INVALID_CREDENTIALS) {
        setError('Email veya şifre hatalı.');
      } else if (error?.error?.code === ZALT_ERROR_CODES.ACCOUNT_LOCKED) {
        setError('Hesabınız kilitlendi. Lütfen destek ile iletişime geçin.');
      } else {
        setError('Bir hata oluştu. Lütfen tekrar deneyin.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="email" className="block text-sm font-medium text-gray-700">
          Email
        </label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="email"
          className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          placeholder="ornek@clinisyn.com"
        />
      </div>

      <div>
        <label htmlFor="password" className="block text-sm font-medium text-gray-700">
          Şifre
        </label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
          className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
      </div>

      {error && (
        <div className="rounded-md bg-red-50 p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      <button
        type="submit"
        disabled={loading}
        className="w-full rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
      </button>

      <div className="text-center">
        <a href="/forgot-password" className="text-sm text-blue-600 hover:text-blue-500">
          Şifremi unuttum
        </a>
      </div>
    </form>
  );
}

export default LoginForm;
