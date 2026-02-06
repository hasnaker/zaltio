'use client';

import { useState } from 'react';
import { useAuth } from '@zalt/react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function SignInPage() {
  const { signIn, isLoading } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [sessionId, setSessionId] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      const result = await signIn(email, password);
      
      if (result.mfaRequired) {
        setMfaRequired(true);
        setSessionId(result.sessionId!);
      } else {
        router.push('/dashboard');
      }
    } catch (err) {
      setError('Invalid email or password');
    }
  };

  if (mfaRequired) {
    return (
      <MFAVerification 
        sessionId={sessionId} 
        onSuccess={() => router.push('/dashboard')} 
      />
    );
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <h1 className="text-3xl font-bold text-center mb-8">Sign In</h1>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="p-3 bg-red-100 text-red-700 rounded-lg">
              {error}
            </div>
          )}
          
          <div>
            <label className="block text-sm font-medium mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
              required
            />
          </div>
          
          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
          >
            {isLoading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        
        <p className="text-center mt-4 text-gray-600">
          Don't have an account?{' '}
          <Link href="/sign-up" className="text-indigo-600 hover:underline">
            Sign Up
          </Link>
        </p>
      </div>
    </main>
  );
}

function MFAVerification({ 
  sessionId, 
  onSuccess 
}: { 
  sessionId: string; 
  onSuccess: () => void;
}) {
  const { mfa } = useAuth();
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await mfa.verify(sessionId, code);
      onSuccess();
    } catch (err) {
      setError('Invalid code. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <h1 className="text-3xl font-bold text-center mb-4">Two-Factor Authentication</h1>
        <p className="text-gray-600 text-center mb-8">
          Enter the 6-digit code from your authenticator app
        </p>
        
        <form onSubmit={handleVerify} className="space-y-4">
          {error && (
            <div className="p-3 bg-red-100 text-red-700 rounded-lg">
              {error}
            </div>
          )}
          
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            className="w-full px-4 py-3 text-center text-2xl tracking-widest border rounded-lg focus:ring-2 focus:ring-indigo-500"
            placeholder="000000"
            maxLength={6}
            autoFocus
          />
          
          <button
            type="submit"
            disabled={isLoading || code.length !== 6}
            className="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
          >
            {isLoading ? 'Verifying...' : 'Verify'}
          </button>
        </form>
      </div>
    </main>
  );
}
