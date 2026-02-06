'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion } from 'framer-motion';
import Image from 'next/image';
import { Mail, Lock, Eye, EyeOff, ArrowRight, Fingerprint, Shield } from 'lucide-react';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  // MFA state
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaSessionId, setMfaSessionId] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          mfaRequired 
            ? { mfa_session_id: mfaSessionId, mfa_code: mfaCode }
            : { email, password }
        ),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Invalid credentials');
      }

      // Check if MFA is required
      if (data.mfa_required) {
        setMfaRequired(true);
        setMfaSessionId(data.mfa_session_id);
        setLoading(false);
        return;
      }

      // Success - redirect to dashboard
      router.push('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleBackToLogin = () => {
    setMfaRequired(false);
    setMfaSessionId('');
    setMfaCode('');
    setError('');
  };

  return (
    <main className="min-h-screen bg-neutral-950 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.03)_1px,transparent_1px)] bg-[size:50px_50px]" />
      
      {/* Corner brackets */}
      <div className="absolute top-10 left-10 w-12 h-12 border-l-2 border-t-2 border-emerald-500/20" />
      <div className="absolute top-10 right-10 w-12 h-12 border-r-2 border-t-2 border-emerald-500/20" />
      <div className="absolute bottom-10 left-10 w-12 h-12 border-l-2 border-b-2 border-emerald-500/20" />
      <div className="absolute bottom-10 right-10 w-12 h-12 border-r-2 border-b-2 border-emerald-500/20" />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative z-10 w-full max-w-md"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <Link href="/" className="inline-block">
            <Image
              src="/zalt-full-logo.svg"
              alt="Zalt"
              width={150}
              height={208}
              className="h-28 w-auto mx-auto"
              priority
            />
          </Link>
        </div>

        {/* Login Card */}
        <div className="bg-neutral-900 border border-emerald-500/20 rounded-lg overflow-hidden">
          <div className="p-8">
            {/* MFA Verification View */}
            {mfaRequired ? (
              <>
                <div className="text-center mb-6">
                  <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Shield className="w-8 h-8 text-emerald-400" />
                  </div>
                  <h1 className="font-outfit text-2xl font-bold text-white">Two-Factor Authentication</h1>
                  <p className="text-neutral-400 text-sm mt-1">Enter the code from your authenticator app</p>
                </div>

                {error && (
                  <div className="mb-6 p-3 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                    {error}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">VERIFICATION CODE</label>
                    <input
                      type="text"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      required
                      autoFocus
                      className="w-full px-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-center text-2xl tracking-[0.5em] font-mono placeholder:text-neutral-600 focus:outline-none focus:border-emerald-500/50"
                    />
                  </div>

                  <motion.button
                    type="submit"
                    disabled={loading || mfaCode.length !== 6}
                    whileHover={{ scale: 1.01 }}
                    whileTap={{ scale: 0.99 }}
                    className="w-full py-3 bg-emerald-500 text-neutral-950 font-semibold rounded flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {loading ? (
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                        className="w-5 h-5 border-2 border-neutral-950 border-t-transparent rounded-full"
                      />
                    ) : (
                      <>
                        Verify
                        <ArrowRight size={16} />
                      </>
                    )}
                  </motion.button>

                  <button
                    type="button"
                    onClick={handleBackToLogin}
                    className="w-full py-2 text-neutral-400 text-sm hover:text-white transition-colors"
                  >
                    ← Back to login
                  </button>
                </form>
              </>
            ) : (
              /* Normal Login View */
              <>
                <div className="text-center mb-6">
                  <h1 className="font-outfit text-2xl font-bold text-white">Welcome back</h1>
                  <p className="text-neutral-400 text-sm mt-1">Sign in to your account</p>
                </div>

                {error && (
                  <div className="mb-6 p-3 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                    {error}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">EMAIL</label>
                    <div className="relative">
                      <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="admin@company.com"
                        required
                        className="w-full pl-10 pr-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm placeholder:text-neutral-600 focus:outline-none focus:border-emerald-500/50"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">PASSWORD</label>
                    <div className="relative">
                      <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="••••••••"
                        required
                        className="w-full pl-10 pr-12 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm placeholder:text-neutral-600 focus:outline-none focus:border-emerald-500/50"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-emerald-500/50 hover:text-emerald-400"
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-sm">
                    <label className="flex items-center gap-2 text-neutral-400">
                      <input type="checkbox" className="rounded border-emerald-500/30 bg-neutral-950" />
                      Remember me
                    </label>
                    <Link href="/forgot-password" className="text-emerald-400 hover:underline">
                      Forgot password?
                    </Link>
                  </div>

                  <motion.button
                    type="submit"
                    disabled={loading}
                    whileHover={{ scale: 1.01 }}
                    whileTap={{ scale: 0.99 }}
                    className="w-full py-3 bg-emerald-500 text-neutral-950 font-semibold rounded flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {loading ? (
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                        className="w-5 h-5 border-2 border-neutral-950 border-t-transparent rounded-full"
                      />
                    ) : (
                      <>
                        Sign in
                        <ArrowRight size={16} />
                      </>
                    )}
                  </motion.button>

                  <button
                    type="button"
                    className="w-full py-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-medium rounded flex items-center justify-center gap-2 hover:bg-emerald-500/20 transition-colors"
                  >
                    <Fingerprint size={16} />
                    Sign in with Passkey
                  </button>
                </form>
              </>
            )}
          </div>

          <div className="px-8 py-4 bg-neutral-950 border-t border-emerald-500/10 text-center">
            <p className="text-neutral-500 text-sm">
              Don't have an account?{' '}
              <Link href="/signup" className="text-emerald-400 hover:underline">
                Sign up
              </Link>
            </p>
          </div>
        </div>

        <p className="mt-8 text-center text-neutral-600 text-xs font-mono">
          © {new Date().getFullYear()} ZALT.IO // SECURE_AUTH
        </p>
      </motion.div>
    </main>
  );
}