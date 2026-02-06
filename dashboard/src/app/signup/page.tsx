'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion } from 'framer-motion';
import Image from 'next/image';
import { Mail, Lock, Eye, EyeOff, ArrowRight, User, Building } from 'lucide-react';

export default function SignupPage() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    company: '',
    password: '',
    confirmPassword: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(1);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (step === 1) {
      setStep(2);
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Signup failed');
      }

      router.push('/onboarding');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  const getPasswordStrength = () => {
    const { password } = formData;
    if (!password) return 0;
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    return strength;
  };

  const strengthColors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-emerald-500'];
  const strengthLabels = ['Weak', 'Fair', 'Good', 'Strong'];

  return (
    <main className="min-h-screen bg-neutral-950 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.03)_1px,transparent_1px)] bg-[size:50px_50px]" />

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

        {/* Signup Card */}
        <div className="bg-neutral-900 border border-emerald-500/20 rounded-lg overflow-hidden">
          <div className="p-8">
            <div className="text-center mb-6">
              <h1 className="font-outfit text-2xl font-bold text-white">Create account</h1>
              <p className="text-neutral-400 text-sm mt-1">Start your 14-day free trial</p>
            </div>

            {/* Progress */}
            <div className="flex items-center gap-2 mb-6">
              <div className={`flex-1 h-1 rounded ${step >= 1 ? 'bg-emerald-500' : 'bg-neutral-800'}`} />
              <div className={`flex-1 h-1 rounded ${step >= 2 ? 'bg-emerald-500' : 'bg-neutral-800'}`} />
            </div>

            {error && (
              <div className="mb-6 p-3 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              {step === 1 ? (
                <>
                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">FULL NAME</label>
                    <div className="relative">
                      <User size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
                      <input
                        type="text"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                        placeholder="John Doe"
                        required
                        className="w-full pl-10 pr-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm placeholder:text-neutral-600 focus:outline-none focus:border-emerald-500/50"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">WORK EMAIL</label>
                    <div className="relative">
                      <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
                      <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        placeholder="john@company.com"
                        required
                        className="w-full pl-10 pr-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm placeholder:text-neutral-600 focus:outline-none focus:border-emerald-500/50"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">COMPANY</label>
                    <div className="relative">
                      <Building size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
                      <input
                        type="text"
                        name="company"
                        value={formData.company}
                        onChange={handleChange}
                        placeholder="Acme Inc."
                        required
                        className="w-full pl-10 pr-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm placeholder:text-neutral-600 focus:outline-none focus:border-emerald-500/50"
                      />
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">PASSWORD</label>
                    <div className="relative">
                      <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        name="password"
                        value={formData.password}
                        onChange={handleChange}
                        placeholder="••••••••"
                        required
                        minLength={8}
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
                    {formData.password && (
                      <div className="mt-2">
                        <div className="flex gap-1 mb-1">
                          {[0, 1, 2, 3].map(i => (
                            <div
                              key={i}
                              className={`flex-1 h-1 rounded ${i < getPasswordStrength() ? strengthColors[getPasswordStrength() - 1] : 'bg-neutral-800'}`}
                            />
                          ))}
                        </div>
                        <p className="text-xs text-neutral-500">
                          {getPasswordStrength() > 0 ? strengthLabels[getPasswordStrength() - 1] : 'Enter password'}
                        </p>
                      </div>
                    )}
                  </div>

                  <div>
                    <label className="block text-xs text-emerald-500/70 font-mono mb-2">CONFIRM PASSWORD</label>
                    <div className="relative">
                      <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
                      <input
                        type="password"
                        name="confirmPassword"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        placeholder="••••••••"
                        required
                        className="w-full pl-10 pr-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm placeholder:text-neutral-600 focus:outline-none focus:border-emerald-500/50"
                      />
                    </div>
                  </div>
                </>
              )}

              <div className="flex gap-3">
                {step === 2 && (
                  <button
                    type="button"
                    onClick={() => setStep(1)}
                    className="flex-1 py-3 bg-neutral-800 text-neutral-300 font-medium rounded hover:bg-neutral-700 transition-colors"
                  >
                    Back
                  </button>
                )}
                <motion.button
                  type="submit"
                  disabled={loading}
                  whileHover={{ scale: 1.01 }}
                  whileTap={{ scale: 0.99 }}
                  className="flex-1 py-3 bg-emerald-500 text-neutral-950 font-semibold rounded flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {loading ? (
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                      className="w-5 h-5 border-2 border-neutral-950 border-t-transparent rounded-full"
                    />
                  ) : (
                    <>
                      {step === 1 ? 'Continue' : 'Create account'}
                      <ArrowRight size={16} />
                    </>
                  )}
                </motion.button>
              </div>

              <p className="text-xs text-neutral-500 text-center">
                By signing up, you agree to our{' '}
                <Link href="/terms" className="text-emerald-400 hover:underline">Terms</Link>
                {' '}and{' '}
                <Link href="/privacy" className="text-emerald-400 hover:underline">Privacy Policy</Link>
              </p>
            </form>
          </div>

          <div className="px-8 py-4 bg-neutral-950 border-t border-emerald-500/10 text-center">
            <p className="text-neutral-500 text-sm">
              Already have an account?{' '}
              <Link href="/login" className="text-emerald-400 hover:underline">
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </motion.div>
    </main>
  );
}