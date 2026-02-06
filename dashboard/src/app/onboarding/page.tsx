'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import Image from 'next/image';
import { Check, Copy, ArrowRight, Code, Zap, Lock, Globe } from 'lucide-react';

const steps = [
  { id: 'welcome', title: 'Welcome' },
  { id: 'api-keys', title: 'API Keys' },
  { id: 'integrate', title: 'Integrate' },
  { id: 'done', title: 'Done' },
];

export default function OnboardingPage() {
  const router = useRouter();
  const [currentStep, setCurrentStep] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);

  // Mock data - will come from API
  const realmId = 'acme-abc123';
  const publishableKey = 'pk_live_zalt_acme_abc123';
  const secretKey = 'sk_live_zalt_••••••••••••••••';

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const nextStep = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      router.push('/dashboard');
    }
  };

  return (
    <main className="min-h-screen bg-neutral-950 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.02)_1px,transparent_1px)] bg-[size:50px_50px]" />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative z-10 w-full max-w-2xl"
      >
        {/* Progress */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {steps.map((step, index) => (
            <div key={step.id} className="flex items-center">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-mono ${
                index < currentStep ? 'bg-emerald-500 text-neutral-950' :
                index === currentStep ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500' :
                'bg-neutral-800 text-neutral-500'
              }`}>
                {index < currentStep ? <Check size={14} /> : index + 1}
              </div>
              {index < steps.length - 1 && (
                <div className={`w-12 h-0.5 mx-2 ${
                  index < currentStep ? 'bg-emerald-500' : 'bg-neutral-800'
                }`} />
              )}
            </div>
          ))}
        </div>

        {/* Content */}
        <div className="bg-neutral-900 border border-emerald-500/20 rounded-lg overflow-hidden">
          {currentStep === 0 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-8 text-center"
            >
              <div className="flex items-center justify-center mx-auto mb-6">
                <Image
                  src="/zalt-full-logo.svg"
                  alt="Zalt"
                  width={140}
                  height={194}
                  className="h-32 w-auto"
                  priority
                />
              </div>
              <h1 className="font-outfit text-2xl font-bold text-white mb-2">
                Welcome to Zalt! 🎉
              </h1>
              <p className="text-neutral-400 mb-8 max-w-md mx-auto">
                Your account is ready. Let's get you set up with enterprise-grade authentication in just a few minutes.
              </p>

              <div className="grid grid-cols-3 gap-4 mb-8">
                {[
                  { icon: Zap, label: '5 min setup' },
                  { icon: Lock, label: 'Bank-grade security' },
                  { icon: Globe, label: 'Global scale' },
                ].map((item) => (
                  <div key={item.label} className="p-4 bg-neutral-800/50 rounded-lg">
                    <item.icon size={20} className="text-emerald-500 mx-auto mb-2" />
                    <p className="text-xs text-neutral-400">{item.label}</p>
                  </div>
                ))}
              </div>

              <button
                onClick={nextStep}
                className="px-8 py-3 bg-emerald-500 text-neutral-950 font-semibold rounded-lg hover:bg-emerald-400 transition-colors inline-flex items-center gap-2"
              >
                Get Started
                <ArrowRight size={16} />
              </button>
            </motion.div>
          )}

          {currentStep === 1 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-8"
            >
              <h2 className="font-outfit text-xl font-bold text-white mb-2">Your API Keys</h2>
              <p className="text-neutral-400 text-sm mb-6">
                Use these keys to authenticate with the Zalt API. Keep your secret key safe!
              </p>

              <div className="space-y-4 mb-8">
                <div>
                  <label className="block text-xs text-emerald-500/70 font-mono mb-2">REALM ID</label>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 px-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm font-mono">
                      {realmId}
                    </code>
                    <button
                      onClick={() => copyToClipboard(realmId, 'realm')}
                      className="p-3 bg-neutral-800 rounded hover:bg-neutral-700 transition-colors"
                    >
                      {copied === 'realm' ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} className="text-neutral-400" />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-emerald-500/70 font-mono mb-2">PUBLISHABLE KEY (Frontend)</label>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 px-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm font-mono">
                      {publishableKey}
                    </code>
                    <button
                      onClick={() => copyToClipboard(publishableKey, 'pk')}
                      className="p-3 bg-neutral-800 rounded hover:bg-neutral-700 transition-colors"
                    >
                      {copied === 'pk' ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} className="text-neutral-400" />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-emerald-500/70 font-mono mb-2">SECRET KEY (Backend only)</label>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 px-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-white text-sm font-mono">
                      {secretKey}
                    </code>
                    <button className="p-3 bg-neutral-800 rounded text-neutral-500 cursor-not-allowed">
                      <Lock size={16} />
                    </button>
                  </div>
                  <p className="text-xs text-neutral-500 mt-1">
                    View full key in Settings → API Keys
                  </p>
                </div>
              </div>

              <button
                onClick={nextStep}
                className="w-full py-3 bg-emerald-500 text-neutral-950 font-semibold rounded-lg hover:bg-emerald-400 transition-colors inline-flex items-center justify-center gap-2"
              >
                Continue
                <ArrowRight size={16} />
              </button>
            </motion.div>
          )}

          {currentStep === 2 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-8"
            >
              <h2 className="font-outfit text-xl font-bold text-white mb-2">Quick Integration</h2>
              <p className="text-neutral-400 text-sm mb-6">
                Add Zalt to your app in 3 lines of code.
              </p>

              <div className="space-y-4 mb-8">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-emerald-500/70 font-mono">1. INSTALL</span>
                    <button
                      onClick={() => copyToClipboard('npm install @zalt.io/react', 'install')}
                      className="text-neutral-500 hover:text-white"
                    >
                      {copied === 'install' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    </button>
                  </div>
                  <pre className="px-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-sm font-mono overflow-x-auto">
                    <span className="text-neutral-500">$</span> <span className="text-emerald-400">npm install @zalt.io/react</span>
                  </pre>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-emerald-500/70 font-mono">2. WRAP YOUR APP</span>
                    <button
                      onClick={() => copyToClipboard(`import { ZaltProvider } from '@zalt.io/react';\n\nexport default function App({ children }) {\n  return (\n    <ZaltProvider\n      publishableKey="${publishableKey}"\n    >\n      {children}\n    </ZaltProvider>\n  );\n}`, 'init')}
                      className="text-neutral-500 hover:text-white"
                    >
                      {copied === 'init' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    </button>
                  </div>
                  <pre className="px-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-sm font-mono overflow-x-auto text-neutral-300">
{`import { ZaltProvider } from '@zalt.io/react';

export default function App({ children }) {
  return (
    <ZaltProvider
      publishableKey="${publishableKey}"
    >
      {children}
    </ZaltProvider>
  );
}`}
                  </pre>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-emerald-500/70 font-mono">3. USE COMPONENTS</span>
                  </div>
                  <pre className="px-4 py-3 bg-neutral-950 border border-emerald-500/20 rounded text-sm font-mono overflow-x-auto text-neutral-300">
{`import { SignInButton, UserButton } from '@zalt.io/react';

// Login button
<SignInButton />

// User profile dropdown (when logged in)
<UserButton />`}
                  </pre>
                </div>
              </div>

              <button
                onClick={nextStep}
                className="w-full py-3 bg-emerald-500 text-neutral-950 font-semibold rounded-lg hover:bg-emerald-400 transition-colors inline-flex items-center justify-center gap-2"
              >
                Finish Setup
                <ArrowRight size={16} />
              </button>
            </motion.div>
          )}

          {currentStep === 3 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-8 text-center"
            >
              <div className="w-16 h-16 rounded-full bg-emerald-500 flex items-center justify-center mx-auto mb-6">
                <Check size={32} className="text-neutral-950" />
              </div>
              <h2 className="font-outfit text-2xl font-bold text-white mb-2">
                You're all set! 🚀
              </h2>
              <p className="text-neutral-400 mb-8">
                Your Zalt account is ready. Start building secure authentication today.
              </p>

              <div className="grid grid-cols-2 gap-4 mb-8">
                <a
                  href="/docs/quickstart"
                  className="p-4 bg-neutral-800/50 rounded-lg hover:bg-neutral-800 transition-colors text-left"
                >
                  <Code size={20} className="text-emerald-500 mb-2" />
                  <p className="text-sm text-white font-medium">Documentation</p>
                  <p className="text-xs text-neutral-500">Full integration guides</p>
                </a>
                <a
                  href="/dashboard/settings"
                  className="p-4 bg-neutral-800/50 rounded-lg hover:bg-neutral-800 transition-colors text-left"
                >
                  <Lock size={20} className="text-emerald-500 mb-2" />
                  <p className="text-sm text-white font-medium">API Keys</p>
                  <p className="text-xs text-neutral-500">Manage your keys</p>
                </a>
              </div>

              <button
                onClick={() => router.push('/dashboard')}
                className="w-full py-3 bg-emerald-500 text-neutral-950 font-semibold rounded-lg hover:bg-emerald-400 transition-colors inline-flex items-center justify-center gap-2"
              >
                Go to Dashboard
                <ArrowRight size={16} />
              </button>
            </motion.div>
          )}
        </div>
      </motion.div>
    </main>
  );
}
