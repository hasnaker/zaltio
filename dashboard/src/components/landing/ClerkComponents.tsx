'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ChevronDown, ChevronRight } from 'lucide-react';

// Component categories
const categories = [
  {
    id: 'user-auth',
    title: 'USER AUTHENTICATION',
    isOpen: true,
    description: 'Add user <SignUp/> and <SignIn/>, provide account access through a dropdown menu, and manage profile and security settings.',
    components: [
      '<SignUp />',
      '<SignIn />',
      '<UserButton />',
      '<UserProfile />',
      '<Waitlist />',
    ],
  },
  {
    id: 'b2b-auth',
    title: 'B2B AUTHENTICATION',
    isOpen: false,
    components: [
      '<OrganizationSwitcher />',
      '<OrganizationProfile />',
      '<CreateOrganization />',
    ],
  },
  {
    id: 'billing',
    title: 'BILLING',
    isOpen: false,
    components: [
      '<PricingTable />',
      '<Checkout />',
      '<BillingPortal />',
    ],
  },
];

// Mock SignUp form preview
function SignUpPreview() {
  return (
    <div className="bg-white rounded-2xl shadow-2xl border border-neutral-200 p-8 w-[380px]">
      {/* Header */}
      <div className="text-center mb-6">
        <div className="w-12 h-12 bg-neutral-900 rounded-xl mx-auto mb-4 flex items-center justify-center">
          <span className="text-white text-xl">✦</span>
        </div>
        <h3 className="text-xl font-semibold text-neutral-900">Create your account</h3>
        <p className="text-sm text-neutral-500 mt-1">
          Welcome! Please fill in the details to get started.
        </p>
      </div>

      {/* Social buttons */}
      <div className="space-y-3 mb-6">
        <button className="w-full flex items-center justify-center gap-3 px-4 py-2.5 border border-neutral-200 rounded-lg hover:bg-neutral-50 transition-colors">
          <svg className="w-5 h-5" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          <span className="text-sm font-medium text-neutral-700">Continue with Google</span>
          <span className="ml-auto text-xs text-neutral-400">Last used</span>
        </button>
        <button className="w-full flex items-center justify-center gap-3 px-4 py-2.5 border border-neutral-200 rounded-lg hover:bg-neutral-50 transition-colors">
          <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
          </svg>
          <span className="text-sm font-medium text-neutral-700">Continue with GitHub</span>
        </button>
      </div>

      {/* Divider */}
      <div className="relative my-6">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-neutral-200"></div>
        </div>
        <div className="relative flex justify-center text-sm">
          <span className="px-2 bg-white text-neutral-400">or</span>
        </div>
      </div>

      {/* Form fields */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-1.5">
            Email address
          </label>
          <input
            type="email"
            placeholder="cameron.walker@gmail.com"
            className="w-full px-3 py-2.5 border border-neutral-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-[#6C47FF] focus:border-transparent"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-1.5">
            Password
          </label>
          <input
            type="password"
            placeholder="••••••••••"
            className="w-full px-3 py-2.5 border border-neutral-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-[#6C47FF] focus:border-transparent"
          />
        </div>
      </div>

      {/* Submit button */}
      <button className="w-full mt-6 px-4 py-2.5 bg-[#6C47FF] hover:bg-[#5a3ad9] text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2">
        Continue
        <ChevronRight size={16} />
      </button>

      {/* Footer */}
      <p className="mt-6 text-center text-sm text-neutral-500">
        Already have an account?{' '}
        <a href="#" className="text-[#6C47FF] hover:underline">Sign in</a>
      </p>

      {/* Secured by */}
      <div className="mt-6 pt-4 border-t border-neutral-100 flex items-center justify-center gap-2 text-xs text-neutral-400">
        <span>Secured by</span>
        <span className="font-semibold text-neutral-600">⚡ zalt</span>
      </div>
    </div>
  );
}

// Account switcher preview
function AccountSwitcherPreview() {
  return (
    <div className="bg-white rounded-xl shadow-lg border border-neutral-200 p-4 w-[280px]">
      <div className="text-sm font-medium text-neutral-500 mb-3">Choose an account</div>
      <p className="text-xs text-neutral-400 mb-4">Select the account with which you want to continue</p>
      
      <div className="space-y-2">
        <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-neutral-50 cursor-pointer">
          <div className="w-8 h-8 bg-neutral-200 rounded-full"></div>
          <span className="text-sm text-neutral-700">Personal account</span>
        </div>
        <div className="flex items-center gap-3 p-2 rounded-lg bg-neutral-50">
          <div className="w-8 h-8 bg-[#6C47FF] rounded-full flex items-center justify-center text-white text-xs">Z</div>
          <div>
            <div className="text-sm font-medium text-neutral-900">Zalt App</div>
            <div className="text-xs text-neutral-400">Admin</div>
          </div>
        </div>
        <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-neutral-50 cursor-pointer">
          <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-xs">C</div>
          <div>
            <div className="text-sm text-neutral-700">Clinisyn Sample App</div>
            <div className="text-xs text-neutral-400">Admin</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function ClerkComponents() {
  const [openCategory, setOpenCategory] = useState('user-auth');
  const [selectedComponent, setSelectedComponent] = useState('<SignUp />');

  return (
    <section className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-6">
        {/* Section header */}
        <div className="mb-12">
          <span className="text-[#6C47FF] text-sm font-medium">Zalt Components</span>
          <h2 className="mt-2 text-4xl md:text-5xl font-bold text-neutral-900">
            Pixel-perfect UIs,
            <br />
            embedded in minutes
          </h2>
          <p className="mt-4 text-lg text-neutral-500 max-w-xl">
            Drop-in UI components for authentication, profile management, 
            organization management, and billing. Match to your brand with 
            any CSS library, then deploy to your own domain.
          </p>
          <a href="#" className="inline-flex items-center gap-1 mt-4 text-[#6C47FF] font-medium hover:underline">
            Explore all components
            <ChevronRight size={16} />
          </a>
        </div>

        {/* Main content grid */}
        <div className="grid lg:grid-cols-2 gap-12 items-start">
          {/* Left: Component list */}
          <div className="space-y-4">
            {categories.map((category) => (
              <div key={category.id} className="border-b border-neutral-100 pb-4">
                <button
                  onClick={() => setOpenCategory(openCategory === category.id ? '' : category.id)}
                  className="flex items-center justify-between w-full py-2"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${openCategory === category.id ? 'bg-[#6C47FF]' : 'bg-neutral-300'}`} />
                    <span className="text-sm font-medium tracking-wide text-neutral-700">
                      {category.title}
                    </span>
                  </div>
                  <ChevronDown 
                    size={16} 
                    className={`text-neutral-400 transition-transform ${openCategory === category.id ? 'rotate-180' : ''}`}
                  />
                </button>
                
                {openCategory === category.id && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-2 ml-5 space-y-1"
                  >
                    {category.description && (
                      <p className="text-sm text-neutral-500 mb-3">{category.description}</p>
                    )}
                    {category.components.map((comp) => (
                      <button
                        key={comp}
                        onClick={() => setSelectedComponent(comp)}
                        className={`block w-full text-left px-3 py-1.5 rounded text-sm font-mono ${
                          selectedComponent === comp
                            ? 'text-[#6C47FF] bg-[#6C47FF]/5'
                            : 'text-neutral-600 hover:text-neutral-900'
                        }`}
                      >
                        {comp}
                      </button>
                    ))}
                  </motion.div>
                )}
              </div>
            ))}
          </div>

          {/* Right: Preview */}
          <div className="relative">
            {/* Background decorations */}
            <div className="absolute -top-10 -right-10 w-64 h-64 bg-gradient-to-br from-[#6C47FF]/5 to-transparent rounded-full blur-3xl" />
            
            {/* Preview cards */}
            <div className="relative flex gap-6">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
              >
                <SignUpPreview />
              </motion.div>
              
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: 0.2 }}
                className="absolute top-20 -right-4"
              >
                <AccountSwitcherPreview />
              </motion.div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default ClerkComponents;
