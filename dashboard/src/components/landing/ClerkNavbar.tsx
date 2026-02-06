'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, Menu, X } from 'lucide-react';

const navItems = [
  {
    label: 'Product',
    hasDropdown: true,
    items: [
      { name: 'Authentication', description: 'Secure sign-in and sign-up', href: '/docs/authentication' },
      { name: 'User Management', description: 'Complete user lifecycle', href: '/docs/user-management' },
      { name: 'Organizations', description: 'Multi-tenancy made easy', href: '/docs/organizations' },
      { name: 'Billing', description: 'Subscription management', href: '/docs/billing' },
    ],
  },
  {
    label: 'Developers',
    hasDropdown: true,
    items: [
      { name: 'Documentation', description: 'Guides and references', href: '/docs' },
      { name: 'API Reference', description: 'REST API documentation', href: '/docs/api' },
      { name: 'SDKs', description: 'Client libraries', href: '/docs/sdk' },
      { name: 'Quickstart', description: 'Get started in minutes', href: '/docs/quickstart' },
    ],
  },
  { label: 'Pricing', href: '/pricing' },
  { label: 'Blog', href: '/blog' },
];

export function ClerkNavbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-white/80 backdrop-blur-lg border-b border-neutral-100">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2">
            <span className="text-2xl">⚡</span>
            <span className="text-xl font-bold text-neutral-900">zalt</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center gap-1">
            {navItems.map((item) => (
              <div
                key={item.label}
                className="relative"
                onMouseEnter={() => item.hasDropdown && setActiveDropdown(item.label)}
                onMouseLeave={() => setActiveDropdown(null)}
              >
                {item.hasDropdown ? (
                  <button className="flex items-center gap-1 px-4 py-2 text-sm text-neutral-600 hover:text-neutral-900 transition-colors">
                    {item.label}
                    <ChevronDown size={14} className={`transition-transform ${activeDropdown === item.label ? 'rotate-180' : ''}`} />
                  </button>
                ) : (
                  <Link
                    href={item.href || '#'}
                    className="px-4 py-2 text-sm text-neutral-600 hover:text-neutral-900 transition-colors"
                  >
                    {item.label}
                  </Link>
                )}

                {/* Dropdown */}
                <AnimatePresence>
                  {item.hasDropdown && activeDropdown === item.label && (
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: 10 }}
                      transition={{ duration: 0.15 }}
                      className="absolute top-full left-0 mt-1 w-64 bg-white rounded-xl shadow-lg border border-neutral-100 p-2"
                    >
                      {item.items?.map((subItem) => (
                        <Link
                          key={subItem.name}
                          href={subItem.href}
                          className="block px-3 py-2 rounded-lg hover:bg-neutral-50 transition-colors"
                        >
                          <div className="font-medium text-sm text-neutral-900">{subItem.name}</div>
                          <div className="text-xs text-neutral-500">{subItem.description}</div>
                        </Link>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>

          {/* Right side buttons */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              href="/login"
              className="px-4 py-2 text-sm text-neutral-600 hover:text-neutral-900 transition-colors"
            >
              Sign in
            </Link>
            <Link
              href="/signup"
              className="px-4 py-2 bg-[#6C47FF] hover:bg-[#5a3ad9] text-white text-sm font-medium rounded-lg transition-colors"
            >
              Get started
            </Link>
          </div>

          {/* Mobile menu button */}
          <button
            className="md:hidden p-2"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="md:hidden bg-white border-t border-neutral-100"
          >
            <div className="px-6 py-4 space-y-4">
              {navItems.map((item) => (
                <div key={item.label}>
                  {item.hasDropdown ? (
                    <div className="space-y-2">
                      <div className="font-medium text-neutral-900">{item.label}</div>
                      {item.items?.map((subItem) => (
                        <Link
                          key={subItem.name}
                          href={subItem.href}
                          className="block pl-4 py-1 text-sm text-neutral-600"
                          onClick={() => setMobileMenuOpen(false)}
                        >
                          {subItem.name}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <Link
                      href={item.href || '#'}
                      className="block font-medium text-neutral-900"
                      onClick={() => setMobileMenuOpen(false)}
                    >
                      {item.label}
                    </Link>
                  )}
                </div>
              ))}
              <div className="pt-4 border-t border-neutral-100 space-y-2">
                <Link
                  href="/login"
                  className="block w-full py-2 text-center text-neutral-600"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Sign in
                </Link>
                <Link
                  href="/signup"
                  className="block w-full py-2 bg-[#6C47FF] text-white text-center rounded-lg"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Get started
                </Link>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
}

export default ClerkNavbar;
