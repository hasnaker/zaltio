'use client';

import React from 'react';
import Link from 'next/link';

const footerLinks = {
  Product: [
    { name: 'Authentication', href: '/docs/authentication' },
    { name: 'User Management', href: '/docs/user-management' },
    { name: 'Organizations', href: '/docs/organizations' },
    { name: 'Billing', href: '/docs/billing' },
    { name: 'Security', href: '/docs/security' },
  ],
  Developers: [
    { name: 'Documentation', href: '/docs' },
    { name: 'API Reference', href: '/docs/api' },
    { name: 'SDKs', href: '/docs/sdk' },
    { name: 'Quickstart', href: '/docs/quickstart' },
    { name: 'Changelog', href: '/changelog' },
  ],
  Resources: [
    { name: 'Blog', href: '/blog' },
    { name: 'Guides', href: '/guides' },
    { name: 'Support', href: '/support' },
    { name: 'Status', href: 'https://status.zalt.io' },
    { name: 'Community', href: '/community' },
  ],
  Company: [
    { name: 'About', href: '/about' },
    { name: 'Careers', href: '/careers' },
    { name: 'Contact', href: '/contact' },
    { name: 'Privacy', href: '/privacy' },
    { name: 'Terms', href: '/terms' },
  ],
};

const socialLinks = [
  { name: 'Twitter', href: 'https://twitter.com/zaltio', icon: '𝕏' },
  { name: 'GitHub', href: 'https://github.com/zalt-io', icon: '⌘' },
  { name: 'Discord', href: 'https://discord.gg/zalt', icon: '💬' },
  { name: 'LinkedIn', href: 'https://linkedin.com/company/zalt-io', icon: 'in' },
];

export function ClerkFooter() {
  return (
    <footer className="bg-[#0F0F10] text-white py-16">
      <div className="max-w-7xl mx-auto px-6">
        {/* Main footer content */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8 mb-12">
          {/* Logo and description */}
          <div className="col-span-2 md:col-span-1">
            <Link href="/" className="flex items-center gap-2 mb-4">
              <span className="text-2xl">⚡</span>
              <span className="text-xl font-bold">zalt</span>
            </Link>
            <p className="text-sm text-neutral-400 mb-4">
              Complete user management for modern applications.
            </p>
            <div className="flex gap-4">
              {socialLinks.map((social) => (
                <a
                  key={social.name}
                  href={social.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-8 h-8 bg-neutral-800 rounded-lg flex items-center justify-center text-neutral-400 hover:text-white hover:bg-neutral-700 transition-colors"
                >
                  {social.icon}
                </a>
              ))}
            </div>
          </div>

          {/* Link columns */}
          {Object.entries(footerLinks).map(([category, links]) => (
            <div key={category}>
              <h4 className="font-medium text-white mb-4">{category}</h4>
              <ul className="space-y-2">
                {links.map((link) => (
                  <li key={link.name}>
                    <Link
                      href={link.href}
                      className="text-sm text-neutral-400 hover:text-white transition-colors"
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="border-t border-neutral-800 pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-sm text-neutral-500">
            © {new Date().getFullYear()} Zalt.io. All rights reserved.
          </p>
          <div className="flex items-center gap-6 text-sm text-neutral-500">
            <Link href="/privacy" className="hover:text-white transition-colors">
              Privacy Policy
            </Link>
            <Link href="/terms" className="hover:text-white transition-colors">
              Terms of Service
            </Link>
            <Link href="/security" className="hover:text-white transition-colors">
              Security
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default ClerkFooter;
