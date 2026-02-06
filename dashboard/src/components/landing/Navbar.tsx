'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, ChevronDown, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import { springs } from '@/lib/motion';

interface NavLink {
  href: string;
  label: string;
  children?: { href: string; label: string; description?: string }[];
}

const navLinks: NavLink[] = [
  { 
    href: '#features', 
    label: 'Product',
    children: [
      { href: '/features/authentication', label: 'Authentication', description: 'Secure user sign-in' },
      { href: '/features/mfa', label: 'Multi-Factor Auth', description: 'WebAuthn, TOTP, SMS' },
      { href: '/features/sso', label: 'Single Sign-On', description: 'SAML & OIDC support' },
      { href: '/features/organizations', label: 'Organizations', description: 'Multi-tenant support' },
    ]
  },
  { href: '/docs', label: 'Docs' },
  { href: '#pricing', label: 'Pricing' },
  { href: '/blog', label: 'Blog' },
];

// Dropdown menu component
function NavDropdown({ 
  link, 
  isOpen, 
  onToggle 
}: { 
  link: NavLink; 
  isOpen: boolean;
  onToggle: () => void;
}) {
  const dropdownId = `dropdown-${link.label.toLowerCase().replace(/\s+/g, '-')}`;
  
  return (
    <div className="relative">
      <button
        onClick={onToggle}
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-controls={dropdownId}
        className={cn(
          'flex items-center gap-1 px-4 py-2 text-sm font-medium transition-colors',
          isOpen ? 'text-primary' : 'text-neutral-600 hover:text-neutral-900'
        )}
      >
        {link.label}
        <ChevronDown 
          size={14} 
          aria-hidden="true"
          className={cn(
            'transition-transform duration-200',
            isOpen && 'rotate-180'
          )} 
        />
      </button>

      <AnimatePresence>
        {isOpen && link.children && (
          <motion.div
            id={dropdownId}
            role="menu"
            aria-label={`${link.label} submenu`}
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            className="absolute top-full left-0 mt-2 w-64 bg-white rounded-xl shadow-xl border border-neutral-100 overflow-hidden z-50"
          >
            <div className="p-2">
              {link.children.map((child) => (
                <Link
                  key={child.href}
                  href={child.href}
                  role="menuitem"
                  className="block px-4 py-3 rounded-lg hover:bg-neutral-50 transition-colors group"
                >
                  <p className="text-sm font-medium text-neutral-900 group-hover:text-primary transition-colors">
                    {child.label}
                  </p>
                  {child.description && (
                    <p className="text-xs text-neutral-500 mt-0.5">
                      {child.description}
                    </p>
                  )}
                </Link>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = () => setOpenDropdown(null);
    if (openDropdown) {
      document.addEventListener('click', handleClickOutside);
      return () => document.removeEventListener('click', handleClickOutside);
    }
  }, [openDropdown]);

  return (
    <>
      <motion.nav
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
        className={cn(
          'fixed top-0 left-0 right-0 z-50 transition-all duration-300',
          isScrolled 
            ? 'bg-white/80 backdrop-blur-xl shadow-sm border-b border-neutral-100' 
            : 'bg-transparent'
        )}
      >
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link href="/" className="flex items-center">
              <Image
                src="/zalt-full-logo.svg"
                alt="Zalt"
                width={100}
                height={32}
                className="h-8 w-auto"
                priority
              />
            </Link>

            {/* Desktop nav */}
            <div className="hidden md:flex items-center gap-1">
              {navLinks.map((link) => (
                link.children ? (
                  <NavDropdown
                    key={link.href}
                    link={link}
                    isOpen={openDropdown === link.href}
                    onToggle={() => {
                      setOpenDropdown(openDropdown === link.href ? null : link.href);
                    }}
                  />
                ) : (
                  <Link
                    key={link.href}
                    href={link.href}
                    className="px-4 py-2 text-sm font-medium text-neutral-600 hover:text-neutral-900 transition-colors"
                  >
                    {link.label}
                  </Link>
                )
              ))}
            </div>

            {/* CTA */}
            <div className="hidden md:flex items-center gap-3">
              <Link href="/login">
                <Button variant="ghost" size="sm">
                  Sign in
                </Button>
              </Link>
              <Link href="/signup">
                <Button 
                  variant="primary" 
                  size="sm"
                  rightIcon={<ArrowRight size={14} />}
                >
                  Get Started
                </Button>
              </Link>
            </div>

            {/* Mobile menu button */}
            <button
              onClick={() => setIsMobileOpen(!isMobileOpen)}
              aria-expanded={isMobileOpen}
              aria-controls="mobile-menu"
              aria-label={isMobileOpen ? 'Close navigation menu' : 'Open navigation menu'}
              className="md:hidden p-2 text-neutral-600 hover:text-neutral-900 transition-colors"
            >
              {isMobileOpen ? <X size={24} aria-hidden="true" /> : <Menu size={24} aria-hidden="true" />}
            </button>
          </div>
        </div>
      </motion.nav>

      {/* Mobile dropdown */}
      <AnimatePresence>
        {isMobileOpen && (
          <motion.div
            id="mobile-menu"
            role="navigation"
            aria-label="Mobile navigation"
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-x-0 top-16 z-40 md:hidden bg-white border-b border-neutral-100 shadow-lg"
          >
            <div className="px-6 py-4 space-y-1">
              {navLinks.map((link) => (
                <div key={link.href}>
                  {link.children ? (
                    <div className="py-2">
                      <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-2">
                        {link.label}
                      </p>
                      {link.children.map((child) => (
                        <Link
                          key={child.href}
                          href={child.href}
                          onClick={() => setIsMobileOpen(false)}
                          className="block py-2 text-neutral-600 hover:text-primary transition-colors"
                        >
                          {child.label}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <Link
                      href={link.href}
                      onClick={() => setIsMobileOpen(false)}
                      className="block py-3 text-neutral-600 hover:text-primary transition-colors font-medium"
                    >
                      {link.label}
                    </Link>
                  )}
                </div>
              ))}
              
              <div className="pt-4 mt-4 border-t border-neutral-100 space-y-3">
                <Link href="/login" onClick={() => setIsMobileOpen(false)}>
                  <Button variant="secondary" fullWidth>
                    Sign in
                  </Button>
                </Link>
                <Link href="/signup" onClick={() => setIsMobileOpen(false)}>
                  <Button variant="primary" fullWidth rightIcon={<ArrowRight size={16} />}>
                    Get Started
                  </Button>
                </Link>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

export default Navbar;
