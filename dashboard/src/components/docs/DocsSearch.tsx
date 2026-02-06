'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Search, X, FileText, Hash, ArrowRight, Command } from 'lucide-react';
import Link from 'next/link';

export interface DocsSearchProps {
  /** Placeholder text */
  placeholder?: string;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

interface SearchResult {
  id: string;
  title: string;
  section: string;
  href: string;
  excerpt: string;
  relevance: number;
}

// Mock search index (in production, this would be from a search service)
const searchIndex: Omit<SearchResult, 'relevance'>[] = [
  { id: '1', title: 'Quickstart Guide', section: 'Getting Started', href: '/docs/quickstart', excerpt: 'Get up and running with Zalt authentication in 5 minutes.' },
  { id: '2', title: 'React SDK', section: 'SDK Reference', href: '/docs/sdk/react', excerpt: 'Install and configure the @zalt/react SDK for your React application.' },
  { id: '3', title: 'Next.js Integration', section: 'SDK Reference', href: '/docs/sdk/nextjs', excerpt: 'Server-side authentication with the @zalt/next middleware.' },
  { id: '4', title: 'WebAuthn Setup', section: 'Authentication', href: '/docs/auth/webauthn', excerpt: 'Enable passwordless authentication with WebAuthn and passkeys.' },
  { id: '5', title: 'TOTP MFA', section: 'Multi-Factor Auth', href: '/docs/mfa/totp', excerpt: 'Set up time-based one-time passwords for additional security.' },
  { id: '6', title: 'Organizations', section: 'Organizations', href: '/docs/orgs/multi-tenancy', excerpt: 'Implement multi-tenant architecture with organizations.' },
  { id: '7', title: 'RBAC', section: 'Organizations', href: '/docs/orgs/rbac', excerpt: 'Role-based access control for fine-grained permissions.' },
  { id: '8', title: 'Webhooks', section: 'API Reference', href: '/docs/api/webhooks', excerpt: 'Receive real-time notifications for authentication events.' },
  { id: '9', title: 'Error Codes', section: 'API Reference', href: '/docs/api/errors', excerpt: 'Complete list of error codes and troubleshooting guides.' },
  { id: '10', title: 'SSO/SAML', section: 'Organizations', href: '/docs/orgs/sso', excerpt: 'Enterprise single sign-on with SAML 2.0 and OIDC.' },
];

/**
 * Search function with relevance ranking
 */
function searchDocs(query: string): SearchResult[] {
  if (!query.trim()) return [];
  
  const normalizedQuery = query.toLowerCase().trim();
  const queryWords = normalizedQuery.split(/\s+/);
  
  const results = searchIndex
    .map(doc => {
      let relevance = 0;
      const titleLower = doc.title.toLowerCase();
      const excerptLower = doc.excerpt.toLowerCase();
      const sectionLower = doc.section.toLowerCase();
      
      // Exact title match (highest relevance)
      if (titleLower === normalizedQuery) {
        relevance += 100;
      }
      // Title starts with query
      else if (titleLower.startsWith(normalizedQuery)) {
        relevance += 50;
      }
      // Title contains query
      else if (titleLower.includes(normalizedQuery)) {
        relevance += 30;
      }
      
      // Word matches
      queryWords.forEach(word => {
        if (titleLower.includes(word)) relevance += 20;
        if (excerptLower.includes(word)) relevance += 10;
        if (sectionLower.includes(word)) relevance += 5;
      });
      
      return { ...doc, relevance };
    })
    .filter(doc => doc.relevance > 0)
    .sort((a, b) => b.relevance - a.relevance)
    .slice(0, 8);
  
  return results;
}

/**
 * Highlight matching text in search results
 */
function highlightMatch(text: string, query: string): React.ReactNode {
  if (!query.trim()) return text;
  
  const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
  const parts = text.split(regex);
  
  return parts.map((part, i) => 
    regex.test(part) ? (
      <mark key={i} className="bg-primary/20 text-primary rounded px-0.5">
        {part}
      </mark>
    ) : part
  );
}

/**
 * Documentation Search Component
 * Implements search with keyboard shortcuts and relevance ranking
 */
export function DocsSearch({
  placeholder = 'Search documentation...',
  className,
  'data-testid': testId = 'docs-search',
}: DocsSearchProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Search when query changes
  useEffect(() => {
    const searchResults = searchDocs(query);
    setResults(searchResults);
    setSelectedIndex(0);
  }, [query]);

  // Keyboard shortcut to open search (Cmd/Ctrl + K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen(true);
      }
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Focus input when modal opens
  useEffect(() => {
    if (isOpen) {
      inputRef.current?.focus();
    }
  }, [isOpen]);

  // Handle keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => Math.min(prev + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => Math.max(prev - 1, 0));
    } else if (e.key === 'Enter' && results[selectedIndex]) {
      window.location.href = results[selectedIndex].href;
    }
  }, [results, selectedIndex]);

  const closeSearch = () => {
    setIsOpen(false);
    setQuery('');
  };

  return (
    <>
      {/* Search trigger button */}
      <button
        onClick={() => setIsOpen(true)}
        className={cn(
          'flex items-center gap-2 px-4 py-2 rounded-lg border border-neutral-200 dark:border-neutral-700',
          'bg-white dark:bg-neutral-800 text-neutral-500 dark:text-neutral-400',
          'hover:border-primary/50 transition-colors',
          className
        )}
        data-testid={testId}
      >
        <Search className="w-4 h-4" />
        <span className="text-sm">{placeholder}</span>
        <kbd className="hidden sm:flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-700 text-xs">
          <Command className="w-3 h-3" />K
        </kbd>
      </button>

      {/* Search modal */}
      <AnimatePresence>
        {isOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={closeSearch}
              className="fixed inset-0 bg-black/50 z-50"
            />

            {/* Modal */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="fixed top-[20%] left-1/2 -translate-x-1/2 w-full max-w-xl z-50 px-4"
            >
              <div className="bg-white dark:bg-neutral-800 rounded-xl shadow-2xl border border-neutral-200 dark:border-neutral-700 overflow-hidden">
                {/* Search input */}
                <div className="flex items-center gap-3 px-4 py-3 border-b border-neutral-200 dark:border-neutral-700">
                  <Search className="w-5 h-5 text-neutral-400" />
                  <input
                    ref={inputRef}
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder={placeholder}
                    className="flex-1 bg-transparent text-neutral-900 dark:text-white placeholder:text-neutral-400 outline-none"
                    data-testid="search-input"
                  />
                  <button
                    onClick={closeSearch}
                    className="p-1 rounded hover:bg-neutral-100 dark:hover:bg-neutral-700 transition-colors"
                  >
                    <X className="w-4 h-4 text-neutral-400" />
                  </button>
                </div>

                {/* Results */}
                <div className="max-h-96 overflow-y-auto">
                  {results.length > 0 ? (
                    <div className="p-2">
                      {results.map((result, index) => (
                        <Link
                          key={result.id}
                          href={result.href}
                          onClick={closeSearch}
                          className={cn(
                            'flex items-start gap-3 px-3 py-3 rounded-lg transition-colors',
                            index === selectedIndex
                              ? 'bg-primary/10 text-primary'
                              : 'hover:bg-neutral-100 dark:hover:bg-neutral-700'
                          )}
                          data-testid={`search-result-${result.id}`}
                        >
                          <FileText className="w-5 h-5 flex-shrink-0 mt-0.5" />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-neutral-900 dark:text-white">
                                {highlightMatch(result.title, query)}
                              </span>
                              <span className="text-xs text-neutral-400 flex items-center gap-1">
                                <Hash className="w-3 h-3" />
                                {result.section}
                              </span>
                            </div>
                            <p className="text-sm text-neutral-500 dark:text-neutral-400 truncate mt-0.5">
                              {highlightMatch(result.excerpt, query)}
                            </p>
                          </div>
                          <ArrowRight className="w-4 h-4 flex-shrink-0 opacity-0 group-hover:opacity-100" />
                        </Link>
                      ))}
                    </div>
                  ) : query ? (
                    <div className="px-4 py-8 text-center text-neutral-500">
                      <p>No results found for "{query}"</p>
                      <p className="text-sm mt-1">Try different keywords</p>
                    </div>
                  ) : (
                    <div className="px-4 py-8 text-center text-neutral-500">
                      <p>Start typing to search...</p>
                    </div>
                  )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between px-4 py-2 border-t border-neutral-200 dark:border-neutral-700 text-xs text-neutral-400">
                  <div className="flex items-center gap-4">
                    <span className="flex items-center gap-1">
                      <kbd className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-700">↑↓</kbd>
                      Navigate
                    </span>
                    <span className="flex items-center gap-1">
                      <kbd className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-700">↵</kbd>
                      Select
                    </span>
                  </div>
                  <span className="flex items-center gap-1">
                    <kbd className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-700">Esc</kbd>
                    Close
                  </span>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}

export default DocsSearch;
