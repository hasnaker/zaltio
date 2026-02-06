'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Copy, Check, Code2, Terminal, Sparkles, Package } from 'lucide-react';
import { scrollAnimations, staggerVariants, staggerItemVariants } from '@/lib/motion';
import { codeSnippets, getCodeSnippet } from '@/data/codeSnippets';
import { FrameworkLogos, frameworks } from './FrameworkLogos';

// Framework configurations - use from FrameworkLogos
type FrameworkId = 'nextjs' | 'react' | 'vue' | 'node' | 'python' | 'express';

// Code examples for each framework - use from codeSnippets
const getCodeExample = (frameworkId: FrameworkId): { code: string; highlightLines: number[]; install: string; filename: string } => {
  const snippet = getCodeSnippet(frameworkId);
  if (!snippet) {
    return { code: '', highlightLines: [], install: '', filename: '' };
  }
  
  // Determine highlight lines based on important patterns
  const lines = snippet.code.split('\n');
  const highlightLines: number[] = [];
  lines.forEach((line, index) => {
    if (line.includes('import') && line.includes('@zalt')) {
      highlightLines.push(index + 1);
    }
    if (line.includes('ZaltProvider') || line.includes('ZaltClient') || line.includes('authMiddleware')) {
      highlightLines.push(index + 1);
    }
    if (line.includes('useAuth') || line.includes('require_auth')) {
      highlightLines.push(index + 1);
    }
  });
  
  return {
    code: snippet.code,
    highlightLines: highlightLines.slice(0, 5), // Max 5 highlighted lines
    install: snippet.install,
    filename: snippet.filename,
  };
};

// Syntax highlighting tokens
const syntaxColors = {
  keyword: '#C792EA',      // purple - import, from, const, function, async, await
  string: '#C3E88D',       // green - strings
  function: '#82AAFF',     // blue - function names
  comment: '#546E7A',      // gray - comments
  variable: '#F78C6C',     // orange - variables
  property: '#FFCB6B',     // yellow - properties
  bracket: '#89DDFF',      // cyan - brackets
  operator: '#89DDFF',     // cyan - operators
  default: '#EEFFFF',      // white - default text
};

// Simple syntax highlighter
function highlightSyntax(code: string): React.ReactNode[] {
  const lines = code.split('\n');
  
  return lines.map((line, lineIndex) => {
    const tokens: React.ReactNode[] = [];
    let remaining = line;
    let keyIndex = 0;
    
    // Process line character by character with regex patterns
    const patterns: [RegExp, keyof typeof syntaxColors][] = [
      [/^(\/\/.*|#.*)/, 'comment'],
      [/^(["'`].*?["'`])/, 'string'],
      [/^(import|from|export|default|const|let|var|function|async|await|return|if|else|class|def|try|except|with|for|in|as)\b/, 'keyword'],
      [/^(@\w+)/, 'variable'],
      [/^(\w+)(?=\s*\()/, 'function'],
      [/^(\w+)(?=\s*[=:])/, 'property'],
      [/^([{}()\[\]])/, 'bracket'],
      [/^([=<>!+\-*/&|]+)/, 'operator'],
      [/^(\w+)/, 'default'],
      [/^(\s+)/, 'default'],
      [/^(.)/, 'default'],
    ];
    
    while (remaining.length > 0) {
      let matched = false;
      
      for (const [pattern, colorKey] of patterns) {
        const match = remaining.match(pattern);
        if (match) {
          tokens.push(
            <span key={`${lineIndex}-${keyIndex++}`} style={{ color: syntaxColors[colorKey] }}>
              {match[1]}
            </span>
          );
          remaining = remaining.slice(match[1].length);
          matched = true;
          break;
        }
      }
      
      if (!matched) {
        tokens.push(remaining[0]);
        remaining = remaining.slice(1);
      }
    }
    
    return tokens;
  });
}

interface CodeShowcaseProps {
  className?: string;
}

export function CodeShowcase({ className = '' }: CodeShowcaseProps) {
  const [activeFramework, setActiveFramework] = useState<FrameworkId>('nextjs');
  const [copied, setCopied] = useState(false);
  const [copiedInstall, setCopiedInstall] = useState(false);
  const [displayedLines, setDisplayedLines] = useState<number>(0);
  const [isTyping, setIsTyping] = useState(true);

  const currentExample = getCodeExample(activeFramework);
  const totalLines = currentExample.code.split('\n').length;
  const highlightedCode = useMemo(() => highlightSyntax(currentExample.code), [currentExample.code]);

  // Typing effect - reveal lines progressively
  useEffect(() => {
    setDisplayedLines(0);
    setIsTyping(true);
    
    const interval = setInterval(() => {
      setDisplayedLines(prev => {
        if (prev >= totalLines) {
          setIsTyping(false);
          clearInterval(interval);
          return prev;
        }
        return prev + 1;
      });
    }, 80);

    return () => clearInterval(interval);
  }, [activeFramework, totalLines]);

  const copyCode = useCallback(() => {
    navigator.clipboard.writeText(currentExample.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [currentExample.code]);

  const copyInstall = useCallback(() => {
    navigator.clipboard.writeText(currentExample.install);
    setCopiedInstall(true);
    setTimeout(() => setCopiedInstall(false), 2000);
  }, [currentExample.install]);

  const activeFrameworkData = frameworks.find(f => f.id === activeFramework);

  return (
    <section className={`py-24 md:py-32 px-6 bg-white relative overflow-hidden ${className}`}>
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-neutral-50 to-white" />
      
      {/* Decorative elements */}
      <div className="absolute top-20 left-10 w-72 h-72 bg-primary/5 rounded-full blur-3xl" />
      <div className="absolute bottom-20 right-10 w-96 h-96 bg-accent/5 rounded-full blur-3xl" />

      <div className="max-w-6xl mx-auto relative">
        {/* Section header */}
        <motion.div
          {...scrollAnimations.fadeUp}
          className="text-center mb-16"
        >
          <motion.div 
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/5 border border-primary/10 mb-6"
            whileHover={{ scale: 1.02 }}
          >
            <Code2 size={16} className="text-primary" />
            <span className="text-sm font-medium text-primary">Developer Experience</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-neutral-900 mb-4">
            Ship auth in{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              minutes
            </span>
          </h2>
          
          <p className="text-lg text-neutral-600 max-w-2xl mx-auto">
            Clean, type-safe APIs for every framework. Copy, paste, and you're authenticated.
          </p>
        </motion.div>

        {/* Code showcase card */}
        <motion.div
          {...scrollAnimations.scaleUp}
          className="bg-neutral-900 rounded-2xl overflow-hidden shadow-2xl border border-neutral-800"
        >
          {/* Framework tabs */}
          <div className="flex items-center justify-between px-4 py-3 bg-neutral-950 border-b border-neutral-800">
            <div className="flex items-center gap-1">
              {/* Window controls */}
              <div className="flex items-center gap-1.5 mr-4">
                <div className="w-3 h-3 rounded-full bg-red-500/80" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                <div className="w-3 h-3 rounded-full bg-green-500/80" />
              </div>
              
              {/* Framework tabs */}
              <div className="flex items-center gap-1 overflow-x-auto" role="tablist" aria-label="Framework selection">
                {frameworks.map((framework) => (
                  <motion.button
                    key={framework.id}
                    role="tab"
                    aria-selected={activeFramework === framework.id}
                    aria-controls={`code-panel-${framework.id}`}
                    onClick={() => setActiveFramework(framework.id as FrameworkId)}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                      activeFramework === framework.id
                        ? 'bg-primary/20 text-primary'
                        : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800'
                    }`}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <span className="w-4 h-4" style={{ color: activeFramework === framework.id ? undefined : framework.color }}>
                      {framework.icon}
                    </span>
                    <span className="hidden sm:inline">{framework.name}</span>
                  </motion.button>
                ))}
              </div>
            </div>

            {/* Copy button */}
            <motion.button
              onClick={copyCode}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm text-neutral-400 hover:text-white hover:bg-neutral-800 transition-all"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              aria-label={copied ? 'Copied!' : 'Copy code'}
            >
              <AnimatePresence mode="wait">
                {copied ? (
                  <motion.div
                    key="check"
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    exit={{ scale: 0 }}
                    className="flex items-center gap-1 text-green-400"
                  >
                    <Check size={14} />
                    <span>Copied!</span>
                  </motion.div>
                ) : (
                  <motion.div
                    key="copy"
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    exit={{ scale: 0 }}
                    className="flex items-center gap-1"
                  >
                    <Copy size={14} />
                    <span className="hidden sm:inline">Copy</span>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.button>
          </div>

          {/* Code content */}
          <div 
            id={`code-panel-${activeFramework}`}
            role="tabpanel"
            aria-labelledby={`tab-${activeFramework}`}
            className="relative"
          >
            {/* Line numbers + code */}
            <div className="flex overflow-x-auto">
              {/* Line numbers */}
              <div className="flex-shrink-0 py-4 pl-4 pr-2 text-right select-none border-r border-neutral-800">
                {highlightedCode.map((_, index) => (
                  <div
                    key={index}
                    className={`text-xs font-mono leading-6 ${
                      currentExample.highlightLines.includes(index + 1)
                        ? 'text-primary'
                        : 'text-neutral-600'
                    } ${index >= displayedLines ? 'opacity-0' : 'opacity-100'}`}
                    style={{ transition: 'opacity 0.1s' }}
                  >
                    {index + 1}
                  </div>
                ))}
              </div>

              {/* Code */}
              <div className="flex-1 py-4 px-4 overflow-x-auto">
                <pre className="font-mono text-sm leading-6">
                  <code>
                    {highlightedCode.map((lineTokens, index) => (
                      <div
                        key={index}
                        className={`${
                          currentExample.highlightLines.includes(index + 1)
                            ? 'bg-primary/10 -mx-4 px-4 border-l-2 border-primary'
                            : ''
                        } ${index >= displayedLines ? 'opacity-0' : 'opacity-100'}`}
                        style={{ transition: 'opacity 0.1s' }}
                      >
                        {lineTokens}
                        {index === displayedLines - 1 && isTyping && (
                          <motion.span
                            animate={{ opacity: [1, 0] }}
                            transition={{ duration: 0.5, repeat: Infinity }}
                            className="inline-block w-2 h-4 bg-primary ml-0.5 align-middle"
                          />
                        )}
                      </div>
                    ))}
                  </code>
                </pre>
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between px-4 py-2 bg-neutral-950 border-t border-neutral-800">
              <div className="flex items-center gap-2">
                <Terminal size={12} className="text-neutral-500" />
                <span className="text-xs text-neutral-500 font-mono">
                  {activeFrameworkData?.name || 'Framework'} • {currentExample.filename}
                </span>
              </div>
              
              <div className="flex items-center gap-2">
                <Sparkles size={12} className="text-primary" />
                <span className="text-xs text-neutral-500">
                  Full type safety included
                </span>
              </div>
            </div>
          </div>

          {/* Installation command */}
          <div className="px-4 py-3 bg-neutral-950 border-t border-neutral-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3 flex-1">
                <Package size={14} className="text-neutral-500" />
                <code className="text-sm text-neutral-300 font-mono">
                  {currentExample.install}
                </code>
              </div>
              <motion.button
                onClick={copyInstall}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm text-neutral-400 hover:text-white hover:bg-neutral-800 transition-all"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                aria-label={copiedInstall ? 'Copied!' : 'Copy install command'}
              >
                <AnimatePresence mode="wait">
                  {copiedInstall ? (
                    <motion.div
                      key="check"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      exit={{ scale: 0 }}
                      className="flex items-center gap-1 text-green-400"
                    >
                      <Check size={14} />
                      <span>Copied!</span>
                    </motion.div>
                  ) : (
                    <motion.div
                      key="copy"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      exit={{ scale: 0 }}
                      className="flex items-center gap-1"
                    >
                      <Copy size={14} />
                      <span className="hidden sm:inline">Copy</span>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.button>
            </div>
          </div>
        </motion.div>

        {/* Bottom features */}
        <motion.div
          variants={staggerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-12"
        >
          {[
            { label: 'Type-safe APIs', value: '100%' },
            { label: 'Bundle size', value: '<10KB' },
            { label: 'Setup time', value: '5 min' },
            { label: 'Framework support', value: '10+' },
          ].map((stat) => (
            <motion.div
              key={stat.label}
              variants={staggerItemVariants}
              className="text-center p-4 rounded-xl bg-neutral-50 border border-neutral-100"
            >
              <div className="text-2xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                {stat.value}
              </div>
              <div className="text-sm text-neutral-600 mt-1">{stat.label}</div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

export default CodeShowcase;
