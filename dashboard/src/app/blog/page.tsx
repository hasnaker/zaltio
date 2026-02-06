'use client';

import { BlogLayout } from '@/components/blog/BlogLayout';
import { BlogPost } from '@/components/blog/BlogCard';

const blogPosts: BlogPost[] = [
  {
    slug: 'why-we-disabled-sms-mfa-by-default',
    title: 'Why We Disabled SMS MFA by Default',
    excerpt: 'SS7 vulnerabilities make SMS-based authentication a security risk. Here\'s why Zalt takes a different approach and what you should use instead.',
    author: 'Security Team',
    date: 'Feb 1, 2026',
    readingTime: 8,
    category: 'Security',
    tags: ['mfa', 'security', 'ss7', 'webauthn'],
    featured: true,
  },
  {
    slug: 'introducing-ai-risk-scoring',
    title: 'Introducing AI-Powered Risk Scoring',
    excerpt: 'Our new Bedrock-powered risk engine analyzes login patterns in real-time to detect credential stuffing and account takeover attempts.',
    author: 'Engineering',
    date: 'Jan 28, 2026',
    readingTime: 6,
    category: 'Product',
    tags: ['ai', 'security', 'bedrock', 'risk-scoring'],
  },
  {
    slug: 'building-hipaa-compliant-auth',
    title: 'Building HIPAA-Compliant Authentication',
    excerpt: 'How we designed Zalt to meet healthcare compliance requirements from day one, including audit logging, encryption, and access controls.',
    author: 'Engineering',
    date: 'Jan 25, 2026',
    readingTime: 12,
    category: 'Engineering',
    tags: ['hipaa', 'compliance', 'healthcare', 'security'],
  },
  {
    slug: 'mcp-server-ai-agents',
    title: 'MCP Server: Authentication for AI Agents',
    excerpt: 'Introducing our Model Context Protocol server that lets AI agents authenticate users and manage sessions programmatically.',
    author: 'Engineering',
    date: 'Jan 20, 2026',
    readingTime: 7,
    category: 'Product',
    tags: ['mcp', 'ai', 'agents', 'sdk'],
  },
  {
    slug: 'webauthn-passkeys-guide',
    title: 'The Complete Guide to WebAuthn and Passkeys',
    excerpt: 'Everything you need to know about implementing phishing-proof authentication with WebAuthn and passkeys in your application.',
    author: 'Security Team',
    date: 'Jan 15, 2026',
    readingTime: 15,
    category: 'Tutorial',
    tags: ['webauthn', 'passkeys', 'security', 'tutorial'],
  },
  {
    slug: 'clinisyn-case-study',
    title: 'Case Study: Clinisyn\'s Migration to Zalt',
    excerpt: 'How Clinisyn migrated 4,000 psychologists across 11 countries to Zalt in under a week, with zero downtime.',
    author: 'Customer Success',
    date: 'Jan 10, 2026',
    readingTime: 5,
    category: 'Company',
    tags: ['case-study', 'healthcare', 'migration'],
  },
  {
    slug: 'session-tasks-step-up-auth',
    title: 'Session Tasks: Implementing Step-Up Authentication',
    excerpt: 'Learn how to use Zalt\'s session tasks feature to require additional verification for sensitive operations.',
    author: 'Engineering',
    date: 'Jan 5, 2026',
    readingTime: 10,
    category: 'Tutorial',
    tags: ['session-tasks', 'step-up-auth', 'security', 'tutorial'],
  },
  {
    slug: 'device-fingerprinting-explained',
    title: 'Device Fingerprinting: How We Detect Suspicious Logins',
    excerpt: 'A deep dive into our device fingerprinting system and how 70% fuzzy matching helps detect account takeover attempts.',
    author: 'Engineering',
    date: 'Dec 28, 2025',
    readingTime: 9,
    category: 'Engineering',
    tags: ['device-fingerprinting', 'security', 'fraud-detection'],
  },
  {
    slug: 'argon2id-password-hashing',
    title: 'Why We Use Argon2id for Password Hashing',
    excerpt: 'The technical reasons behind our choice of Argon2id with 32MB memory cost for password hashing.',
    author: 'Security Team',
    date: 'Dec 20, 2025',
    readingTime: 8,
    category: 'Security',
    tags: ['argon2id', 'passwords', 'cryptography', 'security'],
  },
];

const categories = ['Engineering', 'Security', 'Product', 'Company', 'Tutorial'];

export default function BlogPage() {
  return <BlogLayout posts={blogPosts} categories={categories} />;
}
