'use client';

import { LegalPageLayout } from '@/components/legal/LegalPageLayout';

const tableOfContents = [
  { id: 'overview', title: 'Security Overview' },
  { id: 'encryption', title: 'Encryption' },
  { id: 'authentication', title: 'Authentication Security' },
  { id: 'infrastructure', title: 'Infrastructure' },
  { id: 'compliance', title: 'Compliance' },
  { id: 'incident-response', title: 'Incident Response' },
  { id: 'reporting', title: 'Security Reporting' },
];

export default function SecurityPolicyPage() {
  return (
    <LegalPageLayout
      title="Security Policy"
      lastUpdated="February 1, 2026"
      tableOfContents={tableOfContents}
    >
      <p className="text-neutral-300 lead">
        Security is at the core of everything we do at Zalt.io. This document outlines our 
        security practices and commitments.
      </p>

      <section id="overview">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">1. Security Overview</h2>
        <p className="text-neutral-300">
          Zalt.io is designed to be darkweb-resistant and protect against sophisticated threats 
          including credential stuffing, phishing proxies, and nation-state level attacks.
        </p>
        <p className="text-neutral-300 mt-4">
          Our security architecture is built on the principle of defense in depth, with multiple 
          layers of protection at every level.
        </p>
      </section>

      <section id="encryption">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">2. Encryption</h2>
        <h3 className="text-lg font-semibold text-white mt-6 mb-2">In Transit</h3>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>TLS 1.3 for all connections</li>
          <li>HSTS enabled with preloading</li>
          <li>Certificate transparency monitoring</li>
        </ul>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">At Rest</h3>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>AES-256 encryption for all stored data</li>
          <li>AWS KMS for key management</li>
          <li>Automatic key rotation every 30 days</li>
        </ul>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Password Hashing</h3>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Argon2id algorithm (winner of Password Hashing Competition)</li>
          <li>32MB memory cost, time cost 5, parallelism 2</li>
          <li>Unique salt per password</li>
        </ul>
      </section>

      <section id="authentication">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">3. Authentication Security</h2>
        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Token Security</h3>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>RS256 (RSA-SHA256) JWT signing - FIPS compliant</li>
          <li>15-minute access token expiry</li>
          <li>7-day refresh tokens with rotation on each use</li>
          <li>30-second grace period for network retries</li>
        </ul>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Multi-Factor Authentication</h3>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>WebAuthn/Passkeys (phishing-proof, mandatory for healthcare)</li>
          <li>TOTP (Google Authenticator compatible)</li>
          <li>SMS MFA disabled by default due to SS7 vulnerabilities</li>
        </ul>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Session Security</h3>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Device fingerprinting with 70% fuzzy matching</li>
          <li>Session binding to device</li>
          <li>Automatic invalidation on password change</li>
          <li>Configurable concurrent session limits</li>
        </ul>
      </section>

      <section id="infrastructure">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">4. Infrastructure Security</h2>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>AWS infrastructure with VPC isolation</li>
          <li>AWS WAF for attack protection</li>
          <li>DDoS protection via AWS Shield</li>
          <li>Regular penetration testing</li>
          <li>Automated vulnerability scanning</li>
          <li>Infrastructure as Code for reproducibility</li>
        </ul>
      </section>

      <section id="compliance">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">5. Compliance</h2>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li><strong>SOC 2 Type II:</strong> Annual audit of security controls</li>
          <li><strong>HIPAA:</strong> Healthcare data protection compliance</li>
          <li><strong>GDPR:</strong> EU data protection compliance</li>
          <li><strong>ISO 27001:</strong> Information security management</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          Compliance reports are available to enterprise customers upon request.
        </p>
      </section>

      <section id="incident-response">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">6. Incident Response</h2>
        <p className="text-neutral-300">
          We maintain a comprehensive incident response plan including:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>24/7 security monitoring</li>
          <li>Automated threat detection and alerting</li>
          <li>Defined escalation procedures</li>
          <li>Customer notification within 72 hours of confirmed breach</li>
          <li>Post-incident analysis and remediation</li>
        </ul>
      </section>

      <section id="reporting">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">7. Security Reporting</h2>
        <p className="text-neutral-300">
          We welcome responsible disclosure of security vulnerabilities. Please report 
          security issues to:
        </p>
        <p className="text-neutral-300 mt-4">
          <a href="mailto:security@zalt.io" className="text-emerald-400">security@zalt.io</a>
        </p>
        <p className="text-neutral-300 mt-4">
          We commit to acknowledging reports within 24 hours and providing updates on 
          remediation progress.
        </p>
      </section>
    </LegalPageLayout>
  );
}
