'use client';

import { LegalPageLayout } from '@/components/legal/LegalPageLayout';

const tableOfContents = [
  { id: 'acceptance', title: 'Acceptance of Terms' },
  { id: 'services', title: 'Our Services' },
  { id: 'account', title: 'Your Account' },
  { id: 'acceptable-use', title: 'Acceptable Use' },
  { id: 'intellectual-property', title: 'Intellectual Property' },
  { id: 'limitation', title: 'Limitation of Liability' },
  { id: 'termination', title: 'Termination' },
  { id: 'changes', title: 'Changes to Terms' },
];

export default function TermsPage() {
  return (
    <LegalPageLayout
      title="Terms of Service"
      lastUpdated="February 1, 2026"
      tableOfContents={tableOfContents}
    >
      <p className="text-neutral-300 lead">
        These Terms of Service govern your use of Zalt.io authentication services. 
        By using our services, you agree to these terms.
      </p>

      <section id="acceptance">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">1. Acceptance of Terms</h2>
        <p className="text-neutral-300">
          By accessing or using Zalt.io services, you agree to be bound by these Terms of Service 
          and our Privacy Policy. If you do not agree, do not use our services.
        </p>
        <p className="text-neutral-300 mt-4">
          If you are using our services on behalf of an organization, you represent that you have 
          authority to bind that organization to these terms.
        </p>
      </section>

      <section id="services">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">2. Our Services</h2>
        <p className="text-neutral-300">
          Zalt.io provides authentication-as-a-service including:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>User authentication and session management</li>
          <li>Multi-factor authentication (MFA)</li>
          <li>Single sign-on (SSO) integration</li>
          <li>Organization and team management</li>
          <li>API access and SDKs</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          We reserve the right to modify, suspend, or discontinue any part of our services 
          with reasonable notice.
        </p>
      </section>

      <section id="account">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">3. Your Account</h2>
        <p className="text-neutral-300">You are responsible for:</p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Maintaining the security of your account credentials</li>
          <li>All activities that occur under your account</li>
          <li>Notifying us immediately of any unauthorized access</li>
          <li>Ensuring your contact information is accurate</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          We recommend enabling multi-factor authentication for enhanced security.
        </p>
      </section>

      <section id="acceptable-use">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">4. Acceptable Use</h2>
        <p className="text-neutral-300">You agree not to:</p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Use our services for any illegal purpose</li>
          <li>Attempt to gain unauthorized access to our systems</li>
          <li>Interfere with or disrupt our services</li>
          <li>Transmit malware or malicious code</li>
          <li>Violate the rights of others</li>
          <li>Resell our services without authorization</li>
          <li>Use our services to send spam or phishing attempts</li>
        </ul>
      </section>

      <section id="intellectual-property">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">5. Intellectual Property</h2>
        <p className="text-neutral-300">
          Zalt.io and its licensors retain all rights to our services, including trademarks, 
          logos, and proprietary technology. You may not copy, modify, or distribute our 
          intellectual property without permission.
        </p>
        <p className="text-neutral-300 mt-4">
          You retain ownership of your data. By using our services, you grant us a limited 
          license to process your data as necessary to provide our services.
        </p>
      </section>

      <section id="limitation">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">6. Limitation of Liability</h2>
        <p className="text-neutral-300">
          TO THE MAXIMUM EXTENT PERMITTED BY LAW, ZALT.IO SHALL NOT BE LIABLE FOR ANY INDIRECT, 
          INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING LOSS OF PROFITS, 
          DATA, OR GOODWILL.
        </p>
        <p className="text-neutral-300 mt-4">
          Our total liability shall not exceed the amount you paid us in the twelve months 
          preceding the claim.
        </p>
      </section>

      <section id="termination">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">7. Termination</h2>
        <p className="text-neutral-300">
          Either party may terminate this agreement at any time. Upon termination:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Your access to our services will be revoked</li>
          <li>You may request export of your data within 30 days</li>
          <li>We will delete your data according to our retention policy</li>
          <li>Provisions that should survive termination will remain in effect</li>
        </ul>
      </section>

      <section id="changes">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">8. Changes to Terms</h2>
        <p className="text-neutral-300">
          We may update these terms from time to time. We will notify you of material changes 
          via email or through our services. Continued use after changes constitutes acceptance.
        </p>
        <p className="text-neutral-300 mt-4">
          For questions about these terms, contact us at{' '}
          <a href="mailto:legal@zalt.io" className="text-emerald-400">legal@zalt.io</a>.
        </p>
      </section>
    </LegalPageLayout>
  );
}
