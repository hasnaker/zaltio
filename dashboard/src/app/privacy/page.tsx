'use client';

import { LegalPageLayout } from '@/components/legal/LegalPageLayout';

const tableOfContents = [
  { id: 'information-we-collect', title: 'Information We Collect' },
  { id: 'how-we-use', title: 'How We Use Information' },
  { id: 'data-sharing', title: 'Data Sharing' },
  { id: 'data-retention', title: 'Data Retention' },
  { id: 'your-rights', title: 'Your Rights' },
  { id: 'security', title: 'Security' },
  { id: 'contact', title: 'Contact Us' },
];

export default function PrivacyPage() {
  return (
    <LegalPageLayout
      title="Privacy Policy"
      lastUpdated="February 1, 2026"
      tableOfContents={tableOfContents}
    >
      <p className="text-neutral-300 lead">
        At Zalt.io, we take your privacy seriously. This Privacy Policy explains how we collect, 
        use, disclose, and safeguard your information when you use our authentication services.
      </p>

      <section id="information-we-collect">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">1. Information We Collect</h2>
        
        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Account Information</h3>
        <p className="text-neutral-300">
          When you create an account, we collect:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Email address</li>
          <li>Password (stored as a secure hash using Argon2id)</li>
          <li>Name (optional)</li>
          <li>Profile information you choose to provide</li>
        </ul>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Authentication Data</h3>
        <p className="text-neutral-300">
          To provide secure authentication, we collect:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Device fingerprints for session security</li>
          <li>IP addresses for security monitoring</li>
          <li>Login timestamps and session information</li>
          <li>MFA device registrations (WebAuthn credentials, TOTP secrets)</li>
        </ul>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Usage Data</h3>
        <p className="text-neutral-300">
          We automatically collect certain information about your use of our services:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Browser type and version</li>
          <li>Operating system</li>
          <li>Pages visited and features used</li>
          <li>Time and date of access</li>
        </ul>
      </section>

      <section id="how-we-use">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">2. How We Use Your Information</h2>
        <p className="text-neutral-300">We use the information we collect to:</p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Provide and maintain our authentication services</li>
          <li>Detect and prevent fraud, abuse, and security threats</li>
          <li>Improve and personalize your experience</li>
          <li>Communicate with you about service updates</li>
          <li>Comply with legal obligations</li>
          <li>Enforce our terms of service</li>
        </ul>
      </section>

      <section id="data-sharing">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">3. Data Sharing</h2>
        <p className="text-neutral-300">
          We do not sell your personal information. We may share your information with:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li><strong>Service Providers:</strong> AWS for infrastructure, email delivery services</li>
          <li><strong>Your Organization:</strong> If you use Zalt through an organization, administrators may access certain account information</li>
          <li><strong>Legal Requirements:</strong> When required by law or to protect our rights</li>
        </ul>
      </section>

      <section id="data-retention">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">4. Data Retention</h2>
        <p className="text-neutral-300">
          We retain your information for as long as your account is active or as needed to provide services. 
          Audit logs are retained for compliance purposes (typically 7 years for HIPAA-covered entities).
        </p>
        <p className="text-neutral-300 mt-4">
          You can request deletion of your account and associated data at any time, subject to legal retention requirements.
        </p>
      </section>

      <section id="your-rights">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">5. Your Rights</h2>
        <p className="text-neutral-300">Depending on your location, you may have the right to:</p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Access your personal data</li>
          <li>Correct inaccurate data</li>
          <li>Delete your data</li>
          <li>Export your data in a portable format</li>
          <li>Object to certain processing</li>
          <li>Withdraw consent</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          To exercise these rights, contact us at <a href="mailto:privacy@zalt.io" className="text-emerald-400">privacy@zalt.io</a>.
        </p>
      </section>

      <section id="security">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">6. Security</h2>
        <p className="text-neutral-300">
          We implement industry-standard security measures including:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Encryption in transit (TLS 1.3) and at rest (AES-256)</li>
          <li>Argon2id password hashing with high memory cost</li>
          <li>Multi-factor authentication options</li>
          <li>Regular security audits and penetration testing</li>
          <li>SOC 2 Type II compliance</li>
        </ul>
      </section>

      <section id="contact">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">7. Contact Us</h2>
        <p className="text-neutral-300">
          If you have questions about this Privacy Policy, please contact us:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Email: <a href="mailto:privacy@zalt.io" className="text-emerald-400">privacy@zalt.io</a></li>
          <li>Address: Istanbul, Turkey</li>
        </ul>
      </section>
    </LegalPageLayout>
  );
}
