'use client';

import { LegalPageLayout } from '@/components/legal/LegalPageLayout';

const tableOfContents = [
  { id: 'what-are-cookies', title: 'What Are Cookies' },
  { id: 'how-we-use', title: 'How We Use Cookies' },
  { id: 'types', title: 'Types of Cookies' },
  { id: 'third-party', title: 'Third-Party Cookies' },
  { id: 'managing', title: 'Managing Cookies' },
  { id: 'contact', title: 'Contact Us' },
];

export default function CookiesPage() {
  return (
    <LegalPageLayout
      title="Cookie Policy"
      lastUpdated="February 1, 2026"
      tableOfContents={tableOfContents}
    >
      <p className="text-neutral-300 lead">
        This Cookie Policy explains how Zalt.io uses cookies and similar technologies 
        when you visit our website or use our services.
      </p>

      <section id="what-are-cookies">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">1. What Are Cookies</h2>
        <p className="text-neutral-300">
          Cookies are small text files stored on your device when you visit a website. 
          They help websites remember your preferences and improve your experience.
        </p>
        <p className="text-neutral-300 mt-4">
          We also use similar technologies like local storage and session storage for 
          similar purposes.
        </p>
      </section>

      <section id="how-we-use">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">2. How We Use Cookies</h2>
        <p className="text-neutral-300">We use cookies to:</p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Keep you signed in to your account</li>
          <li>Remember your preferences and settings</li>
          <li>Understand how you use our services</li>
          <li>Improve our services based on usage patterns</li>
          <li>Protect against fraud and unauthorized access</li>
        </ul>
      </section>

      <section id="types">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">3. Types of Cookies We Use</h2>
        
        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Essential Cookies</h3>
        <p className="text-neutral-300">
          Required for the website to function. These cannot be disabled.
        </p>
        <table className="w-full mt-4 text-sm">
          <thead>
            <tr className="border-b border-neutral-700">
              <th className="text-left py-2 text-neutral-400">Cookie</th>
              <th className="text-left py-2 text-neutral-400">Purpose</th>
              <th className="text-left py-2 text-neutral-400">Duration</th>
            </tr>
          </thead>
          <tbody className="text-neutral-300">
            <tr className="border-b border-neutral-800">
              <td className="py-2 font-mono text-xs">zalt_session</td>
              <td className="py-2">Authentication session</td>
              <td className="py-2">Session</td>
            </tr>
            <tr className="border-b border-neutral-800">
              <td className="py-2 font-mono text-xs">zalt_csrf</td>
              <td className="py-2">CSRF protection</td>
              <td className="py-2">Session</td>
            </tr>
            <tr className="border-b border-neutral-800">
              <td className="py-2 font-mono text-xs">zalt_device</td>
              <td className="py-2">Device fingerprint</td>
              <td className="py-2">1 year</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Functional Cookies</h3>
        <p className="text-neutral-300">
          Remember your preferences and settings.
        </p>
        <table className="w-full mt-4 text-sm">
          <thead>
            <tr className="border-b border-neutral-700">
              <th className="text-left py-2 text-neutral-400">Cookie</th>
              <th className="text-left py-2 text-neutral-400">Purpose</th>
              <th className="text-left py-2 text-neutral-400">Duration</th>
            </tr>
          </thead>
          <tbody className="text-neutral-300">
            <tr className="border-b border-neutral-800">
              <td className="py-2 font-mono text-xs">zalt_theme</td>
              <td className="py-2">Dark/light mode preference</td>
              <td className="py-2">1 year</td>
            </tr>
            <tr className="border-b border-neutral-800">
              <td className="py-2 font-mono text-xs">zalt_locale</td>
              <td className="py-2">Language preference</td>
              <td className="py-2">1 year</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Analytics Cookies</h3>
        <p className="text-neutral-300">
          Help us understand how visitors use our website.
        </p>
        <table className="w-full mt-4 text-sm">
          <thead>
            <tr className="border-b border-neutral-700">
              <th className="text-left py-2 text-neutral-400">Cookie</th>
              <th className="text-left py-2 text-neutral-400">Purpose</th>
              <th className="text-left py-2 text-neutral-400">Duration</th>
            </tr>
          </thead>
          <tbody className="text-neutral-300">
            <tr className="border-b border-neutral-800">
              <td className="py-2 font-mono text-xs">_ga</td>
              <td className="py-2">Google Analytics</td>
              <td className="py-2">2 years</td>
            </tr>
            <tr className="border-b border-neutral-800">
              <td className="py-2 font-mono text-xs">_gid</td>
              <td className="py-2">Google Analytics</td>
              <td className="py-2">24 hours</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="third-party">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">4. Third-Party Cookies</h2>
        <p className="text-neutral-300">
          We use the following third-party services that may set cookies:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li><strong>Google Analytics:</strong> Website analytics</li>
          <li><strong>Intercom:</strong> Customer support chat (if enabled)</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          These third parties have their own privacy policies governing their use of cookies.
        </p>
      </section>

      <section id="managing">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">5. Managing Cookies</h2>
        <p className="text-neutral-300">
          You can control cookies through your browser settings:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li><strong>Chrome:</strong> Settings → Privacy and security → Cookies</li>
          <li><strong>Firefox:</strong> Settings → Privacy & Security → Cookies</li>
          <li><strong>Safari:</strong> Preferences → Privacy → Cookies</li>
          <li><strong>Edge:</strong> Settings → Cookies and site permissions</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          Note: Disabling essential cookies may prevent you from using our services.
        </p>
      </section>

      <section id="contact">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">6. Contact Us</h2>
        <p className="text-neutral-300">
          If you have questions about our use of cookies, please contact us at{' '}
          <a href="mailto:privacy@zalt.io" className="text-emerald-400">privacy@zalt.io</a>.
        </p>
      </section>
    </LegalPageLayout>
  );
}
