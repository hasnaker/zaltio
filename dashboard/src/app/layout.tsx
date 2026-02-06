import type { Metadata } from 'next';
import { Inter, Outfit, JetBrains_Mono } from 'next/font/google';
import Script from 'next/script';
import './globals.css';

// Google Analytics Measurement ID
const GA_MEASUREMENT_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID;

const inter = Inter({ 
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const outfit = Outfit({ 
  subsets: ['latin'],
  variable: '--font-outfit',
  display: 'swap',
  weight: ['500', '600', '700', '800'],
});

const jetbrainsMono = JetBrains_Mono({ 
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
  weight: ['400', '500'],
});

export const metadata: Metadata = {
  title: 'Zalt.io - Enterprise Authentication Platform',
  description: 'Secure, scalable authentication for modern applications. HIPAA-compliant, enterprise-grade security with developer-friendly APIs.',
  keywords: ['authentication', 'auth', 'security', 'HIPAA', 'enterprise', 'API', 'SDK'],
  authors: [{ name: 'Zalt.io' }],
  openGraph: {
    title: 'Zalt.io - Enterprise Authentication Platform',
    description: 'Secure, scalable authentication for modern applications.',
    url: 'https://zalt.io',
    siteName: 'Zalt.io',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Zalt.io - Enterprise Authentication Platform',
    description: 'Secure, scalable authentication for modern applications.',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${outfit.variable} ${jetbrainsMono.variable}`}>
      <head>
        {/* Google Analytics 4 */}
        {GA_MEASUREMENT_ID && (
          <>
            <Script
              src={`https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`}
              strategy="afterInteractive"
            />
            <Script id="google-analytics" strategy="afterInteractive">
              {`
                window.dataLayer = window.dataLayer || [];
                function gtag(){dataLayer.push(arguments);}
                gtag('js', new Date());
                gtag('config', '${GA_MEASUREMENT_ID}', {
                  page_path: window.location.pathname,
                  send_page_view: true,
                });
              `}
            </Script>
          </>
        )}
      </head>
      <body className={`${inter.className} antialiased`}>{children}</body>
    </html>
  );
}
