import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { ZaltProvider } from '@zalt/react';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Zalt Auth Example',
  description: 'Example Next.js app with Zalt authentication',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <ZaltProvider 
          realmId={process.env.NEXT_PUBLIC_ZALT_REALM_ID!}
          appearance={{
            theme: 'auto',
            variables: {
              colorPrimary: '#6366f1',
              borderRadius: '8px',
            },
          }}
        >
          {children}
        </ZaltProvider>
      </body>
    </html>
  );
}
