'use client';

import { SignedIn, SignedOut, UserButton, SignInButton, SignUpButton } from '@zalt/react';
import Link from 'next/link';

export default function Home() {
  return (
    <main className="min-h-screen p-8">
      <nav className="flex justify-between items-center mb-12">
        <h1 className="text-2xl font-bold">Zalt Example</h1>
        <div className="flex gap-4 items-center">
          <SignedIn>
            <Link href="/dashboard" className="text-indigo-600 hover:underline">
              Dashboard
            </Link>
            <UserButton />
          </SignedIn>
          <SignedOut>
            <SignInButton mode="redirect" redirectUrl="/dashboard">
              Sign In
            </SignInButton>
            <SignUpButton mode="redirect" redirectUrl="/onboarding">
              Sign Up
            </SignUpButton>
          </SignedOut>
        </div>
      </nav>

      <div className="max-w-2xl mx-auto text-center">
        <h2 className="text-4xl font-bold mb-4">
          Welcome to Zalt Auth Example
        </h2>
        <p className="text-gray-600 mb-8">
          This example demonstrates Zalt authentication with Next.js including
          login, registration, MFA setup, and WebAuthn passkeys.
        </p>

        <SignedOut>
          <div className="flex gap-4 justify-center">
            <SignInButton className="px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
              Get Started
            </SignInButton>
          </div>
        </SignedOut>

        <SignedIn>
          <Link 
            href="/dashboard"
            className="px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 inline-block"
          >
            Go to Dashboard
          </Link>
        </SignedIn>
      </div>
    </main>
  );
}
