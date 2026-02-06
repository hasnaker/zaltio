import { getAuth, currentUser } from '@zalt/next';
import { redirect } from 'next/navigation';
import Link from 'next/link';

export default async function DashboardPage() {
  const { userId } = await getAuth();
  
  if (!userId) {
    redirect('/sign-in');
  }
  
  const user = await currentUser();

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-8">Dashboard</h1>
        
        <div className="grid gap-6 md:grid-cols-2">
          {/* User Info Card */}
          <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow">
            <h2 className="text-xl font-semibold mb-4">Profile</h2>
            <div className="space-y-2">
              <p><span className="text-gray-500">Email:</span> {user?.email}</p>
              <p><span className="text-gray-500">Name:</span> {user?.profile?.firstName} {user?.profile?.lastName}</p>
              <p><span className="text-gray-500">User ID:</span> {userId}</p>
            </div>
          </div>
          
          {/* Security Card */}
          <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow">
            <h2 className="text-xl font-semibold mb-4">Security</h2>
            <div className="space-y-3">
              <Link 
                href="/dashboard/mfa"
                className="block p-3 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg hover:bg-indigo-100"
              >
                <span className="font-medium">Two-Factor Authentication</span>
                <p className="text-sm text-gray-500">Secure your account with 2FA</p>
              </Link>
              <Link 
                href="/dashboard/passkeys"
                className="block p-3 bg-green-50 dark:bg-green-900/20 rounded-lg hover:bg-green-100"
              >
                <span className="font-medium">Passkeys (WebAuthn)</span>
                <p className="text-sm text-gray-500">Login with fingerprint or face</p>
              </Link>
              <Link 
                href="/dashboard/sessions"
                className="block p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg hover:bg-orange-100"
              >
                <span className="font-medium">Active Sessions</span>
                <p className="text-sm text-gray-500">Manage your logged-in devices</p>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
