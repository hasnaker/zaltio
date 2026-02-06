/**
 * useZaltClient Hook
 * @zalt/react
 */

'use client';

import type { ZaltClient } from '@zalt.io/core';
import { useZaltContext } from '../context';

/**
 * Hook to access the raw ZaltClient instance
 * 
 * Use this for advanced use cases where you need direct access to the client.
 * For most cases, prefer useAuth() or useUser().
 * 
 * @example
 * ```tsx
 * import { useZaltClient } from '@zalt/react';
 * 
 * function AdvancedComponent() {
 *   const client = useZaltClient();
 * 
 *   const handleWebAuthn = async () => {
 *     const options = await client.webauthn.getRegistrationOptions();
 *     // ... handle WebAuthn registration
 *   };
 * 
 *   return <button onClick={handleWebAuthn}>Setup Passkey</button>;
 * }
 * ```
 */
export function useZaltClient(): ZaltClient {
  const { client } = useZaltContext();
  return client;
}

export default useZaltClient;
