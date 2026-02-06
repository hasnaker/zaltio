# MFA Setup Implementation Tasks

## Tasks

- [ ] 1. TOTP Implementation
  - [ ] 1.1 Create MFA settings page
    - List current MFA methods
    - Add new method button
  - [ ] 1.2 Create TOTP setup flow
    - Generate secret via `useMFA().setup('totp')`
    - Display QR code
    - Show manual entry code
  - [ ] 1.3 Create verification step
    - 6-digit code input
    - Verify via `useMFA().verify(code)`
  - [ ] 1.4 Display backup codes
    - Show 10 backup codes
    - Download/print option
    - Confirm user saved codes

- [ ] 2. WebAuthn Implementation
  - [ ] 2.1 Check browser support
    ```typescript
    const supported = await client.webauthn.isSupported();
    ```
  - [ ] 2.2 Create passkey registration
    - Name input for passkey
    - Register via `client.webauthn.register()`
  - [ ] 2.3 Create passkey list
    - Show registered passkeys
    - Created date, last used
    - Remove option
  - [ ] 2.4 Add passkey login button
    - `<PasskeyButton />` component

- [ ] 3. MFA Verification Page
  - [ ] 3.1 Create verification form
    - 6-digit code input
    - Auto-submit on 6 digits
  - [ ] 3.2 Add backup code option
    - Toggle to backup code input
    - 8-character code format
  - [ ] 3.3 Add remember device
    - Checkbox for trusted device
    - 30-day trust period

- [ ] 4. Login Flow Integration
  - [ ] 4.1 Handle mfaRequired response
    ```typescript
    const result = await signIn(email, password);
    if (result.mfaRequired) {
      router.push(`/mfa?session=${result.sessionId}`);
    }
    ```
  - [ ] 4.2 Complete MFA verification
    - Verify code
    - Redirect to original destination

- [ ] 5. Testing
  - [ ] 5.1 Test TOTP setup flow
  - [ ] 5.2 Test WebAuthn registration
  - [ ] 5.3 Test MFA verification
  - [ ] 5.4 Test backup codes
  - [ ] 5.5 Test remember device

## Code Examples

### TOTP Setup
```tsx
import { useMFA } from '@zalt/react';

function TOTPSetup() {
  const { setup, verify, isLoading } = useMFA();
  const [qrCode, setQrCode] = useState('');
  
  const handleSetup = async () => {
    const result = await setup('totp');
    setQrCode(result.qrCode);
  };
  
  return (
    <div>
      {qrCode && <img src={qrCode} alt="Scan with authenticator" />}
      <button onClick={handleSetup}>Enable 2FA</button>
    </div>
  );
}
```

### WebAuthn Registration
```tsx
import { useZaltClient } from '@zalt/react';

function PasskeySetup() {
  const client = useZaltClient();
  
  const handleRegister = async () => {
    await client.webauthn.register({ name: 'My Laptop' });
  };
  
  return <button onClick={handleRegister}>Add Passkey</button>;
}
```
