"""
Zalt Auth Python SDK - Basic Usage Example

This example demonstrates the basic usage of the Zalt Auth Python SDK.
"""

import asyncio
from zalt_auth import (
    ZaltClient,
    ZaltAsyncClient,
    ZaltConfig,
    LoginCredentials,
    RegisterData,
    MFARequiredError,
    AuthenticationError,
)


def sync_example():
    """Synchronous client example."""
    print("=== Sync Client Example ===\n")
    
    # Initialize client
    client = ZaltClient(ZaltConfig(
        publishable_key="pk_test_12345678901234567890123456789012",
        realm_id="example-realm",
        debug=True,
    ))
    
    print(f"Client initialized (test_mode={client.is_test_mode()})")
    
    # Example: Login (would fail without real API)
    try:
        result = client.login(LoginCredentials(
            email="user@example.com",
            password="SecurePassword123!",
        ))
        print(f"Logged in as: {result.user.email}")
    except MFARequiredError as e:
        print(f"MFA required! Session: {e.mfa_session_id}")
        print(f"Available methods: {e.mfa_methods}")
        
        # Verify MFA
        # mfa_result = client.mfa.verify(code="123456", session_id=e.mfa_session_id)
    except AuthenticationError as e:
        print(f"Auth failed: {e.message}")
    except Exception as e:
        print(f"Error (expected without real API): {type(e).__name__}")
    
    # Cleanup
    client.close()


async def async_example():
    """Asynchronous client example."""
    print("\n=== Async Client Example ===\n")
    
    # Using context manager
    async with ZaltAsyncClient(ZaltConfig(
        publishable_key="pk_test_12345678901234567890123456789012",
        realm_id="example-realm",
        debug=True,
    )) as client:
        print(f"Async client initialized (test_mode={client.is_test_mode()})")
        
        # Example: Register (would fail without real API)
        try:
            result = await client.register(RegisterData(
                email="newuser@example.com",
                password="SecurePassword123!",
            ))
            print(f"Registered: {result.user.email}")
        except Exception as e:
            print(f"Error (expected without real API): {type(e).__name__}")


def mfa_example():
    """MFA operations example."""
    print("\n=== MFA Example ===\n")
    
    client = ZaltClient(ZaltConfig(
        publishable_key="pk_test_12345678901234567890123456789012",
    ))
    
    # Note: These would require authentication first
    print("MFA operations available:")
    print("  - client.mfa.setup(method='totp')")
    print("  - client.mfa.verify(code='123456')")
    print("  - client.mfa.disable(code='123456')")
    print("  - client.mfa.get_status()")
    
    # SMS MFA (with security warning)
    print("\nSMS MFA (requires risk acceptance):")
    print("  - client.sms.setup(phone='+1234567890', accept_risk=True)")
    
    client.close()


if __name__ == "__main__":
    sync_example()
    asyncio.run(async_example())
    mfa_example()
    
    print("\n✅ Examples completed!")
