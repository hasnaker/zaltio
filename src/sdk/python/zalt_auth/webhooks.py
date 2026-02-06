"""
Webhook Signature Verification for Zalt.io Python SDK

Provides utilities for verifying webhook signatures in your application.
Use this to ensure webhook payloads are authentic and haven't been tampered with.

Security:
- HMAC-SHA256 signatures
- Timing-safe comparison to prevent timing attacks
- Timestamp validation to prevent replay attacks

Validates: Requirement 12.10

Example:
    from zalt_auth.webhooks import verify_webhook_signature, WebhookVerificationError
    
    @app.post("/webhooks/zalt")
    def handle_webhook(request):
        signature = request.headers.get("zalt-signature")
        payload = request.body  # raw body string
        
        try:
            verify_webhook_signature(payload, signature, os.environ["WEBHOOK_SECRET"])
            # Process webhook...
        except WebhookVerificationError as e:
            return {"error": str(e)}, 401
"""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Union


# Default timestamp tolerance in seconds (5 minutes)
DEFAULT_TIMESTAMP_TOLERANCE = 300


class WebhookVerificationErrorCode(str, Enum):
    """Error codes for webhook verification failures."""
    INVALID_SIGNATURE_FORMAT = "INVALID_SIGNATURE_FORMAT"
    SIGNATURE_MISMATCH = "SIGNATURE_MISMATCH"
    TIMESTAMP_EXPIRED = "TIMESTAMP_EXPIRED"
    MISSING_SIGNATURE = "MISSING_SIGNATURE"
    MISSING_SECRET = "MISSING_SECRET"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"


class WebhookVerificationError(Exception):
    """Error thrown when webhook verification fails."""
    
    def __init__(self, code: WebhookVerificationErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ParsedSignature:
    """Parsed webhook signature components."""
    timestamp: int
    signature: str


@dataclass
class WebhookPayload:
    """Webhook payload structure."""
    id: str
    type: str
    timestamp: str
    data: Dict[str, Any]


def verify_webhook_signature(
    payload: Union[str, bytes, Dict[str, Any]],
    signature: Optional[str],
    secret: Optional[str],
    timestamp_tolerance: int = DEFAULT_TIMESTAMP_TOLERANCE,
    current_timestamp: Optional[int] = None,
) -> bool:
    """
    Verify a webhook signature.
    
    Validates that the webhook payload was sent by Zalt.io and hasn't been
    tampered with. Also validates the timestamp to prevent replay attacks.
    
    Args:
        payload: The raw webhook payload (string, bytes, or dict)
        signature: The signature from the 'zalt-signature' header
        secret: Your webhook signing secret (starts with 'whsec_')
        timestamp_tolerance: Maximum age of webhook in seconds (default: 300)
        current_timestamp: Current timestamp for testing (defaults to now)
        
    Returns:
        True if signature is valid
        
    Raises:
        WebhookVerificationError: If verification fails
        
    Example:
        is_valid = verify_webhook_signature(
            request.body,
            request.headers.get("zalt-signature"),
            os.environ["WEBHOOK_SECRET"]
        )
    """
    # Validate inputs
    if not signature:
        raise WebhookVerificationError(
            WebhookVerificationErrorCode.MISSING_SIGNATURE,
            "Missing webhook signature header"
        )
    
    if not secret:
        raise WebhookVerificationError(
            WebhookVerificationErrorCode.MISSING_SECRET,
            "Missing webhook secret"
        )
    
    # Convert payload to string
    if isinstance(payload, bytes):
        payload_string = payload.decode("utf-8")
    elif isinstance(payload, dict):
        payload_string = json.dumps(payload, separators=(",", ":"))
    else:
        payload_string = payload
    
    if not payload_string:
        raise WebhookVerificationError(
            WebhookVerificationErrorCode.INVALID_PAYLOAD,
            "Invalid webhook payload"
        )
    
    # Parse signature header
    parsed = parse_signature_header(signature)
    
    # Validate timestamp
    if current_timestamp is None:
        current_timestamp = int(time.time())
    
    if timestamp_tolerance > 0:
        age = current_timestamp - parsed.timestamp
        if age > timestamp_tolerance:
            raise WebhookVerificationError(
                WebhookVerificationErrorCode.TIMESTAMP_EXPIRED,
                f"Webhook timestamp too old ({age}s > {timestamp_tolerance}s tolerance)"
            )
        if age < -timestamp_tolerance:
            raise WebhookVerificationError(
                WebhookVerificationErrorCode.TIMESTAMP_EXPIRED,
                "Webhook timestamp is in the future"
            )
    
    # Compute expected signature
    signed_payload = f"{parsed.timestamp}.{payload_string}"
    expected_signature = compute_signature(signed_payload, secret)
    
    # Timing-safe comparison
    is_valid = safe_compare(parsed.signature, expected_signature)
    
    if not is_valid:
        raise WebhookVerificationError(
            WebhookVerificationErrorCode.SIGNATURE_MISMATCH,
            "Webhook signature does not match"
        )
    
    return True


def parse_signature_header(header: str) -> ParsedSignature:
    """
    Parse the signature header into components.
    
    Signature format: t=timestamp,v1=signature
    
    Args:
        header: The signature header value
        
    Returns:
        ParsedSignature with timestamp and signature
        
    Raises:
        WebhookVerificationError: If format is invalid
    """
    timestamp: Optional[int] = None
    signature: Optional[str] = None
    
    parts = header.split(",")
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            if key == "t":
                try:
                    timestamp = int(value)
                except ValueError:
                    pass
            elif key == "v1":
                signature = value
    
    # Check for simple hex signature format (wrong format)
    if timestamp is None and signature is None:
        if len(header) == 64 and all(c in "0123456789abcdefABCDEF" for c in header):
            raise WebhookVerificationError(
                WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
                "Invalid signature format. Expected: t=timestamp,v1=signature"
            )
    
    if timestamp is None:
        raise WebhookVerificationError(
            WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
            "Missing or invalid timestamp in signature header"
        )
    
    if signature is None:
        raise WebhookVerificationError(
            WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
            "Missing signature value in signature header"
        )
    
    return ParsedSignature(timestamp=timestamp, signature=signature)


def compute_signature(payload: str, secret: str) -> str:
    """
    Compute HMAC-SHA256 signature.
    
    Args:
        payload: The payload to sign
        secret: The signing secret
        
    Returns:
        Hex-encoded signature
    """
    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def safe_compare(a: str, b: str) -> bool:
    """
    Timing-safe string comparison.
    
    Prevents timing attacks by ensuring comparison takes constant time
    regardless of where strings differ.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal
    """
    return hmac.compare_digest(a, b)


def construct_webhook_event(payload: Union[str, bytes, Dict[str, Any]]) -> WebhookPayload:
    """
    Construct a webhook event from raw payload.
    
    Parses and validates the webhook payload structure.
    
    Args:
        payload: Raw payload string, bytes, or dict
        
    Returns:
        Parsed WebhookPayload
        
    Raises:
        WebhookVerificationError: If payload structure is invalid
    """
    if isinstance(payload, bytes):
        data = json.loads(payload.decode("utf-8"))
    elif isinstance(payload, str):
        data = json.loads(payload)
    else:
        data = payload
    
    required_fields = ["id", "type", "timestamp", "data"]
    for field in required_fields:
        if field not in data:
            raise WebhookVerificationError(
                WebhookVerificationErrorCode.INVALID_PAYLOAD,
                f"Invalid webhook payload structure: missing '{field}'"
            )
    
    return WebhookPayload(
        id=data["id"],
        type=data["type"],
        timestamp=data["timestamp"],
        data=data["data"]
    )


def create_test_signature(
    payload: Union[str, Dict[str, Any]],
    secret: str,
    timestamp: Optional[int] = None,
) -> str:
    """
    Create a signature for testing purposes.
    
    Useful for testing webhook handlers in development.
    
    Args:
        payload: The payload to sign
        secret: The signing secret
        timestamp: Optional timestamp (defaults to current time)
        
    Returns:
        Formatted signature header value
    """
    if timestamp is None:
        timestamp = int(time.time())
    
    if isinstance(payload, dict):
        payload_string = json.dumps(payload, separators=(",", ":"))
    else:
        payload_string = payload
    
    signed_payload = f"{timestamp}.{payload_string}"
    signature = compute_signature(signed_payload, secret)
    
    return f"t={timestamp},v1={signature}"
