"""
Webhook Signature Verification Tests
Validates: Requirement 12.10
"""

import json
import time
import pytest

from zalt_auth.webhooks import (
    verify_webhook_signature,
    parse_signature_header,
    compute_signature,
    safe_compare,
    construct_webhook_event,
    create_test_signature,
    WebhookVerificationError,
    WebhookVerificationErrorCode,
    DEFAULT_TIMESTAMP_TOLERANCE,
)


class TestVerifyWebhookSignature:
    """Tests for verify_webhook_signature function."""
    
    TEST_SECRET = "whsec_test_secret_12345"
    TEST_PAYLOAD = json.dumps({
        "id": "evt_123",
        "type": "user.created",
        "timestamp": "2026-02-02T10:00:00Z",
        "data": {"user_id": "user_123", "email": "test@example.com"}
    })
    
    def test_verify_valid_signature(self):
        """Should verify valid signature."""
        timestamp = int(time.time())
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, timestamp)
        
        result = verify_webhook_signature(self.TEST_PAYLOAD, signature, self.TEST_SECRET)
        assert result is True
    
    def test_verify_signature_with_dict_payload(self):
        """Should verify signature with dict payload."""
        payload = {"id": "evt_123", "type": "user.created", "timestamp": "2026-02-02T10:00:00Z", "data": {}}
        timestamp = int(time.time())
        signature = create_test_signature(payload, self.TEST_SECRET, timestamp)
        
        result = verify_webhook_signature(payload, signature, self.TEST_SECRET)
        assert result is True
    
    def test_verify_signature_with_bytes_payload(self):
        """Should verify signature with bytes payload."""
        payload_bytes = self.TEST_PAYLOAD.encode("utf-8")
        timestamp = int(time.time())
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, timestamp)
        
        result = verify_webhook_signature(payload_bytes, signature, self.TEST_SECRET)
        assert result is True
    
    def test_throw_on_missing_signature(self):
        """Should throw on missing signature."""
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook_signature(self.TEST_PAYLOAD, None, self.TEST_SECRET)
        assert exc_info.value.code == WebhookVerificationErrorCode.MISSING_SIGNATURE
        
        with pytest.raises(WebhookVerificationError):
            verify_webhook_signature(self.TEST_PAYLOAD, "", self.TEST_SECRET)
    
    def test_throw_on_missing_secret(self):
        """Should throw on missing secret."""
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET)
        
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook_signature(self.TEST_PAYLOAD, signature, None)
        assert exc_info.value.code == WebhookVerificationErrorCode.MISSING_SECRET
        
        with pytest.raises(WebhookVerificationError):
            verify_webhook_signature(self.TEST_PAYLOAD, signature, "")
    
    def test_throw_on_invalid_signature(self):
        """Should throw on invalid signature."""
        timestamp = int(time.time())
        invalid_signature = f"t={timestamp},v1=invalid_signature_hex"
        
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook_signature(self.TEST_PAYLOAD, invalid_signature, self.TEST_SECRET)
        assert exc_info.value.code == WebhookVerificationErrorCode.SIGNATURE_MISMATCH
    
    def test_throw_on_tampered_payload(self):
        """Should throw on tampered payload."""
        timestamp = int(time.time())
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, timestamp)
        tampered_payload = self.TEST_PAYLOAD.replace("user_123", "user_456")
        
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook_signature(tampered_payload, signature, self.TEST_SECRET)
        assert exc_info.value.code == WebhookVerificationErrorCode.SIGNATURE_MISMATCH
    
    def test_throw_on_expired_timestamp(self):
        """Should throw on expired timestamp."""
        old_timestamp = int(time.time()) - 600  # 10 minutes ago
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, old_timestamp)
        
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook_signature(self.TEST_PAYLOAD, signature, self.TEST_SECRET)
        assert exc_info.value.code == WebhookVerificationErrorCode.TIMESTAMP_EXPIRED
    
    def test_throw_on_future_timestamp(self):
        """Should throw on future timestamp."""
        future_timestamp = int(time.time()) + 600  # 10 minutes in future
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, future_timestamp)
        
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook_signature(self.TEST_PAYLOAD, signature, self.TEST_SECRET)
        assert exc_info.value.code == WebhookVerificationErrorCode.TIMESTAMP_EXPIRED
    
    def test_allow_custom_timestamp_tolerance(self):
        """Should allow custom timestamp tolerance."""
        old_timestamp = int(time.time()) - 600  # 10 minutes ago
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, old_timestamp)
        
        # Should pass with 15 minute tolerance
        result = verify_webhook_signature(
            self.TEST_PAYLOAD, signature, self.TEST_SECRET,
            timestamp_tolerance=900
        )
        assert result is True
    
    def test_skip_timestamp_validation_when_tolerance_is_zero(self):
        """Should skip timestamp validation when tolerance is 0."""
        very_old_timestamp = int(time.time()) - 86400  # 1 day ago
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, very_old_timestamp)
        
        result = verify_webhook_signature(
            self.TEST_PAYLOAD, signature, self.TEST_SECRET,
            timestamp_tolerance=0
        )
        assert result is True
    
    def test_use_custom_current_timestamp(self):
        """Should use custom current timestamp for testing."""
        timestamp = 1700000000
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, timestamp)
        
        result = verify_webhook_signature(
            self.TEST_PAYLOAD, signature, self.TEST_SECRET,
            current_timestamp=timestamp + 60  # 1 minute later
        )
        assert result is True


class TestParseSignatureHeader:
    """Tests for parse_signature_header function."""
    
    def test_parse_valid_signature_header(self):
        """Should parse valid signature header."""
        header = "t=1700000000,v1=abc123def456"
        parsed = parse_signature_header(header)
        
        assert parsed.timestamp == 1700000000
        assert parsed.signature == "abc123def456"
    
    def test_handle_different_order(self):
        """Should handle different order."""
        header = "v1=abc123def456,t=1700000000"
        parsed = parse_signature_header(header)
        
        assert parsed.timestamp == 1700000000
        assert parsed.signature == "abc123def456"
    
    def test_throw_on_missing_timestamp(self):
        """Should throw on missing timestamp."""
        with pytest.raises(WebhookVerificationError) as exc_info:
            parse_signature_header("v1=abc123")
        assert exc_info.value.code == WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT
    
    def test_throw_on_missing_signature(self):
        """Should throw on missing signature."""
        with pytest.raises(WebhookVerificationError) as exc_info:
            parse_signature_header("t=1700000000")
        assert exc_info.value.code == WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT
    
    def test_throw_on_invalid_format(self):
        """Should throw on invalid format."""
        with pytest.raises(WebhookVerificationError):
            parse_signature_header("invalid")
    
    def test_throw_on_simple_hex_signature(self):
        """Should throw on simple hex signature (wrong format)."""
        hex_signature = "a" * 64
        with pytest.raises(WebhookVerificationError) as exc_info:
            parse_signature_header(hex_signature)
        assert exc_info.value.code == WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT


class TestComputeSignature:
    """Tests for compute_signature function."""
    
    TEST_SECRET = "whsec_test_secret"
    
    def test_compute_consistent_signatures(self):
        """Should compute consistent signatures."""
        payload = "test payload"
        sig1 = compute_signature(payload, self.TEST_SECRET)
        sig2 = compute_signature(payload, self.TEST_SECRET)
        
        assert sig1 == sig2
    
    def test_produce_different_signatures_for_different_payloads(self):
        """Should produce different signatures for different payloads."""
        sig1 = compute_signature("payload1", self.TEST_SECRET)
        sig2 = compute_signature("payload2", self.TEST_SECRET)
        
        assert sig1 != sig2
    
    def test_produce_different_signatures_for_different_secrets(self):
        """Should produce different signatures for different secrets."""
        payload = "test payload"
        sig1 = compute_signature(payload, "secret1")
        sig2 = compute_signature(payload, "secret2")
        
        assert sig1 != sig2
    
    def test_produce_64_character_hex_string(self):
        """Should produce 64-character hex string."""
        sig = compute_signature("test", self.TEST_SECRET)
        
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)


class TestSafeCompare:
    """Tests for safe_compare function."""
    
    def test_return_true_for_equal_strings(self):
        """Should return true for equal strings."""
        hex_str = "abc123def456abc123def456abc123def456abc123def456abc123def456abc123"
        assert safe_compare(hex_str, hex_str) is True
    
    def test_return_false_for_different_strings(self):
        """Should return false for different strings."""
        hex1 = "abc123def456abc123def456abc123def456abc123def456abc123def456abc123"
        hex2 = "abc123def456abc123def456abc123def456abc123def456abc123def456abc124"
        assert safe_compare(hex1, hex2) is False
    
    def test_return_false_for_different_lengths(self):
        """Should return false for different lengths."""
        assert safe_compare("abc123", "abc123def456") is False


class TestConstructWebhookEvent:
    """Tests for construct_webhook_event function."""
    
    def test_parse_valid_webhook_payload(self):
        """Should parse valid webhook payload."""
        payload = {
            "id": "evt_123",
            "type": "user.created",
            "timestamp": "2026-02-02T10:00:00Z",
            "data": {"user_id": "user_123"}
        }
        
        event = construct_webhook_event(payload)
        assert event.id == "evt_123"
        assert event.type == "user.created"
        assert event.data["user_id"] == "user_123"
    
    def test_parse_string_payload(self):
        """Should parse string payload."""
        payload = json.dumps({
            "id": "evt_123",
            "type": "user.created",
            "timestamp": "2026-02-02T10:00:00Z",
            "data": {}
        })
        
        event = construct_webhook_event(payload)
        assert event.id == "evt_123"
    
    def test_parse_bytes_payload(self):
        """Should parse bytes payload."""
        payload = json.dumps({
            "id": "evt_123",
            "type": "user.created",
            "timestamp": "2026-02-02T10:00:00Z",
            "data": {}
        }).encode("utf-8")
        
        event = construct_webhook_event(payload)
        assert event.id == "evt_123"
    
    def test_throw_on_missing_required_fields(self):
        """Should throw on missing required fields."""
        with pytest.raises(WebhookVerificationError):
            construct_webhook_event({"id": "evt_123"})
        
        with pytest.raises(WebhookVerificationError):
            construct_webhook_event({"id": "evt_123", "type": "test"})


class TestCreateTestSignature:
    """Tests for create_test_signature function."""
    
    TEST_SECRET = "whsec_test_secret"
    TEST_PAYLOAD = '{"test": true}'
    
    def test_create_valid_signature(self):
        """Should create valid signature."""
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET)
        
        assert signature.startswith("t=")
        assert ",v1=" in signature
    
    def test_use_provided_timestamp(self):
        """Should use provided timestamp."""
        timestamp = 1700000000
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET, timestamp)
        
        assert f"t={timestamp}" in signature
    
    def test_create_verifiable_signature(self):
        """Should create verifiable signature."""
        signature = create_test_signature(self.TEST_PAYLOAD, self.TEST_SECRET)
        
        result = verify_webhook_signature(self.TEST_PAYLOAD, signature, self.TEST_SECRET)
        assert result is True


class TestDefaultTimestampTolerance:
    """Tests for DEFAULT_TIMESTAMP_TOLERANCE constant."""
    
    def test_is_5_minutes(self):
        """Should be 5 minutes (300 seconds)."""
        assert DEFAULT_TIMESTAMP_TOLERANCE == 300


class TestWebhookVerificationError:
    """Tests for WebhookVerificationError class."""
    
    def test_has_code_property(self):
        """Should have code property."""
        error = WebhookVerificationError(
            WebhookVerificationErrorCode.SIGNATURE_MISMATCH,
            "Test error"
        )
        assert error.code == WebhookVerificationErrorCode.SIGNATURE_MISMATCH
    
    def test_has_message_property(self):
        """Should have message property."""
        error = WebhookVerificationError(
            WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
            "Test error message"
        )
        assert error.message == "Test error message"
        assert str(error) == "Test error message"
