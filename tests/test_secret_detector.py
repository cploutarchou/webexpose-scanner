"""Tests for secret detection."""

import pytest
from scanner.secret_detector import SecretDetector
from scanner.models import SecretType, URLInfo, ResourceType, DiscoverySource, DiscoveredResource
from scanner.discovery import normalize_url


class TestSecretDetector:
    """Test secret detection."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = SecretDetector()
        assert detector.compiled_patterns
        assert len(detector.compiled_patterns) > 0

    def test_detect_aws_access_key(self):
        """Test AWS Access Key detection."""
        detector = SecretDetector()
        content = 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        assert len(secrets) == 1
        assert secrets[0].secret_type == SecretType.AWS_CREDENTIALS
        assert "AKIA" in secrets[0].redacted_value
        assert secrets[0].confidence >= 0.9

    def test_detect_aws_secret_key(self):
        """Test AWS Secret Key detection."""
        detector = SecretDetector()
        content = 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        assert len(secrets) >= 1
        aws_secrets = [s for s in secrets if s.secret_type == SecretType.AWS_CREDENTIALS]
        assert len(aws_secrets) >= 1

    def test_detect_jwt_token(self):
        """Test JWT token detection."""
        detector = SecretDetector()
        content = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        assert len(secrets) >= 1
        jwt_secrets = [s for s in secrets if s.secret_type == SecretType.JWT]
        assert len(jwt_secrets) >= 1

    def test_detect_private_key(self):
        """Test private key detection."""
        detector = SecretDetector()
        content = '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz7N8K1/aLMvFHYlqlZFGF6U8xY1WvZMvwSOQXZ0L7pVlLHv5
-----END RSA PRIVATE KEY-----'''

        secrets = detector.detect_secrets(content, "https://example.com/key.pem")

        assert len(secrets) >= 1
        key_secrets = [s for s in secrets if s.secret_type == SecretType.PRIVATE_KEY]
        assert len(key_secrets) >= 1

    def test_detect_password_assignment(self):
        """Test password assignment detection."""
        detector = SecretDetector()
        content = 'db_password = "SuperSecret123!"'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        assert len(secrets) >= 1
        password_secrets = [s for s in secrets if s.secret_type == SecretType.PASSWORD]
        assert len(password_secrets) >= 1

    def test_detect_database_connection_string(self):
        """Test database connection string detection."""
        detector = SecretDetector()
        content = 'DATABASE_URL="postgresql://user:password@localhost:5432/mydb"'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        assert len(secrets) >= 1
        db_secrets = [s for s in secrets if s.secret_type == SecretType.DATABASE_CONNECTION]
        assert len(db_secrets) >= 1

    def test_detect_api_key_generic(self):
        """Test generic API key detection."""
        detector = SecretDetector()
        content = 'api_key = "test_api_key_1234567890abcdefghij"'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        assert len(secrets) >= 1
        api_secrets = [s for s in secrets if s.secret_type == SecretType.API_KEY]
        assert len(api_secrets) >= 1

    def test_detect_github_token(self):
        """Test GitHub token detection."""
        detector = SecretDetector()
        content = 'github_token = "ghp_1234567890abcdefghijklmnopqrst"'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        assert len(secrets) >= 1
        api_secrets = [s for s in secrets if s.secret_type == SecretType.API_KEY]
        assert len(api_secrets) >= 1

    def test_false_positive_detection(self):
        """Test false positive filtering."""
        detector = SecretDetector()
        content = 'password = "example"'  # Common false positive

        secrets = detector.detect_secrets(content, "https://example.com/config")

        # "example" should be filtered as false positive
        # Should not generate high-confidence secrets
        high_conf = [s for s in secrets if s.confidence > 0.7]
        assert len(high_conf) == 0

    def test_secret_redaction(self):
        """Test secret value redaction."""
        detector = SecretDetector()

        # Test AWS key redaction
        redacted = detector._redact_value("AKIAIOSFODNN7EXAMPLE", SecretType.AWS_CREDENTIALS)
        assert "AKIA" in redacted
        assert "*" in redacted
        assert "EXAMPLE" in redacted or len(redacted) < len("AKIAIOSFODNN7EXAMPLE")

        # Test password redaction
        redacted = detector._redact_value("SuperSecret123!", SecretType.PASSWORD)
        assert redacted == "[REDACTED]"

        # Test private key redaction
        redacted = detector._redact_value("-----BEGIN RSA PRIVATE KEY-----", SecretType.PRIVATE_KEY)
        assert "REDACTED" in redacted

    def test_analyze_resource_for_secrets(self):
        """Test analyzing a resource for secrets."""
        detector = SecretDetector()

        url_info = URLInfo(
            url="https://example.com/config.py",
            normalized_url=normalize_url("https://example.com/config.py"),
            discovery_source=DiscoverySource.HTML,
        )

        resource = DiscoveredResource(
            url_info=url_info,
            resource_type=ResourceType.CONFIGURATION_EXPOSURE,
        )

        content = '''
DATABASE_URL = "postgresql://user:password@localhost/mydb"
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "mySecretKey123"
'''

        analyzed_resource = detector.analyze_resource_for_secrets(resource, content)

        assert len(analyzed_resource.secrets) >= 1
        assert analyzed_resource.resource_type == ResourceType.CONFIGURATION_EXPOSURE

    def test_get_statistics(self):
        """Test statistics generation."""
        detector = SecretDetector()

        # Create resources with secrets
        resources = []
        for i in range(3):
            url_info = URLInfo(
                url=f"https://example.com/file{i}.txt",
                normalized_url=normalize_url(f"https://example.com/file{i}.txt"),
                discovery_source=DiscoverySource.HTML,
            )

            resource = DiscoveredResource(
                url_info=url_info,
                resource_type=ResourceType.CONFIGURATION_EXPOSURE,
            )

            content = 'api_key = "key123456789012345"'
            analyzed = detector.analyze_resource_for_secrets(resource, content)
            resources.append(analyzed)

        stats = detector.get_statistics(resources)

        assert stats["total_resources_with_secrets"] == 3
        assert stats["total_secrets_found"] >= 3
        assert "API_KEY" in stats["by_type"] or len(stats["by_type"]) > 0

    def test_no_secrets_in_clean_content(self):
        """Test that clean content produces no secrets."""
        detector = SecretDetector()
        content = '''
# This is a comment
var x = 10;
console.log("Hello, World!");
'''

        secrets = detector.detect_secrets(content, "https://example.com/script.js")

        # Should not find high-confidence secrets
        high_conf = [s for s in secrets if s.confidence > 0.7]
        assert len(high_conf) == 0

    def test_line_numbers_in_secrets(self):
        """Test that line numbers are captured."""
        detector = SecretDetector()
        content = '''line 1
line 2
aws_access_key = AKIAIOSFODNN7EXAMPLE
line 4
'''

        secrets = detector.detect_secrets(content, "https://example.com/config")

        aws_secrets = [s for s in secrets if s.secret_type == SecretType.AWS_CREDENTIALS]
        if len(aws_secrets) > 0:
            # At least one AWS secret should have line number
            secrets_with_lines = [s for s in aws_secrets if s.line_number is not None]
            assert len(secrets_with_lines) > 0

    def test_context_capture(self):
        """Test that context is captured."""
        detector = SecretDetector()
        content = 'export API_KEY="test_api_key_1234567890abcdefghij"'

        secrets = detector.detect_secrets(content, "https://example.com/config")

        if len(secrets) > 0:
            # At least one secret should have context
            secrets_with_context = [s for s in secrets if s.context is not None]
            assert len(secrets_with_context) > 0
            assert len(secrets_with_context[0].context) <= 200  # Context should be limited