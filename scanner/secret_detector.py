#!/usr/bin/env python3
"""Detection of secrets in exposed files."""

import re
from typing import List, Optional, Pattern, Dict, Any
from enum import Enum

from scanner.models import SecretMatch, SecretType, DiscoveredResource


class SecretDetector:
    """
    Detects potential secrets in file content.

    IMPORTANT: This is defensive pattern matching.
    Does not confirm validity, only identifies potential exposure.
    """

    # Secret patterns with confidence levels
    SECRET_PATTERNS: Dict[SecretType, List[tuple[str, float]]] = {
        SecretType.AWS_CREDENTIALS: [
            # AWS Access Key ID
            (r'AKIA[0-9A-Z]{16}', 0.95),  # AWS Access Key
            # AWS Secret Access Key context
            (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/]{40})', 0.90),
        ],

        SecretType.API_KEY: [
            # Generic API keys
            (r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', 0.70),
            (r'(?i)apikey["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', 0.70),
            # Stripe
            (r'sk_(live|test)_[0-9a-zA-Z]{24,}', 0.95),
            (r'pk_(live|test)_[0-9a-zA-Z]{24,}', 0.95),
            # GitHub
            (r'ghp_[A-Za-z0-9]{36}', 0.95),
            (r'gho_[A-Za-z0-9]{36}', 0.95),
            (r'ghu_[A-Za-z0-9]{36}', 0.95),
            (r'ghs_[A-Za-z0-9]{36}', 0.95),
            (r'ghr_[A-Za-z0-9]{36}', 0.95),
            # Slack
            (r'xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24,}', 0.95),
            # Google
            (r'AIza[0-9A-Za-z\-_]{35}', 0.80),
            # SendGrid
            (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', 0.95),
            # Twilio
            (r'AC[a-z0-9]{32}', 0.90),
        ],

        SecretType.JWT: [
            # JWT tokens
            (r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', 0.85),
        ],

        SecretType.PRIVATE_KEY: [
            # Private key markers
            (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', 0.99),
            (r'-----BEGIN RSA PRIVATE KEY-----', 0.99),
            (r'-----BEGIN EC PRIVATE KEY-----', 0.99),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 0.99),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 0.99),
        ],

        SecretType.PASSWORD: [
            # Password assignments (higher confidence if it's clearly a password field)
            (r'(?i)password["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-@#$%^&*]{8,})', 0.60),
            (r'(?i)passwd["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-@#$%^&*]{8,})', 0.60),
            (r'(?i)pass["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-@#$%^&*]{8,})', 0.50),
            # Database passwords
            (r'(?i)(db|database|mysql|postgres|mongodb)_?password["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,})', 0.75),
        ],

        SecretType.DATABASE_CONNECTION: [
            # Connection strings
            (r'(?i)mongodb://[^\s]+', 0.85),
            (r'(?i)mysql://[^\s]+', 0.85),
            (r'(?i)postgresql://[^\s]+', 0.85),
            (r'(?i)postgres://[^\s]+', 0.85),
            (r'(?i)redis://[^\s]+', 0.85),
            # JDBC strings
            (r'jdbc:[a-z]+://[^\s]+', 0.80),
        ],

        SecretType.AUTHORIZATION_HEADER: [
            # Basic auth
            (r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]+', 0.90),
            # Bearer tokens
            (r'Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]+', 0.85),
            # Other auth headers
            (r'(?i)(x-)?api[_-]?key:\s*[A-Za-z0-9_\-]{20,}', 0.80),
        ],

        SecretType.ENCRYPTION_KEY: [
            # Encryption keys
            (r'(?i)encrypt(ion)?[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', 0.70),
            (r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', 0.70),
            (r'(?i)jwt[_-]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', 0.75),
            # Hex keys
            (r'(?i)key["\']?\s*[:=]\s*["\']?(0x)?[0-9a-f]{32,}', 0.60),
        ],
    }

    # Patterns that commonly produce false positives
    FALSE_POSITIVE_PATTERNS = [
        r'^example$', r'^test$', r'^demo$', r'^sample$', r'^placeholder$',
        r'^xxx+$', r'^yyy+$', r'^zzz+$', r'^aaa+$', r'^bbb+$',
        r'^[0-9]+$',  # Just numbers
        r'^[a-zA-Z]{1,5}$',  # Short common words
        r'<password>', '<username>', '<secret>', '<key>', '<token>',
    ]

    def __init__(self):
        """Initialize the detector with compiled patterns."""
        self._compile_patterns()
        self._compile_false_positives()

    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        self.compiled_patterns = {}
        for secret_type, pattern_list in self.SECRET_PATTERNS.items():
            self.compiled_patterns[secret_type] = [
                (re.compile(pattern, re.IGNORECASE), confidence)
                for pattern, confidence in pattern_list
            ]

    def _compile_false_positives(self):
        """Compile false positive patterns."""
        self.false_positive_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.FALSE_POSITIVE_PATTERNS
        ]

    def _is_false_positive(self, match: str) -> bool:
        """Check if a match is likely a false positive."""
        match = match.strip()
        for pattern in self.false_positive_patterns:
            if pattern.match(match):
                return True
        return False

    def _redact_value(self, value: str, secret_type: SecretType) -> str:
        """
        Redact a secret value for reporting.

        Shows enough to prove the finding but not the full value.
        """
        if not value:
            return "[EMPTY]"

        value = value.strip()

        # For different types, use different redaction strategies
        if secret_type == SecretType.AWS_CREDENTIALS:
            # AKIA... -> AKIA************X7Q2
            if value.startswith("AKIA"):
                if len(value) >= 4:
                    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
            return f"{value[:4]}{'*' * (len(value) - 4)}"

        elif secret_type == SecretType.PRIVATE_KEY:
            return "PRIVATE KEY MATERIAL DETECTED - CONTENT REDACTED"

        elif secret_type == SecretType.JWT:
            return f"{value[:20]}{'*' * 20}...[REDACTED JWT]"

        elif secret_type == SecretType.API_KEY:
            if len(value) > 8:
                return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
            return "****"

        elif secret_type in [SecretType.PASSWORD, SecretType.DATABASE_CONNECTION]:
            return "[REDACTED]"

        else:
            # Generic redaction
            if len(value) > 10:
                return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"
            return "***"

    def detect_secrets(
        self,
        content: str,
        context_url: str,
        max_line_length: int = 1000,
    ) -> List[SecretMatch]:
        """
        Detect secrets in text content.

        Args:
            content: Text content to analyze
            context_url: URL where content was found (for context)
            max_line_length: Maximum line length to process (prevents DoS)

        Returns:
            List of SecretMatch objects
        """
        secrets = []

        # Prevent processing of extremely long lines
        if len(content) > max_line_length * 1000:  # 1000 lines of max length
            return secrets

        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Skip extremely long lines
            if len(line) > max_line_length:
                continue

            for secret_type, patterns in self.compiled_patterns.items():
                for pattern, confidence in patterns:
                    matches = pattern.finditer(line)
                    for match in matches:
                        # Extract the matched value
                        if match.groups():
                            value = match.group(1)
                        else:
                            value = match.group(0)

                        # Check for false positives
                        if self._is_false_positive(value):
                            continue

                        # Only include if it meets minimum confidence
                        if confidence >= 0.5:
                            redacted = self._redact_value(value, secret_type)

                            secret_match = SecretMatch(
                                secret_type=secret_type,
                                pattern=pattern.pattern,
                                redacted_value=redacted,
                                line_number=line_num,
                                context=line.strip()[:200],  # Limit context length
                                confidence=confidence,
                            )
                            secrets.append(secret_match)

        return secrets

    def analyze_resource_for_secrets(
        self,
        resource: DiscoveredResource,
        content: str,
    ) -> DiscoveredResource:
        """
        Analyze a resource for secret exposure.

        Updates the resource with any discovered secrets.
        May upgrade resource severity based on findings.

        Args:
            resource: The resource to analyze
            content: Text content to analyze

        Returns:
            Updated resource with secrets
        """
        if not content:
            return resource

        secrets = self.detect_secrets(content, resource.url_info.url)

        for secret in secrets:
            resource.add_secret(secret)

        return resource

    def get_statistics(self, resources: List[DiscoveredResource]) -> Dict[str, Any]:
        """
        Get statistics about secrets found in resources.

        Args:
            resources: List of analyzed resources

        Returns:
            Dictionary with secret statistics
        """
        stats = {
            "total_resources_with_secrets": 0,
            "total_secrets_found": 0,
            "by_type": {},
            "by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
        }

        for resource in resources:
            if resource.secrets:
                stats["total_resources_with_secrets"] += 1
                stats["total_secrets_found"] += len(resource.secrets)

                for secret in resource.secrets:
                    secret_type = secret.secret_type.value
                    stats["by_type"][secret_type] = stats["by_type"].get(secret_type, 0) + 1

        return stats