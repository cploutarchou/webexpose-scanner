#!/usr/bin/env python3
"""
Installation validation script for Web Exposure Scanner.

Tests basic functionality to ensure the scanner is properly installed.
"""

import sys
import asyncio
from scanner import (
    create_scan_target, ScanConfiguration, normalize_url,
    SensitiveFileDetector, SecretDetector, ScopeValidationError
)
from scanner.models import DiscoverySource, URLInfo


def test_imports():
    """Test that all modules can be imported."""
    print("[*] Testing imports...")
    try:
        from scanner import (
            WebExposureScanner, SecurityHTTPClient, PassiveDiscovery,
            WebCrawler, RiskAssessor, ReportGenerator
        )
        print("  [+] All core modules imported successfully")
        return True
    except ImportError as e:
        print(f"  [-] Import failed: {e}")
        return False


def test_scope_validation():
    """Test scope validation."""
    print("[*] Testing scope validation...")
    try:
        # Test valid URL
        target = create_scan_target("https://example.com")
        assert target.hostname == "example.com"
        assert target.scheme == "https"
        print("  [+] Valid target creation works")

        # Test private IP blocking
        try:
            create_scan_target("http://192.168.1.1")
            print("  [-] Private IP should be blocked")
            return False
        except ScopeValidationError:
            print("  [+] Private IPs properly blocked")

        # Test URL normalization
        normalized = normalize_url("https://example.com/../test")
        print(f"  [+] URL normalization works: {normalized}")

        return True
    except Exception as e:
        print(f"  [-] Scope validation failed: {e}")
        return False


def test_file_detection():
    """Test file detection."""
    print("[*] Testing file detection...")
    try:
        detector = SensitiveFileDetector()

        # Test .env detection
        resource_type, severity = detector.classify_file("https://example.com/.env")
        print(f"  [+] .env classified as {resource_type.value} with {severity.value} severity")

        # Test database file detection
        resource_type, severity = detector.classify_file("https://example.com/backup.sql")
        print(f"  [+] backup.sql classified as {resource_type.value} with {severity.value} severity")

        # Test source control detection
        resource_type, severity = detector.classify_file("https://example.com/.git/config")
        print(f"  [+] .git/config classified as {resource_type.value} with {severity.value} severity")

        return True
    except Exception as e:
        print(f"  [-] File detection failed: {e}")
        return False


def test_secret_detection():
    """Test secret detection."""
    print("[*] Testing secret detection...")
    try:
        detector = SecretDetector()

        # Test AWS key detection
        content = 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE'
        secrets = detector.detect_secrets(content, "https://example.com/config")
        if secrets:
            print(f"  [+] AWS key detected and redacted: {secrets[0].redacted_value}")
        else:
            print("  [-] AWS key not detected")
            return False

        # Test secret redaction
        redacted = detector._redact_value("AKIAIOSFODNN7EXAMPLE", secrets[0].secret_type)
        if "AKIA" in redacted and "*" in redacted:
            print(f"  [+] Secret redaction works: {redacted}")
        else:
            print("  [-] Secret redaction failed")
            return False

        return True
    except Exception as e:
        print(f"  [-] Secret detection failed: {e}")
        return False


def test_configuration():
    """Test configuration."""
    print("[*] Testing configuration...")
    try:
        config = ScanConfiguration(
            max_pages=100,
            workers=5,
            timeout=10,
            rate_limit=0.3
        )
        print(f"  [+] Configuration created: {config.max_pages} pages, {config.workers} workers")
        return True
    except Exception as e:
        print(f"  [-] Configuration failed: {e}")
        return False


def test_url_operations():
    """Test URL operations."""
    print("[*] Testing URL operations...")
    try:
        from scanner.discovery import URLDeduplicator

        dedup = URLDeduplicator()

        url1 = URLInfo(
            url="https://example.com/page",
            normalized_url="https://example.com/page",
            discovery_source=DiscoverySource.HTML
        )

        url2 = URLInfo(
            url="https://example.com/page/",  # Trailing slash
            normalized_url="https://example.com/page",  # Should normalize to same
            discovery_source=DiscoverySource.HTML
        )

        # Add both
        dedup.add(url1)
        result1 = dedup.add(url2)

        # Second should not be added (duplicate)
        if not result1:
            print("  [+] URL deduplication works correctly")
            return True
        else:
            print("  [-] URL deduplication failed")
            return False

    except Exception as e:
        print(f"  [-] URL operations failed: {e}")
        return False


def main():
    """Run all validation tests."""
    print("=" * 80)
    print("Web Exposure Scanner - Installation Validation")
    print("=" * 80)
    print()

    tests = [
        ("Imports", test_imports),
        ("Scope Validation", test_scope_validation),
        ("File Detection", test_file_detection),
        ("Secret Detection", test_secret_detection),
        ("Configuration", test_configuration),
        ("URL Operations", test_url_operations),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"[-] Test '{name}' crashed: {e}")
            results.append((name, False))

    # Summary
    print("\n" + "="*80)
    print("VALIDATION SUMMARY")
    print("="*80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status:8} {name}")

    print("="*80)
    print(f"Result: {passed}/{total} tests passed")

    if passed == total:
        print("\nAll validation tests passed! The scanner is ready to use.")
        print("\nExample usage:")
        print("  python main.py audit https://example.com")
        return 0
    else:
        print(f"\n{total - passed} validation test(s) failed.")
        print("Please check the installation and dependencies.")
        return 1


if __name__ == "__main__":
    sys.exit(main())