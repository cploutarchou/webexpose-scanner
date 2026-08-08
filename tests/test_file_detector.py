"""Tests for file detection and classification."""

import pytest
from scanner.file_detector import SensitiveFileDetector
from scanner.models import ResourceType, Severity, DiscoverySource, URLInfo
from scanner.discovery import normalize_url


class TestSensitiveFileDetector:
    """Test sensitive file detection."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = SensitiveFileDetector()
        assert detector.compiled_patterns
        assert len(detector.compiled_patterns) > 0

    def test_classify_env_file(self):
        """Test .env file classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/.env")

        assert resource_type == ResourceType.CONFIGURATION_EXPOSURE
        assert severity == Severity.HIGH

    def test_classify_git_config(self):
        """Test .git/config file classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/.git/config")

        assert resource_type == ResourceType.SOURCE_CONTROL_EXPOSURE
        assert severity == Severity.CRITICAL

    def test_classify_database_file(self):
        """Test database file classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/backup.sql")

        assert resource_type == ResourceType.DATABASE_EXPOSURE
        assert severity == Severity.CRITICAL

    def test_classify_backup_file(self):
        """Test backup file classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/config.php.bak")

        assert resource_type == ResourceType.BACKUP_EXPOSURE
        assert severity == Severity.HIGH

    def test_classify_log_file(self):
        """Test log file classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/error.log")

        assert resource_type == ResourceType.LOG_EXPOSURE
        assert severity == Severity.MEDIUM

    def test_classify_pdf_document(self):
        """Test PDF document classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/document.pdf")

        assert resource_type == ResourceType.PUBLIC_DOCUMENT
        assert severity == Severity.LOW

    def test_classify_sensitive_document(self):
        """Test sensitive document classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/internal-document.pdf")

        # Should be classified as potentially sensitive due to "internal" keyword
        assert resource_type == ResourceType.POTENTIAL_SENSITIVE_DOCUMENT
        assert severity == Severity.MEDIUM

    def test_classify_image(self):
        """Test image file classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/image.jpg")

        assert resource_type == ResourceType.PUBLIC_IMAGE
        assert severity == Severity.INFORMATIONAL

    def test_classify_public_page(self):
        """Test public page classification."""
        detector = SensitiveFileDetector()
        resource_type, severity = detector.classify_file("https://example.com/page.html")

        assert resource_type == ResourceType.PUBLIC_EXPECTED
        assert severity == Severity.INFORMATIONAL

    def test_get_curated_sensitive_paths(self):
        """Test curated sensitive paths list."""
        detector = SensitiveFileDetector()
        paths = detector.get_curated_sensitive_paths()

        assert len(paths) > 0
        assert ".env" in paths
        assert ".git/config" in paths
        assert "backup.sql" in paths
        assert "error.log" in paths

    def test_analyze_resource_basic(self):
        """Test basic resource analysis."""
        detector = SensitiveFileDetector()

        url_info = URLInfo(
            url="https://example.com/.env",
            normalized_url=normalize_url("https://example.com/.env"),
            discovery_source=DiscoverySource.COMMON_PATHS,
        )

        resource = detector.analyze_resource(url_info)

        assert resource.url_info == url_info
        assert resource.resource_type == ResourceType.CONFIGURATION_EXPOSURE
        assert resource.severity == Severity.HIGH
        assert resource.is_accessible == False  # No HTTP response provided

    def test_analyze_resource_with_http_response(self):
        """Test resource analysis with HTTP response."""
        from scanner.models import HTTPResponse

        detector = SensitiveFileDetector()

        url_info = URLInfo(
            url="https://example.com/.env",
            normalized_url=normalize_url("https://example.com/.env"),
            discovery_source=DiscoverySource.COMMON_PATHS,
        )

        http_response = HTTPResponse(
            url="https://example.com/.env",
            final_url="https://example.com/.env",
            status_code=200,
            content_type="text/plain",
            is_directory_listing=False,
        )

        resource = detector.analyze_resource(url_info, http_response)

        assert resource.is_accessible == True
        assert resource.resource_type == ResourceType.CONFIGURATION_EXPOSURE
        assert resource.severity == Severity.HIGH

    def test_analyze_directory_listing(self):
        """Test directory listing detection."""
        from scanner.models import HTTPResponse

        detector = SensitiveFileDetector()

        url_info = URLInfo(
            url="https://example.com/files/",
            normalized_url=normalize_url("https://example.com/files/"),
            discovery_source=DiscoverySource.HTML,
        )

        http_response = HTTPResponse(
            url="https://example.com/files/",
            final_url="https://example.com/files/",
            status_code=200,
            content_type="text/html",
            is_directory_listing=True,
        )

        resource = detector.analyze_resource(url_info, http_response)

        assert resource.resource_type == ResourceType.DIRECTORY_LISTING
        assert resource.severity == Severity.MEDIUM

    def test_analyze_path_exposure_sensitive(self):
        """Test path exposure analysis for sensitive paths."""
        from scanner.models import HTTPResponse

        detector = SensitiveFileDetector()

        http_response = HTTPResponse(
            url="https://example.com/.env",
            final_url="https://example.com/.env",
            status_code=200,
            content_type="text/plain",
        )

        resource = detector.analyze_path_exposure(".env", "https://example.com/", http_response)

        assert resource is not None
        assert resource.resource_type == ResourceType.CONFIGURATION_EXPOSURE
        assert resource.url_info.discovery_source == DiscoverySource.COMMON_PATHS

    def test_analyze_path_exposure_public(self):
        """Test path exposure analysis for public paths."""
        from scanner.models import HTTPResponse

        detector = SensitiveFileDetector()

        http_response = HTTPResponse(
            url="https://example.com/page.html",
            final_url="https://example.com/page.html",
            status_code=200,
            content_type="text/html",
        )

        resource = detector.analyze_path_exposure("page.html", "https://example.com/", http_response)

        # Public page should return None (not sensitive)
        assert resource is None