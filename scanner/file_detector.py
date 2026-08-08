#!/usr/bin/env python3
"""Detection of exposed sensitive files."""

import re
from urllib.parse import urlparse

from scanner.models import (
    DiscoveredResource,
    DiscoverySource,
    HTTPResponse,
    ResourceType,
    Severity,
    URLInfo,
)


class SensitiveFileDetector:
    """
    Detects potentially exposed sensitive files.

    Uses:
    1. Discovered URLs from crawling
    2. Historical/index sources
    3. A curated list of common security-sensitive paths
    """

    # Sensitive file patterns
    SENSITIVE_PATTERNS = {
        # Configuration files
        "config": [
            r"\.env$", r"\.env\.", r"\.env\.",
            r"config\.(php|js|json|yaml|yml|xml|ini|conf)$",
            r"configuration\.(php|js|json|yaml|yml|xml|ini|conf)$",
            r"web\.config$", r"app\.config$", r"application\.config$",
            r"settings\.(php|py|js|json|yaml|yml|xml|ini)$",
            r"\.conf$", r"\.config$", r"\.ini$",
        ],
        # Source control
        "source_control": [
            r"\.git/", r"\.gitignore$", r"\.gitattributes$",
            r"\.svn/", r"\.hg/",
            r"\.git/config$", r"\.git/HEAD$",
        ],
        # Database files
        "database": [
            r"\.sql$", r"\.sqlite$", r"\.db$",
            r"\.dump$", r"backup\.(sql|db|sqlite)$",
            r"database\.(sql|db|sqlite)$",
            r"dump\.(sql|txt)$",
        ],
        # Backup files
        "backup": [
            r"\.bak$", r"\.backup$", r"\.old$", r"\.orig$",
            r"\.save$", r"\.tmp$",
            r"backup\.(zip|tar|tar\.gz|tgz|gz|7z|rar)$",
            r"\~$", r"\.swp$", r"\.swo$",
        ],
        # Archive files
        "archive": [
            r"\.zip$", r"\.tar$", r"\.tar\.gz$", r"\.tgz$",
            r"\.gz$", r"\.7z$", r"\.rar$",
        ],
        # Log files
        "logs": [
            r"\.log$", r"\.trace$", r"\.out$", r"\.err$",
            r"error\.log$", r"access\.log$",
            r"debug\.log$", r"apache\.log$", r"nginx\.log$",
        ],
        # Key/credential files
        "credentials": [
            r"id_rsa$", r"id_dsa$", r"id_ecdsa$", r"id_ed25519$",
            r"\.key$", r"\.pem$", r"\.crt$", r"\.cer$",
            r"\.p12$", r"\.pfx$", r"\.keystore$",
            r"\.htpasswd$", r"\.htaccess$", r"\.htusers$",
            r"authorization\.php$", r"auth\.php$",
            r"passwords\.(txt|csv|json|xml)$",
        ],
        # Development files
        "development": [
            r"\.DS_Store$", r"Thumbs\.db$", r"desktop\.ini$",
            r"\.project$", r"\.classpath$", r"\.settings$",
            r"package-lock\.json$", r"yarn\.lock$",
            r"composer\.lock$", r"Gemfile\.lock$",
            r"\.map$", r"\.tsbuildinfo$",
        ],
        # AWS/Cloud specific
        "cloud": [
            r"\.aws/", r"aws/credentials$", r"aws/config$",
            r"credentials$", r"\.aws/credentials$",
        ],
    }

    # Document extensions that might contain sensitive info
    SENSITIVE_DOC_EXTENSIONS = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt",
        ".rtf", ".odt", ".ods", ".ppt", ".pptx",
    }

    # High-sensitivity keywords in filenames
    SENSITIVE_KEYWORDS = {
        "internal", "confidential", "secret", "private",
        "admin", "administrator", "password", "credentials",
        "backup", "database", "config", "settings",
        "deploy", "production", "staging", "dev",
        "test", "testing", "tmp", "temp",
    }

    def __init__(self):
        """Initialize the detector with compiled regex patterns."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        self.compiled_patterns = {}

        for category, patterns in self.SENSITIVE_PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    def classify_file(self, url: str) -> tuple[ResourceType, Severity]:
        """
        Classify a file URL by its sensitivity.

        Returns:
            Tuple of (resource_type, severity)
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        filename = path.rsplit("/", 1)[-1] if "/" in path else path

        # Check each category - check both filename and full path
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(filename) or pattern.search(path):
                    return self._category_to_type_severity(category)

        # Check sensitive document extensions
        for ext in self.SENSITIVE_DOC_EXTENSIONS:
            if filename.endswith(ext):
                # Additional checks for document sensitivity
                if self._has_sensitive_keyword(filename):
                    return (ResourceType.POTENTIAL_SENSITIVE_DOCUMENT, Severity.MEDIUM)
                return (ResourceType.PUBLIC_DOCUMENT, Severity.LOW)

        # Check for images
        image_extensions = {".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp"}
        for ext in image_extensions:
            if filename.endswith(ext):
                return (ResourceType.PUBLIC_IMAGE, Severity.INFORMATIONAL)

        return (ResourceType.PUBLIC_EXPECTED, Severity.INFORMATIONAL)

    def _category_to_type_severity(self, category: str) -> tuple[ResourceType, Severity]:
        """Map pattern category to resource type and severity."""
        mapping = {
            "config": (ResourceType.CONFIGURATION_EXPOSURE, Severity.HIGH),
            "source_control": (ResourceType.SOURCE_CONTROL_EXPOSURE, Severity.CRITICAL),
            "database": (ResourceType.DATABASE_EXPOSURE, Severity.CRITICAL),
            "backup": (ResourceType.BACKUP_EXPOSURE, Severity.HIGH),
            "archive": (ResourceType.BACKUP_EXPOSURE, Severity.MEDIUM),
            "logs": (ResourceType.LOG_EXPOSURE, Severity.MEDIUM),
            "credentials": (ResourceType.CONFIGURATION_EXPOSURE, Severity.CRITICAL),
            "development": (ResourceType.PUBLIC_EXPECTED, Severity.LOW),
            "cloud": (ResourceType.CONFIGURATION_EXPOSURE, Severity.CRITICAL),
        }

        return mapping.get(category, (ResourceType.PUBLIC_EXPECTED, Severity.LOW))

    def _has_sensitive_keyword(self, filename: str) -> bool:
        """Check if filename contains sensitive keywords."""
        filename_lower = filename.lower()
        return any(keyword in filename_lower for keyword in self.SENSITIVE_KEYWORDS)

    def analyze_resource(
        self,
        url_info: URLInfo,
        http_response: HTTPResponse | None = None,
    ) -> DiscoveredResource:
        """
        Analyze a discovered resource for sensitivity.

        Args:
            url_info: The URL information
            http_response: Optional HTTP response for additional analysis

        Returns:
            DiscoveredResource with classification and severity
        """
        # Classify by URL
        resource_type, severity = self.classify_file(url_info.url)

        # Create the resource
        resource = DiscoveredResource(
            url_info=url_info,
            http_response=http_response,
            resource_type=resource_type,
            severity=severity,
            is_accessible=http_response is not None and http_response.status_code == 200,
        )

        # Additional analysis if we have response data
        if http_response:
            # Check if directory listing
            if http_response.is_directory_listing:
                resource.resource_type = ResourceType.DIRECTORY_LISTING
                resource.severity = Severity.MEDIUM
                resource.description = "Directory listing is enabled, exposing all files in this directory"
                resource.evidence = f"Directory listing detected at {url_info.url}"

            # Upgrade severity if critical exposure
            if resource_type in [
                ResourceType.SOURCE_CONTROL_EXPOSURE,
                ResourceType.DATABASE_EXPOSURE,
            ] and resource.is_accessible:
                if severity != Severity.CRITICAL:
                    resource.severity = Severity.CRITICAL

        return resource

    def get_curated_sensitive_paths(self) -> list[str]:
        """
        Get a curated list of common sensitive paths to check.

        Returns:
            List of path strings to check against the target
        """
        return [
            # Configuration
            ".env", ".env.local", ".env.production", ".env.development",
            ".env.backup", ".env.old",
            "config.json", "config.php.bak", "config.py",
            "web.config", "app.config", "application.config",
            "settings.py", "settings.json", "settings.yaml",
            "database.yml", "database.php",

            # Source control
            ".git/config", ".git/HEAD",
            ".svn/entries",
            ".hg/",

            # Database/backups
            "backup.sql", "backup.zip", "backup.tar.gz",
            "database.sql", "db.sql", "dump.sql",
            "backup.db", "backup.sqlite",
            "data.zip", "files.zip",

            # Logs
            "error.log", "access.log", "debug.log",
            "apache.log", "nginx.log", "application.log",

            # Development
            ".DS_Store", "Thumbs.db", "desktop.ini",
            "package.json", "composer.json", "Gemfile",

            # Credentials
            "id_rsa", "id_dsa", ".pem", ".key",
            ".htpasswd", ".htaccess", ".htusers",
            "passwords.txt", "credentials.json",

            # Admin panels
            "admin/", "administrator/", "wp-admin/",
            "phpmyadmin/", "adminer/", "mysql/",
            "console/", "dashboard/", "controlpanel/",

            # Upload directories
            "uploads/", "upload/", "files/", "attachments/",
            "documents/", "docs/", "public/",

            # Development/staging
            "dev/", "development/", "staging/", "testing/",
            "tmp/", "temp/", "temporary/",

            # Common web app paths
            "wp-content/", "wp-includes/", "wp-config.php.bak",
            "server-status", "server-info", "phpinfo.php",

            # Other
            "robots.txt", "sitemap.xml", "humans.txt",
            ".well-known/security.txt", ".well-known/",
        ]

    def analyze_path_exposure(
        self,
        path: str,
        base_url: str,
        http_response: HTTPResponse | None = None,
    ) -> DiscoveredResource | None:
        """
        Analyze a specific path for exposure.

        Args:
            path: Path to check (relative or absolute)
            base_url: Base URL of the target
            http_response: Optional HTTP response

        Returns:
            DiscoveredResource if the path is sensitive, None otherwise
        """
        from urllib.parse import urljoin

        from scanner.discovery import normalize_url

        full_url = urljoin(base_url, path)

        url_info = URLInfo(
            url=full_url,
            normalized_url=normalize_url(full_url),
            discovery_source=DiscoverySource.COMMON_PATHS,
        )

        resource = self.analyze_resource(url_info, http_response)

        # Only return if it's actually sensitive
        if resource.resource_type != ResourceType.PUBLIC_EXPECTED:
            return resource

        return None