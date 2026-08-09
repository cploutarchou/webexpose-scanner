#!/usr/bin/env python3
"""Data models for web exposure scanning."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse


class Severity(Enum):
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ResourceType(Enum):
    """Types of resources that can be discovered."""
    PUBLIC_EXPECTED = "PUBLIC_EXPECTED"
    PUBLIC_DOCUMENT = "PUBLIC_DOCUMENT"
    PUBLIC_IMAGE = "PUBLIC_IMAGE"
    PUBLIC_DATA = "PUBLIC_DATA"
    POTENTIAL_SENSITIVE_DOCUMENT = "POTENTIAL_SENSITIVE_DOCUMENT"
    CONFIGURATION_EXPOSURE = "CONFIGURATION_EXPOSURE"
    BACKUP_EXPOSURE = "BACKUP_EXPOSURE"
    DATABASE_EXPOSURE = "DATABASE_EXPOSURE"
    LOG_EXPOSURE = "LOG_EXPOSURE"
    SOURCE_CONTROL_EXPOSURE = "SOURCE_CONTROL_EXPOSURE"
    DIRECTORY_LISTING = "DIRECTORY_LISTING"
    HISTORICAL_ONLY = "HISTORICAL_ONLY"
    NOT_ACCESSIBLE = "NOT_ACCESSIBLE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class DiscoverySource(Enum):
    """Sources where URLs are discovered."""
    HTML = "HTML"
    ROBOTS = "ROBOTS"
    SITEMAP = "SITEMAP"
    JAVASCRIPT = "JAVASCRIPT"
    CSS = "CSS"
    SEARCH_ENGINE = "SEARCH_ENGINE"
    COMMON_CRAWL = "COMMON_CRAWL"
    WEB_ARCHIVE = "WEB_ARCHIVE"
    DIRECT_CHECK = "DIRECT_CHECK"
    COMMON_PATHS = "COMMON_PATHS"


class SecretType(Enum):
    """Types of secrets that can be detected."""
    API_KEY = "API_KEY"
    ACCESS_TOKEN = "ACCESS_TOKEN"
    JWT = "JWT"
    PRIVATE_KEY = "PRIVATE_KEY"
    DATABASE_CONNECTION = "DATABASE_CONNECTION"
    PASSWORD = "PASSWORD"
    AWS_CREDENTIALS = "AWS_CREDENTIALS"
    AUTHORIZATION_HEADER = "AUTHORIZATION_HEADER"
    ENCRYPTION_KEY = "ENCRYPTION_KEY"


@dataclass
class SecretMatch:
    """A secret pattern match found in content."""
    secret_type: SecretType
    pattern: str
    redacted_value: str
    line_number: int | None = None
    context: str | None = None
    confidence: float = 0.8  # 0.0 to 1.0


@dataclass
class URLInfo:
    """Information about a discovered URL."""
    url: str
    normalized_url: str
    discovery_source: DiscoverySource
    discovery_context: str | None = None  # Where in the source it was found

    @property
    def domain(self) -> str:
        """Extract domain from URL."""
        return urlparse(self.url).netloc

    @property
    def path(self) -> str:
        """Extract path from URL."""
        return urlparse(self.url).path

    @property
    def extension(self) -> str:
        """Extract file extension from URL."""
        path = self.path
        if "." in path:
            return "." + path.rsplit(".", 1)[-1].lower()
        return ""


@dataclass
class HTTPResponse:
    """HTTP response information."""
    url: str
    final_url: str  # After redirects
    status_code: int
    content_type: str | None = None
    content_length: int | None = None
    last_modified: str | None = None
    etag: str | None = None
    server: str | None = None
    title: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    is_directory_listing: bool = False
    response_sample: str | None = None  # First N bytes for analysis
    error: str | None = None


@dataclass
class DiscoveredResource:
    """A discovered resource with full analysis."""
    url_info: URLInfo
    http_response: HTTPResponse | None = None
    resource_type: ResourceType = ResourceType.PUBLIC_EXPECTED
    severity: Severity = Severity.INFORMATIONAL
    confidence: float = 1.0  # 0.0 to 1.0
    title: str | None = None
    description: str | None = None
    evidence: str | None = None
    is_current: bool = True  # vs historical
    is_accessible: bool = False
    secrets: list[SecretMatch] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def add_secret(self, secret: SecretMatch) -> None:
        """Add a secret match to this resource."""
        self.secrets.append(secret)
        # Upgrade severity if critical secrets found
        if secret.secret_type in [SecretType.PRIVATE_KEY, SecretType.AWS_CREDENTIALS]:
            if self.severity != Severity.CRITICAL:
                self.severity = Severity.CRITICAL


@dataclass
class ScanTarget:
    """The target of a security scan."""
    original_url: str
    scheme: str
    hostname: str
    base_domain: str
    port: int | None = None
    canonical_hostname: str | None = None

    @property
    def base_url(self) -> str:
        """Get the base URL for this target."""
        port_part = f":{self.port}" if self.port and self.port != {"https": 443, "http": 80}.get(self.scheme) else ""
        return f"{self.scheme}://{self.hostname}{port_part}/"

    def is_in_scope(self, url: str, include_subdomains: bool = True) -> bool:
        """Check if a URL is within the authorized scope."""
        parsed = urlparse(url)
        if not parsed.netloc:
            return False

        # Exact match
        if parsed.netloc == self.hostname:
            return True

        # Subdomain handling
        if include_subdomains:
            if parsed.netloc.endswith(f".{self.base_domain}"):
                return True

        return False


@dataclass
class ScanConfiguration:
    """Configuration for a security scan."""
    max_pages: int = 150
    max_depth: int = 3
    workers: int = 5
    timeout: int = 10
    rate_limit: float = 0.3  # seconds between requests
    output_directory: str = "./reports"
    passive_only: bool = False
    active: bool = True
    include_subdomains: bool = False
    user_agent: str = "Mozilla/5.0 (compatible; DeepExposeScan/1.0; authorized-recon)"
    verbose: bool = False
    max_response_size: int = 100 * 1024 * 1024  # 100MB
    max_redirects: int = 5
    retry_count: int = 3
    retry_backoff: float = 1.0
    head_first: bool = True  # Try HEAD before GET
    common_paths_check: bool = True
    search_engine_check: bool = False  # Requires API keys
    archive_check: bool = True
    json_output: bool = True
    markdown_output: bool = True
    text_output: bool = False


@dataclass
class ScanStatistics:
    """Statistics from a security scan."""
    start_time: datetime
    end_time: datetime | None = None

    urls_discovered: int = 0
    urls_checked: int = 0
    currently_accessible: int = 0

    documents: int = 0
    images: int = 0
    data_files: int = 0
    potential_sensitive_files: int = 0

    historical_urls: int = 0
    search_indexed_urls: int = 0

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    total_secrets_found: int = 0

    @property
    def duration_seconds(self) -> float | None:
        """Get scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


@dataclass
class SecurityFinding:
    """A security finding from the scan."""
    resource: DiscoveredResource
    severity: Severity
    title: str
    description: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    cwe: str | None = None  # CWE identifier if applicable
    owasp: str | None = None  # OWASP category if applicable


@dataclass
class ScanReport:
    """Complete scan report."""
    target: ScanTarget
    configuration: ScanConfiguration
    statistics: ScanStatistics
    findings: list[SecurityFinding]
    all_resources: list[DiscoveredResource]

    # Categorized findings for quick access
    critical_findings: list[SecurityFinding] = field(default_factory=list)
    high_findings: list[SecurityFinding] = field(default_factory=list)
    medium_findings: list[SecurityFinding] = field(default_factory=list)
    low_findings: list[SecurityFinding] = field(default_factory=list)
    info_findings: list[SecurityFinding] = field(default_factory=list)

    # Historical data
    search_indexed_resources: list[DiscoveredResource] = field(default_factory=list)
    common_crawl_resources: list[DiscoveredResource] = field(default_factory=list)
    web_archive_resources: list[DiscoveredResource] = field(default_factory=list)

    # Metadata
    scan_version: str = "1.0.1"
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        """Categorize findings by severity."""
        self.critical_findings = [f for f in self.findings if f.severity == Severity.CRITICAL]
        self.high_findings = [f for f in self.findings if f.severity == Severity.HIGH]
        self.medium_findings = [f for f in self.findings if f.severity == Severity.MEDIUM]
        self.low_findings = [f for f in self.findings if f.severity == Severity.LOW]
        self.info_findings = [f for f in self.findings if f.severity == Severity.INFORMATIONAL]