#!/usr/bin/env python3
"""Main scanner orchestration - coordinates all components."""

from datetime import UTC, datetime
from typing import Any

from scanner.crawler import WebCrawler
from scanner.discovery import PassiveDiscovery, normalize_url
from scanner.file_detector import SensitiveFileDetector
from scanner.http_client import SecurityHTTPClient
from scanner.models import (
    DiscoveredResource,
    DiscoverySource,
    ResourceType,
    ScanConfiguration,
    ScanReport,
    ScanStatistics,
    Severity,
    URLInfo,
)
from scanner.reporter import ReportGenerator
from scanner.risk import RiskAssessor
from scanner.scope import create_scan_target
from scanner.secret_detector import SecretDetector


class WebExposureScanner:
    """
    Main scanner orchestrator.

    Coordinates all components to perform comprehensive web exposure scanning.
    """

    def __init__(self, target_url: str, configuration: ScanConfiguration | None = None):
        """
        Initialize the scanner.

        Args:
            target_url: The target URL to scan
            configuration: Scan configuration (uses defaults if not provided)
        """
        # Validate and create target
        self.target = create_scan_target(target_url)

        # Configuration
        self.configuration = configuration or ScanConfiguration()

        # Initialize components
        self.http_client: SecurityHTTPClient | None = None
        self.discovery = PassiveDiscovery(self.target, self.configuration, None)  # Will be set in run
        self.crawler: WebCrawler | None = None
        self.file_detector = SensitiveFileDetector()
        self.secret_detector = SecretDetector()
        self.risk_assessor = RiskAssessor()
        self.reporter = ReportGenerator(self.configuration.output_directory)

        # Statistics
        self.statistics = ScanStatistics(start_time=datetime.now(UTC))

        # Results storage
        self.discovered_resources: list[DiscoveredResource] = []
        self.all_url_infos: list[URLInfo] = []

        # Set during analysis: True if the target serves a catch-all 200 page
        # (soft-404) for nonexistent paths, making bare 200s untrustworthy
        self.catch_all_detected: bool = False

    async def run(self) -> ScanReport:
        """
        Execute the complete scan.

        Returns:
            ScanReport with all findings and data
        """
        print("\n=== Web Exposure Scanner ===")
        print(f"Target: {self.target.base_url}")
        print(f"Configuration: {self.configuration.max_pages} pages, {self.configuration.max_depth} depth")
        print(f"Workers: {self.configuration.workers}, Rate limit: {self.configuration.rate_limit}s")
        print()

        async with SecurityHTTPClient(
            self.configuration,
            self.target.hostname,
            self.target.base_domain,
        ) as http_client:
            self.http_client = http_client

            # Phase 1: Initial passive discovery
            print("[*] Phase 1: Initial passive discovery")
            await self._run_initial_discovery()

            # Phase 2: Recursive crawling (if not passive-only)
            if not self.configuration.passive_only:
                print("[*] Phase 2: Recursive web crawling")
                await self._run_crawling()
            else:
                print("[*] Skipping crawling (passive-only mode)")

            # Phase 3: Check common sensitive paths
            if self.configuration.common_paths_check:
                print("[*] Phase 3: Checking common sensitive paths")
                await self._check_common_paths()

            # Phase 4: Analyze all discovered resources
            print("[*] Phase 4: Analyzing discovered resources")
            await self._analyze_resources()

            # Phase 5: Secret detection on accessible text files
            print("[*] Phase 5: Secret detection")
            await self._detect_secrets()

            # Phase 6: Risk assessment and findings generation
            print("[*] Phase 6: Risk assessment and findings generation")
            await self._generate_findings()

            # Complete statistics
            self.statistics.end_time = datetime.now(UTC)

        # Generate report
        print("[*] Phase 7: Generating reports")
        return await self._generate_report()

    async def _run_initial_discovery(self):
        """Run initial passive discovery from base URL."""
        if not self.http_client:
            return

        discovery = PassiveDiscovery(self.target, self.configuration, self.http_client)
        initial_urls = await discovery.run_initial_discovery()

        self.all_url_infos.extend(initial_urls)
        print(f"    Discovered {len(initial_urls)} URLs from robots.txt, sitemap.xml, and main page")

    async def _run_crawling(self):
        """Run recursive web crawling."""
        if not self.http_client:
            return

        crawler = WebCrawler(self.target, self.configuration, self.http_client)
        crawled_urls = await crawler.crawl()

        self.all_url_infos.extend(crawled_urls)
        print(f"    Crawling discovered {len(crawled_urls)} total URLs")

    async def _check_common_paths(self):
        """Check common sensitive paths."""
        if not self.http_client:
            return

        common_paths = self.file_detector.get_curated_sensitive_paths()
        print(f"    Checking {len(common_paths)} common sensitive paths...")

        from urllib.parse import urljoin

        for path in common_paths[:50]:  # Limit to prevent excessive requests
            full_url = urljoin(self.target.base_url, path)

            url_info = URLInfo(
                url=full_url,
                normalized_url=normalize_url(full_url),
                discovery_source=DiscoverySource.COMMON_PATHS,
                discovery_context=path,
            )

            # Check if already discovered
            if any(u.normalized_url == url_info.normalized_url for u in self.all_url_infos):
                continue

            self.all_url_infos.append(url_info)

        print(f"    Added {len(common_paths)} common paths to check")

    async def _analyze_resources(self):
        """Analyze all discovered resources."""
        if not self.http_client:
            return

        print(f"    Analyzing {len(self.all_url_infos)} URLs...")

        # Calibrate: probe a guaranteed-nonexistent path to detect a catch-all
        # (soft-404) page that returns HTTP 200 for every URL.
        await self._calibrate_catch_all()

        # Fetch URLs in batches
        batch_size = self.configuration.workers * 2
        all_resources = []

        for i in range(0, len(self.all_url_infos), batch_size):
            batch = self.all_url_infos[i:i + batch_size]
            urls_to_fetch = [url_info.url for url_info in batch]

            responses = await self.http_client.fetch_multiple(urls_to_fetch)

            for url_info, response in zip(batch, responses):
                # Analyze the resource
                resource = self.file_detector.analyze_resource(
                    url_info, response, catch_all_detected=self.catch_all_detected
                )
                all_resources.append(resource)

                # Update statistics
                if response and response.status_code == 200:
                    self.statistics.currently_accessible += 1

                    # Categorize
                    file_category = self.discovery.get_file_category(url_info.url)
                    if file_category == "document":
                        self.statistics.documents += 1
                    elif file_category == "image":
                        self.statistics.images += 1
                    elif file_category == "data":
                        self.statistics.data_files += 1

        self.discovered_resources = all_resources
        self.statistics.urls_discovered = len(self.all_url_infos)
        self.statistics.urls_checked = len(all_resources)

        print(f"    Analyzed {len(all_resources)} resources")

    async def _calibrate_catch_all(self):
        """
        Probe a guaranteed-nonexistent random path to detect a catch-all
        (soft-404) page that returns HTTP 200 for every URL.

        Sets self.catch_all_detected so that bare 200 responses for sensitive
        paths can be treated as false positives.
        """
        if not self.http_client:
            return

        import secrets as _secrets
        from urllib.parse import urljoin

        random_path = f"wxs-calibration-{_secrets.token_hex(8)}.txt"
        probe_url = urljoin(self.target.base_url, random_path)

        try:
            response = await self.http_client.fetch_url(probe_url)
        except Exception:
            response = None

        if response and response.status_code == 200:
            self.catch_all_detected = True
            print(
                "    [!] Catch-all/soft-404 page detected (random path returned "
                "HTTP 200); sensitive-path 200s will be treated as false positives"
            )

    async def _detect_secrets(self):
        """Detect secrets in accessible text files."""
        if not self.http_client:
            return

        # Only check smaller text files for secrets (to avoid downloading huge files)
        text_files = [
            resource for resource in self.discovered_resources
            if resource.is_accessible
            and resource.http_response
            and resource.http_response.content_type
            and any(text_type in resource.http_response.content_type.lower()
                   for text_type in ["text/", "application/json", "application/xml", "javascript"])
            and resource.http_response.content_length
            and resource.http_response.content_length < 100000  # < 100KB
        ]

        print(f"    Checking {len(text_files)} text files for secrets...")

        for resource in text_files:
            if resource.http_response and resource.http_response.response_sample:
                content = resource.http_response.response_sample
                analyzed_resource = self.secret_detector.analyze_resource_for_secrets(
                    resource, content
                )

                # Update in the list
                for i, r in enumerate(self.discovered_resources):
                    if r.url_info.normalized_url == resource.url_info.normalized_url:
                        self.discovered_resources[i] = analyzed_resource
                        break

        # Count secrets
        total_secrets = sum(len(r.secrets) for r in self.discovered_resources)
        self.statistics.total_secrets_found = total_secrets

        print(f"    Found {total_secrets} potential secrets")

    async def _generate_findings(self):
        """Generate security findings from resources."""
        findings = []

        for resource in self.discovered_resources:
            # Skip low-risk resources for findings
            if resource.severity in [Severity.INFORMATIONAL]:
                # Still include them in the report, but don't create detailed findings
                continue

            finding = self.risk_assessor.create_finding(resource, self.target)
            findings.append(finding)

            # Update severity counts
            if finding.severity == Severity.CRITICAL:
                self.statistics.critical_count += 1
            elif finding.severity == Severity.HIGH:
                self.statistics.high_count += 1
            elif finding.severity == Severity.MEDIUM:
                self.statistics.medium_count += 1
            elif finding.severity == Severity.LOW:
                self.statistics.low_count += 1
            else:
                self.statistics.info_count += 1

        # Count potentially sensitive files
        self.statistics.potential_sensitive_files = sum(
            1 for r in self.discovered_resources
            if r.resource_type in [ResourceType.POTENTIAL_SENSITIVE_DOCUMENT,
                                   ResourceType.CONFIGURATION_EXPOSURE,
                                   ResourceType.BACKUP_EXPOSURE,
                                   ResourceType.DATABASE_EXPOSURE]
        )

        print(f"    Generated {len(findings)} security findings")

    async def _generate_report(self) -> ScanReport:
        """Generate the final scan report."""
        # Collect findings
        findings = []

        for resource in self.discovered_resources:
            # Create findings for non-trivial resources
            if resource.severity != Severity.INFORMATIONAL:
                finding = self.risk_assessor.create_finding(resource, self.target)
                findings.append(finding)
            else:
                self.statistics.info_count += 1

        # Create the report
        report = ScanReport(
            target=self.target,
            configuration=self.configuration,
            statistics=self.statistics,
            findings=findings,
            all_resources=self.discovered_resources,
        )

        # Generate reports on disk
        generated_reports = self.reporter.generate_all_reports(report)

        print("\n[*] Reports generated:")
        for format_name, file_path in generated_reports.items():
            print(f"    {format_name.upper()}: {file_path}")

        return report

    def get_summary(self) -> dict[str, Any]:
        """Get scan summary."""
        return {
            "target": self.target.base_url,
            "urls_discovered": self.statistics.urls_discovered,
            "urls_checked": self.statistics.urls_checked,
            "currently_accessible": self.statistics.currently_accessible,
            "documents": self.statistics.documents,
            "images": self.statistics.images,
            "data_files": self.statistics.data_files,
            "potential_sensitive_files": self.statistics.potential_sensitive_files,
            "critical": self.statistics.critical_count,
            "high": self.statistics.high_count,
            "medium": self.statistics.medium_count,
            "low": self.statistics.low_count,
            "info": self.statistics.info_count,
            "secrets_found": self.statistics.total_secrets_found,
            "duration_seconds": self.statistics.duration_seconds,
        }


async def scan_target(target_url: str, configuration: ScanConfiguration | None = None) -> ScanReport:
    """
    Convenience function to scan a target.

    Args:
        target_url: The target URL to scan
        configuration: Optional scan configuration

    Returns:
        ScanReport with all findings
    """
    scanner = WebExposureScanner(target_url, configuration)
    return await scanner.run()