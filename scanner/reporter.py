#!/usr/bin/env python3
"""Report generation for web exposure scans."""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from scanner.models import (
    ScanReport, SecurityFinding, Severity, DiscoveredResource,
    ResourceType, ScanStatistics
)
from scanner.risk import RiskAssessor


class ReportGenerator:
    """Generates comprehensive security reports in multiple formats."""

    def __init__(self, output_directory: str = "./reports"):
        self.output_directory = output_directory
        self.risk_assessor = RiskAssessor()

    def ensure_output_directory(self, domain: str) -> str:
        """Ensure output directory exists for the domain."""
        domain_dir = os.path.join(self.output_directory, domain.replace(":", "_"))
        os.makedirs(domain_dir, exist_ok=True)
        return domain_dir

    def generate_markdown_report(self, report: ScanReport) -> str:
        """
        Generate a comprehensive Markdown report.

        Returns:
            Path to the generated report file
        """
        domain = report.target.hostname
        domain_dir = self.ensure_output_directory(domain)
        report_path = os.path.join(domain_dir, "report.md")

        with open(report_path, "w", encoding="utf-8") as f:
            # Title and metadata
            f.write(f"# Web Exposure Security Assessment\n\n")
            f.write(f"**Target:** {report.target.base_url}\n")
            f.write(f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Scan Version:** {report.scan_version}\n\n")

            # Executive Summary
            self._write_executive_summary(f, report)

            # Target and Scope
            self._write_target_scope(f, report)

            # Scan Configuration
            self._write_scan_configuration(f, report)

            # Key Findings
            self._write_key_findings(f, report)

            # Detailed Findings by Severity
            self._write_severity_findings(f, report)

            # Exposed Resources
            self._write_exposed_resources(f, report)

            # Historical Data
            self._write_historical_data(f, report)

            # Secrets Detected
            self._write_secrets_detected(f, report)

            # Security Headers
            self._write_security_headers(f, report)

            # Evidence
            self._write_evidence(f, report)

            # Recommended Remediation
            self._write_remediation(f, report)

            # Limitations
            self._write_limitations(f, report)

            # Methodology
            self._write_methodology(f, report)

        return report_path

    def _write_executive_summary(self, f, report: ScanReport):
        """Write executive summary section."""
        f.write("## Executive Summary\n\n")
        f.write(f"A web exposure assessment was conducted against **{report.target.base_url}** ")
        f.write(f"on {report.generated_at.strftime('%Y-%m-%d')}. The scan discovered ")
        f.write(f"**{report.statistics.urls_discovered} URLs** and analyzed ")
        f.write(f"**{report.statistics.urls_checked} resources**.\n\n")

        f.write("### Risk Summary\n\n")
        f.write("| Severity | Count |\n")
        f.write("|----------|-------|\n")
        f.write(f"| CRITICAL | {report.statistics.critical_count} |\n")
        f.write(f"| HIGH     | {report.statistics.high_count} |\n")
        f.write(f"| MEDIUM   | {report.statistics.medium_count} |\n")
        f.write(f"| LOW      | {report.statistics.low_count} |\n")
        f.write(f"| INFO     | {report.statistics.info_count} |\n")
        f.write("|----------|-------|\n")
        f.write(f"| **TOTAL** | **{len(report.findings)}** |\n\n")

        if report.statistics.critical_count > 0 or report.statistics.high_count > 0:
            f.write("### ⚠️ Immediate Attention Required\n\n")
            if report.statistics.critical_count > 0:
                f.write(f"- **{report.statistics.critical_count} CRITICAL** findings require immediate remediation\n")
            if report.statistics.high_count > 0:
                f.write(f"- **{report.statistics.high_count} HIGH** findings should be addressed urgently\n")
            f.write("\n")

    def _write_target_scope(self, f, report: ScanReport):
        """Write target and scope section."""
        f.write("## Target\n\n")
        f.write(f"- **Base URL:** {report.target.base_url}\n")
        f.write(f"- **Hostname:** {report.target.hostname}\n")
        f.write(f"- **Scheme:** {report.target.scheme}\n")
        f.write(f"- **Port:** {report.target.port}\n")
        f.write(f"- **Base Domain:** {report.target.base_domain}\n\n")

        f.write("## Scope\n\n")
        f.write(f"- **Include Subdomains:** {'Yes' if report.configuration.include_subdomains else 'No'}\n")
        f.write(f"- **Max Pages:** {report.configuration.max_pages}\n")
        f.write(f"- **Max Depth:** {report.configuration.max_depth}\n")
        f.write(f"- **Rate Limit:** {report.configuration.rate_limit}s between requests\n\n")

    def _write_scan_configuration(self, f, report: ScanReport):
        """Write scan configuration section."""
        f.write("## Scan Configuration\n\n")
        f.write(f"- **Workers:** {report.configuration.workers}\n")
        f.write(f"- **Timeout:** {report.configuration.timeout}s\n")
        f.write(f"- **Retry Count:** {report.configuration.retry_count}\n")
        f.write(f"- **Max Response Size:** {report.configuration.max_response_size / (1024*1024):.1f} MB\n")
        f.write(f"- **HEAD First:** {'Enabled' if report.configuration.head_first else 'Disabled'}\n")
        f.write(f"- **Search Engine Check:** {'Enabled' if report.configuration.search_engine_check else 'Disabled'}\n")
        f.write(f"- **Archive Check:** {'Enabled' if report.configuration.archive_check else 'Disabled'}\n\n")

    def _write_key_findings(self, f, report: ScanReport):
        """Write key findings summary."""
        f.write("## Key Findings\n\n")

        if not report.findings:
            f.write("*No significant findings detected.*\n\n")
            return

        # Critical findings
        critical = report.critical_findings
        if critical:
            f.write("### 🔴 Critical Findings\n\n")
            for finding in critical[:5]:  # Limit to top 5
                f.write(f"#### {finding.title}\n\n")
                f.write(f"**URL:** {finding.resource.url_info.url}\n\n")
                f.write(f"{finding.description}\n\n")
                f.write(f"**Remediation:** {finding.remediation}\n\n")
            if len(critical) > 5:
                f.write(f"*... and {len(critical) - 5} more critical findings*\n\n")

        # High findings
        high = report.high_findings
        if high:
            f.write("### 🟠 High Findings\n\n")
            for finding in high[:5]:  # Limit to top 5
                f.write(f"#### {finding.title}\n\n")
                f.write(f"**URL:** {finding.resource.url_info.url}\n\n")
                f.write(f"{finding.description}\n\n")
            if len(high) > 5:
                f.write(f"*... and {len(high) - 5} more high findings*\n\n")

    def _write_severity_findings(self, f, report: ScanReport):
        """Write detailed findings by severity."""
        f.write("## Detailed Findings\n\n")

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            findings_by_severity = [f for f in report.findings if f.severity == severity]
            if findings_by_severity:
                f.write(f"### {severity.value} Findings ({len(findings_by_severity)})\n\n")
                for finding in findings_by_severity:
                    f.write(f"#### {finding.title}\n\n")
                    f.write(f"**URL:** {finding.resource.url_info.url}\n\n")
                    f.write(f"**Status:** {finding.resource.http_response.status_code if finding.resource.http_response else 'N/A'}\n\n")
                    f.write(f"**Description:**\n\n{finding.description}\n\n")
                    f.write(f"**Evidence:**\n\n```\n{finding.evidence}\n```\n\n")
                    f.write(f"**Risk:** {severity.value}\n\n")
                    f.write(f"**Remediation:**\n\n{finding.remediation}\n\n")
                    f.write("---\n\n")

    def _write_exposed_resources(self, f, report: ScanReport):
        """Write exposed resources summary."""
        f.write("## Currently Exposed Resources\n\n")

        # Categorize resources
        categories = self.risk_assessor.categorize_resources(report.all_resources)

        f.write(f"### Documents ({len(categories['documents'])})\n\n")
        for resource in categories['documents'][:20]:
            f.write(f"- {resource.url_info.url}\n")
        if len(categories['documents']) > 20:
            f.write(f"- ... and {len(categories['documents']) - 20} more\n")
        f.write("\n")

        f.write(f"### Images ({len(categories['images'])})\n\n")
        for resource in categories['images'][:20]:
            f.write(f"- {resource.url_info.url}\n")
        if len(categories['images']) > 20:
            f.write(f"- ... and {len(categories['images']) - 20} more\n")
        f.write("\n")

        f.write(f"### Data Files ({len(categories['data_files'])})\n\n")
        for resource in categories['data_files']:
            f.write(f"- {resource.url_info.url}\n")
        f.write("\n")

        f.write(f"### Configuration Files ({len(categories['configuration_files'])})\n\n")
        for resource in categories['configuration_files']:
            f.write(f"- {resource.url_info.url}\n")
        f.write("\n")

        f.write(f"### Backup Files ({len(categories['backup_files'])})\n\n")
        for resource in categories['backup_files']:
            f.write(f"- {resource.url_info.url}\n")
        f.write("\n")

        f.write(f"### Logs ({len(categories['logs'])})\n\n")
        for resource in categories['logs']:
            f.write(f"- {resource.url_info.url}\n")
        f.write("\n")

        f.write(f"### Directory Listings ({len(categories['directory_listings'])})\n\n")
        for resource in categories['directory_listings']:
            f.write(f"- {resource.url_info.url}\n")
        f.write("\n")

    def _write_historical_data(self, f, report: ScanReport):
        """Write historical data section."""
        f.write("## Historical Data\n\n")

        # Historical URLs
        historical = [r for r in report.all_resources if not r.is_current]
        f.write(f"### Historical URLs No Longer Accessible ({len(historical)})\n\n")
        for resource in historical[:20]:
            f.write(f"- {resource.url_info.url}\n")
        if len(historical) > 20:
            f.write(f"- ... and {len(historical) - 20} more\n")
        f.write("\n")

        # Search indexed
        f.write(f"### Search Engine Indexed Resources ({len(report.search_indexed_resources)})\n\n")
        for resource in report.search_indexed_resources[:20]:
            f.write(f"- {resource.url_info.url}\n")
        if len(report.search_indexed_resources) > 20:
            f.write(f"- ... and {len(report.search_indexed_resources) - 20} more\n")
        f.write("\n")

    def _write_secrets_detected(self, f, report: ScanReport):
        """Write secrets detected section."""
        f.write("## Potential Secrets Detected\n\n")

        resources_with_secrets = [r for r in report.all_resources if r.secrets]
        if not resources_with_secrets:
            f.write("*No secrets detected.*\n\n")
            return

        f.write(f"**{len(resources_with_secrets)}** resources contain potential secrets:\n\n")

        for resource in resources_with_secrets:
            f.write(f"### {resource.url_info.url}\n\n")
            for secret in resource.secrets:
                f.write(f"- **{secret.secret_type.value}:** {secret.redacted_value} ")
                f.write(f"(confidence: {secret.confidence:.0%})\n")
                if secret.line_number:
                    f.write(f"  - Line {secret.line_number}\n")
                if secret.context:
                    f.write(f"  - Context: `{secret.context[:100]}...`\n")
            f.write("\n")

    def _write_security_headers(self, f, report: ScanReport):
        """Write security headers analysis."""
        f.write("## Security Headers Analysis\n\n")
        f.write("*Security headers analysis was performed on all crawled pages.*\n\n")
        f.write("This feature tracks missing security headers but detailed analysis ")
        f.write("should be added in future versions.\n\n")

    def _write_evidence(self, f, report: ScanReport):
        """Write evidence section."""
        f.write("## Evidence\n\n")
        f.write("Detailed evidence for findings is included in each finding above.\n\n")
        f.write("For additional evidence, review the JSON report which contains ")
        f.write("full response data and classification details.\n\n")

    def _write_remediation(self, f, report: ScanReport):
        """Write overall remediation guidance."""
        f.write("## Recommended Remediation\n\n")
        f.write("### Immediate Actions (Critical/High)\n\n")
        f.write("1. Remove or restrict access to all CRITICAL and HIGH severity findings\n")
        f.write("2. Rotate any exposed credentials or API keys\n")
        f.write("3. Review source code and configuration for potential compromises\n")
        f.write("4. Scan exposed databases for sensitive information exposure\n\n")

        f.write("### Follow-up Actions (Medium/Low)\n\n")
        f.write("1. Review and clean up exposed logs\n")
        f.write("2. Implement proper access controls for internal documents\n")
        f.write("3. Disable directory listings where not required\n")
        f.write("4. Review backup storage and retention policies\n\n")

        f.write("### Long-term Improvements\n\n")
        f.write("1. Implement regular security scanning\n")
        f.write("2. Establish secure development practices\n")
        f.write("3. Use environment-specific configuration management\n")
        f.write("4. Implement proper secrets management\n")
        f.write("5. Regular review of public-facing content\n\n")

    def _write_limitations(self, f, report: ScanReport):
        """Write limitations section."""
        f.write("## Limitations\n\n")
        f.write("1. **Scope:** Scan was limited to the authorized target domain\n")
        f.write("2. **Authentication:** No authentication bypass attempts were made\n")
        f.write("3. **Depth:** Crawl limited to configured maximum depth\n")
        f.write("4. **Rate Limiting:** Conservative rate limits were used\n")
        f.write("5. **Content:** Large files were not downloaded in full\n")
        f.write("6. **Search Engines:")
        if report.configuration.search_engine_check:
            f.write(" Search engine checks were enabled\n")
        else:
            f.write(" Search engine checks were disabled (no API keys)\n")
        f.write("7. **Archives:")
        if report.configuration.archive_check:
            f.write(" Archive checks were enabled\n")
        else:
            f.write(" Archive checks were disabled\n")
        f.write("\n")

    def _write_methodology(self, f, report: ScanReport):
        """Write methodology section."""
        f.write("## Methodology\n\n")
        f.write("### Discovery Methods\n\n")
        f.write("1. **HTML Parsing:** Extracted links, scripts, and resources from HTML pages\n")
        f.write("2. **robots.txt:** Analyzed for disallowed paths\n")
        f.write("3. **sitemap.xml:** Processed for listed URLs\n")
        f.write("4. **Recursive Crawling:** Followed same-domain links within depth limits\n")
        f.write("5. **Common Paths:** Checked curated list of sensitive paths\n\n")

        if report.configuration.search_engine_check:
            f.write("6. **Search Engine Indexing:** Queried search engines for indexed content\n")
        if report.configuration.archive_check:
            f.write("7. **Web Archives:** Checked historical archives for past exposures\n")

        f.write("\n### Analysis Methods\n\n")
        f.write("1. **File Classification:** Categorized resources by type and sensitivity\n")
        f.write("2. **Secret Detection:** Pattern matching for potential secrets\n")
        f.write("3. **Risk Assessment:** Evaluated exposure risk based on multiple factors\n")
        f.write("4. **HTTP Analysis:** Examined headers, status codes, and responses\n\n")

        f.write("### Security Controls\n\n")
        f.write("1. **Scope Validation:** Strict enforcement of authorized domain boundaries\n")
        f.write("2. **Rate Limiting:** Configurable delays between requests\n")
        f.write("3. **Redirect Safety:** Validation of all redirect destinations\n")
        f.write("4. **Size Limits:** Maximum response size enforcement\n")
        f.write("5. **Timeout Protection:** Request timeout enforcement\n\n")

    def generate_json_report(self, report: ScanReport) -> str:
        """
        Generate a comprehensive JSON report.

        Returns:
            Path to the generated report file
        """
        domain = report.target.hostname
        domain_dir = self.ensure_output_directory(domain)
        report_path = os.path.join(domain_dir, "report.json")

        # Convert report to serializable dict
        report_dict = self._report_to_dict(report)

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=str)

        return report_path

    def _report_to_dict(self, report: ScanReport) -> Dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "target": {
                "base_url": report.target.base_url,
                "hostname": report.target.hostname,
                "base_domain": report.target.base_domain,
                "scheme": report.target.scheme,
                "port": report.target.port,
            },
            "configuration": {
                "max_pages": report.configuration.max_pages,
                "max_depth": report.configuration.max_depth,
                "workers": report.configuration.workers,
                "timeout": report.configuration.timeout,
                "rate_limit": report.configuration.rate_limit,
                "include_subdomains": report.configuration.include_subdomains,
            },
            "statistics": {
                "start_time": report.statistics.start_time.isoformat(),
                "end_time": report.statistics.end_time.isoformat() if report.statistics.end_time else None,
                "urls_discovered": report.statistics.urls_discovered,
                "urls_checked": report.statistics.urls_checked,
                "currently_accessible": report.statistics.currently_accessible,
                "documents": report.statistics.documents,
                "images": report.statistics.images,
                "data_files": report.statistics.data_files,
                "potential_sensitive_files": report.statistics.potential_sensitive_files,
                "historical_urls": report.statistics.historical_urls,
                "search_indexed_urls": report.statistics.search_indexed_urls,
                "critical_count": report.statistics.critical_count,
                "high_count": report.statistics.high_count,
                "medium_count": report.statistics.medium_count,
                "low_count": report.statistics.low_count,
                "info_count": report.statistics.info_count,
                "total_secrets_found": report.statistics.total_secrets_found,
            },
            "findings": [
                {
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "url": finding.resource.url_info.url,
                    "resource_type": finding.resource.resource_type.value,
                    "is_accessible": finding.resource.is_accessible,
                    "secrets": [
                        {
                            "type": secret.secret_type.value,
                            "redacted_value": secret.redacted_value,
                            "confidence": secret.confidence,
                        }
                        for secret in finding.resource.secrets
                    ],
                }
                for finding in report.findings
            ],
            "scan_version": report.scan_version,
            "generated_at": report.generated_at.isoformat(),
        }

    def generate_text_summary(self, report: ScanReport) -> str:
        """
        Generate a simple text summary.

        Returns:
            Path to the generated file
        """
        domain = report.target.hostname
        domain_dir = self.ensure_output_directory(domain)
        report_path = os.path.join(domain_dir, "urls.txt")

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"Web Exposure Scan - {report.target.base_url}\n")
            f.write(f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"=" * 80 + "\n\n")

            # Write all discovered URLs
            for resource in report.all_resources:
                status = f"[{resource.http_response.status_code}] " if resource.http_response else "[UNKNOWN] "
                f.write(f"{status}{resource.url_info.url}\n")

        return report_path

    def generate_all_reports(self, report: ScanReport) -> Dict[str, str]:
        """
        Generate all report formats.

        Returns:
            Dictionary mapping format names to file paths
        """
        reports = {}

        try:
            if report.configuration.markdown_output:
                reports["markdown"] = self.generate_markdown_report(report)
        except Exception as e:
            print(f"[ERROR] Failed to generate markdown report: {e}")

        try:
            if report.configuration.json_output:
                reports["json"] = self.generate_json_report(report)
        except Exception as e:
            print(f"[ERROR] Failed to generate JSON report: {e}")

        try:
            if report.configuration.text_output:
                reports["text"] = self.generate_text_summary(report)
        except Exception as e:
            print(f"[ERROR] Failed to generate text report: {e}")

        return reports