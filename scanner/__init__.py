#!/usr/bin/env python3
"""WebExpose Scanner Package."""

from scanner.crawler import WebCrawler
from scanner.discovery import PassiveDiscovery, normalize_url
from scanner.file_detector import SensitiveFileDetector
from scanner.http_client import SecurityHTTPClient
from scanner.models import (
    DiscoveredResource,
    DiscoverySource,
    HTTPResponse,
    ResourceType,
    ScanConfiguration,
    ScanReport,
    ScanStatistics,
    ScanTarget,
    SecretMatch,
    SecretType,
    SecurityFinding,
    Severity,
    URLInfo,
)
from scanner.orchestrator import WebExposureScanner, scan_target
from scanner.reporter import ReportGenerator
from scanner.risk import RiskAssessor
from scanner.scope import (
    RedirectOutOfScopeError,
    ScopeValidationError,
    create_scan_target,
)
from scanner.secret_detector import SecretDetector

__version__ = "1.0.0"
__author__ = "Christos Ploutarchou <cploutarchou@gmail.com>"
__description__ = "WebExpose Scanner - Professional web exposure assessment tool"

__all__ = [
    # Core models
    "Severity", "ResourceType", "DiscoverySource", "SecretType",
    "ScanTarget", "ScanConfiguration", "ScanStatistics",
    "DiscoveredResource", "URLInfo", "HTTPResponse", "SecretMatch",
    "SecurityFinding", "ScanReport",

    # Scope and validation
    "create_scan_target", "ScopeValidationError", "RedirectOutOfScopeError",

    # Main components
    "SecurityHTTPClient", "PassiveDiscovery", "normalize_url", "WebCrawler",
    "SensitiveFileDetector", "SecretDetector", "RiskAssessor", "ReportGenerator",

    # Main scanner
    "WebExposureScanner", "scan_target",
]