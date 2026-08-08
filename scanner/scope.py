#!/usr/bin/env python3
"""Target scope validation and normalization."""

import ipaddress
import re
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

from scanner.models import ScanTarget


class ScopeValidationError(Exception):
    """Raised when target validation fails."""


class RedirectOutOfScopeError(Exception):
    """Raised when a redirect would take us outside authorized scope."""


# Internal/private IP ranges that should never be scanned without explicit authorization
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback
    ipaddress.ip_network("10.0.0.0/8"),      # Private network
    ipaddress.ip_network("172.16.0.0/12"),  # Private network
    ipaddress.ip_network("192.168.0.0/16"), # Private network
    ipaddress.ip_network("169.254.0.0/16"), # Link-local
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 private
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
    ipaddress.ip_network("fd00::/8"),       # IPv6 unique local
]

AWS_METADATA_IP = "169.254.169.254"
GCP_METADATA_IP = "metadata.google.internal"
AZURE_METADATA_IP = "169.254.169.254"


def normalize_url(url: str) -> Tuple[str, str, str, Optional[int], str]:
    """
    Normalize and validate a target URL.

    Returns:
        Tuple of (scheme, hostname, base_domain, port, normalized_url)

    Raises:
        ScopeValidationError: If the URL is invalid or unauthorized
    """
    if not url or not isinstance(url, str):
        raise ScopeValidationError("URL must be a non-empty string")

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ScopeValidationError(f"Invalid URL format: {e}")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ScopeValidationError(f"Unsupported scheme: {scheme}. Only http and https are supported")

    hostname = parsed.hostname
    if not hostname:
        raise ScopeValidationError("No hostname found in URL")

    # Validate hostname is not an IP address in private ranges
    validate_hostname_not_private(hostname)

    # Determine port
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80

    # Extract base domain (for subdomain handling)
    base_domain = extract_base_domain(hostname)

    # Rebuild normalized URL
    normalized_parts = (scheme, hostname, "", "", "", "")
    normalized_url = urlunparse(normalized_parts)

    return scheme, hostname, base_domain, port, normalized_url


def extract_base_domain(hostname: str) -> str:
    """
    Extract the base domain from a hostname.

    Examples:
        "www.example.com" -> "example.com"
        "api.sub.example.co.uk" -> "example.co.uk"
        "example.com" -> "example.com"
    """
    parts = hostname.split(".")

    # Handle common TLD patterns
    if len(parts) <= 2:
        return hostname

    # Known multi-part TLDs (simplified list - can be expanded)
    multi_part_tlds = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "nhs.uk",
        "co.jp", "ac.jp", "go.jp", "ne.jp",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "org.nz", "ac.nz", "govt.nz",
        "co.in", "ac.in", "gov.in", "nic.in",
    }

    # Check if the last two parts form a known multi-part TLD
    tld_candidate = ".".join(parts[-2:])
    if tld_candidate in multi_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])

    # Default: return last two parts
    return ".".join(parts[-2:])


def validate_hostname_not_private(hostname: str) -> None:
    """
    Ensure hostname is not a private/internal address.

    Raises:
        ScopeValidationError: If hostname is in a private range
    """
    # Check for common metadata service hostnames
    if hostname in (GCP_METADATA_IP,):
        raise ScopeValidationError(f"Cannot scan cloud metadata service: {hostname}")

    # Check if it's an IP address
    try:
        addr = ipaddress.ip_address(hostname)
        # Check against private ranges
        for private_range in PRIVATE_IP_RANGES:
            if addr in private_range:
                raise ScopeValidationError(
                    f"Cannot scan private IP address: {hostname}. "
                    "Only public IPs are allowed for safety."
                )
    except ValueError:
        # Not an IP address, continue
        pass


def is_safe_redirect(url: str, authorized_hostname: str, authorized_base_domain: str) -> bool:
    """
    Check if a redirect destination is safe (within authorized scope).

    Args:
        url: The redirect destination URL
        authorized_hostname: The original authorized hostname
        authorized_base_domain: The base domain for subdomain checks

    Returns:
        True if redirect is safe, False otherwise

    Raises:
        RedirectOutOfScopeError: If redirect goes to unsafe location
    """
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return False

        redirect_host = parsed.hostname

        # Check against private IPs
        try:
            addr = ipaddress.ip_address(redirect_host)
            for private_range in PRIVATE_IP_RANGES:
                if addr in private_range:
                    raise RedirectOutOfScopeError(
                        f"Redirect to private IP blocked: {redirect_host}"
                    )

            # Check for AWS metadata IP
            if str(addr) == AWS_METADATA_IP:
                raise RedirectOutOfScopeError(
                    f"Redirect to cloud metadata service blocked: {redirect_host}"
                )

        except ValueError:
            # Not an IP address, continue below
            pass

        # Check if redirect is to same host or subdomain
        if redirect_host == authorized_hostname:
            return True

        if redirect_host.endswith(f".{authorized_base_domain}"):
            return True

        # Redirect to different domain
        raise RedirectOutOfScopeError(
            f"Redirect to unauthorized domain blocked: {redirect_host} "
            f"(authorized: {authorized_hostname})"
        )

    except RedirectOutOfScopeError:
        raise
    except Exception as e:
        raise RedirectOutOfScopeError(f"Failed to validate redirect: {e}")


def create_scan_target(url: str) -> ScanTarget:
    """
    Create a validated ScanTarget from a URL.

    Args:
        url: The target URL

    Returns:
        A validated ScanTarget object

    Raises:
        ScopeValidationError: If the URL is invalid
    """
    scheme, hostname, base_domain, port, normalized_url = normalize_url(url)

    return ScanTarget(
        original_url=url,
        scheme=scheme,
        hostname=hostname,
        base_domain=base_domain,
        port=port,
        canonical_hostname=hostname,
    )


def is_safe_url(url: str) -> bool:
    """
    Basic safety check for a URL to prevent obvious SSRF targets.

    Returns:
        True if URL appears safe for scanning, False if suspicious
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False

        # Check for localhost variants
        localhost_patterns = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
        if hostname.lower() in localhost_patterns:
            return False

        # Check for private IP ranges
        try:
            addr = ipaddress.ip_address(hostname)
            for private_range in PRIVATE_IP_RANGES:
                if addr in private_range:
                    return False
        except ValueError:
            pass

        # Check for cloud metadata
        if hostname in (AWS_METADATA_IP, GCP_METADATA_IP, AZURE_METADATA_IP):
            return False

        return True

    except Exception:
        return False


def validate_file_path_for_scanning(path: str) -> bool:
    """
    Validate that a file path is safe to check.

    This prevents scanning obviously dangerous paths like ../../../etc/passwd.
    """
    # Check for path traversal attempts
    if "../" in path or "..\\" in path:
        return False

    # Check for absolute file system paths
    if path.startswith(("/", "\\")) or (len(path) > 1 and path[1] == ":"):
        return False

    # Check for common system files that should never be accessed
    dangerous_patterns = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "\\windows\\system32\\", "c:\\windows\\",
    ]
    path_lower = path.lower()
    for pattern in dangerous_patterns:
        if pattern in path_lower:
            return False

    return True