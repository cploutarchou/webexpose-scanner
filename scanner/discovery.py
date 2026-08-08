#!/usr/bin/env python3
"""Passive discovery of URLs and resources."""

import re
from typing import List, Set, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from scanner.models import URLInfo, DiscoverySource, ScanTarget, ScanConfiguration
from scanner.http_client import SecurityHTTPClient


class URLDeduplicator:
    """Deduplicate URLs while preserving discovery context."""

    def __init__(self):
        self.seen_urls: Dict[str, URLInfo] = {}
        self.normalized_urls: Set[str] = set()

    def add(self, url_info: URLInfo) -> bool:
        """
        Add a URL to the deduplicator.

        Returns:
            True if URL is new, False if already seen
        """
        # Check by normalized URL
        if url_info.normalized_url in self.normalized_urls:
            return False

        self.seen_urls[url_info.normalized_url] = url_info
        self.normalized_urls.add(url_info.normalized_url)
        return True

    def get_all(self) -> List[URLInfo]:
        """Get all unique URLs."""
        return list(self.seen_urls.values())

    def get_normalized_set(self) -> Set[str]:
        """Get set of all normalized URLs."""
        return self.normalized_urls.copy()


def normalize_url(url: str) -> str:
    """
    Normalize a URL for deduplication.

    - Lowercase scheme and hostname
    - Remove fragment
    - Remove trailing slash (except for root)
    """
    try:
        parsed = urlparse(url)

        # Lowercase scheme and netloc
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Remove fragment
        fragment = ""

        # Remove trailing slash except for root
        path = parsed.path
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        # Rebuild
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"

        return normalized

    except Exception:
        return url.lower()


class PassiveDiscovery:
    """
    Passive discovery of URLs through legitimate reconnaissance.

    Discovers resources from:
    - HTML pages (links, scripts, styles, images, etc.)
    - robots.txt
    - sitemap.xml
    - JavaScript files
    - CSS files
    """

    # File extensions to categorize
    DOCUMENT_EXTENSIONS = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx",
        ".txt", ".rtf", ".odt", ".ods", ".ps", ".eps",
    }

    DATA_EXTENSIONS = {
        ".json", ".xml", ".yaml", ".yml", ".ini", ".conf", ".config",
        ".sql", ".db", ".sqlite", ".dump",
    }

    ARCHIVE_EXTENSIONS = {
        ".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".7z", ".rar",
        ".bak", ".backup", ".old", ".orig",
    }

    IMAGE_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
        ".tiff", ".ico", ".png", ".psd", ".ai",
    }

    LOG_EXTENSIONS = {".log", ".trace", ".out", ".err"}

    # Extensions for pages to crawl (not files to download)
    PAGE_EXTENSIONS = {"", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jsf"}

    def __init__(
        self,
        target: ScanTarget,
        configuration: ScanConfiguration,
        http_client: SecurityHTTPClient,
    ):
        self.target = target
        self.config = configuration
        self.http_client = http_client
        self.deduplicator = URLDeduplicator()

    async def discover_from_html(self, html_content: str, base_url: str) -> List[URLInfo]:
        """
        Extract URLs from HTML content.

        Extracts from:
        - <a href>
        - <img src>
        - <script src>
        - <link href>
        - <iframe src>
        - <embed src>
        - <source src>
        """
        urls = []

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Tag and attribute combinations to extract
            tag_attrs = [
                ("a", "href"),
                ("img", "src"),
                ("script", "src"),
                ("link", "href"),
                ("iframe", "src"),
                ("embed", "src"),
                ("source", "src"),
                ("video", "src"),
                ("audio", "src"),
                ("track", "src"),
                ("object", "data"),
            ]

            for tag, attr in tag_attrs:
                for element in soup.find_all(tag):
                    href = element.get(attr)
                    if href and self._is_valid_link(href):
                        absolute_url = urljoin(base_url, href)
                        if self.target.is_in_scope(absolute_url, self.config.include_subdomains):
                            url_info = URLInfo(
                                url=absolute_url,
                                normalized_url=normalize_url(absolute_url),
                                discovery_source=DiscoverySource.HTML,
                                discovery_context=f"{tag}.{attr}",
                            )
                            urls.append(url_info)

        except Exception as e:
            if self.config.verbose:
                print(f"[ERROR] Failed to parse HTML: {e}")

        return urls

    async def discover_from_robots_txt(self) -> List[URLInfo]:
        """
        Discover URLs from robots.txt.

        Some sites list disallowed paths which can reveal sensitive directories.
        """
        urls = []
        robots_url = urljoin(self.target.base_url, "robots.txt")

        try:
            response = await self.http_client.fetch_url(robots_url)
            if not response or response.status_code != 200:
                return urls

            if response.response_sample:
                content = response.response_sample
                # Extract paths from robots.txt
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith(("Disallow:", "Allow:", "Sitemap:")):
                        # Extract the path value
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and path != "/":
                                absolute_url = urljoin(self.target.base_url, path)
                                if self.target.is_in_scope(absolute_url, self.config.include_subdomains):
                                    url_info = URLInfo(
                                        url=absolute_url,
                                        normalized_url=normalize_url(absolute_url),
                                        discovery_source=DiscoverySource.ROBOTS,
                                    )
                                    urls.append(url_info)

        except Exception as e:
            if self.config.verbose:
                print(f"[ERROR] Failed to fetch robots.txt: {e}")

        return urls

    async def discover_from_sitemap(self) -> List[URLInfo]:
        """
        Discover URLs from sitemap.xml.

        Handles both regular sitemaps and sitemap indexes.
        """
        urls = []
        sitemap_url = urljoin(self.target.base_url, "sitemap.xml")

        try:
            response = await self.http_client.fetch_url(sitemap_url)
            if not response or response.status_code != 200:
                return urls

            if response.response_sample:
                content = response.response_sample
                soup = BeautifulSoup(content, "html.parser")

                # Extract all <loc> URLs
                for loc in soup.find_all("loc"):
                    url_text = loc.text.strip()
                    if url_text and self.target.is_in_scope(url_text, self.config.include_subdomains):
                        url_info = URLInfo(
                            url=url_text,
                            normalized_url=normalize_url(url_text),
                            discovery_source=DiscoverySource.SITEMAP,
                        )
                        urls.append(url_info)

                # Check for sitemap index (references to other sitemaps)
                for sitemap in soup.find_all("sitemap"):
                    loc = sitemap.find("loc")
                    if loc:
                        # Could recursively fetch child sitemaps here
                        # For now, just record the sitemap URL
                        sitemap_url = loc.text.strip()
                        if self.target.is_in_scope(sitemap_url, self.config.include_subdomains):
                            url_info = URLInfo(
                                url=sitemap_url,
                                normalized_url=normalize_url(sitemap_url),
                                discovery_source=DiscoverySource.SITEMAP,
                                discovery_context="sitemap_index",
                            )
                            urls.append(url_info)

        except Exception as e:
            if self.config.verbose:
                print(f"[ERROR] Failed to fetch sitemap.xml: {e}")

        return urls

    async def discover_from_javascript(self, js_content: str, base_url: str) -> List[URLInfo]:
        """
        Extract URLs from JavaScript content.

        Looks for:
        - String literals that look like URLs
        - API endpoint definitions
        - Resource references
        """
        urls = []

        # Pattern for URLs in JavaScript
        url_patterns = [
            r'["\']https?://[^"\']+["\']',  # URLs in quotes
            r'["\'][/][^"\']+["\']',  # Relative paths in quotes
            r'url\(["\']?([^"\'")]+)["\']?\)',  # CSS url() patterns
        ]

        for pattern in url_patterns:
            matches = re.finditer(pattern, js_content)
            for match in matches:
                url_candidate = match.group(0).strip('\'"()')
                if self._is_valid_link(url_candidate):
                    absolute_url = urljoin(base_url, url_candidate)
                    if self.target.is_in_scope(absolute_url, self.config.include_subdomains):
                        url_info = URLInfo(
                            url=absolute_url,
                            normalized_url=normalize_url(absolute_url),
                            discovery_source=DiscoverySource.JAVASCRIPT,
                        )
                        urls.append(url_info)

        return urls

    async def discover_from_css(self, css_content: str, base_url: str) -> List[URLInfo]:
        """
        Extract URLs from CSS content.

        Looks for:
        - url() references
        - @import statements
        """
        urls = []

        # Pattern for URLs in CSS
        patterns = [
            r'url\(["\']?([^"\'())]+)["\']?\)',  # url() references
            r'@import\s+["\']?([^"\'())]+)["\']?',  # @import statements
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, css_content)
            for match in matches:
                url_candidate = match.group(1)
                if url_candidate and not url_candidate.startswith("data:"):
                    absolute_url = urljoin(base_url, url_candidate)
                    if self.target.is_in_scope(absolute_url, self.config.include_subdomains):
                        url_info = URLInfo(
                            url=absolute_url,
                            normalized_url=normalize_url(absolute_url),
                            discovery_source=DiscoverySource.CSS,
                        )
                        urls.append(url_info)

        return urls

    def _is_valid_link(self, link: str) -> bool:
        """Check if a link is valid for extraction."""
        if not link or link.strip() == "":
            return False

        # Skip these protocols
        if link.startswith(("mailto:", "tel:", "javascript:", "data:", "ftp:", "file:")):
            return False

        # Skip anchors
        if link.startswith("#"):
            return False

        return True

    def get_file_category(self, url: str) -> Optional[str]:
        """
        Categorize a URL by file extension.

        Returns:
            Category name or None if not a file
        """
        parsed = urlparse(url)
        path = parsed.path.lower()

        if "." in path:
            ext = "." + path.rsplit(".", 1)[-1].lower()

            if ext in self.DOCUMENT_EXTENSIONS:
                return "document"
            elif ext in self.DATA_EXTENSIONS:
                return "data"
            elif ext in self.ARCHIVE_EXTENSIONS:
                return "archive"
            elif ext in self.IMAGE_EXTENSIONS:
                return "image"
            elif ext in self.LOG_EXTENSIONS:
                return "log"
            elif ext in self.PAGE_EXTENSIONS:
                return "page"

        return None

    async def run_initial_discovery(self) -> List[URLInfo]:
        """
        Run initial passive discovery from the base URL.

        Returns:
            List of discovered URLs
        """
        all_urls = []

        # Fetch the main page
        response = await self.http_client.fetch_url(self.target.base_url)
        if response and response.status_code == 200 and response.response_sample:
            # Discover from HTML
            html_urls = await self.discover_from_html(
                response.response_sample, self.target.base_url
            )
            all_urls.extend(html_urls)

        # Discover from robots.txt
        robots_urls = await self.discover_from_robots_txt()
        all_urls.extend(robots_urls)

        # Discover from sitemap.xml
        sitemap_urls = await self.discover_from_sitemap()
        all_urls.extend(sitemap_urls)

        # Deduplicate
        unique_urls = []
        for url_info in all_urls:
            if self.deduplicator.add(url_info):
                unique_urls.append(url_info)

        return unique_urls