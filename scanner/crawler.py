#!/usr/bin/env python3
"""Web crawler for recursive page discovery."""

import asyncio
from collections import deque
from typing import List, Set, Optional, Callable, Dict, Any

from scanner.models import URLInfo, DiscoverySource, ScanTarget, ScanConfiguration, HTTPResponse
from scanner.http_client import SecurityHTTPClient
from scanner.discovery import PassiveDiscovery, normalize_url


class WebCrawler:
    """
    Recursive web crawler that stays within scope.

    Features:
    - Breadth-first crawling
    - Depth limiting
    - Same-domain scope enforcement
    - Page-type filtering (only crawls HTML pages, not downloads)
    - Polite rate limiting (inherited from HTTP client)
    - Progress tracking
    """

    def __init__(
        self,
        target: ScanTarget,
        configuration: ScanConfiguration,
        http_client: SecurityHTTPClient,
    ):
        self.target = target
        self.config = configuration
        self.http_client = http_client
        self.discovery = PassiveDiscovery(target, configuration, http_client)

        # Crawling state
        self.visited_urls: Set[str] = set()
        self.queue: deque = deque()
        self.crawled_pages = 0

        # Discovered resources
        self.discovered_urls: List[URLInfo] = []
        self.page_responses: Dict[str, HTTPResponse] = {}

        # Statistics
        self.total_urls_found = 0
        self.unique_urls_found = 0

    async def crawl(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[URLInfo]:
        """
        Perform recursive crawl starting from base URL.

        Args:
            progress_callback: Optional callback(current_page, max_pages)

        Returns:
            List of all discovered URLs
        """
        # Start with base URL
        start_url = self.target.base_url
        self.queue.append((start_url, 0))  # (url, depth)

        print(f"[*] Starting crawl of {self.target.base_url} (max {self.config.max_pages} pages, depth {self.config.max_depth})")

        while self.queue and self.crawled_pages < self.config.max_pages:
            current_url, current_depth = self.queue.popleft()

            # Skip if already visited
            normalized = normalize_url(current_url)
            if normalized in self.visited_urls:
                continue

            # Skip if depth exceeded
            if current_depth > self.config.max_depth:
                continue

            # Mark as visited
            self.visited_urls.add(normalized)

            # Fetch the page
            response = await self.http_client.fetch_url(current_url)
            if not response or response.status_code != 200:
                continue

            # Store response
            self.page_responses[current_url] = response
            self.crawled_pages += 1

            # Only process HTML pages
            if response.content_type and "text/html" not in response.content_type.lower():
                # It's a file, not a page to crawl
                url_info = URLInfo(
                    url=current_url,
                    normalized_url=normalized,
                    discovery_source=DiscoverySource.HTML,
                )
                self.discovered_urls.append(url_info)
                continue

            # Discover new URLs from this page
            if response.response_sample:
                discovered = await self.discovery.discover_from_html(
                    response.response_sample, current_url
                )

                for url_info in discovered:
                    # Track all discovered URLs
                    self.total_urls_found += 1

                    # Check if new
                    if url_info.normalized_url not in self.visited_urls:
                        self.unique_urls_found += 1
                        self.discovered_urls.append(url_info)

                        # Add to queue if it's a page to crawl
                        if self._should_crawl(url_info.url):
                            self.queue.append((url_info.url, current_depth + 1))

            # Progress callback
            if progress_callback:
                progress_callback(self.crawled_pages, self.config.max_pages)

            # Progress output
            if self.crawled_pages % 10 == 0 or self.crawled_pages == 1:
                print(f"[*] Crawled {self.crawled_pages}/{self.config.max_pages} pages, found {self.unique_urls_found} unique URLs")

        print(f"[*] Crawl complete: {self.crawled_pages} pages crawled, {len(self.discovered_urls)} URLs discovered")

        return self.discovered_urls

    def _should_crawl(self, url: str) -> bool:
        """
        Determine if a URL should be crawled (not just downloaded).

        Only crawl HTML pages, not PDFs, images, etc.
        """
        # Check extension
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()

        # Skip common file extensions
        skip_extensions = {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico",
            ".zip", ".tar", ".gz", ".7z", ".rar",
            ".mp3", ".mp4", ".avi", ".mov", ".wmv",
            ".txt", ".xml", ".json", ".yaml", ".yml",
        }

        for ext in skip_extensions:
            if path.endswith(ext):
                return False

        # Allow pages with these extensions or no extension
        page_extensions = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx"}
        if any(path.endswith(ext) for ext in page_extensions):
            return True

        # Default: if no extension, assume it's a page
        if "." not in path or path.rfind(".") < path.rfind("/"):
            return True

        return False

    async def recursive_discovery(
        self,
        seed_urls: List[str],
        max_depth: Optional[int] = None,
    ) -> List[URLInfo]:
        """
        Perform recursive discovery starting from seed URLs.

        Args:
            seed_urls: Initial URLs to start discovery from
            max_depth: Maximum depth to crawl (overrides config if provided)

        Returns:
            List of all discovered URLs
        """
        # Override depth if specified
        original_max_depth = self.config.max_depth
        if max_depth is not None:
            self.config.max_depth = max_depth

        # Add seed URLs to queue
        for seed_url in seed_urls:
            if self.target.is_in_scope(seed_url, self.config.include_subdomains):
                self.queue.append((seed_url, 0))

        # Run crawl
        discovered = await self.crawl()

        # Restore original depth
        self.config.max_depth = original_max_depth

        return discovered

    def get_statistics(self) -> Dict[str, Any]:
        """Get crawler statistics."""
        return {
            "pages_crawled": self.crawled_pages,
            "total_urls_found": self.total_urls_found,
            "unique_urls_found": self.unique_urls_found,
            "urls_queued": len(self.queue),
            "urls_visited": len(self.visited_urls),
        }