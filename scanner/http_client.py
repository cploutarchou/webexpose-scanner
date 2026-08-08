#!/usr/bin/env python3
"""HTTP client with security controls and rate limiting."""

import asyncio
import time
from typing import Any

import httpx
from httpx import AsyncClient, RequestError, Response

from scanner.models import HTTPResponse, ScanConfiguration
from scanner.scope import RedirectOutOfScopeError, is_safe_redirect


class SecurityHTTPClient:
    """
    HTTP client with security controls for authorized security scanning.

    Features:
    - Strict scope validation
    - Request timeout and size limits
    - Redirect validation (prevents SSRF)
    - Rate limiting
    - HEAD before GET optimization
    - Automatic retries with backoff
    """

    def __init__(
        self,
        configuration: ScanConfiguration,
        authorized_hostname: str,
        authorized_base_domain: str,
    ):
        self.config = configuration
        self.authorized_hostname = authorized_hostname
        self.authorized_base_domain = authorized_base_domain

        # Rate limiting
        self.last_request_time = 0.0
        self.request_semaphore = asyncio.Semaphore(configuration.workers)

        # HTTP client setup
        self.client: AsyncClient | None = None

        # Statistics
        self.total_requests = 0
        self.failed_requests = 0
        self.redirects_blocked = 0

    async def __aenter__(self):
        """Initialize async HTTP client."""
        timeout = httpx.Timeout(
            timeout=self.config.timeout,
            connect=10.0,
        )

        limits = httpx.Limits(
            max_connections=self.config.workers,
            max_keepalive_connections=self.config.workers,
        )

        self.client = AsyncClient(
            timeout=timeout,
            limits=limits,
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=False,  # We handle redirects manually for security
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup HTTP client."""
        if self.client:
            await self.client.aclose()

    async def _rate_limit_wait(self):
        """Apply rate limiting between requests."""
        if self.config.rate_limit > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time

            if time_since_last < self.config.rate_limit:
                wait_time = self.config.rate_limit - time_since_last
                await asyncio.sleep(wait_time)

            self.last_request_time = time.time()

    async def _validate_response_redirect(
        self, response: Response
    ) -> str | None:
        """
        Validate that any redirect is within authorized scope.

        Returns:
            The redirect URL if safe, None if not following redirect

        Raises:
            RedirectOutOfScopeError: If redirect is outside scope
        """
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location")
            if location:
                try:
                    is_safe_redirect(
                        location,
                        self.authorized_hostname,
                        self.authorized_base_domain
                    )
                    return location
                except RedirectOutOfScopeError as e:
                    self.redirects_blocked += 1
                    if self.config.verbose:
                        print(f"[BLOCKED] {e}")
                    raise

        return None

    async def _fetch_with_retry(
        self, url: str, method: str = "GET", **kwargs
    ) -> Response | None:
        """
        Fetch a URL with retries and error handling.

        Args:
            url: The URL to fetch
            method: HTTP method (GET or HEAD)
            **kwargs: Additional arguments for httpx

        Returns:
            Response object or None if all retries fail
        """
        if not self.client:
            raise RuntimeError("HTTP client not initialized. Use async context manager.")

        last_error = None

        for attempt in range(self.config.retry_count):
            try:
                async with self.request_semaphore:
                    await self._rate_limit_wait()

                    self.total_requests += 1
                    response = await self.client.request(method, url, **kwargs)

                    # Validate redirects
                    redirect_url = await self._validate_response_redirect(response)
                    if redirect_url:
                        # Follow the safe redirect
                        return await self._fetch_with_retry(redirect_url, method, **kwargs)

                    return response

            except RequestError as e:
                last_error = e
                if self.config.verbose:
                    print(f"[RETRY] Attempt {attempt + 1}/{self.config.retry_count} failed for {url}: {e}")

                # Exponential backoff
                if attempt < self.config.retry_count - 1:
                    backoff = self.config.retry_backoff * (2 ** attempt)
                    await asyncio.sleep(backoff)

            except RedirectOutOfScopeError:
                # Don't retry on blocked redirects
                return None
            except Exception as e:
                last_error = e
                if self.config.verbose:
                    print(f"[ERROR] Unexpected error fetching {url}: {e}")
                break

        self.failed_requests += 1
        if self.config.verbose:
            print(f"[FAILED] Could not fetch {url} after {self.config.retry_count} attempts")
        return None

    async def fetch_url(self, url: str) -> HTTPResponse | None:
        """
        Fetch a URL and return comprehensive HTTP response information.

        Args:
            url: The URL to fetch

        Returns:
            HTTPResponse object with full response details, or None if failed
        """
        # Try HEAD first if configured
        if self.config.head_first:
            head_response = await self._fetch_with_retry(url, "HEAD")
            if head_response and head_response.status_code < 400:
                # HEAD succeeded, but we still need GET for content analysis
                pass
            elif head_response and head_response.status_code == 405:
                # Method not allowed, fall through to GET
                pass
            elif head_response:
                # HEAD gave us enough info
                return self._build_http_response(head_response, url, full_response=False)

        # Get full response
        response = await self._fetch_with_retry(url, "GET")
        if not response:
            return None

        return self._build_http_response(response, url, full_response=True)

    def _build_http_response(
        self, response: Response, original_url: str, full_response: bool = False
    ) -> HTTPResponse:
        """Build an HTTPResponse object from httpx response."""
        # Get content length
        content_length = None
        if "content-length" in response.headers:
            try:
                content_length = int(response.headers["content-length"])
            except ValueError:
                pass

        # Get last modified
        last_modified = response.headers.get("last-modified")

        # Get ETag
        etag = response.headers.get("etag")

        # Get server
        server = response.headers.get("server")

        # Extract title if HTML
        title = None
        is_directory_listing = False
        response_sample = None

        if full_response and response.status_code == 200:
            # Only parse HTML responses for content analysis
            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type.lower():
                # Get first few bytes for analysis
                content = response.text[:5000] if hasattr(response, "text") else ""
                response_sample = content

                # Simple title extraction
                if "<title>" in content.lower():
                    title_start = content.lower().find("<title>") + 7
                    title_end = content.lower().find("</title>", title_start)
                    if title_end > title_start:
                        title = content[title_start:title_end].strip()

                # Check for directory listing
                content_lower = content.lower()
                directory_listing_indicators = [
                    "index of /",
                    "<title>directory listing",
                    "parent directory</a>",
                    "name<t",
                    "last modified</a>",
                ]
                is_directory_listing = any(
                    indicator in content_lower
                    for indicator in directory_listing_indicators
                )

        return HTTPResponse(
            url=original_url,
            final_url=str(response.url),
            status_code=response.status_code,
            content_type=response.headers.get("content-type"),
            content_length=content_length,
            last_modified=last_modified,
            etag=etag,
            server=server,
            title=title,
            headers=dict(response.headers),
            is_directory_listing=is_directory_listing,
            response_sample=response_sample if full_response else None,
        )

    async def fetch_multiple(
        self, urls: list[str], progress_callback=None
    ) -> list[HTTPResponse | None]:
        """
        Fetch multiple URLs concurrently.

        Args:
            urls: List of URLs to fetch
            progress_callback: Optional callback function(current, total)

        Returns:
            List of HTTPResponse objects (same order as input)
        """
        results = []
        completed = 0

        async def fetch_with_progress(url: str) -> HTTPResponse | None:
            nonlocal completed
            result = await self.fetch_url(url)
            completed += 1
            if progress_callback:
                progress_callback(completed, len(urls))
            return result

        tasks = [fetch_with_progress(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                if self.config.verbose:
                    print(f"[ERROR] Task failed: {result}")
                processed_results.append(None)
            else:
                processed_results.append(result)

        return processed_results

    def get_statistics(self) -> dict[str, Any]:
        """Get client statistics."""
        return {
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (
                (self.total_requests - self.failed_requests) / self.total_requests
                if self.total_requests > 0
                else 0
            ),
            "redirects_blocked": self.redirects_blocked,
        }