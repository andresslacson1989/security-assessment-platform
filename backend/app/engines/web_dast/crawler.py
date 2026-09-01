"""
Contract 01, 03 & 08 Scoped Asynchronous Web Discovery Crawler.
Implements breadth-first search (BFS) crawling with strict same-origin scoping,
exclude pattern filtering, robots/sitemap seeding, and rate limiting.
"""

from __future__ import annotations
import logging
import asyncio
from collections import deque
import fnmatch
import hashlib
import re
import urllib.parse
from typing import List, Optional, Set, Callable, Awaitable, Dict, Any
from bs4 import BeautifulSoup
import httpx

from app.core.models import CrawlerConfig, DiscoveredEndpoint, LogLevel
from app.core.rate_limiter import TokenBucketRateLimiter
from app.engines.base import LogCallback

logger = logging.getLogger("cyberassess.engines.crawler")


STATIC_ASSET_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
    ".webm", ".ogg", ".wav", ".pdf", ".zip", ".tar", ".gz", ".map",
}


class WebCrawler:
    """
    Asynchronous Breadth-First Search (BFS) crawler for automated endpoint and attack surface discovery.
    """

    def __init__(
        self,
        target_url: str,
        config: CrawlerConfig,
        client: httpx.AsyncClient,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        emit_log: Optional[LogCallback] = None,
        on_endpoint_discovered: Optional[Callable[[DiscoveredEndpoint], Awaitable[None]]] = None,
        is_authenticated: bool = False,
    ):
        self.target_url = target_url.strip()
        self.config = config
        self.client = client
        self.rate_limiter = rate_limiter
        self.emit_log = emit_log
        self.on_endpoint_discovered = on_endpoint_discovered
        self.is_authenticated = is_authenticated

        parsed = urllib.parse.urlparse(self.target_url)
        self.target_scheme = parsed.scheme.lower()
        self.target_netloc = parsed.netloc.lower()
        self.target_root = f"{self.target_scheme}://{self.target_netloc}"

        self.visited_hashes: Set[str] = set()
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.page_responses: Dict[str, httpx.Response] = {}
        self.page_html: Dict[str, str] = {}

    def _hash_url(self, url: str) -> str:
        return hashlib.sha256(url.lower().encode("utf-8")).hexdigest()

    def normalize_url(self, base_url: str, link: str) -> Optional[str]:
        """
        Resolves relative paths, strips fragments, normalizes trailing slashes, and verifies scheme.
        """
        if not link or link.startswith("#") or link.startswith("javascript:") or link.startswith("mailto:") or link.startswith("tel:"):
            return None

        # Resolve relative URL against current page base URL
        resolved = urllib.parse.urljoin(base_url, link.strip())
        parsed = urllib.parse.urlparse(resolved)

        if parsed.scheme.lower() not in ("http", "https"):
            return None

        # Strip fragment (#...)
        path = parsed.path
        if not path:
            path = "/"
        elif path != "/" and path.endswith("/"):
            path = path[:-1]

        # Reconstruct normalized URL
        normalized = urllib.parse.urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            parsed.params,
            parsed.query,
            "",  # No fragment
        ))
        return normalized

    def is_in_scope(self, candidate_url: str) -> bool:
        """
        Verifies that candidate URL belongs to the target host and matches no exclude patterns.
        """
        parsed = urllib.parse.urlparse(candidate_url)
        if parsed.netloc.lower() != self.target_netloc:
            return False

        # Ignore static asset files (.js, .css, .png, etc.) so crawl budget visits actual pages/routes
        path_lower = parsed.path.lower()
        for ext in STATIC_ASSET_EXTENSIONS:
            if path_lower.endswith(ext):
                return False

        # Match against exclude patterns (e.g. *logout*, *delete*)
        url_lower = candidate_url.lower()
        for pattern in self.config.exclude_patterns:
            if fnmatch.fnmatch(url_lower, pattern.lower()):
                return False

        return True

    async def fetch_seed_urls(self) -> List[str]:
        """
        Probes /robots.txt and /sitemap.xml to discover initial seeds.
        """
        seeds: List[str] = []
        if not self.config.parse_sitemap:
            return seeds

        # 1. Probe robots.txt
        robots_url = f"{self.target_root}/robots.txt"
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            resp = await self.client.get(robots_url, timeout=5.0)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        sitemap_candidate = line.split(":", 1)[1].strip()
                        norm = self.normalize_url(self.target_root, sitemap_candidate)
                        if norm and self.is_in_scope(norm):
                            seeds.append(norm)
                    elif line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            norm = self.normalize_url(self.target_root, path)
                            if norm and self.is_in_scope(norm):
                                seeds.append(norm)
        except Exception as exc:
            logger.debug("Robots seed retrieval failed: error_type=%s", type(exc).__name__)

        # 2. Probe /sitemap.xml
        sitemap_url = f"{self.target_root}/sitemap.xml"
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            resp = await self.client.get(sitemap_url, timeout=5.0)
            if resp.status_code == 200 and ("<urlset" in resp.text or "<sitemapindex" in resp.text):
                # Extract URLs with regex
                locs = re.findall(r"<loc>(.*?)</loc>", resp.text, flags=re.IGNORECASE)
                for loc in locs:
                    norm = self.normalize_url(self.target_root, loc.strip())
                    if norm and self.is_in_scope(norm):
                        seeds.append(norm)
        except Exception as exc:
            logger.debug("Sitemap seed retrieval failed: error_type=%s", type(exc).__name__)

        return seeds

    async def crawl(self) -> List[DiscoveredEndpoint]:
        """
        Executes breadth-first search crawl loop up to max_depth and max_pages.
        """
        root_normalized = self.normalize_url(self.target_root, self.target_url) or self.target_url
        queue: deque = deque([(root_normalized, 0)])
        self.visited_hashes.add(self._hash_url(root_normalized))

        if self.emit_log:
            await self.emit_log(LogLevel.INFO, f"Initiating web crawl on '{root_normalized}' (max_depth={self.config.max_depth}, max_pages={self.config.max_pages}).")

        # Discover initial seeds from robots.txt & sitemap.xml
        seed_urls = await self.fetch_seed_urls()
        for seed in seed_urls:
            seed_hash = self._hash_url(seed)
            if seed_hash not in self.visited_hashes:
                self.visited_hashes.add(seed_hash)
                queue.append((seed, 1))

        while queue and len(self.discovered_endpoints) < self.config.max_pages:
            current_url, current_depth = queue.popleft()

            if self.rate_limiter:
                await self.rate_limiter.acquire()

            try:
                # Never delegate redirect decisions to httpx: every Location must
                # pass the crawler's same-origin policy before it is queued.
                resp = await self.client.get(current_url, follow_redirects=False)
                if self.config.follow_redirects and 300 <= resp.status_code < 400:
                    location = resp.headers.get("location")
                    redirected = self.normalize_url(current_url, location or "")
                    if redirected and self.is_in_scope(redirected):
                        redirect_hash = self._hash_url(redirected)
                        if redirect_hash not in self.visited_hashes and current_depth < self.config.max_depth:
                            self.visited_hashes.add(redirect_hash)
                            queue.append((redirected, current_depth + 1))
                    elif location and self.emit_log:
                        await self.emit_log(LogLevel.WARNING, f"Blocked out-of-scope redirect from '{current_url}' to '{location}'.")
                self.page_responses[current_url] = resp
                status_code = resp.status_code
                content_type = resp.headers.get("content-type", "")
                is_html = "text/html" in content_type.lower()
                has_forms = False

                if is_html:
                    self.page_html[current_url] = resp.text
                    soup = BeautifulSoup(resp.text, "html.parser")
                    forms = soup.find_all("form")
                    if forms:
                        has_forms = True

                    # Extract links for next BFS layer if within depth limit
                    if current_depth < self.config.max_depth:
                        extracted_links: Set[str] = set()

                        for a in soup.find_all("a", href=True):
                            extracted_links.add(a["href"])
                        for form in forms:
                            if form.get("action"):
                                extracted_links.add(form["action"])

                        for raw_link in extracted_links:
                            norm_link = self.normalize_url(current_url, raw_link)
                            if norm_link and self.is_in_scope(norm_link):
                                link_hash = self._hash_url(norm_link)
                                if link_hash not in self.visited_hashes:
                                    self.visited_hashes.add(link_hash)
                                    queue.append((norm_link, current_depth + 1))

                endpoint = DiscoveredEndpoint(
                    url=current_url,
                    method="GET",
                    depth=current_depth,
                    status_code=status_code,
                    content_type=content_type or None,
                    is_authenticated=self.is_authenticated,
                    has_forms=has_forms,
                )
                self.discovered_endpoints.append(endpoint)

                if self.on_endpoint_discovered:
                    await self.on_endpoint_discovered(endpoint)

            except Exception as e:
                if self.emit_log:
                    await self.emit_log(LogLevel.DEBUG, f"Crawl error on '{current_url}': {str(e)}")

        if self.emit_log:
            await self.emit_log(LogLevel.INFO, f"Crawl complete. Discovered {len(self.discovered_endpoints)} endpoints.")

        return self.discovered_endpoints
