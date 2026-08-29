"""
Unit test suite for Scoped Asynchronous Web Crawler (Contract 01, 03, 08).
"""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest

from app.core.models import CrawlerConfig, DiscoveredEndpoint
from app.engines.web_dast.crawler import WebCrawler


def test_url_normalization_and_scope():
    crawler = WebCrawler(
        target_url="https://app.example.com",
        config=CrawlerConfig(),
        client=AsyncMock(),
    )

    # Normalization tests
    assert crawler.normalize_url("https://app.example.com", "/dashboard") == "https://app.example.com/dashboard"
    assert crawler.normalize_url("https://app.example.com/blog/", "post-1") == "https://app.example.com/blog/post-1"
    assert crawler.normalize_url("https://app.example.com", "/about/#team") == "https://app.example.com/about"
    assert crawler.normalize_url("https://app.example.com", "javascript:void(0)") is None
    assert crawler.normalize_url("https://app.example.com", "mailto:info@example.com") is None
    assert crawler.normalize_url("https://app.example.com", "#section") is None

    # Scope checking tests
    assert crawler.is_in_scope("https://app.example.com/dashboard") is True
    assert crawler.is_in_scope("https://app.example.com/api/v1/users") is True
    assert crawler.is_in_scope("https://other.example.com/test") is False
    assert crawler.is_in_scope("https://google.com") is False


def test_exclude_patterns():
    crawler = WebCrawler(
        target_url="https://app.example.com",
        config=CrawlerConfig(
            exclude_patterns=["*logout*", "*signout*", "*delete*", "*destroy*"]
        ),
        client=AsyncMock(),
    )

    assert crawler.is_in_scope("https://app.example.com/profile") is True
    assert crawler.is_in_scope("https://app.example.com/auth/logout") is False
    assert crawler.is_in_scope("https://app.example.com/user/signout") is False
    assert crawler.is_in_scope("https://app.example.com/api/delete-user") is False
    assert crawler.is_in_scope("https://app.example.com/session/destroy") is False


@pytest.mark.asyncio
async def test_bfs_crawl_depth_and_page_limits():
    mock_client = AsyncMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.headers = {"content-type": "text/html; charset=utf-8"}

        if url == "https://example.com/":
            resp.text = """
            <html>
              <body>
                <a href="/about">About</a>
                <a href="/contact">Contact</a>
                <a href="https://external.org/test">External Link</a>
              </body>
            </html>
            """
        elif url == "https://example.com/about":
            resp.text = """
            <html>
              <body>
                <a href="/team">Our Team</a>
              </body>
            </html>
            """
        elif url == "https://example.com/team":
            resp.text = """
            <html>
              <body>
                <a href="/team/alice">Alice Bio</a>
              </body>
            </html>
            """
        else:
            resp.text = "<html><body>Leaf Page</body></html>"

        return resp

    mock_client.get = AsyncMock(side_effect=mock_get)

    # 1. Test Depth Limit = 2
    crawler = WebCrawler(
        target_url="https://example.com",
        config=CrawlerConfig(max_depth=2, max_pages=50, parse_sitemap=False),
        client=mock_client,
    )

    endpoints = await crawler.crawl()
    urls = [e.url for e in endpoints]

    assert "https://example.com" in urls or "https://example.com/" in urls
    assert "https://example.com/about" in urls
    assert "https://example.com/team" in urls
    # Depth 3 (/team/alice) should NOT be crawled because max_depth=2
    assert "https://example.com/team/alice" not in urls
    # External URLs should never be crawled
    assert "https://external.org/test" not in urls

    # 2. Test Page Cap Limit = 2
    mock_client.get.reset_mock()
    capped_crawler = WebCrawler(
        target_url="https://example.com",
        config=CrawlerConfig(max_depth=5, max_pages=2, parse_sitemap=False),
        client=mock_client,
    )
    capped_endpoints = await capped_crawler.crawl()
    assert len(capped_endpoints) <= 2


@pytest.mark.asyncio
async def test_sitemap_and_robots_seeding():
    mock_client = AsyncMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        if url == "https://example.com/robots.txt":
            resp.text = """
            User-agent: *
            Disallow: /admin
            Sitemap: https://example.com/sitemap.xml
            """
            resp.headers = {"content-type": "text/plain"}
        elif url == "https://example.com/sitemap.xml":
            resp.text = """<?xml version="1.0" encoding="UTF-8"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
               <url>
                  <loc>https://example.com/pricing</loc>
               </url>
               <url>
                  <loc>https://example.com/docs</loc>
               </url>
            </urlset>
            """
            resp.headers = {"content-type": "application/xml"}
        else:
            resp.text = "<html><body>Home</body></html>"
            resp.headers = {"content-type": "text/html"}
        return resp

    mock_client.get = AsyncMock(side_effect=mock_get)

    crawler = WebCrawler(
        target_url="https://example.com",
        config=CrawlerConfig(max_depth=2, max_pages=20, parse_sitemap=True),
        client=mock_client,
    )

    seeds = await crawler.fetch_seed_urls()
    assert "https://example.com/pricing" in seeds
    assert "https://example.com/docs" in seeds
    assert "https://example.com/admin" in seeds


@pytest.mark.asyncio
async def test_form_discovery_flag():
    mock_client = AsyncMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.headers = {"content-type": "text/html"}
        if url.endswith("/login"):
            resp.text = """
            <html>
              <body>
                <form action="/login" method="POST">
                  <input type="text" name="username">
                  <input type="password" name="password">
                  <button type="submit">Sign In</button>
                </form>
              </body>
            </html>
            """
        else:
            resp.text = """
            <html>
              <body>
                <a href="/login">Login Page</a>
                <p>Welcome to our static home</p>
              </body>
            </html>
            """
        return resp

    mock_client.get = AsyncMock(side_effect=mock_get)

    crawler = WebCrawler(
        target_url="https://example.com",
        config=CrawlerConfig(max_depth=2, max_pages=10, parse_sitemap=False),
        client=mock_client,
    )

    endpoints = await crawler.crawl()
    home_ep = next((e for e in endpoints if e.url in ("https://example.com", "https://example.com/")), None)
    login_ep = next((e for e in endpoints if "/login" in e.url), None)

    assert home_ep is not None
    assert home_ep.has_forms is False

    assert login_ep is not None
    assert login_ep.has_forms is True
