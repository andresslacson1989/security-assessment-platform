"""Repeater assurance for the 2026-09-03 audit closure."""

from __future__ import annotations

import httpx
import pytest

from app.api.tools import _extract_tls_metadata, _read_response_body_bounded


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.read_count = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.read_count += 1
            yield chunk


@pytest.mark.asyncio
async def test_repeater_stops_reading_after_hard_response_limit():
    stream = ChunkStream([b"a" * 8, b"b" * 8, b"c" * 8, b"d" * 8])
    response = httpx.Response(200, stream=stream)
    captured, observed, truncated = await _read_response_body_bounded(response, limit_bytes=10)

    assert captured == b"a" * 8 + b"b" * 2
    assert observed == 16
    assert truncated is True
    # The helper broke from the async iterator instead of materializing all 32 bytes.
    assert stream.read_count == 2


@pytest.mark.asyncio
async def test_repeater_preserves_complete_small_response():
    stream = ChunkStream([b"hello", b" world"])
    response = httpx.Response(200, stream=stream)
    captured, observed, truncated = await _read_response_body_bounded(response, limit_bytes=64)
    assert captured == b"hello world"
    assert observed == 11
    assert truncated is False


def test_missing_tls_metadata_remains_unknown_not_tls13():
    response = httpx.Response(200)
    tls_version, cipher = _extract_tls_metadata(response)
    assert tls_version is None
    assert cipher is None


def test_observed_tls_metadata_is_preserved():
    response = httpx.Response(200, extensions={"tls_version": "TLSv1.2", "cipher_suite": "TEST-CIPHER"})
    tls_version, cipher = _extract_tls_metadata(response)
    assert tls_version == "TLSv1.2"
    assert cipher == "TEST-CIPHER"
