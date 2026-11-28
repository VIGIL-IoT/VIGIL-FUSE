from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _sha256_source(content: str) -> str:
    digest = base64.b64encode(hashlib.sha256(content.encode("utf-8")).digest()).decode("ascii")
    return f"'sha256-{digest}'"


def test_vercel_applies_security_headers_to_every_static_route() -> None:
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    rule = config["headers"][0]
    assert rule["source"] == "/(.*)"
    headers = {item["key"].casefold(): item["value"] for item in rule["headers"]}

    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert headers["x-frame-options"] == "SAMEORIGIN"
    assert headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "camera=()" in headers["permissions-policy"]
    assert "microphone=()" in headers["permissions-policy"]

    csp = {}
    for directive in headers["content-security-policy"].split(";"):
        parts = directive.strip().split()
        csp[parts[0]] = parts[1:]
    assert csp["default-src"] == ["'self'"]
    assert csp["object-src"] == ["'none'"]
    assert csp["base-uri"] == ["'self'"]
    assert csp["frame-ancestors"] == ["'self'"]
    assert "https://fonts.googleapis.com" in csp["style-src"]
    assert "https://fonts.gstatic.com" in csp["font-src"]
    assert "'unsafe-eval'" not in csp["script-src"]
    assert "'unsafe-inline'" not in csp["script-src"]
    assert csp["script-src-attr"] == ["'none'"]
    assert csp["style-src-attr"] == ["'unsafe-inline'"]


def test_csp_hashes_match_every_inline_script_and_style_block() -> None:
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    header_items = config["headers"][0]["headers"]
    csp_value = next(
        item["value"] for item in header_items if item["key"] == "Content-Security-Policy"
    )
    directives = {
        parts[0]: parts[1:]
        for directive in csp_value.split(";")
        if (parts := directive.strip().split())
    }

    for page in (ROOT / "site").rglob("*.html"):
        content = page.read_text(encoding="utf-8")
        scripts = re.findall(r"<script\b[^>]*>(.*?)</script\s*>", content, re.I | re.S)
        styles = re.findall(r"<style\b[^>]*>(.*?)</style\s*>", content, re.I | re.S)
        for script in scripts:
            if script.strip():
                assert _sha256_source(script) in directives["script-src"], page
        for style in styles:
            if style.strip():
                assert _sha256_source(style) in directives["style-src"], page


def test_inline_style_attribute_allowance_stays_limited_to_diagrams() -> None:
    pages_with_style_attributes = []
    for page in (ROOT / "site").rglob("*.html"):
        content = page.read_text(encoding="utf-8")
        if re.search(r"\sstyle\s*=", content, re.I):
            pages_with_style_attributes.append(page.relative_to(ROOT / "site").as_posix())

    assert pages_with_style_attributes == [
        "diagrams/fuse-finding-model.html",
        "diagrams/fuse-scan.html",
    ]
