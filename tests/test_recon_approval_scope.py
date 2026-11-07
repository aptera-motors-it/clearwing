"""Approval and scope gates for recon tools that write files, fetch bundles, or rewrite traffic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import clearwing.agent.tools.recon.browser_tools as browser_mod
import clearwing.agent.tools.recon.bundle_tools as bun_mod
import clearwing.agent.tools.recon.discovery_tools as disc_mod
import clearwing.agent.tools.recon.mitm_proxy as mitm_mod
import clearwing.agent.tools.recon.proxy_tools as proxy_mod


@pytest.fixture(autouse=True)
def _reset_inject_rules():
    mitm_mod._inject_rules.clear()
    yield
    mitm_mod._inject_rules.clear()


class TestProxyExportGate:
    def test_declined_export_writes_nothing(self, tmp_path):
        target = tmp_path / "credentials.json"
        target.write_text("keep-me")
        with patch.object(proxy_mod, "interrupt", return_value=False):
            result = proxy_mod.proxy_export_history.invoke({"path": str(target)})
        assert result["success"] is False
        assert target.read_text() == "keep-me"

    def test_prompt_names_resolved_path(self, tmp_path):
        target = tmp_path / "out.json"
        with patch.object(proxy_mod, "interrupt", return_value=True) as gate:
            result = proxy_mod.proxy_export_history.invoke({"path": str(target)})
        assert result["success"] is True
        assert str(target) in gate.call_args.args[0]


class TestScreenshotGate:
    def test_declined_screenshot_not_taken(self, tmp_path):
        page = MagicMock()
        with (
            patch.object(browser_mod, "interrupt", return_value=False),
            patch.object(browser_mod, "_get_page", return_value=page),
        ):
            result = browser_mod.browser_screenshot.invoke({"path": str(tmp_path / "a.png")})
        assert result["success"] is False
        page.screenshot.assert_not_called()

    def test_screenshot_surface_declined_creates_nothing(self, tmp_path):
        out = tmp_path / "gallery"
        with patch.object(disc_mod, "interrupt", return_value=False):
            result = disc_mod.screenshot_surface.invoke(
                {"urls": ["https://example.com"], "out_dir": str(out)}
            )
        assert "error" in result
        assert not out.exists()


class TestBundleScope:
    def test_off_host_script_urls_are_dropped(self):
        html = (
            '<script src="/app.js"></script>'
            '<script src="//evil.example/pwn.js"></script>'
            '<script src="http://169.254.169.254/latest/meta-data/"></script>'
            '<script src="https://127.0.0.1:1/x.js"></script>'
            '<script src="local.js"></script>'
        )
        urls = bun_mod._extract_script_urls(html, "https://engagement.example")
        assert urls == [
            "https://engagement.example/app.js",
            "https://engagement.example/local.js",
        ]

    def test_fetch_js_bundles_never_requests_off_host(self):
        html = '<script src="/a.js"></script><script src="http://169.254.169.254/x.js"></script>'
        fetched: list[str] = []

        def fake_fetch(url, timeout=30):
            fetched.append(url)
            return 200, html if url.endswith("/") else "var x=1;", 1.0

        with (
            patch.object(bun_mod, "interrupt", return_value=True),
            patch.object(bun_mod, "_fetch_url", fake_fetch),
        ):
            bun_mod.fetch_js_bundles.invoke({"target": "https://engagement.example"})
        assert fetched == ["https://engagement.example/", "https://engagement.example/a.js"]


class TestMitmInjectDenied:
    def test_denied_rule_is_not_installed(self):
        with patch.object(mitm_mod, "interrupt", return_value=False):
            result = mitm_mod.mitm_inject_response.invoke(
                {"url_pattern": "*/api/*", "body": "pwned"}
            )
        assert "error" in result
        assert mitm_mod._inject_rules == {}

    def test_approved_rule_is_installed(self):
        with patch.object(mitm_mod, "interrupt", return_value=True):
            mitm_mod.mitm_inject_response.invoke({"url_pattern": "*/api/*", "body": "ok"})
        assert "*/api/*" in mitm_mod._inject_rules
