"""Approval and scope gates for recon tools that write files, fetch bundles, or rewrite traffic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import clearwing.agent.tools.recon.browser_tools as browser_mod
import clearwing.agent.tools.recon.bundle_tools as bun_mod
import clearwing.agent.tools.recon.discovery_tools as disc_mod
import clearwing.agent.tools.recon.mitm_proxy as mitm_mod
import clearwing.agent.tools.recon.proxy_tools as proxy_mod
import clearwing.ui.commands.asm as asm_cmd
from clearwing.agent.tooling import tool_execution_context


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


class TestPromptMatchesWrittenPath:
    def test_proxy_export_tilde(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path / "..")
        with (
            patch.object(proxy_mod, "interrupt", return_value=True) as gate,
            patch.object(proxy_mod._proxy_history, "export") as export,
        ):
            proxy_mod.proxy_export_history.invoke({"path": "~/h.json"})
        assert gate.call_args.args[0].endswith(export.call_args.args[0])
        assert export.call_args.args[0] == str(tmp_path / "h.json")

    def test_browser_screenshot_tilde(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path / "..")
        page = MagicMock()
        with (
            patch.object(browser_mod, "interrupt", return_value=True) as gate,
            patch.object(browser_mod, "_get_page", return_value=page),
        ):
            browser_mod.browser_screenshot.invoke({"path": "~/s.png"})
        written = page.screenshot.call_args.kwargs["path"]
        assert gate.call_args.args[0].endswith(written)
        assert written == str(tmp_path / "s.png")

    def test_screenshot_surface_tilde(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        with (
            patch.object(disc_mod, "interrupt", return_value=True) as gate,
            patch.object(
                browser_mod, "browser_navigate", MagicMock(return_value={"status": "error"})
            ),
        ):
            result = disc_mod.screenshot_surface.invoke({"urls": [], "out_dir": "~/gallery"})
        assert gate.call_args.args[0].endswith(str(tmp_path / "gallery"))
        assert result["gallery"] == str(tmp_path / "gallery" / "gallery.html")
        assert (tmp_path / "gallery" / "gallery.html").exists()
        assert list(cwd.iterdir()) == []


class TestBundlePagePathHost:
    @pytest.mark.parametrize(
        ("tool", "args"),
        [
            (bun_mod.fetch_js_bundles, {}),
            (bun_mod.search_bundle_patterns, {}),
            (bun_mod.extract_api_routes, {}),
        ],
    )
    def test_at_host_page_path_never_requested(self, tool, args):
        fetched: list[str] = []

        def fake_fetch(url, timeout=30):
            fetched.append(url)
            return 200, "", 1.0

        with (
            patch.object(bun_mod, "interrupt", return_value=True),
            patch.object(bun_mod, "_fetch_url", fake_fetch),
        ):
            result = tool.invoke(
                {
                    "target": "https://engagement.example",
                    "page_path": "@169.254.169.254/latest/meta-data/",
                    **args,
                }
            )
        assert fetched == []
        assert "error" in result

    def test_prompt_names_fetched_url(self):
        fetched: list[str] = []

        def fake_fetch(url, timeout=30):
            fetched.append(url)
            return 0, "down", 0.0

        with (
            patch.object(bun_mod, "interrupt", return_value=True) as gate,
            patch.object(bun_mod, "_fetch_url", fake_fetch),
        ):
            bun_mod.search_bundle_patterns.invoke(
                {"target": "https://engagement.example", "page_path": "/app"}
            )
        assert fetched == ["https://engagement.example/app"]
        assert "https://engagement.example/app" in gate.call_args.args[0]


class TestAsmScreenshotConsent:
    def _store(self):
        store = MagicMock()
        store.known_assets.return_value = [MagicMock(value="https://example.com")]
        return store

    def test_asm_screenshot_writes_gallery_without_tool_context(self, tmp_path):
        out = tmp_path / "shots"
        real = disc_mod.screenshot_surface.func
        cli = MagicMock()
        with (
            patch.object(
                disc_mod.screenshot_surface,
                "func",
                lambda urls: real(urls, out_dir=str(out)),
            ),
            patch.object(
                browser_mod, "browser_navigate", MagicMock(return_value={"status": "error"})
            ),
        ):
            asm_cmd._screenshot(cli, self._store(), "scope")
        assert (out / "gallery.html").exists()

    def test_agent_tool_context_without_approval_writes_nothing(self, tmp_path):
        out = tmp_path / "shots"
        with tool_execution_context(resume_decision=False):
            result = disc_mod.screenshot_surface.func(["https://example.com"], out_dir=str(out))
        assert "error" in result
        assert not out.exists()
