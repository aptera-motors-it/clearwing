from __future__ import annotations

import os
import stat
import urllib.parse
from pathlib import Path

import pytest
import yaml

from clearwing.providers import openai_oauth, preset_by_key
from clearwing.safety.auth import (
    APIAuth,
    AuthConfig,
    AuthConfigLoader,
    CookieAuth,
    FormLogin,
    OAuthConfig,
)
from clearwing.sourcehunt.artifact_store import ArtifactStore
from clearwing.ui.commands.setup import _write_config

# ---------------------------------------------------------------------------
# Dataclass defaults
# ---------------------------------------------------------------------------


class TestFormLoginDefaults:
    def test_defaults(self):
        form = FormLogin(url="http://example.com/login")
        assert form.url == "http://example.com/login"
        assert form.username_field == "username"
        assert form.password_field == "password"
        assert form.submit_selector == "button[type=submit]"
        assert form.username == ""
        assert form.password == ""
        assert form.success_indicator == ""
        assert form.failure_indicator == ""


class TestAPIAuthDefaults:
    def test_defaults(self):
        api = APIAuth(auth_type="bearer")
        assert api.auth_type == "bearer"
        assert api.token == ""
        assert api.header_name == "Authorization"
        assert api.header_prefix == "Bearer"
        assert api.api_key_param == ""
        assert api.username == ""
        assert api.password == ""


class TestCookieAuthDefaults:
    def test_defaults(self):
        cookie = CookieAuth()
        assert cookie.cookies == {}


class TestOAuthConfigDefaults:
    def test_defaults(self):
        oauth = OAuthConfig()
        assert oauth.auth_url == ""
        assert oauth.token_url == ""
        assert oauth.client_id == ""
        assert oauth.client_secret == ""
        assert oauth.scope == ""
        assert oauth.redirect_uri == ""


# ---------------------------------------------------------------------------
# AuthConfig.has_credentials
# ---------------------------------------------------------------------------


class TestAuthConfigHasCredentials:
    def test_form_with_credentials(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="form",
            form=FormLogin(url="http://10.0.0.1/login", username="admin", password="secret"),
        )
        assert config.has_credentials() is True

    def test_form_without_credentials(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="form",
            form=FormLogin(url="http://10.0.0.1/login"),
        )
        assert config.has_credentials() is False

    def test_api_with_token(self):
        config = AuthConfig(
            target="http://api.example.com",
            auth_type="api",
            api=APIAuth(auth_type="bearer", token="tok_abc123"),
        )
        assert config.has_credentials() is True

    def test_api_with_basic_auth(self):
        config = AuthConfig(
            target="http://api.example.com",
            auth_type="api",
            api=APIAuth(auth_type="basic", username="user", password="pass"),
        )
        assert config.has_credentials() is True

    def test_api_without_credentials(self):
        config = AuthConfig(
            target="http://api.example.com",
            auth_type="api",
            api=APIAuth(auth_type="bearer"),
        )
        assert config.has_credentials() is False

    def test_cookie_with_cookies(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="cookie",
            cookie=CookieAuth(cookies={"session": "abc123"}),
        )
        assert config.has_credentials() is True

    def test_cookie_without_cookies(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="cookie",
            cookie=CookieAuth(),
        )
        assert config.has_credentials() is False

    def test_oauth_with_client_id(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="oauth",
            oauth=OAuthConfig(client_id="my-client"),
        )
        assert config.has_credentials() is True

    def test_oauth_without_client_id(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="oauth",
            oauth=OAuthConfig(),
        )
        assert config.has_credentials() is False

    def test_none_auth_type(self):
        config = AuthConfig(target="http://10.0.0.1", auth_type="none")
        assert config.has_credentials() is False


# ---------------------------------------------------------------------------
# AuthConfigLoader
# ---------------------------------------------------------------------------

FORM_YAML = """\
target: "http://10.0.0.1"
auth_type: form
form:
  url: "http://10.0.0.1/login"
  username: admin
  password: "${TARGET_PASSWORD}"
  success_indicator: "Dashboard"
"""

API_YAML = """\
target: "http://api.example.com"
auth_type: api
api:
  auth_type: bearer
  token: "tok_abc123"
"""

COOKIE_YAML = """\
target: "http://10.0.0.1"
auth_type: cookie
cookie:
  cookies:
    session: "abc123"
    csrf: "xyz789"
"""

OAUTH_YAML = """\
target: "http://10.0.0.1"
auth_type: oauth
oauth:
  auth_url: "https://auth.example.com/authorize"
  token_url: "https://auth.example.com/token"
  client_id: "my-client"
  client_secret: "${OAUTH_SECRET}"
  scope: "read write"
  redirect_uri: "http://localhost:8080/callback"
"""


@pytest.fixture
def loader(tmp_path, monkeypatch):
    """Create an AuthConfigLoader with a temp CONFIG_DIR."""
    monkeypatch.setattr(AuthConfigLoader, "CONFIG_DIR", tmp_path)
    return AuthConfigLoader()


class TestAuthConfigLoaderLoad:
    def test_load_from_yaml(self, tmp_path, loader, monkeypatch):
        monkeypatch.setenv("TARGET_PASSWORD", "s3cret")
        config_file = tmp_path / "target.yml"
        config_file.write_text(FORM_YAML, encoding="utf-8")

        config = loader.load(str(config_file))

        assert config.target == "http://10.0.0.1"
        assert config.auth_type == "form"
        assert config.form is not None
        assert config.form.url == "http://10.0.0.1/login"
        assert config.form.username == "admin"
        assert config.form.password == "s3cret"
        assert config.form.success_indicator == "Dashboard"

    def test_missing_file_raises(self, loader):
        with pytest.raises(FileNotFoundError, match="Auth config not found"):
            loader.load("/nonexistent/path/config.yml")


class TestAuthConfigLoaderSaveRoundTrip:
    def test_save_and_reload(self, tmp_path, loader):
        original = AuthConfig(
            target="http://10.0.0.1",
            auth_type="form",
            form=FormLogin(
                url="http://10.0.0.1/login",
                username="admin",
                password="secret",
                success_indicator="Dashboard",
            ),
        )
        save_path = str(tmp_path / "roundtrip.yml")
        loader.save(original, path=save_path)

        reloaded = loader.load(save_path)

        assert reloaded.target == original.target
        assert reloaded.auth_type == original.auth_type
        assert reloaded.form.url == original.form.url
        assert reloaded.form.username == original.form.username
        assert reloaded.form.password == original.form.password
        assert reloaded.form.success_indicator == original.form.success_indicator
        assert reloaded.session_persistence == original.session_persistence

    def test_save_is_atomic_and_owner_only(self, tmp_path, loader, monkeypatch):
        original_replace = os.replace
        temporary_modes = []

        def inspect_replace(source, destination):
            temporary_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
            original_replace(source, destination)

        monkeypatch.setattr("clearwing.safety.auth.config.os.replace", inspect_replace)
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="form",
            form=FormLogin(
                url="http://10.0.0.1/login",
                username="admin",
                password="secret",
            ),
        )

        loader.save(config)

        saved_path = tmp_path / "http___10.0.0.1.yml"
        assert temporary_modes == [0o600]
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(saved_path.stat().st_mode) == 0o600


def test_setup_config_is_atomic_and_owner_only(tmp_path, monkeypatch):
    class Config:
        DEFAULT_CONFIG_PATH = tmp_path / ".clearwing" / "config.yaml"

        def set(self, *_keys, value):
            return None

    class Console:
        def print(self, *_args, **_kwargs):
            return None

    class CLI:
        config = Config()
        console = Console()

    original_replace = os.replace
    temporary_modes = []

    def inspect_replace(source, destination):
        temporary_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
        original_replace(source, destination)

    monkeypatch.setattr("clearwing.ui.commands.setup.os.replace", inspect_replace)
    _write_config(
        CLI(),
        preset_by_key("openrouter"),
        base_url="https://openrouter.ai/api/v1",
        api_key_literal="secret-api-key",
        model="test-model",
    )

    path = Config.DEFAULT_CONFIG_PATH
    assert temporary_modes == [0o600]
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_anthropic_oauth_state_is_independent_from_pkce(monkeypatch):
    captured = {}

    monkeypatch.setattr(openai_oauth, "generate_pkce", lambda: ("verifier", "challenge"))
    monkeypatch.setattr(openai_oauth, "create_state", lambda: "independent-state")
    monkeypatch.setattr(openai_oauth, "save_anthropic_oauth_credentials", lambda _creds: None)

    def exchange(**kwargs):
        captured.update(kwargs)
        return openai_oauth.AnthropicOAuthCredentials(token="sk-ant-test-token")

    monkeypatch.setattr(openai_oauth, "exchange_anthropic_authorization_code", exchange)
    printed = []

    openai_oauth.login_anthropic_oauth(
        no_open=True,
        input_fn=lambda _prompt: "authorization-code#independent-state",
        print_fn=printed.append,
    )

    authorize_url = next(line.strip() for line in printed if "claude.ai/oauth/authorize" in line)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(authorize_url).query)["state"][0]
    assert state == "independent-state"
    assert state != "verifier"
    assert captured["state"] == "independent-state"
    assert captured["verifier"] == "verifier"

    with pytest.raises(RuntimeError, match="State mismatch"):
        openai_oauth.login_anthropic_oauth(
            no_open=True,
            input_fn=lambda _prompt: "authorization-code",
            print_fn=lambda _line: None,
        )


def test_artifact_master_key_is_atomically_written_owner_only(tmp_path, monkeypatch):
    original_replace = os.replace
    temporary_modes = []

    def inspect_replace(source, destination):
        temporary_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
        original_replace(source, destination)

    monkeypatch.setattr("clearwing.sourcehunt.artifact_store.os.replace", inspect_replace)

    ArtifactStore(base_dir=tmp_path)

    key_path = tmp_path / "keys" / "master.key"
    assert temporary_modes == [0o600]
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_artifact_master_key_repairs_existing_mode(tmp_path):
    key_path = tmp_path / "keys" / "master.key"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o644)

    ArtifactStore(base_dir=tmp_path)

    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


class TestResolveEnv:
    def test_resolve_env_variable(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET", "hunter2")
        result = AuthConfigLoader._resolve_env("${MY_SECRET}")
        assert result == "hunter2"

    def test_plain_string_no_resolution(self):
        result = AuthConfigLoader._resolve_env("plain_value")
        assert result == "plain_value"

    def test_missing_env_returns_empty(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR_12345", raising=False)
        result = AuthConfigLoader._resolve_env("${NONEXISTENT_VAR_12345}")
        assert result == ""

    def test_non_string_value(self):
        result = AuthConfigLoader._resolve_env(42)
        assert result == "42"


class TestLoadForTarget:
    def test_matching_target(self, tmp_path, loader):
        config_file = tmp_path / "myapp.yml"
        config_file.write_text(FORM_YAML.replace("${TARGET_PASSWORD}", "pass"), encoding="utf-8")

        config = loader.load_for_target("http://10.0.0.1")

        assert config is not None
        assert config.target == "http://10.0.0.1"
        assert config.auth_type == "form"

    def test_no_matching_target(self, loader):
        config = loader.load_for_target("http://unknown.host")
        assert config is None

    def test_matching_yaml_extension(self, tmp_path, loader):
        config_file = tmp_path / "myapp.yaml"
        config_file.write_text(API_YAML, encoding="utf-8")

        config = loader.load_for_target("http://api.example.com")

        assert config is not None
        assert config.auth_type == "api"


class TestParseFormAuth:
    def test_parse_form(self, loader):
        raw = yaml.safe_load(FORM_YAML.replace("${TARGET_PASSWORD}", "pass123"))
        config = loader._parse(raw)

        assert config.auth_type == "form"
        assert config.form is not None
        assert config.form.url == "http://10.0.0.1/login"
        assert config.form.username == "admin"
        assert config.form.password == "pass123"
        assert config.form.success_indicator == "Dashboard"
        assert config.form.username_field == "username"
        assert config.form.password_field == "password"
        assert config.form.submit_selector == "button[type=submit]"


class TestParseAPIAuth:
    def test_parse_api_bearer(self, loader):
        raw = yaml.safe_load(API_YAML)
        config = loader._parse(raw)

        assert config.auth_type == "api"
        assert config.api is not None
        assert config.api.auth_type == "bearer"
        assert config.api.token == "tok_abc123"
        assert config.api.header_name == "Authorization"
        assert config.api.header_prefix == "Bearer"


class TestParseCookieAuth:
    def test_parse_cookie(self, loader):
        raw = yaml.safe_load(COOKIE_YAML)
        config = loader._parse(raw)

        assert config.auth_type == "cookie"
        assert config.cookie is not None
        assert config.cookie.cookies == {"session": "abc123", "csrf": "xyz789"}


class TestParseOAuthConfig:
    def test_parse_oauth(self, loader, monkeypatch):
        monkeypatch.setenv("OAUTH_SECRET", "oauth_secret_val")
        raw = yaml.safe_load(OAUTH_YAML)
        config = loader._parse(raw)

        assert config.auth_type == "oauth"
        assert config.oauth is not None
        assert config.oauth.auth_url == "https://auth.example.com/authorize"
        assert config.oauth.token_url == "https://auth.example.com/token"
        assert config.oauth.client_id == "my-client"
        assert config.oauth.client_secret == "oauth_secret_val"
        assert config.oauth.scope == "read write"
        assert config.oauth.redirect_uri == "http://localhost:8080/callback"
