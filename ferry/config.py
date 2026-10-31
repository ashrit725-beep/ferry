"""Configuration loading.

Ferry reads one TOML file (ferry.toml). Unknown keys are rejected so that a typo
in a security setting fails loudly instead of silently using a default.
Settings that weaken security (public backends, pickle, executables, signer
roles) live only here, on the host: the web console can show them but not
change them.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from .errors import ConfigError

DEFAULT_PORT = 8750
CONFIG_FILENAME = "ferry.toml"
SIGNER_ROLES = ("publisher", "reviewer")
ARTIFACT_KINDS = ("model", "tokenizer", "config", "document", "file")
MODEL_FORMATS = ("gguf", "safetensors", "pickle")
_LICENSE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$")


@dataclass(frozen=True)
class ServerSettings:
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    tls_cert_file: str = ""
    tls_key_file: str = ""
    # "auto" marks the session cookie Secure unless the console is served over
    # plain HTTP on a loopback address.
    cookie_secure: str = "auto"
    cors_origins: tuple[str, ...] = ()
    # Addresses (or networks) of reverse proxies whose X-Forwarded-For/-Proto headers
    # are believed. Empty: the headers are ignored and the TCP peer is the client.
    trusted_proxies: tuple[str, ...] = ()
    max_body_bytes: int = 1_048_576
    session_idle_minutes: int = 30
    session_max_hours: int = 8


@dataclass(frozen=True)
class GatewaySettings:
    max_concurrency: int = 8
    queue_timeout_s: float = 10.0
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 120.0
    # Backends must resolve to loopback/private addresses unless this is true.
    allow_public_backends: bool = False
    health_interval_s: float = 30.0
    # Hard upper bound on max_tokens regardless of what a policy allows.
    max_tokens_ceiling: int = 8192


@dataclass(frozen=True)
class ImportSettings:
    inbox_dir: str = ""
    trust_dir: str = ""
    required_roles: tuple[str, ...] = ("publisher",)
    distinct_signers: bool = True
    allowed_kinds: tuple[str, ...] = ("model", "tokenizer", "config", "document")
    allowed_model_formats: tuple[str, ...] = ("gguf", "safetensors")
    allow_pickle: bool = False
    allow_executables: bool = False
    allowed_licenses: tuple[str, ...] = ("Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause")
    max_bundle_bytes: int = 200 * 1024**3
    max_artifact_bytes: int = 100 * 1024**3
    max_artifacts: int = 1000
    max_manifest_bytes: int = 4 * 1024**2


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    server: ServerSettings = field(default_factory=ServerSettings)
    gateway: GatewaySettings = field(default_factory=GatewaySettings)
    imports: ImportSettings = field(default_factory=ImportSettings)
    config_path: Path | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "ferry.db"

    @property
    def store_dir(self) -> Path:
        return self.data_dir / "store"

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def inbox_dir(self) -> Path:
        return Path(self.imports.inbox_dir) if self.imports.inbox_dir else self.data_dir / "inbox"

    @property
    def trust_dir(self) -> Path:
        return Path(self.imports.trust_dir) if self.imports.trust_dir else self.data_dir / "trust"

    def public_dict(self) -> dict[str, Any]:
        """Effective configuration for display and evidence. Contains no secrets."""
        return {
            "config_path": str(self.config_path) if self.config_path else None,
            "data_dir": str(self.data_dir),
            "inbox_dir": str(self.inbox_dir),
            "trust_dir": str(self.trust_dir),
            "server": _plain(asdict(self.server)),
            "gateway": _plain(asdict(self.gateway)),
            "import": _plain(asdict(self.imports)),
        }


def _plain(d: dict[str, Any]) -> dict[str, Any]:
    return {k: list(v) if isinstance(v, tuple) else v for k, v in d.items()}


def _coerce(where: str, default: Any, value: Any) -> Any:
    # bool is a subclass of int, so it has to be checked first.
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be true or false")
        return value
    if isinstance(default, int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where} must be an integer")
        return value
    if isinstance(default, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where} must be a number")
        return float(value)
    if isinstance(default, str):
        if not isinstance(value, str):
            raise ConfigError(f"{where} must be a string")
        return value
    if isinstance(default, tuple):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where} must be a list of strings")
        return tuple(value)
    raise ConfigError(f"{where}: unsupported setting type")


def _section(cls: type, raw: Any, name: str) -> Any:
    if raw is None:
        return cls()
    if not isinstance(raw, dict):
        raise ConfigError(f"[{name}] must be a table")
    known = {f.name for f in fields(cls)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"unknown setting(s) in [{name}]: {', '.join(unknown)}")
    defaults = cls()
    values = {key: _coerce(f"[{name}].{key}", getattr(defaults, key), raw[key]) for key in raw}
    return cls(**values)


def _require_subset(where: str, values: tuple[str, ...], allowed: tuple[str, ...]) -> None:
    bad = [v for v in values if v not in allowed]
    if bad:
        raise ConfigError(f"{where}: unsupported value(s) {', '.join(bad)}; allowed: {', '.join(allowed)}")
    if len(set(values)) != len(values):
        raise ConfigError(f"{where}: duplicate values")


def validate(settings: Settings) -> None:
    s, g, i = settings.server, settings.gateway, settings.imports
    if not 1 <= s.port <= 65535:
        raise ConfigError("[server].port must be between 1 and 65535")
    if s.cookie_secure not in ("auto", "true", "false"):
        raise ConfigError('[server].cookie_secure must be "auto", "true" or "false"')
    if bool(s.tls_cert_file) != bool(s.tls_key_file):
        raise ConfigError("[server]: set both tls_cert_file and tls_key_file, or neither")
    if not 1024 <= s.max_body_bytes <= 64 * 1024**2:
        raise ConfigError("[server].max_body_bytes must be between 1024 and 67108864")
    for origin in s.cors_origins:
        if origin == "*" or not re.fullmatch(r"https?://[A-Za-z0-9.\-\[\]:]+", origin):
            raise ConfigError(f"[server].cors_origins: {origin!r} must be an explicit http(s)://host[:port] origin")
    for proxy in s.trusted_proxies:
        try:
            ipaddress.ip_network(proxy)  # strict, as uvicorn parses it: 10.0.0.0/8, not 10.0.0.1/8
        except ValueError:
            raise ConfigError(f"[server].trusted_proxies: {proxy!r} is not an IP address or network; list the "
                              'reverse proxy\'s own address, e.g. ["127.0.0.1"]') from None
    if not 1 <= s.session_idle_minutes <= 24 * 60 or not 1 <= s.session_max_hours <= 24 * 7:
        raise ConfigError("[server]: session_idle_minutes must be 1-1440 and session_max_hours 1-168")
    if not 1 <= g.max_concurrency <= 1024:
        raise ConfigError("[gateway].max_concurrency must be between 1 and 1024")
    for key in ("queue_timeout_s", "connect_timeout_s", "read_timeout_s"):
        if not 0 < getattr(g, key) <= 3600:
            raise ConfigError(f"[gateway].{key} must be greater than 0 and at most 3600")
    if g.health_interval_s < 0:
        raise ConfigError("[gateway].health_interval_s must be 0 (disabled) or positive")
    if not 1 <= g.max_tokens_ceiling <= 1_000_000:
        raise ConfigError("[gateway].max_tokens_ceiling must be between 1 and 1000000")
    if not i.required_roles:
        raise ConfigError("[import].required_roles must name at least one signer role")
    _require_subset("[import].required_roles", i.required_roles, SIGNER_ROLES)
    _require_subset("[import].allowed_kinds", i.allowed_kinds, ARTIFACT_KINDS)
    _require_subset("[import].allowed_model_formats", i.allowed_model_formats, MODEL_FORMATS)
    if "pickle" in i.allowed_model_formats and not i.allow_pickle:
        raise ConfigError('[import]: "pickle" is listed in allowed_model_formats but allow_pickle is false; '
                          "pickle loading executes code, so both must be set explicitly")
    for lic in i.allowed_licenses:
        if not _LICENSE_ID.fullmatch(lic):
            raise ConfigError(f"[import].allowed_licenses: {lic!r} is not an SPDX-style identifier")
    for key in ("max_bundle_bytes", "max_artifact_bytes", "max_artifacts", "max_manifest_bytes"):
        if getattr(i, key) <= 0:
            raise ConfigError(f"[import].{key} must be positive")


def load_settings(config_path: str | Path | None = None, data_dir: str | Path | None = None) -> Settings:
    """Load settings from (in order of precedence) arguments, FERRY_CONFIG / FERRY_DATA_DIR, ferry.toml."""
    env_config = os.environ.get("FERRY_CONFIG")
    env_data = os.environ.get("FERRY_DATA_DIR")
    path = Path(config_path) if config_path else (Path(env_config) if env_config else None)
    data = Path(data_dir) if data_dir else (Path(env_data) if env_data else None)
    if path is None and data is not None and (data / CONFIG_FILENAME).is_file():
        path = data / CONFIG_FILENAME

    raw: dict[str, Any] = {}
    if path is not None:
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ConfigError(f"config file not found: {path}") from None
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: invalid TOML: {exc}") from None
    unknown = sorted(set(raw) - {"data_dir", "server", "gateway", "import"})
    if unknown:
        raise ConfigError(f"unknown top-level setting(s): {', '.join(unknown)}")

    base = path.parent if path is not None else Path.cwd()
    if data is None and "data_dir" in raw:
        if not isinstance(raw["data_dir"], str) or not raw["data_dir"]:
            raise ConfigError("data_dir must be a non-empty string")
        data = Path(raw["data_dir"])
        if not data.is_absolute():
            data = base / data
    if data is None:
        raise ConfigError("no data directory: pass --data-dir, set FERRY_DATA_DIR, or set data_dir in ferry.toml")

    imports = _section(ImportSettings, raw.get("import"), "import")
    for key in ("inbox_dir", "trust_dir"):
        value = getattr(imports, key)
        if value and not Path(value).is_absolute():
            imports = replace(imports, **{key: str((base / value).resolve())})

    settings = Settings(
        data_dir=data.resolve(),
        server=_section(ServerSettings, raw.get("server"), "server"),
        gateway=_section(GatewaySettings, raw.get("gateway"), "gateway"),
        imports=imports,
        config_path=path.resolve() if path is not None else None,
    )
    validate(settings)
    return settings


def _toml_str(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def default_config_toml(data_dir: Path) -> str:
    """The commented ferry.toml written by `ferry init`."""
    return f"""# Ferry configuration. Unknown keys are rejected so typos fail loudly.
data_dir = "{_toml_str(data_dir)}"

[server]
host = "127.0.0.1"          # bind address for the gateway API and console
port = {DEFAULT_PORT}
# tls_cert_file = "/etc/ferry/tls/cert.pem"
# tls_key_file = "/etc/ferry/tls/key.pem"
cookie_secure = "auto"      # auto | true | false
cors_origins = []           # the console is same-origin; leave empty unless you know you need it
trusted_proxies = []        # reverse proxy addresses whose X-Forwarded-For/-Proto are believed (none by default)
max_body_bytes = 1048576    # largest request body accepted by the gateway

[gateway]
max_concurrency = 8         # requests in flight across all backends
queue_timeout_s = 10.0      # how long a request may wait for a free slot
connect_timeout_s = 5.0
read_timeout_s = 120.0
allow_public_backends = false   # backends must resolve to loopback/private addresses
health_interval_s = 30.0        # background backend health checks; 0 disables
max_tokens_ceiling = 8192       # hard cap on max_tokens, whatever the policy says

[import]
# inbox_dir = "/media/transfer"    # default: <data_dir>/inbox
# trust_dir = "/etc/ferry/trust"   # default: <data_dir>/trust
required_roles = ["publisher"]     # ["publisher", "reviewer"] requires a second, independent signature
distinct_signers = true            # one key cannot satisfy two required roles
allowed_kinds = ["model", "tokenizer", "config", "document"]
allowed_model_formats = ["gguf", "safetensors"]
allow_pickle = false               # pickle-based weights can execute code when loaded
allow_executables = false
allowed_licenses = ["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause"]
max_bundle_bytes = 214748364800    # 200 GiB
max_artifact_bytes = 107374182400  # 100 GiB
max_artifacts = 1000
max_manifest_bytes = 4194304
"""
