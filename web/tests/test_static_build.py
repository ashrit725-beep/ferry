"""Checks on the built console (ferry/static) and the console sources.

The console ships into disconnected networks and is served under a strict
Content-Security-Policy (spec section 9), so the committed build must not
reference anything off-origin, must not need inline script or style, and must
carry its fonts as files. These tests read files only; they need neither Node
nor a browser, so they also run where only Python is installed.

Run: .venv/bin/python -m pytest web/tests -q
"""

from __future__ import annotations

import gzip
import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[1]
ROOT = WEB.parent
STATIC = ROOT / "ferry" / "static"
SRC = WEB / "src"

ALLOWED_PACKAGES = {
    "react", "react-dom", "typescript", "vite", "@vitejs/plugin-react", "@types/react",
    "@types/react-dom", "@fontsource/ibm-plex-sans", "@fontsource/ibm-plex-mono",
}
SCHEME = re.compile(rb"https?://", re.IGNORECASE)
TEXT_SUFFIXES = {".html", ".js", ".mjs", ".css", ".json", ".svg", ".txt", ".md", ".webmanifest"}


def built_files() -> list[Path]:
    return sorted(p for p in STATIC.rglob("*") if p.is_file())


def source_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*") if p.suffix in {".ts", ".tsx", ".css"})


class _Refs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[dict[str, str | None]] = []
        self.links: list[dict[str, str | None]] = []
        self.style_elements = 0
        self.style_attrs: list[str] = []
        self.handler_attrs: list[str] = []
        self.inline_script_text: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        for name, _ in attrs:
            if name == "style":
                self.style_attrs.append(tag)
            if name.startswith("on"):
                self.handler_attrs.append(f"{tag}[{name}]")
        if tag == "script":
            self.scripts.append(a)
            self._in_script = True
        elif tag == "link":
            self.links.append(a)
        elif tag == "style":
            self.style_elements += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_script_text.append(data.strip()[:60])


@pytest.fixture(scope="module")
def index_html() -> str:
    path = STATIC / "index.html"
    assert path.is_file(), "ferry/static/index.html is missing: run `npm run build` in web/"
    return path.read_text(encoding="utf-8")


def _local_target(ref: str, base: Path) -> Path:
    path = ref.split("?", 1)[0].split("#", 1)[0]
    return (STATIC / path.lstrip("/")) if path.startswith("/") else (base.parent / path)


# ----------------------------------------------------------------- build output


def test_build_has_entry_script_styles_and_fonts() -> None:
    names = [p.relative_to(STATIC).as_posix() for p in built_files()]
    assert "index.html" in names
    assert any(n.startswith("assets/") and n.endswith(".js") for n in names)
    assert any(n.startswith("assets/") and n.endswith(".css") for n in names)
    fonts = [n for n in names if n.endswith(".woff2")]
    assert any("ibm-plex-sans" in n for n in fonts) and any("ibm-plex-mono" in n for n in fonts)
    assert not [n for n in names if n.endswith((".ttf", ".otf", ".woff", ".eot"))], "only woff2 fonts are referenced"


def test_no_url_scheme_anywhere_in_the_build() -> None:
    """grep -ri 'https\\?://' ferry/static must come back empty: text and binary files alike."""
    offenders = []
    for path in built_files():
        data = path.read_bytes()
        m = SCHEME.search(data)
        if m:
            offenders.append(f"{path.relative_to(STATIC)}: {data[max(0, m.start() - 30):m.end() + 40]!r}")
    assert not offenders, "\n".join(offenders)


def test_index_html_is_csp_compatible(index_html: str) -> None:
    refs = _Refs()
    refs.feed(index_html)
    assert refs.scripts, "no script tag"
    assert not refs.inline_script_text, f"inline script content: {refs.inline_script_text}"
    assert refs.style_elements == 0, "inline <style> element"
    assert not refs.style_attrs, f"style attributes on {refs.style_attrs}"
    assert not refs.handler_attrs, f"inline event handlers: {refs.handler_attrs}"
    for script in refs.scripts:
        src = script.get("src") or ""
        assert src.startswith("/assets/"), f"script from {src!r}"
        assert _local_target(src, STATIC / "index.html").is_file(), f"missing {src}"
    for link in refs.links:
        href = link.get("href") or ""
        if href.startswith("data:"):
            assert link.get("rel") == "icon" and href == "data:,", f"unexpected data: link {href!r}"
            continue
        assert href.startswith("/assets/"), f"link to {href!r}"
        assert _local_target(href, STATIC / "index.html").is_file(), f"missing {href}"


def test_css_references_only_bundled_files() -> None:
    css_files = [p for p in built_files() if p.suffix == ".css"]
    assert css_files
    for css in css_files:
        text = css.read_text(encoding="utf-8")
        assert "@import" not in text, f"{css.name}: @import"
        for ref in re.findall(r"url\(\s*[\"']?([^\"')\s]+)", text):
            assert not re.match(r"^data:(font|application)/", ref), f"{css.name}: font as data: URI (font-src 'self')"
            if ref.startswith("data:image/"):
                continue
            assert not re.match(r"^[a-z][a-z0-9+.-]*:|^//", ref, re.I), f"{css.name}: off-origin url({ref})"
            assert _local_target(ref, css).resolve().is_file(), f"{css.name}: url({ref}) does not exist"


def test_no_source_maps_service_workers_or_eval() -> None:
    for path in built_files():
        assert path.suffix != ".map", f"source map shipped: {path.name}"
        if path.suffix not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        name = path.relative_to(STATIC)
        assert "sourceMappingURL" not in text, f"{name}: sourceMappingURL"
        assert not re.search(r"serviceWorker", text), f"{name}: service worker reference"
        if path.suffix == ".js":
            assert not re.search(r"(^|[^.\w$])eval\s*\(", text), f"{name}: eval (blocked by script-src 'self')"
            assert not re.search(r"new\s+Function\s*\(", text), f"{name}: new Function (blocked by script-src 'self')"


def test_bundle_size_budget() -> None:
    """Catches an accidental heavy dependency; today the JS is ~380 KiB raw, ~107 KiB gzip."""
    js = sum(p.stat().st_size for p in built_files() if p.suffix == ".js")
    js_gz = sum(len(gzip.compress(p.read_bytes(), 9)) for p in built_files() if p.suffix == ".js")
    css = sum(p.stat().st_size for p in built_files() if p.suffix == ".css")
    total = sum(p.stat().st_size for p in built_files())
    assert js < 600 * 1024, f"JS is {js} bytes"
    assert js_gz < 180 * 1024, f"JS is {js_gz} bytes gzipped"
    assert css < 80 * 1024, f"CSS is {css} bytes"
    assert total < 1024 * 1024, f"build is {total} bytes"


# ----------------------------------------------------------------- sources


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(^|[^:])//[^\n]*", r"\1", text)


def test_only_the_api_client_calls_fetch() -> None:
    callers = [p.relative_to(SRC).as_posix() for p in source_files()
               if re.search(r"\bfetch\s*\(", _strip_comments(p.read_text(encoding="utf-8")))]
    assert callers == ["api.ts"], callers


@pytest.mark.parametrize("pattern, why", [
    (r"dangerouslySetInnerHTML|\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML|document\.write", "renders HTML from strings"),
    (r"(^|[^.\w$])eval\s*\(|new\s+Function\s*\(", "evaluates code"),
    (r"localStorage|sessionStorage|indexedDB|document\.cookie", "stores data in the browser"),
    (r"serviceWorker|importScripts", "service worker"),
    (r"console\.(log|debug|info|warn|error|trace)\s*\(", "logs to the browser console (could leak keys)"),
    (r"https?://", "literal URL"),
    (r"target=[\"']_blank", "opens new windows"),
    (r"window\.open\s*\(", "opens new windows"),
    (r"style=\{\{", "inline style props (use CSS classes)"),
])
def test_sources_avoid(pattern: str, why: str) -> None:
    hits = []
    for path in source_files():
        text = path.read_text(encoding="utf-8")
        if path.suffix != ".css":
            text = _strip_comments(text)
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(pattern, line):
                hits.append(f"{path.relative_to(SRC)}:{i}: {line.strip()[:100]}")
    assert not hits, f"{why}:\n" + "\n".join(hits)


def test_no_any_types() -> None:
    hits = []
    for path in source_files():
        if path.suffix == ".css":
            continue
        for i, line in enumerate(_strip_comments(path.read_text(encoding="utf-8")).splitlines(), 1):
            if re.search(r":\s*any\b|\bas\s+any\b|<any>|any\[\]", line):
                hits.append(f"{path.relative_to(SRC)}:{i}: {line.strip()}")
    assert not hits, "\n".join(hits)


def test_every_non_get_request_goes_through_request_with_csrf() -> None:
    api = (SRC / "api.ts").read_text(encoding="utf-8")
    assert "headers['X-Ferry-CSRF'] = '1'" in api
    assert "credentials: 'same-origin'" in api
    assert "redirect: 'error'" in api
    assert "cache: 'no-store'" in api


def test_index_html_source_has_no_inline_code() -> None:
    refs = _Refs()
    refs.feed((WEB / "index.html").read_text(encoding="utf-8"))
    assert not refs.inline_script_text and refs.style_elements == 0 and not refs.style_attrs and not refs.handler_attrs


# ----------------------------------------------------------------- dependencies and tooling


def test_dependencies_are_the_allowed_set_pinned_exactly() -> None:
    pkg = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    assert set(deps) == ALLOWED_PACKAGES, sorted(set(deps) ^ ALLOWED_PACKAGES)
    for name, version in deps.items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"{name} is not pinned exactly: {version}"


def test_lockfile_matches_and_resolves_from_the_registry_only() -> None:
    lock = json.loads((WEB / "package-lock.json").read_text(encoding="utf-8"))
    pkg = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
    root = lock["packages"][""]
    assert root.get("dependencies", {}) == pkg.get("dependencies", {})
    assert root.get("devDependencies", {}) == pkg.get("devDependencies", {})
    for name, entry in lock["packages"].items():
        if not name:
            continue
        resolved = entry.get("resolved", "")
        assert resolved.startswith("https://registry.npmjs.org/"), f"{name}: {resolved}"
        assert entry.get("integrity", "").startswith("sha512-"), f"{name}: no sha512 integrity"
    for name in ALLOWED_PACKAGES:
        assert lock["packages"][f"node_modules/{name}"]["version"] == {**pkg["dependencies"], **pkg["devDependencies"]}[name]


def test_npmrc_disables_install_scripts() -> None:
    lines = {line.strip() for line in (WEB / ".npmrc").read_text(encoding="utf-8").splitlines()}
    assert "ignore-scripts=true" in lines
    assert "save-exact=true" in lines


def test_vite_config_targets_ferry_static_and_proxies_the_backend() -> None:
    cfg = (WEB / "vite.config.ts").read_text(encoding="utf-8")
    assert "outDir: '../ferry/static'" in cfg
    assert "emptyOutDir: true" in cfg
    assert "base: '/'" in cfg
    assert "sourcemap: false" in cfg
    assert "assetsInlineLimit: 0" in cfg
    assert "target: 'http://127.0.0.1:8750'" in cfg
    for prefix in ("'/api'", "'/v1'", "'/healthz'"):
        assert prefix in cfg
