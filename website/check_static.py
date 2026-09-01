#!/usr/bin/env python3
"""Bounded static SEO/accessibility contract checks for the MRML website."""

from html.parser import HTMLParser
from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parent


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.json_ld: list[str] = []
        self._json_parts: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        self.tags.append((tag, values))
        if tag == "script":
            if values.get("type") != "application/ld+json" or "src" in values:
                raise AssertionError("only inline JSON-LD scripts are permitted")
            self._json_parts = []

    def handle_data(self, data: str) -> None:
        if self._json_parts is not None:
            self._json_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._json_parts is not None:
            self.json_ld.append("".join(self._json_parts))
            self._json_parts = None


def one(page: Page, tag: str, **attrs: str) -> dict[str, str]:
    matches = [values for found, values in page.tags if found == tag and all(values.get(k) == v for k, v in attrs.items())]
    assert len(matches) == 1, f"expected one {tag} with {attrs}, found {len(matches)}"
    return matches[0]


def check_page(name: str, canonical: str) -> Page:
    source = (ROOT / name).read_text(encoding="utf-8")
    page = Page()
    page.feed(source)
    one(page, "html", lang="en")
    one(page, "meta", name="viewport")
    one(page, "meta", name="description")
    one(page, "link", rel="canonical", href=canonical)
    one(page, "meta", property="og:title")
    one(page, "meta", property="og:description")
    one(page, "meta", property="og:url", content=canonical)
    one(page, "main", id="content")
    one(page, "a", href="#content", **{"class": "skip-link"})
    one(page, "nav", **{"aria-label": "Primary"})
    one(page, "h1")
    for tag, attrs in page.tags:
        for attribute in ("href", "src"):
            value = attrs.get(attribute, "")
            assert not value.startswith("//"), f"protocol-relative asset in {name}"
        if tag in {"script", "link", "img"} and "src" in attrs:
            assert not attrs["src"].startswith(("http://", "https://")), f"external asset in {name}"
    return page


def main() -> int:
    home = check_page("index.html", "https://mrml.ca/")
    privacy = check_page("privacy.html", "https://mrml.ca/privacy.html")
    kinds = {json.loads(value).get("@type") for value in home.json_ld}
    assert kinds == {"Organization", "WebSite"}, f"unexpected JSON-LD types: {kinds}"
    one(privacy, "nav", **{"aria-label": "Breadcrumb"})
    css = (ROOT / "styles.css").read_text(encoding="utf-8")
    assert ":focus-visible" in css
    assert "prefers-reduced-motion: reduce" in css
    legacy = ROOT.parent / "gitea-custom"
    assert not any(path.is_file() for path in legacy.rglob("*")), "legacy Gitea runtime customization remains"
    print("static website contract: 2 pages passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"static website contract failed: {error}", file=sys.stderr)
        raise SystemExit(1)
