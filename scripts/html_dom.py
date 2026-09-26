"""Small, dependency-free HTML tree used by the scrapers."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Iterator


VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}
IGNORED_ELEMENTS = {"script", "style", "noscript"}


class Element:
    def __init__(self, tag: str, attrs: dict[str, str | None] | None = None):
        self.tag = tag.lower()
        self.attrs = attrs or {}
        self.children: list[Element | str] = []
        self.parent: Element | None = None

    def iter(self, tag: str | None = None) -> Iterator[Element]:
        if tag is None or self.tag == tag.lower():
            yield self
        for child in self.children:
            if isinstance(child, Element):
                yield from child.iter(tag)

    def ancestors(self) -> Iterator[Element]:
        current = self.parent
        while current is not None:
            yield current
            current = current.parent

    def text(self) -> str:
        pieces: list[str] = []

        def collect(node: Element) -> None:
            for child in node.children:
                if isinstance(child, str):
                    pieces.append(child)
                else:
                    collect(child)

        collect(self)
        return re.sub(r"\s+", " ", " ".join(pieces)).strip()

    def has_class(self, fragment: str) -> bool:
        classes = str(self.attrs.get("class") or "").lower().split()
        return any(fragment.lower() in item for item in classes)


class _TreeBuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Element("document")
        self.stack = [self.root]
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in IGNORED_ELEMENTS:
            self.ignored_depth += 1
            return
        if self.ignored_depth:
            return
        node = Element(tag, dict(attrs))
        node.parent = self.stack[-1]
        self.stack[-1].children.append(node)
        if tag not in VOID_ELEMENTS:
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in VOID_ELEMENTS and not self.ignored_depth:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in IGNORED_ELEMENTS:
            if self.ignored_depth:
                self.ignored_depth -= 1
            return
        if self.ignored_depth:
            return
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth and data:
            self.stack[-1].children.append(data)


def parse_html(markup: str) -> Element:
    parser = _TreeBuilder()
    parser.feed(markup)
    parser.close()
    return parser.root


def cell_text(element: Element) -> str:
    return element.text()


def direct_children(element: Element, tag: str) -> list[Element]:
    return [
        child for child in element.children
        if isinstance(child, Element) and child.tag == tag
    ]
