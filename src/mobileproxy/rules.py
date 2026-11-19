"""Rule model, matching and body transformations (patches)."""
from __future__ import annotations

import fnmatch
import json
import re
import time
import uuid
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class RuleMatch(BaseModel):
    """Which exchanges a rule applies to. All set fields must match."""

    server: str = Field("*", description="Glob on server id 'host:port' (or alias), e.g. 'test.example.com:80' or '*'.")
    method: Optional[str] = Field(None, description="HTTP method, e.g. GET/POST. None = any.")
    path: str = Field("*", description="Glob on URL path without query, e.g. '/api/meta/*'.")
    query: Optional[str] = Field(None, description="Glob on raw query string (without '?'). None = any.")
    soap_op: Optional[str] = Field(None, description="SOAP operation name (glob), e.g. 'getMetadata'. None = any.")
    body_contains: Optional[str] = Field(None, description="Request body must contain this substring.")
    body_regex: Optional[str] = Field(None, description="Request body must match this regex (search, DOTALL).")
    body_equals: Optional[str] = Field(
        None, description="Request body must equal this (compared normalized: JSON key order / whitespace between XML tags ignored).")
    body_json: Optional[dict[str, Any]] = Field(
        None, description="JSON request body conditions {JSONPath: expected value}; null value = path must exist. E.g. {'$.filter.layer': 'KABEL'}.")
    body_xpath: Optional[dict[str, Optional[str]]] = Field(
        None, description="XML/SOAP request body conditions {XPath: expected text}; null = must exist. E.g. {\"//*[local-name()='id']\": '12'}.")


class Patch(BaseModel):
    """One transformation of the response body."""

    type: Literal["jsonpath", "xpath", "regex"]
    path: Optional[str] = Field(None, description="JSONPath (e.g. $.items[0].name) or XPath (e.g. //*[local-name()='code']).")
    op: Literal["set", "delete", "append", "set_attr", "insert_xml"] = Field(
        "set",
        description="jsonpath: set|delete|append. xpath: set (element text)|delete|set_attr|insert_xml (append child parsed from value).",
    )
    value: Any = Field(None, description="New value (JSON value for jsonpath, string for xpath).")
    attr: Optional[str] = Field(None, description="Attribute name for xpath set_attr.")
    namespaces: Optional[dict[str, str]] = Field(None, description="XPath namespace prefixes, e.g. {'s': 'http://schemas.xmlsoap.org/soap/envelope/'}.")
    pattern: Optional[str] = Field(None, description="Regex pattern (type=regex).")
    replacement: Optional[str] = Field(None, description="Regex replacement, supports \\1 groups (type=regex).")
    count: int = Field(0, description="Regex: max replacements, 0 = all.")


class Rule(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str = ""
    enabled: bool = True
    match: RuleMatch = Field(default_factory=RuleMatch)
    action: Literal["replace", "patch", "delay", "drop"] = Field(
        "replace",
        description="replace = whole response body/status; patch = apply patches to body; delay = only delay; drop = kill connection.",
    )
    status: Optional[int] = Field(None, description="Override HTTP status (replace/patch).")
    headers: Optional[dict[str, str]] = Field(None, description="Response headers to set (replace/patch). Empty string value removes header.")
    body: Optional[str] = Field(None, description="Response body for action=replace.")
    mock: bool = Field(False, description="replace only: answer directly without contacting the server.")
    patches: list[Patch] = Field(default_factory=list)
    delay_ms: int = Field(0, description="Delay before the response is returned to the app (any action).")
    remaining: Optional[int] = Field(None, description="Apply only N more times, None = always. Rule disables itself at 0.")
    hits: int = 0
    created: float = Field(default_factory=time.time)
    note: str = ""


def _glob(pattern: Optional[str], value: Optional[str]) -> bool:
    if pattern is None or pattern == "*":
        return True
    return fnmatch.fnmatchcase((value or ""), pattern)


def normalize_body(text: Optional[str]) -> str:
    """Canonical form of a request body for comparison and grouping."""
    if not text:
        return ""
    t = text.strip()
    if t[:1] in ("{", "["):
        try:
            return json.dumps(json.loads(t), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except Exception:  # noqa: BLE001
            pass
    if t.startswith("<"):
        return re.sub(r">\s+<", "><", t)
    return t


class RequestBody:
    """Lazily parsed request body shared by all rules evaluated for one request."""

    def __init__(self, text: Optional[str]):
        self.text = text or ""
        self._norm: Optional[str] = None
        self._json: Any = ...
        self._xml: Any = ...

    @property
    def norm(self) -> str:
        if self._norm is None:
            self._norm = normalize_body(self.text)
        return self._norm

    def json(self) -> Any:
        if self._json is ...:
            try:
                self._json = json.loads(self.text)
            except Exception:  # noqa: BLE001
                self._json = None
        return self._json

    def xml(self) -> Any:
        if self._xml is ...:
            try:
                from lxml import etree
                parser = etree.XMLParser(resolve_entities=False, no_network=True)
                self._xml = etree.fromstring(self.text.encode("utf-8"), parser)
            except Exception:  # noqa: BLE001
                self._xml = None
        return self._xml


def _loose_eq(a: Any, b: Any) -> bool:
    return a == b or (not isinstance(a, (dict, list)) and str(a) == str(b)) or (
        isinstance(a, bool) and str(a).lower() == str(b).lower())


def _body_json_ok(body: RequestBody, conds: dict[str, Any]) -> bool:
    from jsonpath_ng.ext import parse
    data = body.json()
    if data is None:
        return False
    for path, expected in conds.items():
        try:
            vals = [m.value for m in parse(path).find(data)]
        except Exception:  # noqa: BLE001
            return False
        if not vals:
            return False
        if expected is not None and not any(_loose_eq(v, expected) for v in vals):
            return False
    return True


def _body_xpath_ok(body: RequestBody, conds: dict[str, Optional[str]]) -> bool:
    root = body.xml()
    if root is None:
        return False
    for path, expected in conds.items():
        try:
            res = root.xpath(path)
        except Exception:  # noqa: BLE001
            return False
        if isinstance(res, (bool, float, str)):
            res = [res]
        if not res:
            return False
        if expected is None:
            continue
        texts = []
        for r in res:
            if hasattr(r, "itertext"):
                texts.append("".join(r.itertext()).strip())
            else:
                texts.append(str(r).strip())
        if str(expected) not in texts:
            return False
    return True


def rule_matches(rule: Rule, *, server_id: str, alias: str, method: str, path: str, query: str,
                 soap_op: Optional[str], request_body: "str | RequestBody") -> bool:
    m = rule.match
    if not (_glob(m.server, server_id) or (alias and _glob(m.server, alias))):
        return False
    if m.method and m.method.upper() != method.upper():
        return False
    if not _glob(m.path, path):
        return False
    if m.query is not None and not _glob(m.query, query):
        return False
    if m.soap_op is not None and not _glob(m.soap_op, soap_op or ""):
        return False
    body = request_body if isinstance(request_body, RequestBody) else RequestBody(request_body)
    if m.body_contains and m.body_contains not in body.text:
        return False
    if m.body_regex:
        try:
            if not re.search(m.body_regex, body.text, re.S):
                return False
        except re.error:
            return False
    if m.body_equals is not None and normalize_body(m.body_equals) != body.norm:
        return False
    if m.body_json and not _body_json_ok(body, m.body_json):
        return False
    if m.body_xpath and not _body_xpath_ok(body, m.body_xpath):
        return False
    return True


# ---------------------------------------------------------------- patches

class PatchError(Exception):
    pass


def _apply_jsonpath(text: str, p: Patch) -> str:
    from jsonpath_ng.ext import parse

    try:
        data = json.loads(text)
    except Exception as e:  # noqa: BLE001
        raise PatchError(f"body is not JSON: {e}") from e
    if not p.path:
        raise PatchError("jsonpath patch needs 'path'")
    try:
        expr = parse(p.path)
    except Exception as e:  # noqa: BLE001
        raise PatchError(f"invalid JSONPath {p.path!r}: {e}") from e
    if p.op == "set":
        if expr.find(data):
            data = expr.update(data, p.value)
        else:
            data = expr.update_or_create(data, p.value)
    elif p.op == "delete":
        matches = expr.find(data)
        if not matches:
            raise PatchError(f"JSONPath {p.path!r} matched nothing")
        data = expr.filter(lambda _v: True, data)
    elif p.op == "append":
        matches = expr.find(data)
        if not matches:
            raise PatchError(f"JSONPath {p.path!r} matched nothing")
        for mt in matches:
            if not isinstance(mt.value, list):
                raise PatchError(f"JSONPath {p.path!r} does not point to a list")
            mt.value.append(p.value)
    else:
        raise PatchError(f"op {p.op!r} not supported for jsonpath")
    compact = not ("\n" in text.strip())
    if compact:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(data, ensure_ascii=False, indent=2)


def _apply_xpath(text: str, p: Patch) -> str:
    from lxml import etree

    if not p.path:
        raise PatchError("xpath patch needs 'path'")
    raw = text.encode("utf-8")
    had_decl = text.lstrip().startswith("<?xml")
    try:
        parser = etree.XMLParser(remove_blank_text=False, resolve_entities=False, no_network=True)
        root = etree.fromstring(raw, parser)
    except Exception as e:  # noqa: BLE001
        raise PatchError(f"body is not XML: {e}") from e
    try:
        nodes = root.xpath(p.path, namespaces=p.namespaces or None)
    except Exception as e:  # noqa: BLE001
        raise PatchError(f"invalid XPath {p.path!r}: {e}") from e
    if not isinstance(nodes, list) or not nodes:
        raise PatchError(f"XPath {p.path!r} matched nothing")
    for n in nodes:
        if isinstance(n, etree._ElementUnicodeResult) or isinstance(n, str):  # attribute / text result
            if p.op != "set":
                raise PatchError("XPath points to an attribute/text; only op=set is supported for it")
            parent = n.getparent()
            if n.is_attribute:
                parent.set(n.attrname, "" if p.value is None else str(p.value))
            elif n.is_text:
                parent.text = "" if p.value is None else str(p.value)
            else:
                raise PatchError("unsupported XPath result")
            continue
        if p.op == "set":
            for ch in list(n):
                n.remove(ch)
            n.text = "" if p.value is None else str(p.value)
        elif p.op == "delete":
            parent = n.getparent()
            if parent is None:
                raise PatchError("cannot delete root element")
            parent.remove(n)
        elif p.op == "set_attr":
            if not p.attr:
                raise PatchError("set_attr needs 'attr'")
            if p.value is None:
                n.attrib.pop(p.attr, None)
            else:
                n.set(p.attr, str(p.value))
        elif p.op == "insert_xml":
            try:
                frag = etree.fromstring(str(p.value).encode("utf-8"))
            except Exception as e:  # noqa: BLE001
                raise PatchError(f"insert_xml value is not XML: {e}") from e
            n.append(frag)
        else:
            raise PatchError(f"op {p.op!r} not supported for xpath")
    out = etree.tostring(root, encoding="unicode")
    if had_decl:
        out = '<?xml version="1.0" encoding="utf-8"?>' + out
    return out


def _apply_regex(text: str, p: Patch) -> str:
    if not p.pattern:
        raise PatchError("regex patch needs 'pattern'")
    try:
        rx = re.compile(p.pattern, re.S)
    except re.error as e:
        raise PatchError(f"invalid regex: {e}") from e
    new, n = rx.subn(p.replacement or "", text, count=p.count or 0)
    if n == 0:
        raise PatchError(f"regex {p.pattern!r} matched nothing")
    return new


def apply_patches(text: str, patches: list[Patch]) -> tuple[str, list[str]]:
    """Apply patches in order. Returns (new_text, errors). Failing patch is skipped."""
    errors: list[str] = []
    for i, p in enumerate(patches):
        try:
            if p.type == "jsonpath":
                text = _apply_jsonpath(text, p)
            elif p.type == "xpath":
                text = _apply_xpath(text, p)
            elif p.type == "regex":
                text = _apply_regex(text, p)
        except PatchError as e:
            errors.append(f"patch #{i + 1} ({p.type}): {e}")
        except Exception as e:  # noqa: BLE001
            errors.append(f"patch #{i + 1} ({p.type}): unexpected error {e!r}")
    return text, errors
