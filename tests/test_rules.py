import json

from mobileproxy.addon import detect_soap_op
from mobileproxy.rules import Patch, Rule, RuleMatch, apply_patches, rule_matches

SOAP = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body><getDataResponse xmlns="urn:x"><item code="1">A</item><item code="2">B</item></getDataResponse>'
        '</soap:Body></soap:Envelope>')


def m(rule, **kw):
    base = dict(server_id="srv:80", alias="", method="GET", path="/api/meta", query="", soap_op=None, request_body="")
    base.update(kw)
    return rule_matches(rule, **base)


def test_match_globs_and_soap():
    r = Rule(match=RuleMatch(server="srv:*", path="/api/*", soap_op="get*"))
    assert m(r, soap_op="getData")
    assert not m(r, soap_op="keepAlive")
    assert not m(r, path="/other")
    assert m(Rule(match=RuleMatch(server="test")), alias="test")


def test_jsonpath_ops():
    src = json.dumps({"items": [{"v": 1}, {"v": 2}]})
    out, err = apply_patches(src, [
        Patch(type="jsonpath", path="$.items[*].v", op="set", value=0),
        Patch(type="jsonpath", path="$.items", op="append", value={"v": 9}),
        Patch(type="jsonpath", path="$.new", op="set", value="x"),
        Patch(type="jsonpath", path="$.items[0]", op="delete"),
    ])
    assert not err
    assert json.loads(out) == {"items": [{"v": 0}, {"v": 9}], "new": "x"}


def test_xpath_ops():
    out, err = apply_patches(SOAP, [
        Patch(type="xpath", path="//*[local-name()='item'][@code='1']", op="set", value="Z"),
        Patch(type="xpath", path="//*[local-name()='item'][@code='2']", op="delete"),
        Patch(type="xpath", path="//*[local-name()='item']/@code", op="set", value="7"),
        Patch(type="xpath", path="//x:getDataResponse", op="insert_xml", value="<extra/>", namespaces={"x": "urn:x"}),
    ])
    assert not err, err
    assert out.startswith("<?xml")
    assert 'code="7">Z</item>' in out and ">B<" not in out and "<extra/>" in out


def test_errors_are_reported_not_raised():
    out, err = apply_patches("not json", [Patch(type="jsonpath", path="$.a", op="set", value=1),
                                          Patch(type="regex", pattern="not", replacement="NOT")])
    assert out == "NOT json"
    assert len(err) == 1 and "not JSON" in err[0]


def test_detect_soap_op():
    assert detect_soap_op({"SOAPAction": '"http://www.berit.com/wsdl/StatusService/keepAlive"'}, "") == "keepAlive"
    assert detect_soap_op({}, '<s:Envelope xmlns:s="x"><s:Body>\n  <ns:getData xmlns:ns="y"/></s:Body></s:Envelope>') == "getData"
    assert detect_soap_op({"content-type": 'application/soap+xml; action="urn:op#doIt"'}, "") == "doIt"
    assert detect_soap_op({}, '{"a":1}') is None


def test_body_conditions():
    from mobileproxy.rules import normalize_body
    jb = '{"filter": {"layer": "KABEL", "ids": [1, 2]}, "page": 1}'
    xb = ('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><getFeature xmlns="urn:x">'
          '<id>12</id><layer code="K"/></getFeature></s:Body></s:Envelope>')
    assert m(Rule(match=RuleMatch(body_json={"$.filter.layer": "KABEL"})), request_body=jb)
    assert m(Rule(match=RuleMatch(body_json={"$.filter.ids[*]": 2, "$.page": "1"})), request_body=jb)
    assert not m(Rule(match=RuleMatch(body_json={"$.filter.layer": "SLOUP"})), request_body=jb)
    assert m(Rule(match=RuleMatch(body_json={"$.page": None})), request_body=jb)
    assert not m(Rule(match=RuleMatch(body_json={"$.missing": None})), request_body=jb)
    assert m(Rule(match=RuleMatch(body_xpath={"//*[local-name()='id']": "12"})), request_body=xb)
    assert m(Rule(match=RuleMatch(body_xpath={"//*[local-name()='layer']/@code": "K"})), request_body=xb)
    assert not m(Rule(match=RuleMatch(body_xpath={"//*[local-name()='id']": "13"})), request_body=xb)
    assert m(Rule(match=RuleMatch(body_regex=r"<id>1\d</id>")), request_body=xb)
    # equals is normalized: key order and whitespace do not matter
    assert m(Rule(match=RuleMatch(body_equals='{ "page":1, "filter":{"ids":[1,2],"layer":"KABEL"} }')), request_body=jb)
    assert not m(Rule(match=RuleMatch(body_equals='{"page":2}')), request_body=jb)
    assert normalize_body("<a>\n  <b>1</b>\n</a>") == "<a><b>1</b></a>"
    # body conditions on a body-less request never match
    assert not m(Rule(match=RuleMatch(body_json={"$.a": None})), request_body="")


def test_signature_and_preview():
    from mobileproxy.addon import body_preview, body_signature
    assert body_signature("GET", "x") == ""
    assert body_signature("POST", '{"a":1,"b":2}') == body_signature("POST", '{ "b": 2, "a": 1 }')
    assert body_signature("POST", '{"a":1}') != body_signature("POST", '{"a":2}')
    xb = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\n'
          '  <ns1:getFeature xmlns:ns1="urn:x"><ns1:id>12</ns1:id></ns1:getFeature></soap:Body></soap:Envelope>')
    assert body_preview(xb) == "id=12"
    ext = ('<ber:describeExtension service="Extension" version="1.0.0" handle="" xmlns:ber="http://www.berit.com/ber">'
           '<ber:extension id="samo-mobile" cacheTime="1.1.2000 0:00:00" /></ber:describeExtension>')
    assert body_preview(ext) == "extension(id=samo-mobile, cacheTime=1.1.2000 0:00:00)"
    ka = '<s:Envelope xmlns:s="x"><s:Body><keepAlive xmlns="y"/></s:Body></s:Envelope>'
    assert body_preview(ka) == "keepAlive"
    nested = '<s:Envelope xmlns:s="x"><s:Body><find><filter layer="K"><id>1</id><id>2</id></filter><page>1</page></find></s:Body></s:Envelope>'
    assert body_preview(nested) == "filter(layer=K){id=1 id=2} page=1"
    assert body_preview("<broken") == "<broken"
    assert body_preview('{ "a": 1 }') == '{"a":1}'


def test_default_categories(tmp_path):
    from mobileproxy.store import Store
    st = Store(tmp_path)
    c = st.classify
    # metadata
    assert c("POST", "/samo/ExtensionService", "", None) == "metadata"
    assert c("GET", "/samo/api/rest/metadata/all", "output=groups&groups=x&expanded=true", None) == "metadata"
    assert c("GET", "/samo/rest/metadata/project-info", "", None) == "metadata"
    assert c("GET", "/samo/api/rest/codelists/by-type/12/list", "output=properties", None) == "metadata"
    assert c("POST", "/samo/api/rest/codelists/query", "", None) == "metadata"
    assert c("GET", "/samo/rest/cross-section/feature-types", "", None) == "metadata"
    assert c("GET", "/samo/api/rest/resources/by-id/5/content", "", None) == "metadata"
    assert c("GET", "/gis/WebMapService", "SERVICE=WMS&REQUEST=GetCapabilities", None) == "metadata"
    # data
    assert c("POST", "/samo/api/rest/features/query", "stream=true", None) == "data"
    assert c("GET", "/samo/rest/business/entity/t/10/20", "", None) == "data"
    assert c("POST", "/samo/rest/search/features", "", None) == "data"
    assert c("GET", "/samo/rest/cross-section/10/20", "", None) == "data"
    assert c("GET", "/samo/rest/documents/7/content", "", None) == "data"
    assert c("GET", "/samo/rest/settings", "type=folder", None) == "data"
    # other
    assert c("POST", "/samo/StatusService", "", "keepAlive") == "other"
    assert c("GET", "/samo/rest/security/getCurrentUser", "", None) == "other"
    assert c("GET", "/gis/WebMapService", "REQUEST=GetMap&LAYERS=a", None) == "other"
    assert c("GET", "/unknown", "", None) == "other"


def test_variant_keys():
    from mobileproxy.store import endpoint_key, normalize_query, variant_key
    ep = endpoint_key("GET", "/api/rest/metadata/all", None)
    assert ep == "GET /api/rest/metadata/all"
    assert normalize_query("output=groups&groups=a&expanded=true") == normalize_query("expanded=true&groups=a&output=groups")
    a = variant_key(ep, "output=groups&groups=a", "")
    b = variant_key(ep, "groups=a&output=groups", "")
    c = variant_key(ep, "output=groups&groups=b", "")
    assert a == b != c
    assert variant_key("POST /x #op", "", "abcd1234") == "POST /x #op @abcd1234"


def test_store_variants_and_counts(tmp_path):
    from mobileproxy.store import Store, endpoint_key, variant_key
    st = Store(tmp_path)
    st.touch_server("h", 80, "http")
    def add(q, sig=""):
        ep = endpoint_key("GET", "/m", None)
        st.add_exchange({"id": st.new_id(), "server": "h:80", "method": "GET", "path": "/m", "query": q, "soap_op": None,
                         "endpoint": ep, "variant": variant_key(ep, q, sig), "category": "metadata", "status": 200})
    add("g=a"); add("g=b"); add("g=a")
    eps = st.list_endpoints("h:80")
    assert sorted((e["query"], e["count"]) for e in eps) == [("g=a", 2), ("g=b", 1)]
    assert len(st.list_exchanges("h:80", variant=eps[0]["variant"])) == eps[0]["count"]
    assert len(st.list_endpoints(None, q="g=b")) == 1


def test_search_matcher():
    import time as _t
    from mobileproxy.search import Matcher, SearchQuery, parse_time, status_matches
    now = _t.time()
    ex = {"id": 1, "ts": now - 120, "endpoint": "POST /samo/api/rest/features/query", "query": "stream=true",
          "req_preview": '{"ft":10}', "req_body": '{"ft": 10}', "resp_body": '{"items":[{"name":"Kabel VN"}]}',
          "resp_body_original": '{"items":[{"name":"Sloup"}]}', "status": 200, "method": "POST", "category": "data",
          "req_headers": [["X-Correlation-ID", "abc-123"]], "resp_headers": [["ETag", '"v7"']],
          "rules_applied": [{"id": "r1", "name": "x"}], "modified": True, "mocked": False, "correlation_id": "abc-123"}
    M = lambda **kw: Matcher(SearchQuery(**kw))(ex)
    assert M(text="kabel") is None                      # bodies not searched by default
    hits = M(text="kabel", bodies=True)
    assert hits and hits[0]["field"] == "response body" and "Kabel VN" in hits[0]["snippet"]
    assert M(text="sloup", bodies=True)[0]["field"] == "original response"
    assert M(text=r"kabel\s+v\w", bodies=True, regex=True)
    assert M(text="etag", headers=True) and M(text="etag") is None
    assert M(text="features") == []                      # endpoint match: no snippet needed
    assert M(status="2xx") == [] and M(status="4xx,5xx") is None and M(status="200-299") == []
    assert M(method="get") is None and M(category="metadata") is None
    assert M(since="5m") == [] and M(since="1m") is None and M(until="1m") == []
    assert M(modified=True) == [] and M(mocked=True) is None
    assert M(rule_id="r1") == [] and M(rule_id="r2") is None
    assert M(correlation_id="ABC") == []
    assert status_matches({"status": None, "error": "refused"}, "err")
    assert abs(parse_time("2h") - (now - 7200)) < 5
    import pytest
    with pytest.raises(ValueError):
        Matcher(SearchQuery(text="(", regex=True))


def test_pac_and_settings_migration(tmp_path):
    import json as _json
    from mobileproxy.macos import pac_matches, pac_script
    from mobileproxy.store import APPLE_IGNORE_HOSTS, Store
    pac = pac_script(["172.30.*", "*.berit.cz", " ", "172.30.*"], "127.0.0.1:8080")
    assert pac.count('"172.30.*"') == 1 and "PROXY 127.0.0.1:8080" in pac and 'return "DIRECT"' in pac
    assert pac_matches(["172.30.*"], "172.30.48.20") and not pac_matches(["172.30.*"], "10.0.0.1")
    # old settings.json without Apple ignore pattern gets migrated
    (tmp_path / "settings.json").write_text(_json.dumps({"ignore_hosts": ["^x$"], "strip_cache_headers": False}))
    st = Store(tmp_path)
    assert st.settings.ignore_hosts[0] == "^x$" and APPLE_IGNORE_HOSTS[0] in st.settings.ignore_hosts
    assert st.is_ignored("gateway.icloud.com", 443) and not st.is_ignored("172.30.48.20", 80)
    st.touch_server("172.30.48.20", 80, "http")
    st.touch_server("gateway.icloud.com", 443, "https")  # ignored hosts are not put into the PAC
    st.settings.system_proxy_hosts = ["*.berit.cz"]
    assert st.pac_hosts() == ["*.berit.cz", "172.30.48.20"]
    st.settings.system_proxy_include_seen = False
    assert st.pac_hosts() == ["*.berit.cz"]
