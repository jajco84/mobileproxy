# MobileProxy

Ladicí HTTP(S) proxy pro testování mobilní aplikace SAMO / LIDS Mobile. Zachytí veškerou komunikaci
aplikace se servery a dovolí za běhu měnit data a metadata, která aplikace dostane. Ovládá se z webového
UI nebo přes MCP (Claude Code, Claude Desktop, jiní agenti). Běží na macOS i Windows.

Co umí:

- automaticky vede **seznam serverů**, na které se aplikace připojuje (host:port, volitelný alias),
- u každého serveru drží **historii** a **poslední odpověď každé varianty requestu**:
  - **endpoint** = `METODA /cesta`, u SOAP navíc `#operace` (všechny SOAP operace chodí na stejnou URL),
  - **varianta** = endpoint + query string + tělo requestu. Pořadí query parametrů, pořadí klíčů v JSON
    a mezery mezi XML tagy se ignorují, takže stejný request je vždy stejná varianta,
- requesty jsou rozdělené na **Data / Metadata / Other** a seznam jde podle toho filtrovat (viz níže),
- odpověď jde **podvrhnout podle těla requestu**: celé tělo, podřetězec, regex, JSONPath nebo XPath podmínka,
- **upravit a připíchnout** poslední odpověď: od dalšího požadavku aplikace dostane upravenou verzi,
- **pravidla**:
  - `replace`: celé tělo a status,
  - `patch`: JSONPath, XPath nebo regex; přežije změny dat na serveru,
  - `delay`: zpoždění,
  - `drop`: přerušené spojení,
  - `mock`: odpověď bez kontaktu se serverem,
  - platnost jen N-krát,
- **profily** (scénáře) jako YAML soubory, které jde verzovat v gitu,
- **MCP server** pro automatické úpravy a testy (`wait_for_request`, `patch_response`, …),
- pomocníci pro **adb**: zapnutí/vypnutí proxy v emulátoru, nahrání CA, restart a vymazání dat aplikace,
- neodpovídá 304: proxy odstraňuje `If-None-Match` a `If-Modified-Since` (dá se vypnout).

Jádro je [mitmproxy](https://mitmproxy.org) použité jako knihovna. Web UI, REST API a MCP běží
ve stejném procesu (FastAPI).

## Spuštění

Potřeba je Python ≥ 3.12, nebo lépe [uv](https://docs.astral.sh/uv/), které si správný Python stáhne samo.

```bash
./run.sh            # macOS / Linux
run.bat             # Windows
```

Skripty použijí `uv`, a když chybí, založí `.venv` a nainstalují závislosti. Ručně:
`uv run mobileproxy` nebo `pip install -e . && mobileproxy`.

Výchozí porty a nastavení:

| | |
|---|---|
| proxy | `127.0.0.1:8080` (emulátor ho vidí jako `10.0.2.2:8080`) |
| web UI | http://127.0.0.1:8081 (otevře se samo) |
| MCP | `http://127.0.0.1:8081/mcp` |
| data | `~/.mobileproxy` (Windows `%USERPROFILE%\.mobileproxy`): nastavení, pravidla, profily, CA certifikát |

Přepínače: `--proxy-port`, `--ui-port`, `--proxy-host 0.0.0.0` (fyzické zařízení přes Wi-Fi),
`--data-dir`, `--verify-upstream` (ověřovat TLS certifikáty serverů; ve výchozím stavu vypnuto,
protože testovací servery mívají self-signed certifikáty), `--no-browser`, `--no-mcp`.

## Připojení emulátoru

1. Spusť MobileProxy a emulátor.
2. V horní liště UI dej **Set proxy** (nastaví proxy ve všech běžících emulátorech), případně
   v **Settings** u konkrétního zařízení **Proxy on**. Ručně jde totéž takto:
   ```bash
   adb shell settings put global http_proxy 10.0.2.2:8080
   ```
   Nebo v emulátoru přes *Extended controls → Settings → Proxy*.
3. Spusť aplikaci a zadej normální adresu serveru. Provoz se objeví v záložce **Traffic**.
4. **Po testování proxy vypni** (`adb shell settings put global http_proxy :0` nebo tlačítkem
   **Turn off** v horní liště). Jinak emulátor bez běžící proxy nemá síť.

OkHttp v aplikaci systémovou proxy respektuje, v aplikaci se nic měnit nemusí.

Fyzické zařízení přes USB: tlačítko **Proxy on** v Settings udělá `adb reverse tcp:8080 tcp:8080` a nastaví
proxy na `127.0.0.1:8080`. Přes Wi-Fi spusť proxy s `--proxy-host 0.0.0.0` a v nastavení Wi-Fi
v telefonu zadej IP počítače.

## Připojení iOS Simulatoru (macOS)

iOS Simulator nemá vlastní nastavení proxy, používá síťové nastavení Macu. MobileProxy proto umí působit jako
**systémová proxy macOS**:

1. V **Settings → iOS Simulator & macOS system proxy** vyplň hosty testovacích serverů (glob, např. `172.30.*`,
   `*.berit.cz`). Zaškrtnutím *also all servers MobileProxy already knows* se přidají i servery zachycené
   z Android emulátoru.
2. **Enable** (nebo **Set system proxy** v horní liště). MobileProxy nastaví na všech aktivních síťových
   službách Macu PAC soubor `http://127.0.0.1:8081/proxy.pac`. Ten pošle přes MobileProxy **jen uvedené hosty**,
   zbytek Macu (prohlížeč, Slack, Apple služby) jde dál napřímo. Pokud macOS vyžaduje administrátorská práva,
   zobrazí jedno okno pro heslo.
3. Pro HTTPS dej **Install CA to all** (`xcrun simctl keychain <sim> add-root-cert`). Certifikát se nainstaluje
   do všech běžících simulátorů a v tabulce je vidět, kde už je. iOS aplikace nemá certificate pinning, HTTP
   povoluje `NSAllowsArbitraryLoads`.
4. **Restart app** restartuje aplikaci (`com.asseco.ce.samomobile`) ve všech běžících simulátorech.

Po změně seznamu hostů je potřeba **Apply changes**, aby si macOS PAC načetl znovu.

Bezpečnost a obnova:

- Původní nastavení se uloží do `~/.mobileproxy/system_proxy_backup.json` a při ukončení MobileProxy (Ctrl+C) se
  samo obnoví. Ručně jde obnovit tlačítkem **Disable & restore** nebo **Turn off** v horní liště.
- Když MobileProxy spadne, PAC URL přestane odpovídat a macOS se vrátí k přímému připojení, takže Mac o síť nepřijde.
  Nastavení se obnoví příkazem `./run.sh --restore-system-proxy` nebo při dalším spuštění a ukončení.
- Pokud VPN klient nastavuje vlastní proxy/PAC, macOS může naše nastavení přebít. Štítek v horní liště pak
  hlásí *macOS proxy overridden (VPN?)* (kontroluje se přes `scutil --proxy`).

Apple služby (apple.com, icloud.com, mzstatic.com…) se nezachytávají a nelogují.

### HTTPS

HTTP servery fungují hned. Pro HTTPS proxy vystupuje vůči aplikaci s certifikátem podepsaným vlastní CA,
kterou je potřeba jednou nainstalovat do zařízení:

1. V UI dej **Push CA** (Settings) (soubor se nahraje do `Download/` a otevře se nastavení zabezpečení),
   nebo certifikát stáhni z http://127.0.0.1:8081/api/ca.crt.
2. V zařízení: *Nastavení → Zabezpečení → Šifrování a pověření → Instalovat certifikát → Certifikát CA*.

Aplikace uživatelským CA důvěřuje díky `gui/src/main/res/xml/network_security_config.xml`
(`<certificates src="user"/>`).

> Poznámka k aplikaci: tento config teď platí pro všechny buildy včetně release. Doporučení je přesunout
> důvěru v uživatelské CA do `<debug-overrides>`, aby fungovala jen v debug buildu.

Google a systémový provoz emulátoru (googleapis, gstatic, sentry, …) se nezachytává a neloguje.
Seznam je v **Settings → Ignored hosts**; host jde přidat i tlačítkem **Ignore** u serveru.

## Práce v UI

- **Traffic:** vlevo servery, uprostřed seznam requestů, vpravo detail. Seznam má dva režimy:
  - **Grouped**: requesty seskupené podle endpointu, pod ním varianty (u každé poslední odpověď a počet
    volání `×N`). U variant se ukazují jen query parametry, kterými se liší, a kompaktní náhled těla.
    Endpoint s jedinou variantou je jeden řádek, skupina s více než 8 variantami je sbalená.
  - **Timeline**: všechna volání chronologicky.

  V detailu je u opakovaně volaného requestu výběr předchozích odpovědí téže varianty.
  Odpověď se ukazuje jako čitelný strom (**Readable**; kliknutím na klíč/element se zkopíruje JSONPath/XPath).
  V režimu **Edit** ji uprav (tlačítko **Format** zformátuje JSON/XML) a dej:
  - **Pin**: vytvoří `replace` pravidlo pro stejný server, metodu, cestu a SOAP operaci,
  - **Mock**: totéž, ale server se vůbec nekontaktuje,
  - `× N`: pravidlo se použije jen N-krát, pak se samo vypne,
  - `query` (ve výchozím stavu zapnuto, když request query má): pravidlo platí jen pro stejný query string,
  - `body` (u requestů s tělem, ve výchozím stavu zapnuto): pravidlo platí jen pro request se stejným tělem.
    Pokud má platit jen podle části těla (např. podle id), uprav po vytvoření v záložce Rules podmínku
    `body_equals` na `body_json` nebo `body_xpath`.

  Upravené odpovědi mají štítek **MOD**; původní odpověď serveru je na záložce *Original response*.
- **Rules:** pořadí, zapínání a vypínání a šablony. Editor má u `replace` pravidel nahoře samostatné pole
  **Response body** (naformátované, s kontrolou platnosti JSON/XML) a pod ním **Rule settings** jako JSON
  bez těla a bez prázdných polí. **Preview patch** vyzkouší patch na poslední zachycené odpovědi.
- **Profiles:** uložení a načtení sady pravidel. Soubory jsou v `~/.mobileproxy/profiles/*.yaml`,
  ukázka je v `examples/profiles/`.

### Repeater

V detailu requestu tlačítko **Open in Repeater ↗** otevře nové okno s kopií requestu:

- upravit jde metodu, URL, hlavičky (záložka *Headers*, `Název: hodnota` na řádek, `#` řádek vypne)
  a tělo (naformátované, s kontrolou platnosti JSON/XML). `Host` a `Content-Length` se dopočítají,
- **Send** nebo Ctrl/⌘ + Enter request odešle a odpověď se ukáže v tom samém okně (čitelný strom, *Raw*,
  hlavičky, status, čas, velikost). Předchozí pokusy jsou ve výběru vpravo nahoře, **Reset** vrátí původní request,
- **through MobileProxy** (výchozí): request projde pravidly (mocky, patche) a zapíše se do historie se štítkem
  **REPLAY**; odkaz *recorded as #N* ho otevře v hlavním okně. Bez zaškrtnutí jde request přímo na server
  a nikam se nezapisuje.

Stejně funguje MCP nástroj `replay_request` (vychází z `exchange_id`, umí přepsat `method`, `url`, `body`,
`set_headers` a `remove_headers`).

### Hledání

Pod přepínači seznamu je vyhledávací lišta:

- text se hledá v endpointu, query a náhledu těla requestu (bez ohledu na velikost písmen),
- **bodies**: navíc v celých tělech requestů a odpovědí, včetně původní odpovědi serveru před úpravou pravidlem,
- **headers**: navíc v hlavičkách,
- **regex**: text je regulární výraz,
- status (`2xx` … `5xx`, *failing* = 4xx/5xx/chyba spojení, *connection error*), čas (*last 1 min* … *last hour*),
  **modified** (jen odpovědi změněné pravidlem nebo mockované).

V režimu **Timeline** se hledá v celé historii a pod řádkem je ukázka místa nálezu. V režimu **Grouped** se
hledá v poslední odpovědi každé varianty. Po otevření requestu jsou nálezy zvýrazněné ve stromu odpovědi
(i v *Original response* a *Request*) a tlačítky ▲▼ se mezi nimi přechází.

MCP nástroj `search_exchanges` umí totéž a navíc filtr `method`, `until`, `mocked`, `rule_id` (kde se pravidlo
použilo) a `correlation_id` (X-Correlation-ID). Ve výchozím stavu hledá i v tělech, vrací ukázky nálezů
a stránkuje přes `before_id`. S `latest_per_variant=true` hledá jen v poslední odpovědi každé varianty.

### Kategorie requestů

Filtr **All / Data / Metadata / Other** nad seznamem requestů. Výchozí rozdělení vychází z kódu android-client
(`LoginActivity`, `*ServiceProvider`, `CoreController`):

| kategorie | requesty |
|---|---|
| Metadata | `POST …/ExtensionService` (`describeExtension`: samo-mobile, mobile, mobile-workforce, light-forms, protocols), `…/api/rest/metadata/*` (featureTypes, groups, attributeRules, typy číselníků), `…/rest/metadata/project-info`, `…/api/rest/codelists/*`, `…/rest/cross-section/feature-types`, `…/api/rest/resources/*`, `ResourceManager`, `GetCapabilities` |
| Data | `…/api/rest/features/*`, `…/rest/search/*`, `…/rest/business/*`, `…/rest/telco/*`, `…/rest/cross-section/{ftid}/{fid}`, `…/rest/document-folders/*`, `…/rest/documents/*`, `…/rest/settings*`, `…/api/rest/material/*` |
| Other | `StatusService` (keepAlive, clientClosed), `rest/security/*`, `rest/password`, mapové dlaždice (WMS GetMap, WMTS) a vše neznámé |

Pravidla rozdělení jsou v **Settings → Request categories** jako JSON seznam: první shoda vyhrává, `path` je
glob bez ohledu na velikost písmen, volitelně `method`, `soap_op`, `query_contains`. Po uložení se
překlasifikují i už zachycené requesty. MCP nástroje `list_endpoints` a `list_exchanges` mají parametr `category`.

V seznamu je pod cestou náhled těla requestu v kompaktním tvaru. U XML/SOAP je to obsah Body bez obalujícího
elementu, např. `extension(id=samo-mobile, cacheTime=…)` nebo `id=12`.

### Formát pravidla

```jsonc
{
  "name": "skrytý číselník",
  "enabled": true,
  "match": {
    "server": "test-server:8080",   // glob na host:port nebo alias, "*" = všechny
    "method": "GET",                // null = libovolná
    "path": "/rest/meta/*",          // glob na cestu bez query
    "query": null,                   // glob na query string
    "soap_op": null,                 // SOAP operace (glob)
    "body_contains": null,           // podřetězec v těle requestu
    "body_regex": null,              // regex na tělo requestu
    "body_equals": null,             // celé tělo (normalizovaně: pořadí klíčů JSON, mezery v XML)
    "body_json": {"$.filter.layer": "KABEL", "$.id": null},       // JSONPath -> hodnota, null = existuje
    "body_xpath": {"//*[local-name()='id']": "12"}               // XPath -> text, null = existuje
  },
  "action": "patch",                 // replace | patch | delay | drop
  "status": null,                    // přepsat HTTP status
  "headers": {"ETag": ""},           // nastavit hlavičky ("" = odstranit)
  "body": null,                      // pro replace
  "mock": false,                     // replace/drop bez kontaktu serveru
  "patches": [
    {"type": "jsonpath", "path": "$.items[?(@.code=='X')].visible", "op": "set", "value": false},
    {"type": "jsonpath", "path": "$.items", "op": "append", "value": {"code": "NEW"}},
    {"type": "xpath", "path": "//*[local-name()='status']", "op": "set", "value": "FAIL"},
    {"type": "xpath", "path": "//*[local-name()='item'][@id='3']", "op": "delete"},
    {"type": "regex", "pattern": "\"readonly\":false", "replacement": "\"readonly\":true"}
  ],
  "delay_ms": 0,
  "remaining": null                  // N = jen N-krát
}
```

Pravidla se vyhodnocují shora dolů a efekty `replace` a `patch` se skládají; `replace` a pak `patch`
tedy funguje. Patch, který nic nenajde, se přeskočí a chyba se ukáže v detailu odpovědi.

Operace patchů:

| typ | `op` |
|---|---|
| jsonpath | `set` (vytvoří i chybějící klíč), `delete`, `append` (do pole) |
| xpath | `set` (text elementu nebo hodnota atributu, když XPath končí `/@attr`), `delete`, `set_attr` (+ `attr`), `insert_xml` (přidá potomka) |

U XPath se namespaces nejsnáz obejdou přes `local-name()`, případně přes `"namespaces": {"s": "…"}`.

## MCP

Registrace do Claude Code:

```bash
claude mcp add --transport http mobileproxy http://127.0.0.1:8081/mcp
```

Do Claude Desktop a jiných klientů: `{"mcpServers": {"mobileproxy": {"type": "http", "url": "http://127.0.0.1:8081/mcp"}}}`.
Proxy musí běžet, MCP je její součástí.

Nástroje:

| | |
|---|---|
| čtení | `list_servers`, `set_server_alias`, `list_endpoints`, `list_exchanges`, `search_exchanges`, `get_exchange`, `get_last_response` |
| úpravy | `override_response`, `pin_exchange`, `patch_response`, `preview_patches`, `add_rule`, `update_rule`, `delete_rule`, `clear_rules`, `set_rules_paused` |
| scénáře | `list_profiles`, `save_profile`, `load_profile` |
| pozorování | `wait_for_request` (počká na další požadavek odpovídající filtru), `replay_request` (znovu odešle request, i upravený), `clear_history` |

Příklad zadání pro agenta: *„Na serveru test vrať v metadatech u vrstvy Kabel `visible=false`,
restartuj aplikaci přes adb, počkej na request na /rest/meta a ověř, že odpověď byla upravená.“*

## Vývoj

```bash
uv run --extra dev pytest                 # unit testy (pravidla, patche, detekce SOAP)
python dev/upstream.py --port 9000        # falešný server (JSON + SOAP, gzip, ETag)
python dev/upstream.py --port 9443 --tls  # totéž přes HTTPS (self-signed)
curl --noproxy '' -x http://127.0.0.1:8080 http://127.0.0.1:9000/api/meta
```

Struktura `src/mobileproxy/`:

| soubor | obsah |
|---|---|
| `addon.py` | mitmproxy addon: záznam provozu, detekce SOAP operace, aplikace pravidel |
| `rules.py` | model pravidla, matching, JSONPath/XPath/regex patche |
| `store.py` | stav v paměti (servery, historie, poslední odpovědi), persistence, profily, události |
| `api.py` | REST + WebSocket pro UI, mount MCP |
| `mcp_server.py` | MCP nástroje (mcp SDK 2.x, Streamable HTTP) |
| `adb.py` | pomocníci pro adb |
| `static/` | webové UI (čisté HTML/JS, bez build kroku) |

## Další kroky

- breakpointy: pozastavit odpověď a upravit ji ručně (pozor na timeouty OkHttp),
- diff původní a upravené odpovědi v UI, editor s barvením syntaxe,
- zachycení WebSocketů, pokud je aplikace používá,
- balíček jako samostatný spustitelný soubor (PyInstaller) nebo nativní okno (Tauri).
