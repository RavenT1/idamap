# idamap

**LLM + [ida-mcp](https://github.com/blacktop/ida-mcp-rs) ile yapılan reverse engineering'in kaydını tutan ve görselleştiren yerel web aracı.**

LLM, ida-mcp üzerinden saniyede birkaç tool çağrısı yapar; terminale akan yazıları takip etmek imkânsızdır.
idamap her ida-mcp çağrısını yakalar, bir SQLite corpus'una işler ve tarayıcıda canlı olarak gösterir:

- **Şu an ne yapılıyor** — üst çubukta çalışan çağrı, hedef fonksiyon, süre ve hangi istemci (harness).
- **Nereler reverse'lendi** — tüm binary'nin kapsama haritası (IDA navigation band benzeri adres şeridi + her fonksiyon bir hücre).
- **Neden** — (Claude Code'da) LLM'in her çağrıdan önce yazdığı açıklama ve ait olduğu kullanıcı prompt'u.
- **Nasıl ilerledi** — çağrı grafiğinde incelenen fonksiyonlar, keşfedilmemiş komşular ve keşif sırası.
- **İnsan katmanı** — her fonksiyona kendi inceleme durumun (to do / reviewed / suspicious …) ve notların.
- **Kalıcı kayıt** — Markdown araştırma günlüğü ve kapsamı IDA GUI'ye geri boyayan IDAPython script'i.

ida-mcp'ye hiçbir değişiklik gerekmez. Yakalama iki yoldan yapılır; ikisi aynı veritabanına yazar:

| Yol | Hangi istemciler | Ne kaydeder |
|---|---|---|
| **MCP proxy** (`idamap proxy`) | **Her MCP istemcisi**: Cursor, Codex, Claude Desktop, Claude Code, Gemini CLI, VS Code/Copilot, Windsurf, Zed, Cline, … (stdio veya Streamable HTTP) | Tüm tool çağrıları, sonuçlar, hatalar, süreler, istemci adı |
| **Claude Code hook'ları** (`idamap install`) | Claude Code | Yukarıdakiler **+** kullanıcı prompt'u ve LLM'in her çağrıdan önceki açıklaması (transcript'ten) |

MCP protokolü prompt'u veya modelin düşüncesini sunucuya taşımaz; bu yüzden proxy üzerinden gelen oturumlar
zaman çizelgesinde prompt yerine oturum + boşluk süresine göre "çalışma blokları" halinde gruplanır.
Claude Code'da hook **ve** proxy birlikte kullanılırsa çağrılar iki kez kaydedilmez: Claude Code isteğin
`_meta`'sında kendi `toolUseId`'sini gönderir, proxy bununla hook kaydını birebir bulup kendi kaydını atlar.

## Kurulum

Python ≥ 3.10, harici bağımlılık yok (UI kütüphanesi `cytoscape.js` repoda vendor'lanmış; offline çalışır).

```sh
cd ida_mcp_map
uv tool install -e .          # veya: pipx install -e .   /   pip install -e .
idamap serve --open           # http://127.0.0.1:8777
```

### Herhangi bir MCP istemcisi (proxy)

İstemcinin ida-mcp'yi başlattığı komutu `idamap proxy -- ida-mcp` ile değiştir. Mutlak yollarla hazır
config parçaları için:

```sh
idamap mcp-config                   # tüm istemciler
idamap mcp-config --client cursor   # claude-code | cursor | claude-desktop | windsurf | gemini | vscode | codex | http
```

Örnek (Cursor `~/.cursor/mcp.json`, Claude Desktop, Windsurf, Gemini CLI aynı biçimi kullanır):

```json
{ "mcpServers": { "ida": { "command": "/Users/you/.local/bin/idamap",
                           "args": ["proxy", "--", "/opt/homebrew/bin/ida-mcp"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.ida]
command = "/Users/you/.local/bin/idamap"
args = ["proxy", "--", "/opt/homebrew/bin/ida-mcp"]
```

ida-mcp argümanların (`--workspace`, `--read-only` …) ida-mcp yolundan sonra aynen gelir. GUI uygulamaları
shell `PATH`'ini görmediği için mutlak yol kullan (`mcp-config` bunu senin için yazar).

**HTTP** üzerinden bağlanan istemciler için `ida-mcp serve-http`'in önüne koy:

```sh
ida-mcp serve-http --bind 127.0.0.1:8765
idamap proxy --listen 127.0.0.1:8766 --upstream http://127.0.0.1:8765/
# istemciyi http://127.0.0.1:8766/ adresine yönlendir
```

Proxy baytları önce iletir, gözlemi yan kanalda yapar ve kaydı ayrı bir iş parçacığında yazar: ayrıştırma
veya veritabanı hatası MCP trafiğini asla geciktirmez ya da bozmaz (hatalar `~/.idamap/proxy_errors.log`).
Hem MCP ≤2025 (`initialize` handshake) hem handshake'siz MCP 2026-07-28 (`_meta` içinde clientInfo) desteklenir.

### Claude Code (daha zengin kayıt için hook'lar)

```sh
idamap install                # hook'ları ~/.claude/settings.json'a ekler (tüm projeler)
# yalnızca bir proje için:  idamap install --scope project --project-dir /path/to/research
```

Hook'ları ekledikten sonra Claude Code'u yeniden başlat (veya `/hooks` ekranını aç). Kaldırmak için `idamap uninstall`.
Kurulum durumu ve kayıtlı veritabanları: `idamap status`. ida-mcp sunucun farklı bir isimle kayıtlıysa
`idamap install --matcher 'mcp__benimsunucum__.*'`.

## Tam haritayı almak (önerilir)

Varsayılan olarak idamap yalnızca LLM'in gördüğü fonksiyonları bilir. Binary'nin **tamamını** (tüm fonksiyonlar,
tüm call edge'leri, segmentler) haritalamak için LLM'e şunu çalıştırmasını söyle:

```
run_script(file="<repo>/idamap/ida_scripts/export_map.py")
```

Script JSON'u `~/.idamap/exports/` altına yazar ve LLM bağlamına yalnızca tek bir özet satırı döner; hook bu satırı
görüp haritayı otomatik içe aktarır. Yol `idamap export-script` ile yazdırılabilir. IDA GUI'den de çalıştırabilirsin
(File › Script file…) ve ardından `idamap import <json>`.

## Arayüz

| Sekme | Ne gösterir |
|---|---|
| **Overview** | Kapsama yüzdeleri, aşama dağılımı, son incelenen fonksiyonlar (focus trail), prompt'lar, tool kullanımı, dakika bazlı aktivite, son rename/comment'ler |
| **Coverage map** | Üstte adres şeridi (segment başına, piksel başına en ileri aşama), altta adres sırasıyla her fonksiyon bir hücre. Renk modu: aşama / ısı (çağrı sayısı) / tazelik / insan incelemesi. Arama vurgular, tıklama detay açar |
| **Call graph** | İncelenen fonksiyonlar ve aralarındaki çağrılar; "+ unexplored neighbours" ile sıradaki adaylar; "exploration order" ile LLM'in gezme sırası; canlı takip |
| **Functions** | Filtrelenebilir/sıralanabilir tablo: aşama, kapsama rozetleri (D A B X F M R C T P), çağrı sayısı, son dokunma, inceleme durumu |
| **Timeline** | Prompt → LLM niyeti → tool çağrıları; her çağrı açılınca input/output (pseudocode renklendirilir) |

Herhangi bir fonksiyona tıklayınca açılan panelde: rename geçmişi, eklenen yorumlar, referans verdiği string'ler,
bilinen caller/callee'ler, son pseudocode, o fonksiyona dokunan tüm çağrılar ve **kendi durum/not alanın**.

### Kapsama aşamaları

Bir fonksiyonun aşaması ulaştığı en ileri seviyedir:

| Aşama | Anlamı |
|---|---|
| `seen` | Başka bir sorgunun sonucunda göründü (callee listesi, xref, string ref…) |
| `explored` | Üzerinde xrefs/callers/callees/callgraph sorgulandı |
| `disassembled` | Disassembly, basic block, stack frame veya bellek okuması yapıldı |
| `decompiled` | Hex-Rays pseudocode alındı |
| `annotated` | Rename / comment / tip / patch / Lumina uygulandı |

## Dışa aktarma

- **Export › Markdown research log** (veya `idamap report <db-id>`): kapsama özeti, üzerinde çalışılan fonksiyonlar, rename/comment tablosu ve prompt → niyet → çağrı zaman çizelgesi.
- **Export › IDA coverage sync script** (veya `idamap ida-sync <db-id>`): IDA GUI'de çalıştırınca fonksiyonları aşamasına göre renklendirir ve `[idamap]` etiketli fonksiyon yorumu ekler (`CLEAR = True` ile geri alınır).

## Nasıl çalışır

```
Herhangi bir MCP istemcisi ──▶ idamap proxy ──▶ ida-mcp
                                   │ (kuyruk, ayrı thread)
Claude Code ──hook'lar──▶ idamap.hook ──┴──▶ ~/.idamap/idamap.db (SQLite, WAL)
                                                   ▲ poll
                                     idamap serve ──SSE──▶ tarayıcı
```

- **Başlangıç** (hook'ta PreToolUse, proxy'de `tools/call` isteği): çağrı `running` olarak kaydedilir, hedef adres/fonksiyon çözülür (canlı "şu an" çubuğu).
- **Bitiş** (PostToolUse / yanıt): çıktı ayrıştırılır — fonksiyon kayıtları, call edge'leri, xref'ler, string referansları, rename'ler, yorumlar,
  segmentler, DB metadata'sı. ida-mcp'nin tekli (düz payload) ve toplu (`{"results": [...]}`) yanıt biçimleri desteklenir.
  Adres ile gelen ama henüz bilinmeyen hedefler "stub" fonksiyon olarak tutulur ve harita geldiğinde gerçek fonksiyonla birleştirilir.
- **Niyet** (yalnızca Claude Code hook'ları): tool_use transcript'e yazıldıktan sonra, aynı turdaki son asistan metni çağrıya bağlanır.
- **Çoklu IDB**: oturum başına aktif veritabanı izlenir; ida-mcp `--workspace` modundaki `database_id` de eşlenir.
- Adresler 64-bit güvenli saklanır (iOS kernelcache gibi `0xfffffff0…` adresler dahil); API'de hep hex string'dir.

Veri dizini `IDAMAP_HOME` ile değiştirilebilir (varsayılan `~/.idamap`). Hatalar `~/.idamap/hook_errors.log` ve `proxy_errors.log`'a yazılır.

## Geliştirme

```sh
python3 -m unittest discover -s tests -t .
```

Testler ida-mcp'nin gerçek çıktılarından, gerçek Claude Code hook payload'larından ve sahte stdio/HTTP(SSE) MCP sunucularıyla proxy şeffaflığı üzerinden çalışır.

## Lisans

MIT. `idamap/web/vendor/cytoscape.min.js` — Cytoscape.js (MIT, © The Cytoscape Consortium).
