# idamap

**LLM + [ida-mcp](https://github.com/blacktop/ida-mcp-rs) ile yapılan reverse engineering'in kaydını tutan ve görselleştiren yerel web aracı.**

LLM, ida-mcp üzerinden saniyede birkaç tool çağrısı yapar; terminale akan yazıları takip etmek imkânsızdır.
idamap her `mcp__ida__*` çağrısını **Claude Code hook'ları** ile sessizce yakalar, bir SQLite corpus'una işler ve
tarayıcıda canlı olarak gösterir:

- **Şu an ne yapılıyor** — üst çubukta çalışan çağrı, hedef fonksiyon ve süre.
- **Nereler reverse'lendi** — tüm binary'nin kapsama haritası (IDA navigation band benzeri adres şeridi + her fonksiyon bir hücre).
- **Neden** — LLM'in her çağrıdan önce yazdığı açıklama cümlesi ve ait olduğu kullanıcı prompt'u, çağrıya bağlanır.
- **Nasıl ilerledi** — çağrı grafiğinde incelenen fonksiyonlar, keşfedilmemiş komşular ve keşif sırası (trail).
- **İnsan katmanı** — her fonksiyona kendi inceleme durumun (to do / reviewed / suspicious …) ve notların.
- **Kalıcı kayıt** — Markdown araştırma günlüğü ve kapsamı IDA GUI'ye geri boyayan IDAPython script'i.

ida-mcp'ye hiçbir değişiklik gerekmez; hook'lar yalnızca gözlemci olarak çalışır ve hata alsalar bile çağrıyı asla bozmaz.

## Kurulum

Python ≥ 3.10, harici bağımlılık yok (UI kütüphanesi `cytoscape.js` repoda vendor'lanmış; offline çalışır).

```sh
cd ida_mcp_map
uv tool install -e .          # veya: pipx install -e .   /   pip install -e .
idamap install                # hook'ları ~/.claude/settings.json'a ekler (tüm projeler)
# yalnızca bir proje için:  idamap install --scope project --project-dir /path/to/research
idamap serve --open           # http://127.0.0.1:8765
```

Hook'ları ekledikten sonra Claude Code'u yeniden başlat (veya `/hooks` ekranını aç). Kaldırmak için `idamap uninstall`.
Kurulum durumu ve kayıtlı veritabanları: `idamap status`.

ida-mcp sunucun `ida` dışında bir isimle kayıtlıysa (örn. `mcp__ida-pro__…`), matcher varsayılan olarak `mcp__ida.*`
olduğu için genelde yine yakalanır; farklıysa `idamap install --matcher 'mcp__benimsunucum__.*'`.

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
Claude Code ──PreToolUse──▶ idamap.hook ──▶ ~/.idamap/idamap.db (SQLite, WAL)
     │        PostToolUse                         ▲
     ▼        PostToolUseFailure                  │ poll
  ida-mcp                               idamap serve ──SSE──▶ tarayıcı
```

- **Pre**: çağrı `running` olarak kaydedilir, hedef adres/fonksiyon çözülür (canlı "şu an" çubuğu).
- **Post**: çıktı ayrıştırılır — fonksiyon kayıtları, call edge'leri, xref'ler, string referansları, rename'ler, yorumlar,
  segmentler, DB metadata'sı. ida-mcp'nin tekli (düz payload) ve toplu (`{"results": [...]}`) yanıt biçimleri desteklenir.
  Adres ile gelen ama henüz bilinmeyen hedefler "stub" fonksiyon olarak tutulur ve harita geldiğinde gerçek fonksiyonla birleştirilir.
- **Niyet**: tool_use transcript'e yazıldıktan sonra, aynı turdaki son asistan metni çağrıya bağlanır.
- **Çoklu IDB**: oturum başına aktif veritabanı izlenir; ida-mcp `--workspace` modundaki `database_id` de eşlenir.
- Adresler 64-bit güvenli saklanır (iOS kernelcache gibi `0xfffffff0…` adresler dahil); API'de hep hex string'dir.

Veri dizini `IDAMAP_HOME` ile değiştirilebilir (varsayılan `~/.idamap`). Hook hataları `~/.idamap/hook_errors.log`'a yazılır.

## Geliştirme

```sh
python3 -m unittest discover -s tests -t .
```

Testler ida-mcp'nin gerçek çıktılarından ve gerçek Claude Code hook payload'larından üretilmiş fixture'larla çalışır.

## Lisans

MIT. `idamap/web/vendor/cytoscape.min.js` — Cytoscape.js (MIT, © The Cytoscape Consortium).
