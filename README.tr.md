# idamap

**LLM'in IDA'da ne yaptığını gör.** idamap, LLM'in [ida-mcp](https://github.com/blacktop/ida-mcp-rs) üzerinden
yaptığı her tool çağrısını kaydeder ve reverse engineering çalışmasını canlı, gezilebilir bir haritaya dönüştürür:
nelere bakıldı, şu an ne çalışıyor, neden ve neler hâlâ keşfedilmedi.

ida-mcp'nin önünde şeffaf bir proxy olarak durur; ida-mcp'ye veya IDA'ya dokunmadan MCP istemcileriyle çalışır
(gerçekte nelerin test edildiği için [Uyumluluk](#uyumluluk) bölümüne bak).

> idamap, blacktop'un [**ida-mcp-rs**](https://github.com/blacktop/ida-mcp-rs) projesine eşlik eden bağımsız bir
> araçtır. ida-mcp'nin kodunu içermez: ida-mcp'yi başlatır ve MCP mesajlarını aktarır. blacktop veya Hex-Rays ile
> bağlantılı değildir ve onlar tarafından onaylanmamıştır. IDA Pro, Hex-Rays'in ürünüdür.

> English: [README.md](README.md)

![Genel bakış](docs/overview.jpg)

## Neden

MCP üzerinden IDA'yı kullanan bir LLM saniyede birkaç çağrı yapar. Terminal akışını takip etmek imkânsızdır,
modelin bir fonksiyon hakkındaki anlayışı sohbet bitince kaybolur ve bir sonraki oturum sıfırdan başlar.
idamap bu çalışmanın kalıcı bir kaydını tutar ve gösterir:

| Görünüm | Cevapladığı soru |
|---|---|
| **Şu an çubuğu** | Hangi tool, hangi fonksiyon üzerinde, hangi istemciden, ne kadar süredir çalışıyor |
| **Kapsama haritası** | Binary'nin hangi kısımları reverse edildi: IDA benzeri adres şeridi + her fonksiyon için bir hücre; analiz derinliği, çağrı sayısı, tazelik veya senin inceleme durumuna göre renklenir |
| **Çağrı grafiği** | Üzerinde çalışılan fonksiyonlar, LLM'in gezme sırası ve sıradaki adaylar olan keşfedilmemiş komşular |
| **Fonksiyonlar** | Sıralanabilir, aranabilir tablo (isimler, demangle edilmiş isimler, açıklamalar, kapsama, inceleme durumu) |
| **Zaman çizelgesi** | Senin prompt'un → modelin çağrıdan önce söylediği → yaptığı çağrılar (girdi ve çıktılarıyla) |
| **Fonksiyon paneli** | Rename'ler, yorumlar, LLM açıklamaları, referans verilen string / selector / class / import'lar, caller / callee'ler, son pseudocode, tüm geçmiş ve kendi inceleme durumun ile notların |

Kapsama aşamaları: `seen` (bir sonuçta göründü) → `explored` (xrefs / callers / callees) → `disassembled` →
`decompiled` → `annotated` (rename, yorum, tip, patch veya açıklama).

## Kurulum

**Ön koşul: ida-mcp.** idamap, ida-mcp'yi içermez ve kurmaz; yalnızca onun önünde durur. Önce
[ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs)'i kur ve tek başına çalıştığından emin ol; neye ihtiyaç duyduğu
(IDA Pro vb.) onun README'sinde yazar.

idamap'in kendisi Python ≥ 3.10 ister, başka bağımlılığı yoktur (arayüzün graf kütüphanesi pakette; her şey internetsiz çalışır).

```sh
uv tool install git+https://github.com/RavenT1/idamap      # veya: pipx install git+https://github.com/RavenT1/idamap
idamap serve --open                                         # http://127.0.0.1:8777
```

Kaynaktan: `uv tool install -e .`

## MCP istemcini bağla

### Her istemci: proxy

İstemcinin ida-mcp'yi başlattığı komutu `idamap proxy -- ida-mcp` ile değiştir. Mutlak yollu hazır ayarlar için
(GUI uygulamaları shell `PATH`'ini görmez):

```sh
idamap mcp-config                     # tüm istemciler
idamap mcp-config --client codex      # claude-code | cursor | claude-desktop | windsurf | gemini | vscode | codex | http
```

Mevcut ida-mcp argümanların (`--workspace`, `--read-only` …) ida-mcp yolundan sonra gelir. HTTP ile bağlanan
istemciler için proxy'yi `ida-mcp serve-http`'in önüne koy:

```sh
ida-mcp serve-http --bind 127.0.0.1:8765
idamap proxy --listen 127.0.0.1:8766 --upstream http://127.0.0.1:8765/
```

Proxy baytları önce iletir, gözlemi yan kanalda yapar; kayıt ayrı bir iş parçacığında yazılır. Ayrıştırma veya
veritabanı hatası MCP trafiğini asla geciktirmez ya da bozmaz. ida-mcp kapanırsa proxy aynı çıkış koduyla kapanır.

### Claude Code: hook'lar (daha zengin)

```sh
idamap install                        # ~/.claude/settings.json'a hook ekler
```

Sonra Claude Code'u yeniden başlat. Hook'lar ek olarak **senin prompt'unu** ve **modelin her çağrıdan hemen önce
yazdığını** yakalar; MCP protokolü bunları taşımaz. Hook ve proxy birlikte kullanılabilir, her çağrı bir kez kaydedilir.

## Tüm binary'yi haritala

LLM'e şunu çalıştırmasını söyle (yol: `idamap export-script`):

```
run_script(file="<export_map.py yolu>")
```

Tüm fonksiyonlar, call edge'leri, segmentler, demangle edilmiş isimler ve her fonksiyonun referans verdiği
string/selector/class/import'lar içe aktarılır. Modele yalnızca tek bir özet satırı döner.

## LLM açıklamaları (isteğe bağlı)

```sh
idamap config annotate_tools on       # veya tek istemci için: idamap proxy --annotate-tools -- ida-mcp
```

Proxy modele dört araç daha sunar (idamap'in kendisi yanıtlar, IDA veritabanına hiçbir şey yazılmaz):

- **`idamap_annotate`** — model bir fonksiyonu analiz ettikten sonra özet, önerilen isim, etiketler,
  ait olduğu kütüphane/SDK/framework, güven seviyesi ve kanıtı kaydeder.
- **`idamap_lookup`** — model işe başlamadan önce bilineni okur: önceki açıklamalar (senin onaylayıp
  reddettiğin), notların, rename'ler, referanslar, caller/callee'ler.

- **`idamap_search`** — tüm binary üzerinde kapsama farkındalıklı arama: isim, string, import, Objective-C
  selector/class veya önceki açıklamaya göre; istenirse yalnızca kimsenin üzerinde çalışmadığı fonksiyonlar.
  Her sonuç aşamasını (unseen … annotated), boyutunu ve eşleşen kanıtı taşır; model `list_functions` filtresi
  tahmin etmez, işi tekrarlamaz.
- **`idamap_status`** — araştırmanın durumu: aşamaya göre kapsama, son bakılanlar, kimsenin bakmadığı en
  umut verici fonksiyonlar ve uygulama paketi (aşağıda).

**Uygulama paketleri.** Bir `.app` / IPA içinde ilginç kod çoğu zaman ana binary'de değil framework'tedir. idamap
`Info.plist` ve `Frameworks/` dizinini okur, import edilen sembolleri onları sağlayan framework'e eşler (Swift
modül isimleri dahil) ve modele hangi kardeş binary'de implementasyon olduğunu, analiz edilip edilmediğini söyler.
Overview'da "App bundle" kartı, fonksiyon panelinde "Calls into bundled frameworks" bölümü görünür.

**Otomatik indeksleme.** Search ve status için tüm binary'nin indekslenmesi gerekir. Modeller export script'ini
güvenilir şekilde kendileri çalıştırmaz; bu yüzden araçlar açıkken ihtiyaç duyan ilk çağrıda proxy, ida-mcp'ye
idamap'in kendi salt-okunur export script'ini tek bir `run_script` ile gönderir (IDA veritabanını yalnızca okur,
`~/.idamap/exports` altına tek bir JSON yazar; zaman çizelgesinde `idamap_map` olarak görünür). Hata olursa tekrar
denenmez. idamap'in ida-mcp'ye kendiliğinden istek göndermesini istemiyorsan:

```sh
idamap config auto_map off
```

Araçlar bu durumda modelden export script'ini çalıştırmasını ister.

Açıklamalar **onaylanmamış hipotez** olarak saklanır; fonksiyon panelinde onaylar veya reddedersin. Bilgi idamap'te
durduğu için oturumlar ve istemciler arasında taşınır. Ayarlar arayüzde de var (⚙); isteğe bağlı özellikler
varsayılan olarak kapalıdır.

## Dışa aktarma

- **Markdown araştırma günlüğü** (`Export` menüsü veya `idamap report <db-id>`).
- **IDA kapsama senkron script'i** (`Export` menüsü veya `idamap ida-sync <db-id>`): IDA'da fonksiyonları aşamasına
  göre boyar, özet + notların + LLM açıklamasıyla `[idamap]` yorumu ekler. `CLEAR = True` hepsini geri alır.

## Güvenlik ve gizlilik

- Her şey senin makinende kalır: `~/.idamap/` (`IDAMAP_HOME` ile değiştirilebilir). idamap ağa istek atmaz.
- Arayüz `127.0.0.1`'e bağlanır; kimlik doğrulaması olmadığı için yabancı `Host` başlıklarını (DNS rebinding) ve
  başka kaynaklardan gelen / JSON olmayan yazma isteklerini reddeder.
- Veritabanı analiz ettiğin binary'lerden çıktılar (pseudocode, string'ler) içerir; IDA veritabanı gibi muamele et.

## Uyumluluk

| | Durum |
|---|---|
| macOS + ida-mcp-rs + **Claude Code**, **Codex CLI**, **omp** | gerçek oturumlarla uçtan uca test edildi |
| Linux, Python 3.10 ve 3.13 | birim testleri geçiyor (sahte ida-mcp); gerçek IDA ile test edilmedi |
| Windows | test edilmedi |
| Diğer MCP istemcileri (Cursor, Claude Desktop, VS Code, Gemini CLI, …) | çalışması beklenir (proxy stdio ve Streamable HTTP üzerinden standart MCP konuşur), doğrulanmadı |
| Diğer IDA MCP sunucuları (mrexodia/ida-pro-mcp, Hex-Rays'in kendi sunucusu, …) | test edilmedi; araç adları farklı olabilir |

Diğer kurulumlar için geri bildirim ve düzeltmeler memnuniyetle karşılanır.

## Sorun giderme

| Belirti | Çözüm |
|---|---|
| Hiçbir şey görünmüyor | `idamap status`; ayar değişikliğinden sonra istemciyi yeniden başlat; `~/.idamap/*_errors.log` |
| İstemci sunucuyu başlatamıyor | mutlak yollar kullan (`idamap mcp-config` yazar) |
| İstemci `mcp-client` görünüyor | `idamap proxy --harness istemcim -- ida-mcp` |
| Kapsama birkaç fonksiyonla sınırlı | tam haritayı içe aktar |

## Teşekkür

idamap, eşlik etmek üzere geliştirildiği headless IDA Pro MCP sunucusu blacktop'un
[ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) projesi ve [Model Context Protocol](https://modelcontextprotocol.io)
sayesinde var.

## Lisans

MIT. `idamap/web/vendor/cytoscape.min.js` Cytoscape.js'tir (MIT, © The Cytoscape Consortium).
