# P-CTHunter
<p align="center">
  <img src="assets/logo_pacth.svg" width="120" alt="P@CTH logo">
</p>

# P@CTH Pentest Scanner (POC-only)

```bash
pip install -r requirements.txt
python -m playwright install chromium

# hızlı tarama güvenli mod
python pacth.py quick https://hedef.com --rate-ms 400

# login sonrası örnek
python pacth.py scan https://hedef.com \
  --login-url https://hedef.com/login \
  --auth-user tester --auth-pass S3cr3t!
  --include-pattern "/app|/api" --exclude-pattern "/static|/cdn"
------
 --enable-ssti-rce --enable-sql-time (localde)
--------
Parametrelerden en çok işinize yarayacaklar:
--rate-ms (istek arası gecikme), --max-pages, --max-params-per-page
--include-pattern / --exclude-pattern
--enable-ssti-rce, --enable-sql-time (LAB only)
--login-url --auth-user --auth-pass
-----------------------------------------------

Keşif: siteyi crawl eder (include/exclude regex, hız limiti).
Başlıklar: CSP/HSTS/X-Frame-Options/CORS.
Yönlendirmeler: uzun 302 zinciri, açık yönlendirme (open redirect).
XSS: Reflected + DOM (token yansıması ve sink ipucu).
SSTI: katı/çift doğrulamalı POC ({{7*7}}), isterse LAB’da sınırlı RCE kanıtı.
SQLi: hata tabanlı & boolean farklılığı (opsiyonel LAB’da time-based).
Formlar/CSRF: basit form denemeleri ve yansımalar.
Dizin listeleme & fingerprint: /webmail vb. autoindex ve yazılım izleri.
Backup/source leak: .swp/.bak/~ gibi yedek/swap dosyalarının sızması.
JNLP yüzeyi: all-permissions / jar ipuçları.
Anomali avı: 5xx, stack trace, anormal gecikme/uzunluk.
Parked domain filtresi: Sedo/parking gibi sahte yüzleri düşürür.
Login sonrası tarama: Playwright ile giriş yapar, cookie’yi Requests’e taşır.

P@CTH, ekibin günlük işini hızlandıran, veri sızdırmadan sadece kanıt üreten (POC-only) bir tarayıcıdır. Amaç; “nereden başlamalıyız?” sorusunu sprint’in ilk saatlerinde netleştirmek. Çalışma biçimi basit: siteyi gezip güvenlik başlıklarını ve yönlendirme akışlarını fotoğraflar; parametre isimlerini keşfeder; XSS için yansıma ve DOM’daki tehlikeli sink’leri (innerHTML, document.write, eval vb.) işaretler; SSTI’de iki aşamalı doğrulama ile 49 gibi tesadüfi eşleşmeleri eler; SQLi’de hata/boolean farkını zararsız payload’larla ölçer; dizin listelemeyi, yedek/swap dosyalarını (.swp/.bak/~), eski sunucu banner’larını ve HTTP/TLS eksiklerini bulur; gerekiyorsa Playwright ile giriş yapıp çerezleri devralarak login arkasındaki yüzeyi de tarar. Çıktı tarafında, report.json ve report.md ile beraber terminalde kısa bir “Özet Rehber” verir; her bulgu için URL/param ve güvenli POC ipucu yazar, böylece analist doğrulamaya doğrudan atlar.

Takıma yararı en net triage anında görülür. Diyelim ki /search?q=… üzerinde token yansıması var ama sayfada sink yok; P@CTH bunu “yansıma var, sink izi yok” diye ayırır, gereksiz alarmı kapatır. /orders?page=… için “AND '1'='1” ile “AND '1'='2” arasında gövde uzunluğu bariz değişiyorsa rapora “boolean differ” olarak düşer; analist hangi parametre ve hangi uç nokta ile başlayacağını bilir. /webmail/ altında Apache autoindex açıksa ve klasör isimleri SquirrelMail’i çağrıştırıyorsa hem “dir listing” hem “webmail fingerprint” not edilir; düzeltme önerisi netleşir: Options -Indexes, dizinin erişim politikası ve uygulama giriş noktasına kısıtlama. En kritik senaryo, kaynak kod sızıntılarıdır: bir yerde login.php.swp veya b0VIM imzası görülürse P@CTH bunu CRITICAL olarak öne çeker; yine de yalnızca ilk 2 KB’lık range ile kanıt üretir, dosya çekmez. Bu yaklaşım, kanıt kalitesini yüksek tutarken operasyonel riski düşük tutar.
