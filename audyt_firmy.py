#!/usr/bin/env python3
"""
Audyt linków firmy na budujemydom.pl:
  1) linki produktowe ("Zobacz na stronie producenta") z zakładki firmy
     (w raporcie: adres strony produktu na budujemydom.pl),
  2) linki zewnętrzne w artykułach z zakładek /porady i /newsy.

Użycie jako skrypt:
  python audyt_firmy.py https://budujemydom.pl/irbj/.../fakro
  python audyt_firmy.py -i firmy.txt -o raport.csv
  python audyt_firmy.py URL --debug                    # pokaż znalezione linki, bez sprawdzania
  python audyt_firmy.py --check-link URL               # sprawdź jeden link zewnętrzny
  python audyt_firmy.py --diagnose URL_ARTYKULU        # co skrypt widzi w jednym artykule
  python audyt_firmy.py --diagnose-product URL         # przyciski "Zobacz..." na liście / stronie produktu
  (bez argumentów skrypt zapyta o linki; w pytaniu można też wpisać
   "--check-link URL", "--diagnose-product URL" albo "--diagnose URL")

Użycie jako moduł (Streamlit): audit_firm(url, include_products=..., include_articles=...)
"""
import argparse
import csv
import difflib
import ipaddress
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from curl_cffi import requests as cffi_requests
except Exception:          # biblioteka opcjonalna
    cffi_requests = None

USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')
PAGE_TIMEOUT = 15
LINK_TIMEOUT = 10
LINK_WORKERS = 8
DELAY = 0.5                    # przerwa między stronami serwisu (s)
MAX_LISTING_PAGES = 50         # bezpiecznik paginacji na jedną zakładkę
UNCERTAIN_CODES = {401, 403, 429, 999}
PRODUCT_BTN_TEXT = 'zobacz na stronie producenta'
ARTICLE_PATH_RE = re.compile(r'/\d+-[^/]+/?$')     # np. /porady/12345-tytul
PRODUCT_PATH_RE = re.compile(r'/p/\d+-[^/]+/?$')   # np. /firma/p/30376-nazwa
STRIP_TAB_RE = re.compile(r'(/(porady|newsy))?(/s/\d+)?/?$')
HEADING_TAGS = ['h1', 'h2', 'h3', 'h4', 'h5']

# błędny zapis schematu w CMS, np. "http:///host" albo "http:/host"
MALFORMED_SCHEME_RE = re.compile(r'^(https?):/*(?=[^/])', re.I)
MALFORMED_NOTE = 'adres zapisany błędnie w CMS (np. "http:///") - warto poprawić link'

# wykrywanie "miękkich 404" (strona zwraca 200, ale to błąd / strona główna)
SOFT_CHECK_BYTES = 200 * 1024            # ile bajtów strony analizować
SOFT_404_STATUS = 'BLAD'                 # komunikat o błędzie 404 w treści
HOME_FALLBACK_STATUS = 'BLAD'            # przekierowanie / treść jak strona główna
# porównywanie treści ze stroną główną bywa zawodne (strony ładowane skryptem,
# wspólne menu), więc jest domyślnie wyłączone; przekierowania na stronę
# główną i komunikaty 404 są wykrywane niezależnie
HOME_CONTENT_CHECK = False
ROOT_PATHS = {'', '/index.html', '/index.htm', '/index.php', '/home', '/start'}
SOFT_404_RE = re.compile(
    r'(błąd\s*404|blad\s*404|error\s*404|404\s*error|404\s*[-–:]?\s*not\s*found'
    r'|page\s+not\s+found|strona\s+nie\s+istnieje|podana\s+strona\s+nie\s+istnieje'
    r'|strona\s+nie\s+została\s+znaleziona|nie\s+znaleziono\s+strony)', re.I)

# wyłączenia przy szukaniu linków w treści artykułu
SKIP_TAGS = ['header', 'nav', 'footer', 'aside', 'form']
SKIP_CLASS_RE = re.compile(r'(share|social|author|autor|breadcrumb|comment|newsletter|related)', re.I)
SOCIAL_HOSTS = ('facebook.com', 'twitter.com', 'x.com', 'linkedin.com',
                'pinterest.com', 'whatsapp.com', 'wa.me')
# stałe elementy szablonu serwisu (nie są linkami z treści artykułu)
IGNORED_LINK_PATTERNS = ('google.com/preferences/source',)

# URL = adres produktu (dla produktów) lub adres artykułu (dla artykułów)
FIELDNAMES = ['Firma_URL', 'Typ', 'URL', 'Link', 'Status', 'Opis']

log = logging.getLogger('audyt')


# ---------------------------------------------------------------- HTTP

def make_session():
    session = requests.Session()
    session.headers.update({
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'pl-PL,pl;q=0.9,en;q=0.8',
        'Upgrade-Insecure-Requests': '1',
    })
    retry = Retry(total=2, backoff_factor=0.5,
                  status_forcelist=[502, 503, 504],
                  allowed_methods=['GET', 'HEAD'])
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=LINK_WORKERS * 2)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


SESSION = make_session()
_link_cache = {}
_outbound_cache = {}
_home_cache = {}               # strony główne domen (do wykrywania miękkich 404)
_MALFORMED = set()             # adresy naprawione z błędnego zapisu
_cache_lock = threading.Lock()


def clear_cache():
    with _cache_lock:
        _link_cache.clear()
        _outbound_cache.clear()
        _home_cache.clear()
        _MALFORMED.clear()


def is_safe_url(url):
    """Blokuje adresy lokalne/prywatne (ochrona przed SSRF)."""
    try:
        p = urlparse(url)
        if p.scheme not in ('http', 'https') or not p.hostname:
            return False
        for info in socket.getaddrinfo(p.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                return False
        return True
    except Exception:
        return False


def _fetch_for_check(url):
    """GET ze strumieniem. Zwraca (kod, adres_końcowy, treść).
    Treść (do SOFT_CHECK_BYTES) tylko dla stron HTML ze statusem < 400."""
    r = SESSION.get(url, timeout=LINK_TIMEOUT, stream=True, allow_redirects=True)
    try:
        body = b''
        ctype = (r.headers.get('Content-Type') or '').lower()
        if r.status_code < 400 and 'html' in ctype:
            for chunk in r.iter_content(chunk_size=8192):
                body += chunk
                if len(body) >= SOFT_CHECK_BYTES:
                    break
        return r.status_code, r.url, body
    finally:
        r.close()


def _second_opinion(url):
    """Drugi klient z odciskiem TLS Chrome (omija część blokad botów).
    None = klient niedostępny lub błąd."""
    if cffi_requests is None:
        return None
    try:
        r = cffi_requests.get(url, impersonate='chrome',
                              timeout=LINK_TIMEOUT, allow_redirects=True)
        return r.status_code
    except Exception:
        return None


def _classify(code):
    if code < 400:
        return 'OK'
    if code in UNCERTAIN_CODES:
        return 'NIEPEWNE'
    return 'BLAD'


def _is_root(path):
    return path.rstrip('/').lower() in ROOT_PATHS


def _visible_text(soup):
    for tag in soup(['script', 'style', 'noscript']):
        tag.decompose()
    return ' '.join(soup.get_text(' ', strip=True).split()).lower()


def _homepage(scheme, netloc):
    """(tekst strony głównej, ścieżka po przekierowaniach) albo None. Z cache."""
    key = f'{scheme}://{netloc}'
    with _cache_lock:
        if key in _home_cache:
            return _home_cache[key]
    result = None
    home_url = key + '/'
    if is_safe_url(home_url):
        try:
            code, final, body = _fetch_for_check(home_url)
            if code < 400 and body:
                result = (_visible_text(BeautifulSoup(body, 'html.parser')),
                          urlparse(final).path)
        except requests.RequestException:
            pass
    with _cache_lock:
        _home_cache[key] = result
    return result


def _soft_problem(url, code, final_url, body):
    """Wykrywa "miękkie 404": status 200, ale w rzeczywistości błąd lub strona główna.
    Zwraca (status, opis) albo None, gdy wszystko w porządku."""
    o, f = urlparse(url), urlparse(final_url)

    # 1) przekierowanie głębokiego adresu na stronę główną
    if not _is_root(o.path) and _is_root(f.path):
        return (HOME_FALLBACK_STATUS,
                f'{code}, ale przekierowano na stronę główną ({final_url})')
    if not body:
        return None

    soup = BeautifulSoup(body, 'html.parser')
    text = _visible_text(soup)

    # 2) komunikat o błędzie 404 w treści
    if SOFT_404_RE.search(text[:600]):
        return (SOFT_404_STATUS,
                f'{code}, ale strona zawiera komunikat o błędzie 404 (brak podstrony)')

    # 3) (opcjonalnie) treść identyczna ze stroną główną domeny
    if HOME_CONTENT_CHECK and not _is_root(o.path) and len(text) > 200:
        home = _homepage(f.scheme, f.netloc)
        if home:
            home_text, home_final_path = home
            if (len(home_text) > 200
                    and home_final_path.rstrip('/') != f.path.rstrip('/')
                    and text == home_text):
                return (HOME_FALLBACK_STATUS,
                        f'{code}, ale treść identyczna ze stroną główną (brak podstrony?)')
    return None


def check_external_link(url):
    """Zwraca ('OK' | 'NIEPEWNE' | 'BLAD', opis). Wyniki są cache'owane.
    Sprawdza kod HTTP oraz "miękkie 404" (200, ale błąd / strona główna).
    Błąd jest potwierdzany drugim klientem, żeby ograniczyć fałszywe alarmy."""
    with _cache_lock:
        if url in _link_cache:
            return _link_cache[url]

    if not is_safe_url(url):
        return ('BLAD', 'Niedozwolony lub nieosiągalny adres')

    code, err = None, None
    final_url, body = url, b''
    try:
        code, final_url, body = _fetch_for_check(url)
    except requests.RequestException as e:
        err = type(e).__name__

    if code is not None and code < 400:
        result = _soft_problem(url, code, final_url, body) or ('OK', str(code))
    else:
        code2 = _second_opinion(url)
        if code2 is not None and code2 < 400:
            result = ('OK', f'{code2} (potwierdzone drugim klientem)')
        else:
            final = code2 if code2 is not None else code
            if final is not None:
                result = (_classify(final), str(final))
            else:
                # timeout i błąd certyfikatu SSL nie oznaczają martwego linku
                is_timeout = err in ('Timeout', 'ReadTimeout', 'ConnectTimeout', 'SSLError')
                result = ('NIEPEWNE' if is_timeout else 'BLAD', err)

    with _cache_lock:
        _link_cache[url] = result
    return result


def check_many(links):
    """Sprawdza listę linków równolegle; wynik w tej samej kolejności."""
    if not links:
        return []
    with ThreadPoolExecutor(max_workers=LINK_WORKERS) as pool:
        return list(pool.map(check_external_link, links))


def fetch_soup(url):
    try:
        r = SESSION.get(url, timeout=PAGE_TIMEOUT)
        if r.status_code != 200:
            log.warning('HTTP %s dla %s', r.status_code, url)
            return None
        return BeautifulSoup(r.content, 'html.parser')
    except requests.RequestException as e:
        log.warning('Błąd pobierania %s (%s)', url, type(e).__name__)
        return None


# ---------------------------------------------------------------- URL-e

def normalize_host(netloc):
    host = netloc.lower().split('@')[-1].split(':')[0]
    return host.removeprefix('www.')


def is_external(href, base_domain):
    host = normalize_host(urlparse(href).netloc)
    return bool(host) and host != base_domain and not host.endswith('.' + base_domain)


def clean_url(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip('/'), '', '', ''))


def firm_base_url(url):
    """Zwraca adres głównej zakładki firmy (bez /porady, /newsy, /s/N)."""
    url = clean_url(url.strip())
    return STRIP_TAB_RE.sub('', url)


def _join(base, raw):
    """urljoin z naprawą błędnego zapisu schematu (http:///host, http:/host).
    Naprawiony adres jest zapamiętany, żeby dopisać uwagę w raporcie."""
    raw = raw.strip()
    fixed = MALFORMED_SCHEME_RE.sub(lambda m: m.group(1) + '://', raw)
    url = urljoin(base, fixed)
    if fixed != raw:
        with _cache_lock:
            _MALFORMED.add(url)
    return url


def _with_note(link, desc):
    """Dopisuje uwagę do opisu, jeśli adres był błędnie zapisany w CMS."""
    if link in _MALFORMED:
        return f'{desc} ({MALFORMED_NOTE})'
    return desc


def _row(firm, typ, url, link, status, desc):
    return {'Firma_URL': firm, 'Typ': typ, 'URL': url,
            'Link': link, 'Status': status, 'Opis': desc}


# ---------------------------------------------------------------- listy z paginacją

def crawl_listing(tab_url):
    """Generator (page_url, soup) dla zakładki i jej podstron /s/N.
    Kolejne strony odkrywa z linków paginacji na stronie (bez zgadywania kroku)."""
    tab_url = clean_url(tab_url)
    parsed = urlparse(tab_url)
    pager_re = re.compile('^' + re.escape(parsed.path) + r'/s/\d+$')

    queue, seen = [tab_url], {tab_url}
    while queue and len(seen) <= MAX_LISTING_PAGES:
        url = queue.pop(0)
        soup = fetch_soup(url)
        time.sleep(DELAY)
        if soup is None:
            continue

        # najpierw zbierz paginację (zanim ktoś zmodyfikuje soup)
        for a in soup.find_all('a', href=True):
            full = urljoin(url, a['href'].strip())
            p = urlparse(full)
            if p.netloc == parsed.netloc and pager_re.match(p.path.rstrip('/')):
                nxt = clean_url(full)
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)

        yield url, soup


# ---------------------------------------------------------------- produkty

def _is_product_btn(a):
    classes = a.get('class') or []
    text = a.get_text(' ', strip=True).lower()
    return 'firm__product-btn' in classes or PRODUCT_BTN_TEXT in text


def _slug_name(url):
    last = urlparse(url).path.rstrip('/').split('/')[-1]
    return re.sub(r'^\d+-', '', last).replace('-', ' ').strip()


def extract_product_items(soup, page_url):
    """Zwraca listę produktów z listy firmy:
    {'name', 'product_url', 'outbound', 'page'}
      outbound - link z przycisku, jeśli prowadzi poza budujemydom.pl (inaczej None),
      page     - adres do rozwiązania (strona produktu lub wewnętrzne przekierowanie),
                 gdy przycisk nie prowadzi bezpośrednio do producenta.
    Nazwę (tylko do trybu debug) i adres produktu szuka w najmniejszym kontenerze
    wokół przycisku, który zawiera tylko jeden przycisk produktowy."""
    base_domain = normalize_host(urlparse(page_url).netloc)
    items, seen = [], set()

    for btn in soup.find_all('a', href=True):
        if not _is_product_btn(btn):
            continue
        btn_href = _join(page_url, btn['href'])
        if urlparse(btn_href).scheme not in ('http', 'https'):
            continue

        product_url, name, tile = '', '', None
        node = btn.parent
        for _ in range(6):
            if node is None:
                break
            anchors = node.find_all('a', href=True)
            if sum(1 for x in anchors if _is_product_btn(x)) > 1:
                break                      # za duży kontener (kilka produktów)
            tile = node
            link = None
            for a in anchors:
                href = urljoin(page_url, a['href'].strip())
                if (not is_external(href, base_domain)
                        and PRODUCT_PATH_RE.search(urlparse(href).path)):
                    link, product_url = a, clean_url(href)
                    break
            if link is not None:
                heading = node.find(HEADING_TAGS)
                if heading:
                    name = heading.get_text(' ', strip=True)
                if not name and not _is_product_btn(link):
                    name = link.get_text(' ', strip=True) or (link.get('title') or '').strip()
                break
            node = node.parent

        if not name and tile is not None:
            heading = tile.find(HEADING_TAGS)
            if heading:
                name = heading.get_text(' ', strip=True)
        if not name and product_url:
            name = _slug_name(product_url)

        outbound = btn_href if is_external(btn_href, base_domain) else None
        if outbound is not None:
            page = product_url
        else:
            # przycisk wewnętrzny: użyj jego adresu, ale nie samej strony listy
            # (np. href="#"), bo dałoby to link z innego produktu
            same_as_list = clean_url(btn_href) == clean_url(page_url)
            page = product_url if same_as_list else btn_href

        key = product_url or btn_href
        if key in seen:
            continue
        seen.add(key)
        items.append({'name': name, 'product_url': product_url,
                      'outbound': outbound, 'page': page})
    return items


def _final_url(url):
    """Adres po wszystkich przekierowaniach (None przy błędzie)."""
    try:
        r = SESSION.get(url, timeout=PAGE_TIMEOUT, stream=True, allow_redirects=True)
        final = r.url
        r.close()
        return final
    except requests.RequestException:
        return None


def resolve_outbound(product_page_url):
    """Z wewnętrznego adresu (strona produktu lub przekierowanie) wyciąga link do producenta.
    Obsługuje: przekierowanie wychodzące poza serwis, zewnętrzny href przycisku
    oraz przycisk będący wewnętrznym przekierowaniem na stronę producenta."""
    if not product_page_url:
        return None
    with _cache_lock:
        if product_page_url in _outbound_cache:
            return _outbound_cache[product_page_url]

    result = None
    base_domain = normalize_host(urlparse(product_page_url).netloc)
    try:
        r = SESSION.get(product_page_url, timeout=PAGE_TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        log.warning('Błąd pobierania %s (%s)', product_page_url, type(e).__name__)
        r = None
    time.sleep(DELAY)

    if r is not None:
        if is_external(r.url, base_domain):
            result = r.url                      # przekierowanie wyszło poza serwis
        elif r.status_code == 200:
            soup = BeautifulSoup(r.content, 'html.parser')
            for a in soup.find_all('a', href=True):
                if not _is_product_btn(a):
                    continue
                href = _join(r.url, a['href'])
                if urlparse(href).scheme not in ('http', 'https'):
                    continue
                if is_external(href, base_domain):
                    result = href
                    break
                if clean_url(href) != clean_url(r.url):
                    final = _final_url(href)    # wewnętrzny adres - sprawdź dokąd prowadzi
                    if final and is_external(final, base_domain):
                        result = final
                        break
        else:
            log.warning('HTTP %s dla %s', r.status_code, product_page_url)

    with _cache_lock:
        _outbound_cache[product_page_url] = result
    return result


def _product_rows(firm, page_url, items):
    for it in items:
        it['final'] = it['outbound'] or resolve_outbound(it['page'])

    unique = list(dict.fromkeys(it['final'] for it in items if it['final']))
    status_map = dict(zip(unique, check_many(unique)))

    for it in items:
        # adres produktu na budujemydom.pl; jeśli go nie znaleziono, podajemy stronę listy
        product_ref = it['product_url'] or page_url
        link = it['final']
        if not link:
            status, desc = 'BRAK', 'Nie znaleziono linku do producenta'
        else:
            status, desc = status_map[link]
            desc = _with_note(link, desc)
        # w raporcie: URL = adres produktu, kolumna Link pusta
        yield _row(firm, 'Produkt', product_ref, '', status, desc)


# ---------------------------------------------------------------- artykuły

def extract_article_links(soup, page_url):
    """Linki do artykułów z listy (bez menu, nagłówka, stopki, sidebaru).
    Nie modyfikuje soup."""
    base_domain = normalize_host(urlparse(page_url).netloc)
    links = []
    for a in soup.find_all('a', href=True):
        if a.find_parent(['header', 'nav', 'footer', 'aside']):
            continue
        href = urljoin(page_url, a['href'].strip())
        p = urlparse(href)
        if p.scheme not in ('http', 'https') or is_external(href, base_domain):
            continue
        if p.path.startswith('/firmy/'):
            continue
        if ARTICLE_PATH_RE.search(p.path):
            c = clean_url(href)
            if c not in links:
                links.append(c)
    return links


def find_content_area(soup):
    """Szuka obszaru treści; przy kilku kandydatach tego samego typu bierze
    ten z największą ilością tekstu (a nie pierwszy z brzegu)."""
    for candidates in (soup.find_all('div', itemprop='articleBody'),
                       soup.find_all('article'),
                       soup.find_all('div', class_='item-page')):
        if candidates:
            return max(candidates, key=lambda c: len(c.get_text(' ', strip=True)))
    return None


def _in_skipped_block(a, area):
    for parent in a.parents:
        if parent is area:
            break
        if parent.name in SKIP_TAGS:
            return True
        cls = ' '.join(parent.get('class') or [])
        if cls and SKIP_CLASS_RE.search(cls):
            return True
    return False


def extract_article_external_links(content_area, page_url):
    """Wszystkie linki zewnętrzne w obszarze treści (nie tylko z <p> i <li>)."""
    base_domain = normalize_host(urlparse(page_url).netloc)
    links = []
    for a in content_area.find_all('a', href=True):
        raw = a['href'].strip()
        if not raw or raw.startswith('#'):
            continue
        href = _join(page_url, raw)
        if urlparse(href).scheme not in ('http', 'https'):
            continue
        host = normalize_host(urlparse(href).netloc)
        if any(host == h or host.endswith('.' + h) for h in SOCIAL_HOSTS):
            continue
        if any(p in href for p in IGNORED_LINK_PATTERNS):
            continue
        if _in_skipped_block(a, content_area):
            continue
        if is_external(href, base_domain) and href not in links:
            links.append(href)
    return links


def _article_rows(firm, article_url, links):
    for link, (status, desc) in zip(links, check_many(links)):
        yield _row(firm, 'Artykuł', article_url, link, status,
                   _with_note(link, desc))


# ---------------------------------------------------------------- diagnostyka

def diagnose_article(url):
    """Pokazuje, co skrypt widzi w artykule: obszar treści i wszystkie linki zewnętrzne."""
    soup = fetch_soup(url)
    if soup is None:
        print('Nie udało się pobrać strony.')
        return
    area = find_content_area(soup)
    base_domain = normalize_host(urlparse(url).netloc)
    if area is None:
        print('Obszar treści: NIE ZNALEZIONO')
    else:
        print(f"Obszar treści: <{area.name}> class={area.get('class')} "
              f"itemprop={area.get('itemprop')} "
              f"({len(area.get_text(' ', strip=True))} znaków)")
    print('Linki zewnętrzne na stronie:')
    for a in soup.find_all('a', href=True):
        href = _join(url, a['href'])
        if urlparse(href).scheme not in ('http', 'https') or not is_external(href, base_domain):
            continue
        inside = area is not None and area in list(a.parents)
        skipped = inside and _in_skipped_block(a, area)
        place = 'W TREŚCI' if inside else 'POZA TREŚCIĄ'
        if skipped:
            place += ', POMINIĘTY'
        if any(p in href for p in IGNORED_LINK_PATTERNS):
            place += ', IGNOROWANY (szablon)'
        chain = ' > '.join(
            f"{p.name}" + (f".{'.'.join(p.get('class') or [])}" if p.get('class') else '')
            for p in list(a.parents)[:4][::-1])
        print(f"  [{place}] {href}")
        print(f"      tekst: {a.get_text(' ', strip=True)[:60]!r} | rodzice: {chain}")


def diagnose_product(url):
    """Pokazuje wszystkie elementy 'Zobacz na stronie producenta' / 'Zobacz...'
    na stronie (lista firmy lub strona produktu) - z surowymi atrybutami."""
    try:
        resp = SESSION.get(url, timeout=PAGE_TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        print(f'Błąd pobierania: {type(e).__name__}')
        return
    print(f'HTTP {resp.status_code} | adres końcowy: {resp.url}')
    soup = BeautifulSoup(resp.content, 'html.parser')

    print('\n== Elementy z tekstem "Zobacz na stronie producenta" (dowolny znacznik) ==')
    nodes = soup.find_all(string=re.compile(PRODUCT_BTN_TEXT, re.I))
    print(f'Znaleziono: {len(nodes)}')
    for i, node in enumerate(nodes, 1):
        el = node.parent
        attrs = {k: v for k, v in el.attrs.items()}
        parent = el.parent
        print(f'  {i}. <{el.name}> atrybuty: {attrs}')
        if parent is not None:
            print(f'      rodzic: <{parent.name}> {dict(list(parent.attrs.items())[:4])}')
        if i >= 6:
            print('  ... (pokazano pierwsze 6)')
            break

    print('\n== Wszystkie linki zaczynające się od "Zobacz" ==')
    for a in soup.find_all('a'):
        text = a.get_text(' ', strip=True)
        if text.lower().startswith('zobacz'):
            print(f"  tekst: {text!r}")
            print(f"    href: {a.get('href')!r} | class: {a.get('class')} "
                  f"| target: {a.get('target')} | rel: {a.get('rel')}")


def check_one_link(url):
    """Sprawdza pojedynczy link zewnętrzny i wypisuje wynik."""
    status, desc = check_external_link(url)
    print(f'{status} | {desc}')


# ---------------------------------------------------------------- audyt

def audit_firm(firm_url, debug=False, include_products=True, include_articles=True):
    """Generator wierszy raportu dla jednej firmy.
    Nie drukuje wyników - nadaje się do użycia w Streamlit."""
    base = firm_base_url(firm_url)
    log.info('Firma: %s', base)

    # 1) produkty
    if include_products:
        found_products = False
        for page_url, soup in crawl_listing(base):
            items = extract_product_items(soup, page_url)
            log.info('  Produkty %s: %d', page_url, len(items))
            found_products = found_products or bool(items)
            if debug:
                for it in items:
                    print(f"[PRODUKT] {it['product_url'] or '(brak adresu produktu)'} | "
                          f"{it['outbound'] or '(przez: ' + (it['page'] or 'brak') + ')'}")
                continue
            yield from _product_rows(base, page_url, items)
        if not found_products and not debug:
            yield _row(base, 'Produkt', base, '', 'BRAK',
                       'Nie znaleziono linków produktowych')

    # 2) artykuły (porady + newsy)
    if include_articles:
        seen_articles = set()
        for tab in ('porady', 'newsy'):
            for page_url, soup in crawl_listing(f'{base}/{tab}'):
                articles = [a for a in extract_article_links(soup, page_url)
                            if a not in seen_articles]
                seen_articles.update(articles)
                log.info('  %s %s: %d artykułów', tab, page_url, len(articles))
                for art_url in articles:
                    if debug:
                        print(f'[ARTYKUŁ/{tab}] {art_url}')
                        continue
                    art_soup = fetch_soup(art_url)
                    time.sleep(DELAY)
                    if art_soup is None:
                        yield _row(base, 'Artykuł', art_url, '', 'BLAD',
                                   'Błąd pobierania artykułu')
                        continue
                    area = find_content_area(art_soup)
                    if area is None:
                        yield _row(base, 'Artykuł', art_url, '', 'BRAK',
                                   'Nie znaleziono treści artykułu')
                        continue
                    links = extract_article_external_links(area, art_url)
                    if not links:
                        yield _row(base, 'Artykuł', art_url, '', 'BRAK',
                                   'Brak linków zewnętrznych w tekście')
                        continue
                    yield from _article_rows(base, art_url, links)


# ---------------------------------------------------------------- CLI

def main():
    parser = argparse.ArgumentParser(description='Audyt linków produktowych i artykułowych firmy.')
    parser.add_argument('urls', nargs='*', help='adresy zakładek firm')
    parser.add_argument('-i', '--input', help='plik z adresami firm (jeden na linię)')
    parser.add_argument('-o', '--output', default='raport_firmy.csv')
    parser.add_argument('--debug', action='store_true',
                        help='tylko wypisz znalezione linki (bez sprawdzania i CSV)')
    parser.add_argument('--check-link', metavar='URL',
                        help='sprawdź jeden link zewnętrzny i wypisz wynik')
    parser.add_argument('--diagnose', metavar='URL_ARTYKULU',
                        help='pokaż, jakie linki skrypt widzi w jednym artykule')
    parser.add_argument('--diagnose-product', metavar='URL',
                        help='pokaż przyciski "Zobacz..." na liście firmy lub stronie produktu')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    if args.check_link:
        check_one_link(args.check_link)
        return
    if args.diagnose:
        diagnose_article(args.diagnose)
        return
    if args.diagnose_product:
        diagnose_product(args.diagnose_product)
        return

    urls = list(args.urls)
    if args.input:
        with open(args.input, encoding='utf-8') as f:
            urls += [l.strip() for l in f if l.strip()]

    if not urls:  # uruchomienie bez argumentów (np. IDLE) - zapytaj
        raw = input('Wklej link(i) do firm (oddziel spacją) albo '
                    '"--check-link URL" / "--diagnose-product URL" / "--diagnose URL": ').strip()
        parts = raw.split()
        if len(parts) >= 2 and parts[0] == '--check-link':
            check_one_link(parts[1])
            return
        if len(parts) >= 2 and parts[0] == '--diagnose-product':
            diagnose_product(parts[1])
            return
        if len(parts) >= 2 and parts[0] == '--diagnose':
            diagnose_article(parts[1])
            return
        urls = parts
        if input('Tryb debug (tylko podgląd linków)? [t/N]: ').strip().lower() == 't':
            args.debug = True

    urls = list(dict.fromkeys(firm_base_url(u) for u in urls))
    if not urls:
        parser.error('Podaj przynajmniej jeden adres firmy lub plik -i.')

    if args.debug:
        for u in urls:
            for _ in audit_firm(u, debug=True):
                pass
        return

    counts = {}
    with open(args.output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, delimiter=';')
        writer.writeheader()
        for u in urls:
            for row in audit_firm(u):
                writer.writerow(row)
                f.flush()
                key = (row['Typ'], row['Status'])
                counts[key] = counts.get(key, 0) + 1

    log.info('Gotowe. Zapisano: %s', args.output)
    for (typ, status), n in sorted(counts.items()):
        log.info('  %s / %s: %d', typ, status, n)


if __name__ == '__main__':
    main()
