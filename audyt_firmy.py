#!/usr/bin/env python3
"""
Audyt linków firmy na budujemydom.pl:
  1) linki produktowe ("Zobacz na stronie producenta") z zakładki firmy
     (w raporcie: adres strony produktu na budujemydom.pl),
  2) linki zewnętrzne w artykułach z zakładek /porady i /newsy.

Użycie jako skrypt:
  python audyt_firmy.py https://budujemydom.pl/irbj/.../fakro
  python audyt_firmy.py -i firmy.txt -o raport.csv
  python audyt_firmy.py URL --debug              # pokaż znalezione linki, bez sprawdzania
  python audyt_firmy.py --diagnose URL_ARTYKULU  # co skrypt widzi w jednym artykule
  (bez argumentów skrypt zapyta o linki)

Użycie jako moduł (Streamlit): audit_firm(url, include_products=..., include_articles=...)
"""
import argparse
import csv
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

# wyłączenia przy szukaniu linków w treści artykułu
SKIP_TAGS = ['header', 'nav', 'footer', 'aside', 'form']
SKIP_CLASS_RE = re.compile(r'(share|social|author|autor|breadcrumb|comment|newsletter|related)', re.I)
SOCIAL_HOSTS = ('facebook.com', 'twitter.com', 'x.com', 'linkedin.com',
                'pinterest.com', 'whatsapp.com', 'wa.me')

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
_cache_lock = threading.Lock()


def clear_cache():
    with _cache_lock:
        _link_cache.clear()
        _outbound_cache.clear()


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


def _http_status(url):
    """HEAD, a przy błędzie GET. Zwraca kod HTTP; wyjątki sieciowe propaguje."""
    r = SESSION.head(url, timeout=LINK_TIMEOUT, allow_redirects=True)
    if r.status_code >= 400:
        r = SESSION.get(url, timeout=LINK_TIMEOUT, stream=True, allow_redirects=True)
        r.close()
    return r.status_code


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


def check_external_link(url):
    """Zwraca ('OK' | 'NIEPEWNE' | 'BLAD', opis). Wyniki są cache'owane.
    Błąd jest potwierdzany drugim klientem, żeby ograniczyć fałszywe alarmy."""
    with _cache_lock:
        if url in _link_cache:
            return _link_cache[url]

    if not is_safe_url(url):
        return ('BLAD', 'Niedozwolony lub nieosiągalny adres')

    code, err = None, None
    try:
        code = _http_status(url)
    except requests.RequestException as e:
        err = type(e).__name__

    if code is not None and code < 400:
        result = ('OK', str(code))
    else:
        code2 = _second_opinion(url)
        if code2 is not None and code2 < 400:
            result = ('OK', f'{code2} (potwierdzone drugim klientem)')
        else:
            final = code2 if code2 is not None else code
            if final is not None:
                result = (_classify(final), str(final))
            else:
                is_timeout = err in ('Timeout', 'ReadTimeout', 'ConnectTimeout')
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
      page     - strona do pobrania, gdy trzeba z niej wyciągnąć link do producenta.
    Nazwę (tylko do trybu debug) i adres produktu szuka w najmniejszym kontenerze
    wokół przycisku, który zawiera tylko jeden przycisk produktowy."""
    base_domain = normalize_host(urlparse(page_url).netloc)
    items, seen = [], set()

    for btn in soup.find_all('a', href=True):
        if not _is_product_btn(btn):
            continue
        btn_href = urljoin(page_url, btn['href'].strip())
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
        key = product_url or btn_href
        if key in seen:
            continue
        seen.add(key)
        items.append({'name': name, 'product_url': product_url,
                      'outbound': outbound,
                      'page': btn_href if outbound is None else product_url})
    return items


def resolve_outbound(product_page_url):
    """Z wewnętrznej strony produktu wyciąga link do producenta (lub None)."""
    if not product_page_url:
        return None
    with _cache_lock:
        if product_page_url in _outbound_cache:
            return _outbound_cache[product_page_url]
    soup = fetch_soup(product_page_url)
    time.sleep(DELAY)
    result = None
    if soup is not None:
        base_domain = normalize_host(urlparse(product_page_url).netloc)
        for a in soup.find_all('a', href=True):
            if _is_product_btn(a):
                href = urljoin(product_page_url, a['href'].strip())
                if (urlparse(href).scheme in ('http', 'https')
                        and is_external(href, base_domain)):
                    result = href
                    break
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
        href = urljoin(page_url, raw)
        if urlparse(href).scheme not in ('http', 'https'):
            continue
        host = normalize_host(urlparse(href).netloc)
        if any(host == h or host.endswith('.' + h) for h in SOCIAL_HOSTS):
            continue
        if _in_skipped_block(a, content_area):
            continue
        if is_external(href, base_domain) and href not in links:
            links.append(href)
    return links


def _article_rows(firm, article_url, links):
    for link, (status, desc) in zip(links, check_many(links)):
        yield _row(firm, 'Artykuł', article_url, link, status, desc)


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
        href = urljoin(url, a['href'].strip())
        if urlparse(href).scheme not in ('http', 'https') or not is_external(href, base_domain):
            continue
        inside = area is not None and area in list(a.parents)
        skipped = inside and _in_skipped_block(a, area)
        place = 'W TREŚCI' if inside else 'POZA TREŚCIĄ'
        if skipped:
            place += ', POMINIĘTY'
        chain = ' > '.join(
            f"{p.name}" + (f".{'.'.join(p.get('class') or [])}" if p.get('class') else '')
            for p in list(a.parents)[:4][::-1])
        print(f"  [{place}] {href}")
        print(f"      tekst: {a.get_text(' ', strip=True)[:60]!r} | rodzice: {chain}")


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
                    print(f"[PRODUKT] {it['name'] or '(brak nazwy)'} | "
                          f"{it['product_url'] or '(brak adresu produktu)'} | "
                          f"{it['outbound'] or '(link przez stronę produktu)'}")
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
    parser.add_argument('--diagnose', metavar='URL_ARTYKULU',
                        help='pokaż, jakie linki skrypt widzi w jednym artykule')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    if args.diagnose:
        diagnose_article(args.diagnose)
        return

    urls = list(args.urls)
    if args.input:
        with open(args.input, encoding='utf-8') as f:
            urls += [l.strip() for l in f if l.strip()]

    if not urls:  # uruchomienie bez argumentów (np. IDLE) - zapytaj
        raw = input('Wklej link(i) do firm (oddziel spacją): ').strip()
        urls = raw.split()
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
