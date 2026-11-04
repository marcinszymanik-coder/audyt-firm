#!/usr/bin/env python3
"""
Audyt linków firmy na budujemydom.pl:
  1) linki produktowe ("Zobacz na stronie producenta") z zakładki firmy,
  2) linki zewnętrzne w artykułach z zakładek /porady i /newsy.

Użycie jako skrypt:
  python audyt_firmy.py https://budujemydom.pl/irbj/.../fakro
  python audyt_firmy.py -i firmy.txt -o raport.csv
  python audyt_firmy.py URL --debug      # pokaż znalezione linki, bez sprawdzania
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

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
PAGE_TIMEOUT = 15
LINK_TIMEOUT = 10
LINK_WORKERS = 8
DELAY = 0.5                    # przerwa między stronami serwisu (s)
MAX_LISTING_PAGES = 50         # bezpiecznik paginacji na jedną zakładkę
UNCERTAIN_CODES = {401, 403, 429, 999}
PRODUCT_BTN_TEXT = 'zobacz na stronie producenta'
ARTICLE_PATH_RE = re.compile(r'/\d+-[^/]+/?$')     # np. /porady/12345-tytul
STRIP_TAB_RE = re.compile(r'(/(porady|newsy))?(/s/\d+)?/?$')

FIELDNAMES = ['Firma_URL', 'Typ', 'Zrodlo', 'Link', 'Status', 'Opis']

log = logging.getLogger('audyt')


# ---------------------------------------------------------------- HTTP

def make_session():
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})
    retry = Retry(total=2, backoff_factor=0.5,
                  status_forcelist=[502, 503, 504],
                  allowed_methods=['GET', 'HEAD'])
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=LINK_WORKERS * 2)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


SESSION = make_session()
_link_cache = {}
_cache_lock = threading.Lock()


def clear_cache():
    with _cache_lock:
        _link_cache.clear()


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


def check_external_link(url):
    """Zwraca ('OK' | 'NIEPEWNE' | 'BLAD', opis). Wyniki są cache'owane."""
    with _cache_lock:
        if url in _link_cache:
            return _link_cache[url]

    if not is_safe_url(url):
        return ('BLAD', 'Niedozwolony lub nieosiągalny adres')

    try:
        r = SESSION.head(url, timeout=LINK_TIMEOUT, allow_redirects=True)
        if r.status_code >= 400:
            # część serwerów nie obsługuje HEAD - próbujemy GET
            r = SESSION.get(url, timeout=LINK_TIMEOUT, stream=True,
                            allow_redirects=True)
            r.close()
        code = r.status_code
        if code < 400:
            result = ('OK', str(code))
        elif code in UNCERTAIN_CODES:
            result = ('NIEPEWNE', str(code))
        else:
            result = ('BLAD', str(code))
    except requests.RequestException as e:
        result = ('BLAD', type(e).__name__)

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

def extract_product_links(soup, page_url):
    links = []
    for a in soup.find_all('a', href=True):
        classes = a.get('class') or []
        text = a.get_text(' ', strip=True).lower()
        if 'firm__product-btn' in classes or PRODUCT_BTN_TEXT in text:
            href = urljoin(page_url, a['href'].strip())
            if urlparse(href).scheme in ('http', 'https') and href not in links:
                links.append(href)
    return links


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
    return (soup.find('div', itemprop='articleBody')
            or soup.find('article')
            or soup.find('div', class_='item-page'))


def extract_article_external_links(content_area, page_url):
    base_domain = normalize_host(urlparse(page_url).netloc)
    links = []
    for tag in content_area.find_all(['p', 'li']):
        for a in tag.find_all('a', href=True):
            raw = a['href'].strip()
            if not raw or raw.startswith('#'):
                continue
            href = urljoin(page_url, raw)
            if urlparse(href).scheme not in ('http', 'https'):
                continue
            if 'facebook.com/sharer' in href:
                continue
            if is_external(href, base_domain) and href not in links:
                links.append(href)
    return links


# ---------------------------------------------------------------- audyt

def _rows_for_links(firm, typ, source, links):
    results = check_many(links)
    for link, (status, desc) in zip(links, results):
        yield {'Firma_URL': firm, 'Typ': typ, 'Zrodlo': source,
               'Link': link, 'Status': status, 'Opis': desc}


def audit_firm(firm_url, debug=False, include_products=True, include_articles=True):
    """Generator wierszy raportu dla jednej firmy.
    Nie drukuje wyników - nadaje się do użycia w Streamlit."""
    base = firm_base_url(firm_url)
    log.info('Firma: %s', base)

    # 1) produkty
    if include_products:
        found_products = False
        for page_url, soup in crawl_listing(base):
            links = extract_product_links(soup, page_url)
            log.info('  Produkty %s: %d linków', page_url, len(links))
            found_products = found_products or bool(links)
            if debug:
                for l in links:
                    print(f'[PRODUKT] {l}')
                continue
            yield from _rows_for_links(base, 'Produkt', page_url, links)
        if not found_products and not debug:
            yield {'Firma_URL': base, 'Typ': 'Produkt', 'Zrodlo': base, 'Link': '',
                   'Status': 'BRAK', 'Opis': 'Nie znaleziono linków produktowych'}

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
                        yield {'Firma_URL': base, 'Typ': 'Artykuł', 'Zrodlo': art_url,
                               'Link': '', 'Status': 'BLAD',
                               'Opis': 'Błąd pobierania artykułu'}
                        continue
                    area = find_content_area(art_soup)
                    if area is None:
                        yield {'Firma_URL': base, 'Typ': 'Artykuł', 'Zrodlo': art_url,
                               'Link': '', 'Status': 'BRAK',
                               'Opis': 'Nie znaleziono treści artykułu'}
                        continue
                    links = extract_article_external_links(area, art_url)
                    if not links:
                        yield {'Firma_URL': base, 'Typ': 'Artykuł', 'Zrodlo': art_url,
                               'Link': '', 'Status': 'BRAK',
                               'Opis': 'Brak linków zewnętrznych w tekście'}
                        continue
                    yield from _rows_for_links(base, 'Artykuł', art_url, links)


# ---------------------------------------------------------------- CLI

def main():
    parser = argparse.ArgumentParser(description='Audyt linków produktowych i artykułowych firmy.')
    parser.add_argument('urls', nargs='*', help='adresy zakładek firm')
    parser.add_argument('-i', '--input', help='plik z adresami firm (jeden na linię)')
    parser.add_argument('-o', '--output', default='raport_firmy.csv')
    parser.add_argument('--debug', action='store_true',
                        help='tylko wypisz znalezione linki (bez sprawdzania i CSV)')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

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