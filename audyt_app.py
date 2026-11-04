import re
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

import audyt_firmy as af

st.set_page_config(page_title="Audyt linków firm IRBJ", page_icon="🔗", layout="wide")

ALLOWED_HOST = "budujemydom.pl"
URL_RE = re.compile(r'https?://[^\s,;"\'<>]+')


# ---------------------------------------------------------------- logowanie Google

def require_login():
    """Wpuszcza tylko zalogowanych użytkowników z domeny organizacji.
    Domena pochodzi z secrets (ALLOWED_EMAIL_DOMAIN); brak = dostęp zablokowany."""
    try:
        allowed_domain = str(st.secrets["ALLOWED_EMAIL_DOMAIN"]).lower().lstrip("@")
        has_auth = "auth" in st.secrets
    except Exception:
        allowed_domain, has_auth = "", False

    if not allowed_domain or not has_auth:
        st.error("Brak konfiguracji logowania (secrets: [auth] i ALLOWED_EMAIL_DOMAIN).")
        st.stop()

    if not st.user.is_logged_in:
        st.title("🔗 Audyt linków firm (IRBJ)")
        st.info("Zaloguj się kontem Google organizacji.")
        st.button("Zaloguj przez Google", on_click=st.login, type="primary",
                  key="btn_login")
        st.stop()

    email = (st.user.get("email") or "").lower()
    verified = bool(st.user.get("email_verified", False))
    if not (verified and email.endswith("@" + allowed_domain)):
        st.error(f"Brak dostępu dla konta: {email or 'nieznane'}")
        st.button("Wyloguj", on_click=st.logout, key="btn_logout_denied")
        st.stop()

    with st.sidebar:
        st.caption(f"Zalogowano: {email}")
        st.button("Wyloguj", on_click=st.logout, key="btn_logout")


# ---------------------------------------------------------------- pomocnicze

def is_allowed_firm_url(url: str) -> bool:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    return p.scheme in ("http", "https") and (
        host == ALLOWED_HOST or host.endswith("." + ALLOWED_HOST))


# ---------------------------------------------------------------- aplikacja

def main():
    require_login()

    st.title("🔗 Audyt linków firm (IRBJ)")
    st.markdown(
        "Sprawdza **linki produktowe** („Zobacz na stronie producenta”) oraz "
        "**linki zewnętrzne w artykułach** (porady i newsy) wskazanych firm.")

    urls_in = st.text_area(
        "Linki do zakładek firm (jeden pod drugim):",
        placeholder="https://budujemydom.pl/irbj/.../botament-hydroizolacje",
        height=120, key="audit_urls")

    c1, c2 = st.columns(2)
    inc_products = c1.checkbox("Linki produktowe", value=True, key="audit_inc_prod")
    inc_articles = c2.checkbox("Linki w artykułach (porady + newsy)", value=True,
                               key="audit_inc_art")

    if st.button("Uruchom audyt", type="primary", key="btn_audit"):
        raw = list(dict.fromkeys(URL_RE.findall(urls_in)))
        valid = list(dict.fromkeys(
            af.firm_base_url(u) for u in raw if is_allowed_firm_url(u)))
        rejected = [u for u in raw if not is_allowed_firm_url(u)]

        if rejected:
            st.warning("Pominięto adresy spoza budujemydom.pl:\n\n" + "\n".join(rejected))
        if not valid:
            st.error("Podaj przynajmniej jeden poprawny link do firmy.")
        elif not (inc_products or inc_articles):
            st.error("Zaznacz przynajmniej jeden zakres audytu.")
        else:
            af.clear_cache()   # świeże wyniki przy każdym uruchomieniu
            rows = []
            live = st.empty()
            with st.status("Audyt w toku…", expanded=True) as status:
                for i, firm in enumerate(valid, 1):
                    status.update(label=f"Firma {i}/{len(valid)}: {firm}")
                    try:
                        for row in af.audit_firm(firm,
                                                 include_products=inc_products,
                                                 include_articles=inc_articles):
                            rows.append(row)
                            live.caption(
                                f"Zebrane wiersze: {len(rows)} · "
                                f"ostatnio: {row['Link'] or row['Zrodlo']}")
                    except Exception as e:
                        st.error(f"Błąd przy {firm}: {e}")
                status.update(label=f"Gotowe. Wierszy: {len(rows)}", state="complete")
            live.empty()
            st.session_state["audit_rows"] = rows

    rows = st.session_state.get("audit_rows")
    if not rows:
        return

    df = pd.DataFrame(rows)
    st.subheader("Wyniki")

    counts = df["Status"].value_counts()
    m = st.columns(4)
    for col, name in zip(m, ["OK", "BLAD", "NIEPEWNE", "BRAK"]):
        col.metric(name, int(counts.get(name, 0)))

    f1, f2 = st.columns(2)
    statuses = sorted(df["Status"].unique())
    types = sorted(df["Typ"].unique())
    sel_status = f1.multiselect("Status", statuses, default=statuses, key="flt_status")
    sel_types = f2.multiselect("Typ", types, default=types, key="flt_typ")

    view = df[df["Status"].isin(sel_status) & df["Typ"].isin(sel_types)].copy()
    view["Link"] = view["Link"].replace("", None)

    columns = ["Typ", "Status", "Opis", "Link", "Zrodlo"]
    if df["Firma_URL"].nunique() > 1:
        columns.insert(0, "Firma_URL")

    st.dataframe(
        view[columns],
        hide_index=True,
        column_config={
            "Link": st.column_config.LinkColumn("Link"),
            "Zrodlo": st.column_config.LinkColumn("Źródło"),
        },
    )
    st.caption("`NIEPEWNE` (401/403/429/999) – serwer mógł zablokować bota, "
               "sprawdź link ręcznie w przeglądarce.")

    csv_bytes = ("\ufeff" + df.to_csv(sep=";", index=False)).encode("utf-8")
    st.download_button("Pobierz pełny raport (CSV)", csv_bytes,
                       "raport_firmy.csv", "text/csv", key="down_audit")


if __name__ == "__main__":
    main()