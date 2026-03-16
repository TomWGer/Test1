import io
import json
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import quote_plus

import pandas as pd
import requests
import streamlit as st

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_SEARCH_API_URL = "https://cve.circl.lu/api/search"
SECURITY_RSS_FEEDS = [
    ("Heise Security", "https://www.heise.de/security/rss/news-atom.xml"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://thehackernews.com/feeds/posts/default"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
]
TIMEFRAME_OPTIONS = {"7 Tage": 7, "14 Tage": 14, "21 Tage": 21, "1 Monat": 30}
SCHEDULER_INTERVAL_OPTIONS = {"Täglich": 1, "Wöchentlich": 7, "Monatlich": 30, "Halbjährlich": 182}

HISTORY_FILE = Path("search_history.json")
FIXED_FILE = Path("fixed_cves.json")
SCHEDULER_JOBS_FILE = Path("scheduler_jobs.json")
SCHEDULER_RESULTS_FILE = Path("scheduler_results.json")
SCHEDULER_LOCK = threading.Lock()

BASE_COLUMNS = [
    "Hersteller",
    "Software",
    "CVE",
    "Schweregrad",
    "CVSS",
    "Betroffene Version(en)",
    "Erscheinungsdatum",
    "Beschreibung",
    "Quelle",
    "Security-Artikel",
    "Patch/Update-Link",
    "Neue Versionen",
    "Versionsquelle",
    "Bereits gefixt",
]
SCHEDULER_COLUMNS = ["Scheduler-ID", "Gefunden am", *BASE_COLUMNS]


def apply_modern_style() -> None:
    st.markdown(
        """
        <style>
        .stApp { background: linear-gradient(160deg, #0b1020 0%, #0f1a34 100%); color: #eef3ff; }
        .block-container { max-width: 1220px; padding-top: 1.4rem; }
        .glass-card { background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.16); border-radius: 18px; padding: 12px 16px; }
        .ticker-wrap { overflow: hidden; border-radius: 999px; border: 1px solid rgba(255,255,255,0.16); background: rgba(255,255,255,0.08); padding: 10px 0; margin: 0.2rem 0 1rem 0; }
        .ticker { white-space: nowrap; display: inline-block; padding-left: 100%; animation: ticker 35s linear infinite; color: #d7e7ff; }
        @keyframes ticker { 0% { transform: translateX(0); } 100% { transform: translateX(-100%); } }
        </style>
        """,
        unsafe_allow_html=True,
    )


def parse_date(dt_str: str) -> datetime:
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
    return datetime.fromisoformat(dt_str)


def format_nvd_date(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"


def timeframe_window(days: int) -> tuple[str, str]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return format_nvd_date(start), format_nvd_date(end)


def today_window() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    return format_nvd_date(start), format_nvd_date(now)


def load_json_list(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def save_json_list(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")


def load_fixed_ids() -> set[str]:
    rows = load_json_list(FIXED_FILE)
    return {str(row.get("CVE", "")).strip() for row in rows if row.get("CVE")}


def update_fixed_state(result_df: pd.DataFrame, checked_cves: list[str]) -> None:
    stored = load_json_list(FIXED_FILE)
    fixed_map = {str(row.get("CVE", "")).strip(): row for row in stored if row.get("CVE")}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for _, row in result_df[result_df["CVE"].isin(checked_cves)].iterrows():
        cve_id = str(row["CVE"]).strip()
        fixed_map[cve_id] = {
            "CVE": cve_id,
            "Hersteller": row.get("Hersteller", ""),
            "Software": row.get("Software", ""),
            "fixed_at": now,
        }
    save_json_list(FIXED_FILE, list(fixed_map.values()))


def persist_search_history(range_label: str, source_mode: str, rows: list[dict]) -> None:
    history = load_json_list(HISTORY_FILE)
    history.append({
        "searched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "timeframe": range_label,
        "source_mode": source_mode,
        "result_count": len(rows),
        "results": rows,
    })
    save_json_list(HISTORY_FILE, history)


def history_as_dataframe() -> pd.DataFrame:
    flattened = []
    for entry in load_json_list(HISTORY_FILE):
        for row in entry.get("results", []):
            full = {"Suchdatum": entry.get("searched_at", ""), "Suchzeitraum": entry.get("timeframe", ""), "Suchmodus": entry.get("source_mode", "")}
            full.update(row)
            flattened.append(full)
    if not flattened:
        return pd.DataFrame(columns=["Suchdatum", "Suchzeitraum", "Suchmodus", *BASE_COLUMNS])
    df = pd.DataFrame(flattened)
    df["Bereits gefixt"] = df["CVE"].isin(load_fixed_ids())
    return df.sort_values(by="Suchdatum", ascending=False)


def normalize_vendor_product(vendor: str, product: str) -> tuple[str, str, str]:
    v = (vendor or "").strip()
    p = (product or "").strip()
    return v, p, f"{v} {p}".strip()


def extract_versions(cve_payload: dict) -> str:
    versions = set()
    for conf in cve_payload.get("configurations", []):
        for node in conf.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                parts = cpe.get("criteria", "").split(":")
                if len(parts) > 5 and parts[5] not in {"", "*", "-"}:
                    versions.add(parts[5])
                start = cpe.get("versionStartIncluding") or cpe.get("versionStartExcluding")
                end = cpe.get("versionEndIncluding") or cpe.get("versionEndExcluding")
                if start or end:
                    versions.add(f"{start or '?'} - {end or '?'}")
    return ", ".join(sorted(versions)) if versions else "Nicht angegeben"


def extract_description(cve_payload: dict) -> str:
    descriptions = cve_payload.get("descriptions", [])
    en = next((d for d in descriptions if d.get("lang") == "en"), None)
    return en.get("value", "") if en else (descriptions[0].get("value", "") if descriptions else "")


def parse_feed_entries(source_name: str, xml_text: str) -> list[dict]:
    entries = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return entries
    for item in root.findall(".//item"):
        t, l = (item.findtext("title") or "").strip(), (item.findtext("link") or "").strip()
        if t and l:
            entries.append({"source": source_name, "title": t, "link": l})
    for entry in root.findall(".//{http://www.w3.org/2005/Atom}entry"):
        t = (entry.findtext("{http://www.w3.org/2005/Atom}title") or "").strip()
        link_el = entry.find("{http://www.w3.org/2005/Atom}link")
        l = (link_el.attrib.get("href", "") if link_el is not None else "").strip()
        if t and l:
            entries.append({"source": source_name, "title": t, "link": l})
    return entries


def fetch_security_articles(keyword: str, max_results: int = 3) -> list[str]:
    if not keyword:
        return []
    hits, low = [], keyword.lower()
    for source, feed_url in SECURITY_RSS_FEEDS:
        try:
            resp = requests.get(feed_url, timeout=12)
            resp.raise_for_status()
            for entry in parse_feed_entries(source, resp.text):
                if low in entry["title"].lower():
                    hits.append(f"{entry['source']}: {entry['link']}")
                    if len(hits) >= max_results:
                        return hits
        except requests.RequestException:
            continue
    hits.append(f"Heise-Suche: https://www.heise.de/suche/?q={quote_plus(keyword)}")
    return hits[:max_results]


def extract_patch_links(cve_payload: dict, vendor: str) -> list[str]:
    refs, out = cve_payload.get("references", []), []
    vendor_l = vendor.lower().strip()
    for ref in refs:
        url = ref.get("url", "")
        tags = [t.lower() for t in ref.get("tags", [])]
        if not url:
            continue
        is_patch = any(t in {"patch", "vendor advisory"} for t in tags)
        url_l = url.lower()
        hint = any(k in url_l for k in ["advisory", "security", "update", "patch", "release-notes", "bulletin"])
        if is_patch or ((vendor_l and vendor_l in url_l) and hint):
            out.append(url)
    return list(dict.fromkeys(out))[:3]


def fetch_new_versions(vendor: str, product: str, max_results: int = 3) -> tuple[str, str]:
    candidates = []
    p = (product or "").strip()
    v = (vendor or "").strip()

    # 1) GitHub Releases
    github_query = f"{v} {p}".strip()
    try:
        search_resp = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": github_query or p, "sort": "stars", "order": "desc", "per_page": 3},
            timeout=12,
        )
        if search_resp.ok:
            items = search_resp.json().get("items", [])
            for repo in items[:2]:
                full_name = repo.get("full_name")
                if not full_name:
                    continue
                rel_resp = requests.get(f"https://api.github.com/repos/{full_name}/releases", params={"per_page": max_results}, timeout=12)
                if not rel_resp.ok:
                    continue
                for rel in rel_resp.json()[:max_results]:
                    tag = rel.get("tag_name") or rel.get("name")
                    pub = rel.get("published_at", "")[:10]
                    url = rel.get("html_url", "")
                    if tag and url:
                        candidates.append((f"{tag} ({pub})", f"GitHub: {url}"))
                if candidates:
                    break
    except requests.RequestException:
        pass

    # 2) PyPI fallback
    if not candidates and p:
        pypi_name = p.replace(" ", "-").lower()
        try:
            pypi_resp = requests.get(f"https://pypi.org/pypi/{pypi_name}/json", timeout=10)
            if pypi_resp.ok:
                data = pypi_resp.json()
                ver = data.get("info", {}).get("version")
                rel_url = data.get("info", {}).get("package_url", f"https://pypi.org/project/{pypi_name}/")
                if ver:
                    candidates.append((f"{ver}", f"PyPI: {rel_url}"))
        except requests.RequestException:
            pass

    if not candidates:
        return "Keine Versionsdaten gefunden", "-"

    unique = []
    seen = set()
    for label, link in candidates:
        key = (label, link)
        if key not in seen:
            unique.append((label, link))
            seen.add(key)
        if len(unique) >= max_results:
            break

    versions = "\n".join([u[0] for u in unique])
    sources = "\n".join([u[1] for u in unique])
    return versions, sources


def fetch_nvd_items(keyword: str, days: int) -> tuple[list[dict], str]:
    start_date, end_date = timeframe_window(days)
    params = {
        "keywordSearch": keyword,
        "cvssV3Severity": "CRITICAL",
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "resultsPerPage": 2000,
    }
    try:
        response = requests.get(NVD_API_URL, params=params, timeout=30)
        if response.status_code == 429:
            return [], "NVD-Rate-Limit"
        response.raise_for_status()
        return response.json().get("vulnerabilities", []), "NVD"
    except requests.RequestException:
        return [], "NVD-Fehler"


def fetch_circl_items(vendor: str, product: str, days: int) -> list[dict]:
    query = product.strip() or vendor.strip()
    if not query:
        return []
    endpoint = f"{CIRCL_SEARCH_API_URL}/{quote_plus(query)}"
    try:
        response = requests.get(endpoint, timeout=25)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException:
        return []
    if not isinstance(payload, list):
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out: list[dict] = []
    for item in payload:
        cve_id = item.get("id") or item.get("cve") or ""
        if not cve_id:
            continue
        score = item.get("cvss")
        try:
            score_num = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_num = None
        severity = "CRITICAL" if (score_num is not None and score_num >= 9.0) else "HIGH"
        if severity != "CRITICAL":
            continue

        published_raw = item.get("Published") or item.get("published") or ""
        published = ""
        if published_raw:
            try:
                normalized = str(published_raw).replace(" ", "T")
                if normalized.endswith("+00:00"):
                    normalized = normalized[:-6] + "Z"
                pub_dt = parse_date(normalized)
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                if pub_dt < cutoff:
                    continue
                published = pub_dt.date().isoformat()
            except Exception:
                pass

        out.append({
            "cve": {
                "id": cve_id,
                "published": published,
                "descriptions": [{"lang": "en", "value": item.get("summary", "") or item.get("description", "")}],
                "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": score_num, "baseSeverity": severity}}]},
                "references": [{"url": u, "tags": ["Vendor Advisory"]} for u in item.get("references", []) if isinstance(u, str)],
                "configurations": [],
            }
        })
    return out


def fetch_critical_vulns(vendor: str, product: str, days: int) -> pd.DataFrame:
    vendor, product, keyword = normalize_vendor_product(vendor, product)
    if not keyword:
        return pd.DataFrame(columns=BASE_COLUMNS)

    fixed_ids, rows = load_fixed_ids(), []
    new_versions, version_source = fetch_new_versions(vendor, product)

    items, source_name = fetch_nvd_items(keyword, days)
    if not items:
        fallback_items = fetch_circl_items(vendor, product, days)
        if fallback_items:
            items = fallback_items
            source_name = "CIRCL (Fallback)"

    for item in items:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id or cve_id in fixed_ids:
            continue
        metric = (cve.get("metrics", {}).get("cvssMetricV31", []) or cve.get("metrics", {}).get("cvssMetricV30", []))
        cvss = metric[0].get("cvssData", {}) if metric else {}
        published = parse_date(cve.get("published", "")).date().isoformat() if cve.get("published") else ""
        articles = fetch_security_articles(f"{cve_id} {vendor} {product}".strip(), 2)
        patches = extract_patch_links(cve, vendor)

        rows.append({
            "Hersteller": vendor,
            "Software": product,
            "CVE": cve_id,
            "Schweregrad": cvss.get("baseSeverity", "CRITICAL"),
            "CVSS": cvss.get("baseScore"),
            "Betroffene Version(en)": extract_versions(cve),
            "Erscheinungsdatum": published,
            "Beschreibung": extract_description(cve),
            "Quelle": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if source_name.startswith("NVD") else source_name,
            "Security-Artikel": "\n".join(articles) if articles else "Keine passenden Artikel gefunden",
            "Patch/Update-Link": "\n".join(patches) if patches else "Kein direkter Patch-Link im NVD-Referenzsatz",
            "Neue Versionen": new_versions,
            "Versionsquelle": version_source,
            "Bereits gefixt": False,
        })

    if not rows:
        if new_versions != "Keine Versionsdaten gefunden":
            return pd.DataFrame([{
                "Hersteller": vendor,
                "Software": product,
                "CVE": "",
                "Schweregrad": "INFO",
                "CVSS": "",
                "Betroffene Version(en)": "",
                "Erscheinungsdatum": "",
                "Beschreibung": f"Keine kritischen CVEs im Zeitraum ({source_name}). Neue Version(en) gefunden.",
                "Quelle": source_name,
                "Security-Artikel": "",
                "Patch/Update-Link": "",
                "Neue Versionen": new_versions,
                "Versionsquelle": version_source,
                "Bereits gefixt": False,
            }])
        return pd.DataFrame(columns=BASE_COLUMNS)
    return pd.DataFrame(rows).sort_values(by="Erscheinungsdatum", ascending=False)


def fetch_updates_for_products(products: list[tuple[str, str]]) -> list[str]:
    fixed_ids, ticker_items = load_fixed_ids(), []
    for vendor, product in products[:10]:
        _, _, keyword = normalize_vendor_product(vendor, product)
        if not keyword:
            continue
        items, source_name = fetch_nvd_items(keyword, 1)
        if not items:
            items = fetch_circl_items(vendor, product, 1)
            source_name = "CIRCL"
        for item in items[:2]:
            cve_id = item.get("cve", {}).get("id", "")
            if cve_id and cve_id not in fixed_ids:
                ticker_items.append(f"{vendor or 'Unbekannt'} / {product or 'Alle Produkte'}: {cve_id} ({source_name})")
    return ticker_items


def products_from_history() -> list[tuple[str, str]]:
    products = []
    for entry in load_json_list(HISTORY_FILE):
        for row in entry.get("results", []):
            products.append((str(row.get("Hersteller", "")).strip(), str(row.get("Software", "")).strip()))
    return list(dict.fromkeys([p for p in products if p[0] or p[1]]))


def products_from_excel(df: pd.DataFrame) -> list[tuple[str, str]]:
    vendor_col = "Hersteller" if "Hersteller" in df.columns else None
    items = []
    for _, row in df.iterrows():
        product = str(row.get("Software", "")).strip()
        vendor = str(row.get(vendor_col, "")).strip() if vendor_col else ""
        if vendor or product:
            items.append((vendor, product))
    return list(dict.fromkeys(items))


def validate_excel_columns(df: pd.DataFrame) -> None:
    if "Software" not in df.columns and "Hersteller" not in df.columns:
        raise ValueError("In der Excel-Datei muss mindestens eine Spalte vorhanden sein: Software oder Hersteller")




def sanitize_records(records: Iterable[dict]) -> list[dict]:
    cleaned = []
    for record in records:
        vendor = str(record.get("Hersteller", "") or "").strip()
        product = str(record.get("Software", "") or "").strip()
        if not vendor and not product:
            continue
        cleaned.append({"Hersteller": vendor, "Software": product})
    return cleaned

def run_batch_search(records: Iterable[dict], days: int) -> pd.DataFrame:
    records = sanitize_records(records)
    if not records:
        return pd.DataFrame(columns=BASE_COLUMNS)
    frames, progress = [], st.progress(0, text="Suche wird gestartet...")
    for idx, record in enumerate(records, start=1):
        vendor = record["Hersteller"]
        product = record["Software"]
        data = fetch_critical_vulns(vendor, product, days)
        if not data.empty:
            frames.append(data)
        progress.progress(idx / len(records), text=f"Analysiere {(vendor + ' / ' + product).strip(' /') or 'Unbekannt'} ({idx}/{len(records)})")
    progress.empty()
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=BASE_COLUMNS)


def get_scheduler_jobs() -> list[dict]:
    with SCHEDULER_LOCK:
        return load_json_list(SCHEDULER_JOBS_FILE)


def save_scheduler_jobs(jobs: list[dict]) -> None:
    with SCHEDULER_LOCK:
        save_json_list(SCHEDULER_JOBS_FILE, jobs)


def get_scheduler_results_df() -> pd.DataFrame:
    with SCHEDULER_LOCK:
        rows = load_json_list(SCHEDULER_RESULTS_FILE)
    if not rows:
        return pd.DataFrame(columns=SCHEDULER_COLUMNS)
    df = pd.DataFrame(rows)
    df["Bereits gefixt"] = df["CVE"].isin(load_fixed_ids())
    return df.sort_values(by="Gefunden am", ascending=False)


def append_scheduler_results(job_id: str, result_df: pd.DataFrame) -> None:
    if result_df.empty:
        return
    with SCHEDULER_LOCK:
        rows = load_json_list(SCHEDULER_RESULTS_FILE)
        found_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for _, row in result_df.iterrows():
            item = {"Scheduler-ID": job_id, "Gefunden am": found_at, **row.to_dict()}
            rows.append(item)
        save_json_list(SCHEDULER_RESULTS_FILE, rows)




def get_interval_days(interval_label: str) -> int:
    return SCHEDULER_INTERVAL_OPTIONS.get(interval_label, 7)


def next_run_from(now: datetime, interval_label: str) -> datetime:
    return now + timedelta(days=get_interval_days(interval_label))

def scheduler_loop() -> None:
    while True:
        now = datetime.now(timezone.utc)
        with SCHEDULER_LOCK:
            jobs = load_json_list(SCHEDULER_JOBS_FILE)
        changed = False
        for job in jobs:
            if job.get("status") != "running":
                continue
            try:
                next_run = parse_date(job["next_run"])
            except Exception:
                next_run = now
            if next_run <= now:
                result = fetch_critical_vulns(job.get("vendor", ""), job.get("product", ""), 7)
                append_scheduler_results(job["id"], result)
                job["last_run"] = now.isoformat(timespec="seconds")
                interval_label = job.get("interval", "Wöchentlich")
                job["next_run"] = next_run_from(now, interval_label).isoformat(timespec="seconds")
                changed = True
        if changed:
            with SCHEDULER_LOCK:
                save_json_list(SCHEDULER_JOBS_FILE, jobs)
        time.sleep(60)


@st.cache_resource
def ensure_scheduler_thread() -> bool:
    t = threading.Thread(target=scheduler_loop, daemon=True)
    t.start()
    return True


def build_duplicate_sets(manual_df: pd.DataFrame, scheduler_df: pd.DataFrame) -> tuple[set[str], pd.DataFrame, pd.DataFrame]:
    manual_cves = set(manual_df["CVE"].dropna().astype(str)) if not manual_df.empty and "CVE" in manual_df.columns else set()
    sched_cves = set(scheduler_df["CVE"].dropna().astype(str)) if not scheduler_df.empty and "CVE" in scheduler_df.columns else set()
    dup = manual_cves.intersection(sched_cves)

    m = manual_df.copy()
    s = scheduler_df.copy()
    if not m.empty and "CVE" in m.columns:
        m["Doppelter Treffer"] = m["CVE"].astype(str).isin(dup)
    if not s.empty and "CVE" in s.columns:
        s["Doppelter Treffer"] = s["CVE"].astype(str).isin(dup)
    return dup, m, s


def styled_duplicates(df: pd.DataFrame):
    def row_style(row: pd.Series):
        if bool(row.get("Doppelter Treffer", False)):
            return ["background-color: #fff59d; color: #111;"] * len(row)
        return [""] * len(row)

    return df.style.apply(row_style, axis=1)


def render_ticker(excel_df: pd.DataFrame | None) -> None:
    tracked = products_from_history()
    if excel_df is not None:
        tracked.extend(products_from_excel(excel_df))
    items = fetch_updates_for_products(list(dict.fromkeys(tracked))) if tracked else []
    if not items:
        st.markdown('<div class="ticker-wrap"><div class="ticker">🛡️ Heute noch keine neuen kritischen Security-Updates für bekannte Produkte gefunden.</div></div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="ticker-wrap"><div class="ticker">🛡️ Security Updates heute: {"  •  ".join(items)}</div></div>', unsafe_allow_html=True)


def render_manual_results(result: pd.DataFrame, range_label: str, source_mode: str) -> None:
    if result.empty:
        st.warning("Keine kritischen Sicherheitslücken im gewählten Zeitraum gefunden.")
        return

    result = result.copy()
    result["Bereits gefixt"] = result["CVE"].isin(load_fixed_ids())
    st.session_state["manual_results_df"] = result.copy()

    edited_df = st.data_editor(
        result,
        hide_index=True,
        use_container_width=True,
        height=720,
        key="manual_editor",
        column_config={"Bereits gefixt": st.column_config.CheckboxColumn("Bereits gefixt", default=False)},
    )

    if st.button("Fix-Status speichern (oben)", type="primary"):
        selected = edited_df[edited_df["Bereits gefixt"] == True]["CVE"].astype(str).tolist()  # noqa: E712
        update_fixed_state(edited_df, selected)
        st.success(f"{len(selected)} CVE(s) wurden als gefixt gespeichert.")

    output = io.BytesIO()
    edited_df.to_excel(output, index=False, engine="openpyxl")
    output.seek(0)
    st.download_button("Ergebnis als Excel herunterladen", data=output, file_name="kritische_sicherheitsluecken.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    persist_search_history(range_label, source_mode, edited_df.to_dict(orient="records"))


def render_scheduler_controls() -> None:
    st.subheader("Scheduler")
    source = st.radio("Scheduler-Eingabe", ["Einzelne Software", "Excel-Datei"], horizontal=True, key="sched_source")

    new_jobs = []
    start_dt = st.date_input("Startdatum", value=date.today(), key="sched_start")
    interval_label = st.selectbox("Intervall", list(SCHEDULER_INTERVAL_OPTIONS.keys()), index=1, key="sched_interval")
    if source == "Einzelne Software":
        c1, c2 = st.columns(2)
        with c1:
            vendor = st.text_input("Hersteller (optional)", key="sched_vendor")
        with c2:
            product = st.text_input("Softwarename", key="sched_product")
        if st.button("Scheduler starten", key="start_sched_single"):
            if not product.strip():
                st.error("Für einen Scheduler-Eintrag ist mindestens ein Softwarename erforderlich.")
            else:
                new_jobs.append((vendor.strip(), product.strip(), interval_label))
    else:
        upload = st.file_uploader("Excel für Scheduler", type=["xlsx", "xls"], key="sched_upload")
        if st.button("Scheduler aus Excel starten", key="start_sched_excel"):
            if upload is None:
                st.error("Bitte Excel-Datei hochladen.")
            else:
                df = pd.read_excel(io.BytesIO(upload.getvalue()))
                validate_excel_columns(df)
                if "Hersteller" not in df.columns:
                    df["Hersteller"] = ""
                if "Software" not in df.columns:
                    df["Software"] = ""
                raw_records = df[["Hersteller", "Software"]].fillna("").to_dict(orient="records")
                cleaned = sanitize_records(raw_records)
                skipped = len(raw_records) - len(cleaned)
                if skipped > 0:
                    st.info(f"{skipped} leere Excel-Zeile(n) wurden für den Scheduler übersprungen.")
                for item in cleaned:
                    new_jobs.append((item["Hersteller"], item["Software"], interval_label))

    if new_jobs:
        jobs = get_scheduler_jobs()
        for vendor, product, interval in new_jobs:
            start_dt_utc = datetime.combine(start_dt, datetime.min.time(), tzinfo=timezone.utc)
            jobs.append({
                "id": str(uuid.uuid4())[:8],
                "vendor": vendor,
                "product": product,
                "start_date": start_dt_utc.isoformat(timespec="seconds"),
                "interval": interval,
                "status": "running",
                "last_run": "",
                "next_run": start_dt_utc.isoformat(timespec="seconds"),
            })
        save_scheduler_jobs(jobs)
        st.success(f"{len(new_jobs)} Scheduler-Eintrag/Eingänge gestartet.")

    jobs = get_scheduler_jobs()
    if jobs:
        job_labels = [f"{j['id']} | {j.get('vendor','')} / {j.get('product','')} | {j.get('interval','Wöchentlich')} | {j.get('status')}" for j in jobs]
        selected = st.selectbox("Scheduler auswählen", options=job_labels, key="job_select")
        selected_id = selected.split(" |")[0]

        c1, c2, c3 = st.columns(3)
        if c1.button("Unterbrechen", key="pause_job"):
            for j in jobs:
                if j["id"] == selected_id:
                    j["status"] = "paused"
            save_scheduler_jobs(jobs)
        if c2.button("Fortsetzen", key="resume_job"):
            for j in jobs:
                if j["id"] == selected_id:
                    j["status"] = "running"
            save_scheduler_jobs(jobs)
        if c3.button("Beenden", key="stop_job"):
            for j in jobs:
                if j["id"] == selected_id:
                    j["status"] = "stopped"
            save_scheduler_jobs(jobs)

        jobs_df = pd.DataFrame(jobs)
        if not jobs_df.empty:
            defaults = {
                "interval": "Wöchentlich",
                "vendor": "",
                "product": "",
                "status": "running",
                "next_run": "",
            }
            for col, default_value in defaults.items():
                if col not in jobs_df.columns:
                    jobs_df[col] = default_value
                jobs_df[col] = jobs_df[col].fillna(default_value)
        st.dataframe(jobs_df, use_container_width=True, height=260)

        st.markdown("### Übersicht: Produkte mit aktivem Scheduler")
        overview = jobs_df[jobs_df["status"].isin(["running", "paused"])].copy() if not jobs_df.empty else pd.DataFrame()
        if overview.empty:
            st.info("Derzeit sind keine aktiven oder pausierten Scheduler hinterlegt.")
        else:
            overview = overview[["id", "vendor", "product", "interval", "status", "next_run"]]
            overview.columns = ["Scheduler-ID", "Hersteller", "Software", "Intervall", "Status", "Nächster Lauf"]
            st.dataframe(overview.sort_values(by=["Status", "Hersteller", "Software"]), use_container_width=True, height=220)


def main() -> None:
    ensure_scheduler_thread()
    st.set_page_config(page_title="Security Update Finder", layout="wide")
    apply_modern_style()
    st.title("🛡️ Security Update Finder")

    main_tab, history_tab, scheduler_tab = st.tabs(["Suche", "Ergebnishistory", "Scheduler"])

    with main_tab:
        source = st.radio("Datenquelle", ["Lokale Excel-Datei", "Einzelne Software manuell eingeben"], horizontal=True)
        selected_range = st.selectbox("Suchzeitraum", list(TIMEFRAME_OPTIONS.keys()), index=1)
        range_days = TIMEFRAME_OPTIONS[selected_range]

        excel_df = None
        if source == "Lokale Excel-Datei":
            upload = st.file_uploader("Excel-Datei auswählen", type=["xlsx", "xls"])
            if upload is not None:
                excel_df = pd.read_excel(io.BytesIO(upload.getvalue()))

        render_ticker(excel_df)

        if source == "Lokale Excel-Datei":
            st.info("In Excel muss mindestens eine Spalte vorhanden sein: **Software** oder **Hersteller**.")
            if st.button("Analyse starten", type="primary"):
                if excel_df is None:
                    st.error("Bitte zuerst eine Excel-Datei hochladen.")
                else:
                    validate_excel_columns(excel_df)
                    if "Hersteller" not in excel_df.columns:
                        excel_df["Hersteller"] = ""
                    if "Software" not in excel_df.columns:
                        excel_df["Software"] = ""
                    raw_records = excel_df[["Hersteller", "Software"]].fillna("").to_dict(orient="records")
                    records = sanitize_records(raw_records)
                    skipped = len(raw_records) - len(records)
                    if skipped > 0:
                        st.info(f"{skipped} leere Excel-Zeile(n) wurden automatisch übersprungen.")
                    render_manual_results(run_batch_search(records, range_days), selected_range, source)
        else:
            c1, c2 = st.columns(2)
            with c1:
                vendor = st.text_input("Herstellername (optional)", placeholder="z. B. Microsoft")
            with c2:
                product = st.text_input("Softwarename (optional)", placeholder="z. B. Exchange Server")

            if st.button("Suche starten", type="primary"):
                if not vendor.strip() and not product.strip():
                    st.error("Bitte mindestens Herstellername oder Softwarename ausfüllen.")
                else:
                    render_manual_results(fetch_critical_vulns(vendor.strip(), product.strip(), range_days), selected_range, source)

    with scheduler_tab:
        render_scheduler_controls()

        st.subheader("Scheduler-Funde")
        scheduler_df = get_scheduler_results_df()
        manual_df = st.session_state.get("manual_results_df", pd.DataFrame(columns=BASE_COLUMNS))
        _, manual_marked, sched_marked = build_duplicate_sets(manual_df, scheduler_df)

        if not manual_marked.empty:
            st.caption("Oberes Feld mit Duplikat-Markierung (gelb)")
            st.dataframe(styled_duplicates(manual_marked), use_container_width=True, height=280)

        if scheduler_df.empty:
            st.info("Noch keine Scheduler-Funde vorhanden.")
        else:
            edited_sched = st.data_editor(
                sched_marked,
                hide_index=True,
                use_container_width=True,
                height=540,
                key="scheduler_editor",
                column_config={"Bereits gefixt": st.column_config.CheckboxColumn("Bereits gefixt", default=False)},
            )
            if st.button("Fix-Status speichern (Scheduler-Funde)"):
                selected = edited_sched[edited_sched["Bereits gefixt"] == True]["CVE"].astype(str).tolist()  # noqa: E712
                update_fixed_state(edited_sched, selected)
                st.success("Fix-Status synchronisiert.")

    with history_tab:
        st.subheader("Ergebnishistory")
        history_df = history_as_dataframe()
        if history_df.empty:
            st.info("Noch keine Historie vorhanden.")
        else:
            st.dataframe(history_df, use_container_width=True, height=700)
            out = io.BytesIO()
            history_df.to_excel(out, index=False, engine="openpyxl")
            out.seek(0)
            st.download_button("Historie als Excel herunterladen", data=out, file_name="suchhistorie.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


if __name__ == "__main__":
    main()
