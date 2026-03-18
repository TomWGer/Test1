import io
import json
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote_plus

import pandas as pd
import requests
import streamlit as st

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_SEARCH_API_URL = "https://cve.circl.lu/api/search"
TIMEFRAME_OPTIONS = {"7 Tage": 7, "14 Tage": 14, "21 Tage": 21, "1 Monat": 30}
INTERVAL_OPTIONS = {"Täglich": 1, "Wöchentlich": 7, "Monatlich": 30, "Halbjährlich": 182}

HISTORY_FILE = Path("search_history.json")
FIXED_FILE = Path("fixed_cves.json")
SCHEDULER_JOBS_FILE = Path("scheduler_jobs.json")
SCHEDULER_RESULTS_FILE = Path("scheduler_results.json")
SCHEDULER_LOCK = threading.Lock()

RESULT_COLUMNS = [
    "Hersteller",
    "Software",
    "CVE",
    "Schweregrad",
    "CVSS",
    "Erscheinungsdatum",
    "Beschreibung",
    "Quelle",
    "Neue Versionen",
    "Versionsquelle",
    "Bereits gefixt",
]


def load_json_list(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, list) else []
    except json.JSONDecodeError:
        return []


def save_json_list(path: Path, data: list[dict]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_date(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def format_nvd_date(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"


def timeframe(days: int) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return format_nvd_date(now - timedelta(days=days)), format_nvd_date(now)


def fixed_cves() -> set[str]:
    return {str(x.get("CVE", "")).strip() for x in load_json_list(FIXED_FILE) if x.get("CVE")}


def save_fixed(df: pd.DataFrame) -> None:
    selected = df[df["Bereits gefixt"] == True]  # noqa: E712
    known = {x.get("CVE"): x for x in load_json_list(FIXED_FILE)}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for _, row in selected.iterrows():
        cve = str(row.get("CVE", "")).strip()
        if cve:
            known[cve] = {"CVE": cve, "Hersteller": row.get("Hersteller", ""), "Software": row.get("Software", ""), "fixed_at": now}
    save_json_list(FIXED_FILE, list(known.values()))


def sanitize_records(records: list[dict]) -> list[dict]:
    out = []
    for record in records:
        vendor = str(record.get("Hersteller", "") or "").strip()
        product = str(record.get("Software", "") or "").strip()
        if not vendor and not product:
            continue
        out.append({"Hersteller": vendor, "Software": product})
    return out


def fetch_new_versions(vendor: str, product: str) -> tuple[str, str]:
    q = f"{vendor} {product}".strip() or product.strip()
    if not q:
        return "Keine Versionsdaten gefunden", "-"
    try:
        repo_search = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": q, "sort": "stars", "order": "desc", "per_page": 1},
            timeout=10,
        )
        if repo_search.ok:
            items = repo_search.json().get("items", [])
            if items:
                full_name = items[0].get("full_name")
                rel = requests.get(f"https://api.github.com/repos/{full_name}/releases", params={"per_page": 1}, timeout=10)
                if rel.ok and rel.json():
                    first = rel.json()[0]
                    label = first.get("tag_name") or first.get("name") or "Release"
                    return label, first.get("html_url", "-")
    except requests.RequestException:
        pass
    return "Keine Versionsdaten gefunden", "-"


def fetch_nvd(keyword: str, days: int) -> tuple[list[dict], str]:
    start, end = timeframe(days)
    try:
        resp = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch": keyword,
                "cvssV3Severity": "CRITICAL",
                "pubStartDate": start,
                "pubEndDate": end,
                "resultsPerPage": 2000,
            },
            timeout=25,
        )
        if resp.status_code == 429:
            return [], "NVD-Rate-Limit"
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", []), "NVD"
    except requests.RequestException:
        return [], "NVD-Fehler"


def fetch_circl(keyword: str, days: int) -> list[dict]:
    try:
        resp = requests.get(f"{CIRCL_SEARCH_API_URL}/{quote_plus(keyword)}", timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        return []

    if not isinstance(data, list):
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for item in data:
        cve = item.get("id") or item.get("cve")
        if not cve:
            continue
        try:
            score = float(item.get("cvss", 0))
        except (TypeError, ValueError):
            score = 0
        if score < 9.0:
            continue

        published = item.get("Published") or item.get("published") or ""
        if published:
            try:
                p = parse_date(str(published).replace(" ", "T").replace("+00:00", "Z"))
                if p.tzinfo is None:
                    p = p.replace(tzinfo=timezone.utc)
                if p < cutoff:
                    continue
            except Exception:
                pass

        out.append(
            {
                "cve": {
                    "id": cve,
                    "published": str(published),
                    "descriptions": [{"lang": "en", "value": item.get("summary", "")}],
                    "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": score, "baseSeverity": "CRITICAL"}}]},
                }
            }
        )
    return out


def search_one(vendor: str, product: str, days: int) -> pd.DataFrame:
    vendor = vendor.strip()
    product = product.strip()
    keyword = f"{vendor} {product}".strip()
    if not keyword:
        return pd.DataFrame(columns=RESULT_COLUMNS)

    known_fixed = fixed_cves()
    versions, version_source = fetch_new_versions(vendor, product)
    items, source = fetch_nvd(keyword, days)
    if not items:
        items = fetch_circl(keyword, days)
        if items:
            source = "CIRCL (Fallback)"

    rows = []
    for item in items:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id or cve_id in known_fixed:
            continue
        metric = (cve.get("metrics", {}).get("cvssMetricV31", []) or cve.get("metrics", {}).get("cvssMetricV30", []))
        cvss = metric[0].get("cvssData", {}) if metric else {}
        published = cve.get("published", "")
        published_fmt = ""
        if published:
            try:
                published_fmt = parse_date(str(published).replace(" ", "T").replace("+00:00", "Z")).date().isoformat()
            except Exception:
                published_fmt = str(published)

        rows.append(
            {
                "Hersteller": vendor,
                "Software": product,
                "CVE": cve_id,
                "Schweregrad": cvss.get("baseSeverity", "CRITICAL"),
                "CVSS": cvss.get("baseScore", ""),
                "Erscheinungsdatum": published_fmt,
                "Beschreibung": next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""),
                "Quelle": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if source.startswith("NVD") else source,
                "Neue Versionen": versions,
                "Versionsquelle": version_source,
                "Bereits gefixt": False,
            }
        )

    if not rows and versions != "Keine Versionsdaten gefunden":
        rows.append(
            {
                "Hersteller": vendor,
                "Software": product,
                "CVE": "",
                "Schweregrad": "INFO",
                "CVSS": "",
                "Erscheinungsdatum": "",
                "Beschreibung": "Keine kritischen CVEs im Zeitraum, aber neue Version gefunden.",
                "Quelle": source,
                "Neue Versionen": versions,
                "Versionsquelle": version_source,
                "Bereits gefixt": False,
            }
        )

    return pd.DataFrame(rows, columns=RESULT_COLUMNS)


def run_batch(records: list[dict], days: int) -> pd.DataFrame:
    records = sanitize_records(records)
    if not records:
        return pd.DataFrame(columns=RESULT_COLUMNS)
    progress = st.progress(0, text="Suche startet...")
    frames = []
    for i, r in enumerate(records, start=1):
        df = search_one(r["Hersteller"], r["Software"], days)
        if not df.empty:
            frames.append(df)
        progress.progress(i / len(records), text=f"Analysiere {r['Hersteller']} {r['Software']} ({i}/{len(records)})")
    progress.empty()
    if not frames:
        return pd.DataFrame(columns=RESULT_COLUMNS)
    out = pd.concat(frames, ignore_index=True)
    return out.sort_values(by="Erscheinungsdatum", ascending=False)


def scheduler_loop() -> None:
    while True:
        now = datetime.now(timezone.utc)
        jobs = load_json_list(SCHEDULER_JOBS_FILE)
        changed = False
        for job in jobs:
            if job.get("status") != "running":
                continue
            next_run = job.get("next_run", "")
            due = True
            if next_run:
                try:
                    due = parse_date(next_run) <= now
                except Exception:
                    due = True
            if not due:
                continue
            df = search_one(job.get("vendor", ""), job.get("product", ""), 7)
            if not df.empty:
                found = load_json_list(SCHEDULER_RESULTS_FILE)
                ts = now.isoformat(timespec="seconds")
                for _, row in df.iterrows():
                    found.append({"Scheduler-ID": job.get("id"), "Gefunden am": ts, **row.to_dict()})
                save_json_list(SCHEDULER_RESULTS_FILE, found)
            interval_days = INTERVAL_OPTIONS.get(job.get("interval", "Wöchentlich"), 7)
            job["last_run"] = now.isoformat(timespec="seconds")
            job["next_run"] = (now + timedelta(days=interval_days)).isoformat(timespec="seconds")
            changed = True
        if changed:
            save_json_list(SCHEDULER_JOBS_FILE, jobs)
        time.sleep(60)


@st.cache_resource
def start_scheduler_thread() -> bool:
    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()
    return True


def render_results(df: pd.DataFrame, key_prefix: str) -> None:
    if df.empty:
        st.warning("Keine Treffer gefunden.")
        return
    df = df.copy()
    df["Bereits gefixt"] = df["CVE"].astype(str).isin(fixed_cves())
    edited = st.data_editor(df, use_container_width=True, hide_index=True, height=520, key=f"editor_{key_prefix}")
    c1, c2 = st.columns(2)
    if c1.button("Fix-Status speichern", key=f"fix_{key_prefix}"):
        save_fixed(edited)
        st.success("Fix-Status gespeichert.")
    out = io.BytesIO()
    edited.to_excel(out, index=False, engine="openpyxl")
    out.seek(0)
    c2.download_button("Ergebnis als Excel", data=out, file_name="ergebnis.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", key=f"dl_{key_prefix}")


def scheduler_ui() -> None:
    st.subheader("Scheduler")
    mode = st.radio("Eingabe", ["Einzelne Software", "Excel-Datei"], horizontal=True, key="sched_mode")
    start_dt = st.date_input("Startdatum", value=date.today(), key="sched_start")
    interval = st.selectbox("Intervall", list(INTERVAL_OPTIONS.keys()), index=1, key="sched_interval")

    new_jobs = []
    if mode == "Einzelne Software":
        c1, c2 = st.columns(2)
        vendor = c1.text_input("Hersteller (optional)", key="sched_vendor")
        product = c2.text_input("Software", key="sched_product")
        if st.button("Scheduler starten", key="sched_start_btn") and product.strip():
            new_jobs.append({"Hersteller": vendor.strip(), "Software": product.strip()})
    else:
        upload = st.file_uploader("Excel für Scheduler", type=["xlsx", "xls"], key="sched_file")
        if st.button("Scheduler aus Excel starten", key="sched_excel_btn"):
            if upload is not None:
                df = pd.read_excel(io.BytesIO(upload.getvalue()))
                if "Hersteller" not in df.columns:
                    df["Hersteller"] = ""
                if "Software" not in df.columns:
                    df["Software"] = ""
                raw = df[["Hersteller", "Software"]].fillna("").to_dict(orient="records")
                cleaned = sanitize_records(raw)
                skipped = len(raw) - len(cleaned)
                if skipped:
                    st.info(f"{skipped} leere Zeile(n) übersprungen.")
                new_jobs.extend(cleaned)

    if new_jobs:
        jobs = load_json_list(SCHEDULER_JOBS_FILE)
        start_utc = datetime.combine(start_dt, datetime.min.time(), tzinfo=timezone.utc).isoformat(timespec="seconds")
        for item in new_jobs:
            jobs.append(
                {
                    "id": str(uuid.uuid4())[:8],
                    "vendor": item["Hersteller"],
                    "product": item["Software"],
                    "interval": interval,
                    "status": "running",
                    "start_date": start_utc,
                    "next_run": start_utc,
                    "last_run": "",
                }
            )
        save_json_list(SCHEDULER_JOBS_FILE, jobs)
        st.success(f"{len(new_jobs)} Scheduler erstellt.")

    jobs_df = pd.DataFrame(load_json_list(SCHEDULER_JOBS_FILE))
    if not jobs_df.empty:
        for col, default in {"interval": "Wöchentlich", "vendor": "", "product": "", "status": "running", "next_run": ""}.items():
            if col not in jobs_df.columns:
                jobs_df[col] = default
            jobs_df[col] = jobs_df[col].fillna(default)
        st.markdown("**Produkte mit Scheduler**")
        view = jobs_df[["id", "vendor", "product", "interval", "status", "next_run"]].copy()
        view.columns = ["Scheduler-ID", "Hersteller", "Software", "Intervall", "Status", "Nächster Lauf"]
        st.dataframe(view, use_container_width=True, height=260)

    res_df = pd.DataFrame(load_json_list(SCHEDULER_RESULTS_FILE))
    if not res_df.empty:
        st.markdown("**Scheduler-Funde**")
        render_results(res_df[[c for c in [*RESULT_COLUMNS, "Scheduler-ID", "Gefunden am"] if c in res_df.columns]], "scheduler")


def main() -> None:
    start_scheduler_thread()
    st.set_page_config(page_title="Security Update Finder", layout="wide")
    st.title("Security Update Finder")
    st.caption("Neu aufgebaut: schlanker Workflow, weniger Tabellen, klare Ergebnisse.")

    tab_search, tab_scheduler = st.tabs(["Suche", "Scheduler"])

    with tab_search:
        source = st.radio("Datenquelle", ["Excel-Datei", "Einzelne Eingabe"], horizontal=True)
        range_label = st.selectbox("Suchzeitraum", list(TIMEFRAME_OPTIONS.keys()), index=1)
        days = TIMEFRAME_OPTIONS[range_label]

        if source == "Excel-Datei":
            upload = st.file_uploader("Excel auswählen", type=["xlsx", "xls"])
            if st.button("Analyse starten", type="primary"):
                if upload is None:
                    st.error("Bitte Excel-Datei auswählen.")
                else:
                    df = pd.read_excel(io.BytesIO(upload.getvalue()))
                    if "Hersteller" not in df.columns:
                        df["Hersteller"] = ""
                    if "Software" not in df.columns:
                        df["Software"] = ""
                    raw = df[["Hersteller", "Software"]].fillna("").to_dict(orient="records")
                    clean = sanitize_records(raw)
                    skipped = len(raw) - len(clean)
                    if skipped:
                        st.info(f"{skipped} leere Zeile(n) wurden ausgeblendet.")
                    render_results(run_batch(clean, days), "main_excel")
        else:
            c1, c2 = st.columns(2)
            vendor = c1.text_input("Hersteller (optional)")
            product = c2.text_input("Software (optional)")
            if st.button("Suche starten", type="primary"):
                if not vendor.strip() and not product.strip():
                    st.error("Bitte Hersteller oder Software angeben.")
                else:
                    render_results(search_one(vendor, product, days), "main_manual")

    with tab_scheduler:
        scheduler_ui()


if __name__ == "__main__":
    main()
