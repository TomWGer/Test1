# Security Update Finder

Streamlit-Tool zur Suche nach **kritischen Sicherheitslücken (CVE/NVD)** für Softwareprodukte mit manueller Suche, Excel-Bulk-Analyse und Scheduler.

## Funktionen
- Suchzeitraum auswählbar: **7 Tage, 14 Tage, 21 Tage, 1 Monat**
- Zwei Suchmodi:
  - **Lokale Excel-Datei**
  - **Einzelne Software manuell**
- Leere Zeilen in Excel-Dateien werden automatisch übersprungen
- Zusätzliche Quellen für Artikel-Links: **Heise Security**, BleepingComputer, The Hacker News, SecurityWeek
- CVE-Quelle mit Fallback: primär **NVD**, bei Rate-Limits/Fehlern automatisch **CIRCL CVE Search**
- Prüfung auf **Patch-/Update-Links** aus NVD-Referenzen
- Zusätzliche Suche nach **neuen Software-Versionen** (z. B. über GitHub-Releases/PyPI, falls verfügbar)
- Persistente **Ergebnishistory** und **Fix-Status** (`Bereits gefixt`)
- **Scheduler mit Intervallsteuerung** (Täglich, Wöchentlich, Monatlich, Halbjährlich):
  - einzelnes Produkt (Softwarename + Startdatum)
  - oder mehrere Produkte per Excel
  - Starten, Unterbrechen, Fortsetzen, Beenden
  - Übersicht, für welche Produkte Scheduler angelegt wurden
- Scheduler-Funde in separatem Feld
- Wenn keine kritischen CVEs gefunden wurden, kann trotzdem ein Info-Ergebnis mit neuen Versionen angezeigt werden
- Duplikate zwischen manuellen Suchergebnissen und Scheduler-Funden werden gelb markiert
- Fix-Status ist zwischen beiden Feldern synchron

## Erwartetes Excel-Format
Mindestens eine Spalte muss vorhanden sein:
- `Software`
- `Hersteller`

## Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Persistente Dateien
- `search_history.json`
- `fixed_cves.json`
- `scheduler_jobs.json`
- `scheduler_results.json`


## One-Click Start (Windows)
Du kannst die App mit einem Doppelklick auf `start_software.bat` starten.

Die Datei erledigt automatisch:
- Python-Pruefung
- Anlegen der virtuellen Umgebung (`.venv`)
- Installation/Aktualisierung der Abhaengigkeiten
- Start von Streamlit (`app.py`)

Hinweis: Beim ersten Start kann die Installation der Pakete etwas dauern.
