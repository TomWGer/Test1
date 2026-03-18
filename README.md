# Security Update Finder

Neu aufgebaute, vereinfachte Streamlit-App zur Suche nach Sicherheitsupdates und neuen Software-Versionen.

## Was die App jetzt macht
- Manuelle Suche oder Excel-Bulk-Suche
- Kritische CVEs über **NVD**
- Automatischer Fallback auf **CIRCL**, wenn NVD limitiert/fehlerhaft ist
- Zusätzliche Suche nach neuen Versionen (GitHub-Releases)
- Leere Excel-Zeilen werden automatisch übersprungen
- Scheduler mit Intervallen: Täglich, Wöchentlich, Monatlich, Halbjährlich
- Übersicht, für welche Produkte Scheduler aktiv sind

## Start
### Variante 1 (empfohlen, Windows)
- `start_software.bat` doppelklicken

### Variante 2 (manuell)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Benötigte Dateien (werden automatisch angelegt)
- `fixed_cves.json`
- `scheduler_jobs.json`
- `scheduler_results.json`
