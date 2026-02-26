# Fahrtenbuch

Einfache Web-App, um Fahrten mit Fahrzeugmodell, Verbrauch und Kosten pro Kilometer zu erfassen.

## Funktionen

- Fahrzeugmodell aus vordefinierter Liste auswählen (inkl. Kraftstofftyp)
- Tagesaktuelle Kraftstoffpreise automatisch laden (Quelle: fueleconomy.gov API)
- Kostenkalkulation je Fahrt mit dem geladenen Tagespreis des passenden Kraftstoffs
- Spritverbrauch pro Fahrt berechnen
- Gesamtkosten und Kosten pro Kilometer ausrechnen
- Fahrten lokal im Browser speichern (LocalStorage)
- Fahrtenhistorie anzeigen und löschen

## Start

```bash
python3 -m http.server 8000
```

Dann im Browser öffnen: <http://localhost:8000>
