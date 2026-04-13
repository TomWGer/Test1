# Krav Maga Kursplaner App

Einfache Web-App zur Erstellung von Krav-Maga-Trainingsplänen basierend auf Zielgruppe, Dauer, Intensität und Schwerpunkt.

## Lokal starten

```bash
python3 -m http.server 8000
```

Dann im Browser öffnen:

- <http://localhost:8000>

## Funktionen

- Automatische Minutenverteilung für alle Pflichtblöcke
- Trainingsplan mit Übungsvorschlägen
- YAML-Ausgabe für Weiterverarbeitung
- KI-Prompt-Generator für externe LLMs

---

## Hosting auf Synology NAS (mit überall gleichem Softwarestand)

Die robusteste Variante ist **Docker + Git** auf der Synology. So haben alle Nutzer denselben Stand.

## 1) Voraussetzungen

- Synology DSM 7.x
- Paket **Container Manager** installiert
- Git-Zugriff auf dieses Repository
- Optional: eigene Domain + HTTPS (Let's Encrypt)

## 2) App per Docker auf Synology starten

Im Projekt liegen bereits diese Dateien:

- `Dockerfile`
- `nginx.conf`
- `docker-compose.yml`

### Deployment-Schritte (SSH auf NAS)

```bash
# 1) In ein Verzeichnis auf der NAS wechseln
mkdir -p /volume1/docker/krav-planner
cd /volume1/docker/krav-planner

# 2) Repo klonen (oder bestehendes Repo dorthin kopieren)
git clone <DEIN_REPO_URL> .

# 3) Container bauen und starten
docker compose up -d --build
```

Die App läuft danach auf:

- `http://<NAS-IP>:8088`

## 3) Einheitlicher Softwarestand für alle Geräte

Empfehlung für Updates:

```bash
cd /volume1/docker/krav-planner
git fetch --all
git checkout main
git pull

docker compose up -d --build
```

Damit sehen alle Benutzer sofort dieselbe Version.

## 4) Öffentlicher Zugriff von überall (Internet)

Sicherer Standardweg über Synology:

1. **Systemsteuerung → Anmeldeportal → Reverse Proxy**
   - Quelle: `https://planner.deinedomain.de`
   - Ziel: `http://127.0.0.1:8088`
2. **Systemsteuerung → Sicherheit → Zertifikat**
   - Let's-Encrypt-Zertifikat für `planner.deinedomain.de`
3. Router-Portweiterleitung nur für 443 (HTTPS)
4. Firewall-Regeln auf DSM aktivieren

Danach ist die App unter deiner Domain erreichbar und per TLS abgesichert.

## 5) Optional: Automatische Updates (ohne manuelles Einloggen)

Optionen:

- GitHub Actions/GitLab CI, die per SSH auf die NAS deployen.
- Synology Aufgabenplaner (z. B. täglich), der die Update-Befehle ausführt.

Beispiel-Skript (`update.sh`):

```bash
#!/bin/bash
set -e
cd /volume1/docker/krav-planner
git checkout main
git pull
/docker/bin/docker compose up -d --build
```

## 6) Backup / Wiederherstellung

- Backup des Ordners `/volume1/docker/krav-planner`
- Zusätzlich Git als "Source of Truth" behalten
- Bei NAS-Wechsel: Ordner wiederherstellen + `docker compose up -d --build`
