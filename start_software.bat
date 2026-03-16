@echo off
setlocal

REM Zum Ordner dieser Batch-Datei wechseln
cd /d "%~dp0"

echo [1/5] Pruefe Python ...
where py >nul 2>&1
if %errorlevel%==0 (
  set "PY_CMD=py"
) else (
  where python >nul 2>&1
  if %errorlevel%==0 (
    set "PY_CMD=python"
  ) else (
    echo Fehler: Python wurde nicht gefunden. Bitte Python installieren und erneut starten.
    pause
    exit /b 1
  )
)

echo [2/5] Erstelle virtuelle Umgebung (.venv), falls nicht vorhanden ...
if not exist ".venv\Scripts\python.exe" (
  %PY_CMD% -m venv .venv
  if errorlevel 1 (
    echo Fehler beim Erstellen der virtuellen Umgebung.
    pause
    exit /b 1
  )
)

echo [3/5] Aktualisiere pip ...
".venv\Scripts\python.exe" -m pip install --upgrade pip

echo [4/5] Installiere Abhaengigkeiten aus requirements.txt ...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo Fehler beim Installieren der Abhaengigkeiten.
  pause
  exit /b 1
)

echo [5/5] Starte Security Update Finder ...
start "Security Update Finder" ".venv\Scripts\python.exe" -m streamlit run app.py

echo Die Anwendung startet im Browser unter http://localhost:8501
exit /b 0
