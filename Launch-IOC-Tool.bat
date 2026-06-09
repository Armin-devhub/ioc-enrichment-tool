@echo off
REM Launch the IOC Enrichment Tool GUI using the project's virtual environment.
REM Double-click this file to start the app.
cd /d "%~dp0"
start "" ".venv\Scripts\pythonw.exe" -m ioc_enrich.gui
