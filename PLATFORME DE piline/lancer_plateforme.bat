@echo off
title CTI Pipeline Platform - PFE 2026
echo ======================================================
echo    DEMARRAGE DE LA PLATEFORME CTI (FLASK BACKEND)
echo ======================================================
cd /d "%~dp0"
start python server.py
echo.
echo Le serveur demarre... le dashboard s'ouvrira dans 2 secondes.
timeout /t 3 /nobreak > nul
start http://localhost:5000
exit
