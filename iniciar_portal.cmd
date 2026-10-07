@echo off
setlocal
cd /d "%~dp0"
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" -m dedalo web --abrir
  goto end
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -m dedalo web --abrir
  goto end
)
where python >nul 2>nul
if not errorlevel 1 (
  python -m dedalo web --abrir
  goto end
)
echo No se encuentra Python. Instala Python 3.12 o superior y vuelve a abrir este archivo.
:end
pause
