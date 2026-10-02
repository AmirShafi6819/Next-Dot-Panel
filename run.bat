@echo off
rem Next.Panel local launcher (Windows cmd.exe). Double-click or run "run.bat".
rem Checks dependencies, builds the frontend (if Node is available) and the
rem backend, prepares a local .env on first run, and starts the panel.
rem Safe: never overwrites an existing .env, never touches .\data.
setlocal EnableDelayedExpansion

cd /d "%~dp0"

where go >nul 2>nul
if errorlevel 1 (
  echo error: Go 1.26+ is required but 'go' was not found.
  echo Install it from https://go.dev/dl/ and re-run run.bat
  goto :pause_exit
)

if not exist "web\dist\index.html" (
  where npm >nul 2>nul
  if errorlevel 1 (
    echo --^> WARNING: Node/npm not found and web\dist is missing - starting API-only.
    echo --^> Install Node 20+ from https://nodejs.org/ and re-run to get the web UI.
  ) else (
    echo --^> building the web UI ^(npm install ^&^& npm run build^)^...
    pushd web
    call npm install --no-audit --no-fund || ( popd & echo error: npm install failed & goto :pause_exit )
    call npm run build || ( popd & echo error: frontend build failed & goto :pause_exit )
    popd
  )
) else (
  echo --^> web UI already built.
)

echo --^> building the backend...
go build -o nextpanel.exe .\cmd\nextpanel
if errorlevel 1 (
  echo error: go build failed
  goto :pause_exit
)

if not exist ".env" (
  echo --^> creating .env from .env.example ^(first run only^)...
  copy /y .env.example .env >nul
)

set "HAVE_KEY="
if defined NEXT_PANEL_ENCRYPTION_KEY set "HAVE_KEY=1"
if not defined HAVE_KEY (
  findstr /r "^NEXT_PANEL_ENCRYPTION_KEY=." .env >nul 2>nul
  if not errorlevel 1 set "HAVE_KEY=1"
)
if not defined HAVE_KEY (
  echo --^> generating NEXT_PANEL_ENCRYPTION_KEY...
  for /f "delims=" %%k in ('nextpanel.exe crypto generate-key') do set "GEN_KEY=%%k"
  if not defined GEN_KEY (
    echo error: key generation failed
    goto :pause_exit
  )
  findstr /v "^NEXT_PANEL_ENCRYPTION_KEY=" .env > .env.tmp
  echo NEXT_PANEL_ENCRYPTION_KEY=!GEN_KEY!>> .env.tmp
  move /y .env.tmp .env >nul
  echo --^> wrote a fresh encryption key to .env - back it up separately from .\data.
)

rem Load .env: only NEXT_PANEL_* lines, existing environment wins.
for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
  set "LINE=%%a"
  if "!LINE:~0,1!" NEQ "#" if "!LINE:~0,11!"=="NEXT_PANEL_" (
    if not defined %%a set "%%a=%%b"
  )
)

set "PORT=8080"
if defined NEXT_PANEL_LISTEN (
  for /f "tokens=2 delims=:" %%p in ("!NEXT_PANEL_LISTEN!") do set "PORT=%%p"
)
if "!PORT!"=="" set "PORT=8080"

echo --^> starting Next.Panel - open http://localhost:!PORT!
nextpanel.exe
goto :eof

:pause_exit
echo.
echo Press any key to close this window...
pause >nul
exit /b 1
