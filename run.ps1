# Next.Panel local launcher (Windows PowerShell).
# Checks dependencies, builds the frontend (if Node is available) and the
# backend, prepares a local .env on first run, and starts the panel.
# Safe: never overwrites an existing .env, never touches .\data.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

# 1. Go is required.
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Fail "Go 1.26+ is required but 'go' was not found. Install it from https://go.dev/dl/ and re-run run.ps1"
}

# 2. Frontend: build only when dist is missing and npm exists.
if (-not (Test-Path 'web/dist/index.html')) {
  if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host '--> building the web UI (npm install && npm run build)...'
    Push-Location web
    try {
      & npm install --no-audit --no-fund; if ($LASTEXITCODE -ne 0) { throw 'npm install failed' }
      & npm run build; if ($LASTEXITCODE -ne 0) { throw 'frontend build failed' }
    } finally { Pop-Location }
  } else {
    Write-Host '--> WARNING: Node/npm not found and web/dist is missing - starting API-only.'
    Write-Host '--> Install Node 20+ from https://nodejs.org/ and re-run to get the web UI.'
  }
} else {
  Write-Host '--> web UI already built.'
}

# 3. Backend.
Write-Host '--> building the backend...'
& go build -o nextpanel.exe ./cmd/nextpanel
if ($LASTEXITCODE -ne 0) { Fail 'go build failed' }

# 4. Configuration: create .env from the template on first run only.
if (-not (Test-Path '.env')) {
  Write-Host '--> creating .env from .env.example (first run only)...'
  Copy-Item .env.example .env
}

# 5. Encryption key: generate one only when neither the environment nor .env has it.
$envHasKey = -not [string]::IsNullOrWhiteSpace($env:NEXT_PANEL_ENCRYPTION_KEY)
$fileHasKey = Select-String -LiteralPath .env -Pattern '^NEXT_PANEL_ENCRYPTION_KEY=.' -Quiet
if (-not $envHasKey -and -not $fileHasKey) {
  Write-Host '--> generating NEXT_PANEL_ENCRYPTION_KEY...'
  $key = (& .\nextpanel.exe crypto generate-key).Trim()
  if ([string]::IsNullOrWhiteSpace($key)) { Fail 'key generation failed' }
  $lines = Get-Content .env | Where-Object { $_ -notmatch '^NEXT_PANEL_ENCRYPTION_KEY=' }
  $lines += "NEXT_PANEL_ENCRYPTION_KEY=$key"
  Set-Content -LiteralPath .env -Value $lines -NoNewline:$false
  Write-Host '--> wrote a fresh encryption key to .env - back it up separately from .\data.'
}

# 6. Load .env: only NEXT_PANEL_* lines, existing environment wins.
foreach ($line in (Get-Content .env)) {
  if ($line -match '^(NEXT_PANEL_[A-Za-z0-9_]+)=(.*)$') {
    $name, $value = $Matches[1], $Matches[2]
    if ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name))) {
      [Environment]::SetEnvironmentVariable($name, $value)
    }
  }
}

$port = '8080'
if ($env:NEXT_PANEL_LISTEN -match ':(\d+)\s*$') { $port = $Matches[1] }

Write-Host "--> starting Next.Panel - open http://localhost:$port"
& .\nextpanel.exe
