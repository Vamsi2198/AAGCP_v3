param(
    [int]$PhoenixPort = 7007,
    [string]$PythonExe = "python",
    [int]$ServerPort = 8002
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($PythonExe -eq "python") {
    $condaPy = $null
    if ($env:CONDA_PREFIX) {
        $candidate = Join-Path $env:CONDA_PREFIX "python.exe"
        if (Test-Path $candidate) {
            $condaPy = $candidate
        }
    }

    if ($condaPy) {
        $PythonExe = $condaPy
    } else {
        $PythonExe = (Get-Command python -ErrorAction Stop).Source
    }
}

if (-not (Test-Path $PythonExe)) {
    throw "Python executable not found: $PythonExe"
}

$env:PHOENIX_PORT = "$PhoenixPort"
$env:AAGCP_OTEL = "1"
$env:OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:$PhoenixPort/v1/traces"
$env:PORT = "$ServerPort"

Write-Host "Using Python: $PythonExe"

Write-Host "Starting Phoenix on http://localhost:$PhoenixPort ..."
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$repoRoot'; `$env:PHOENIX_PORT='$PhoenixPort'; & '$PythonExe' run_phoenix_forever.py"
)

Start-Sleep -Seconds 2

Write-Host "Starting AAGCP server on http://localhost:$ServerPort ..."
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$repoRoot'; `$env:AAGCP_OTEL='1'; `$env:OTEL_EXPORTER_OTLP_ENDPOINT='http://localhost:$PhoenixPort/v1/traces'; `$env:PORT='$ServerPort'; & '$PythonExe' server.py"
)

Write-Host "Launched both processes."
Write-Host "Phoenix UI: http://localhost:$PhoenixPort"
Write-Host "Server:     http://localhost:$ServerPort"
Write-Host "Endpoint:   http://localhost:$PhoenixPort/v1/traces"
