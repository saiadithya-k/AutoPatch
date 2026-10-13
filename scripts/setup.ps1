param(
    [string]$Python = "python",
    [string]$EnvironmentName = ".venv"
)
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$environmentPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $EnvironmentName))
if (-not $environmentPath.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The virtual environment must be inside this project."
}
$pythonVersion = & $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or $pythonVersion -ne "3.11") { throw "Supply -Python with a working Python 3.11 executable." }
if (-not (Test-Path -LiteralPath $environmentPath)) {
    & $Python -m venv $environmentPath
    if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
}
$runtimePython = Join-Path $environmentPath "Scripts\python.exe"
$environmentVersion = & $runtimePython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or $environmentVersion -ne "3.11") { throw "The existing environment must use Python 3.11. Choose a different -EnvironmentName to preserve it." }
& $runtimePython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
if (-not (Test-Path -LiteralPath ".env")) { Copy-Item -LiteralPath ".env.example" -Destination ".env" }
& $runtimePython scripts/readiness.py
Write-Host "Start backend: $runtimePython -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"
