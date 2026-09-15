$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "finder.ps1") test @args
exit $LASTEXITCODE
