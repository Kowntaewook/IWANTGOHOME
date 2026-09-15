$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "finder.ps1") login @args
exit $LASTEXITCODE
