$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Project = Join-Path $Root "VPNHub.Client\VPNHub.Client.csproj"
$Tests = Join-Path $Root "VPNHub.Client.Tests\VPNHub.Client.Tests.csproj"
$Output = Join-Path $Root "artifacts\win-x64"

dotnet restore $Project
dotnet build $Project -c Release --no-restore
dotnet test $Tests -c Release

if (Test-Path $Output) {
    Remove-Item $Output -Recurse -Force
}

dotnet publish $Project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false -p:IncludeNativeLibrariesForSelfExtract=true -o $Output

Write-Host ""
Write-Host "VPNHub Client publicado em:"
Write-Host $Output
