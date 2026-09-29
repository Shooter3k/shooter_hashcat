[CmdletBinding()]
param(
  [ValidateSet('Validate', 'Publish')]
  [string] $Action = 'Validate',

  [Parameter(Mandatory = $false)]
  [string] $Tag = '',

  [ValidateRange(1, 256)]
  [int] $Jobs = [Environment]::ProcessorCount
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = [IO.Path]::GetFullPath($PSScriptRoot)
Set-Location $RepoRoot

function Invoke-Checked {
  param(
    [Parameter(Mandatory = $true)] [string] $FilePath,
    [Parameter(ValueFromRemainingArguments = $true)] [string[]] $Arguments
  )
  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($Arguments -join ' ')"
  }
}

function Invoke-Git {
  param([Parameter(Mandatory = $true)] [string[]] $Arguments)
  & git @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "git command failed with exit code $LASTEXITCODE`: git $($Arguments -join ' ')"
  }
}

function Get-TrackedChangedPaths {
  return @(& git status --porcelain --untracked-files=no | ForEach-Object {
    if ($_.Length -ge 4) { $_.Substring(3) }
  })
}

$AllowedPaths = @(
  'CHANGELOG.md'
  'release-windows.ps1'
  'src/backend.c'
  'include/backend.h'
  'src/hashcat.c'
)

$ChangedPaths = @(Get-TrackedChangedPaths)
$Unexpected = @($ChangedPaths | Where-Object { $_ -notin $AllowedPaths })
if ($Unexpected.Count -gt 0) {
  throw "Unexpected tracked changes exist. Commit or revert them before release: $($Unexpected -join ', ')"
}

if ($Action -eq 'Validate') {
  & (Join-Path $RepoRoot 'build-windows.ps1') -Action Rebuild -Jobs $Jobs
  if ($LASTEXITCODE -ne 0) { throw "build-windows.ps1 failed with exit code $LASTEXITCODE." }
  $Version = (& (Join-Path $RepoRoot 'hashcat.exe') --version).Trim()
  if (($LASTEXITCODE -ne 0) -or ($Version -notmatch '^v[0-9].+')) {
    throw "Built hashcat.exe returned an invalid version: $Version"
  }
  Write-Host "Validation passed: $Version"
  exit 0
}

if ([string]::IsNullOrWhiteSpace($Tag)) {
  throw 'Publish requires -Tag, for example v7.1.2-shooter.20260928.62.'
}

$Changelog = Get-Content -LiteralPath (Join-Path $RepoRoot 'CHANGELOG.md') -Raw
if ($Changelog -notmatch ('(?m)^##\s+' + [regex]::Escape($Tag) + '\s*$')) {
  throw "CHANGELOG.md does not contain a release section for $Tag."
}

if ($Tag -notmatch '^v7\.1\.2-shooter\.(\d{8})\.(\d+)$') {
  throw "Tag must match v7.1.2-shooter.YYYYMMDD.REVISION: $Tag"
}
$env:SHOOTER_BUILD_DATE = $Matches[1]
$env:SHOOTER_BUILD_REVISION = $Matches[2]

Invoke-Git @('add', '--', 'CHANGELOG.md', 'release-windows.ps1', 'src/backend.c', 'include/backend.h', 'src/hashcat.c')
& git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
  Invoke-Git @('commit', '-m', "Release $Tag")
}

$ExistingTag = ([string]((& git tag --list $Tag) -join '')).Trim()
if ($ExistingTag -ne '') {
  $TagCommit = ([string]((& git rev-list -n 1 $Tag) -join '')).Trim()
  $HeadCommit = ([string]((& git rev-parse HEAD) -join '')).Trim()
  if ($TagCommit -ne $HeadCommit) { throw "Tag $Tag already exists on a different commit." }
}
else {
  Invoke-Git @('tag', '-a', $Tag, '-m', $Tag)
}

& (Join-Path $RepoRoot 'build-windows.ps1') -Action Rebuild -Jobs $Jobs
if ($LASTEXITCODE -ne 0) { throw "build-windows.ps1 failed with exit code $LASTEXITCODE." }
& (Join-Path $RepoRoot 'package-windows.ps1') -BuildAction Skip -OutputDirectory dist -ExpectedVersion $Tag -Force
if ($LASTEXITCODE -ne 0) { throw "package-windows.ps1 failed with exit code $LASTEXITCODE." }

$Branch = ([string]((& git branch --show-current) -join '')).Trim()
Invoke-Git @('push', 'origin', $Branch)
Invoke-Git @('push', 'origin', $Tag)
Write-Host "Release published: $Tag"
