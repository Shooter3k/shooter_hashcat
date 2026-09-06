param(
  [string]$Hashcat = (Join-Path (Split-Path $PSScriptRoot -Parent) "hashcat.exe"),
  [switch]$RunGpuCrack
)

$ErrorActionPreference = "Stop"
$root = Join-Path ([IO.Path]::GetTempPath()) ("shooter-multi-hash-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null

try {
  $hashes = Join-Path $root "hashes.txt"
  $pot = Join-Path $root "hashcat.potfile"
  $out = Join-Path $root "found.txt"

  @(
    "8743b52063cd84097a65d1633f5c74f5" # MD5("hashcat")
    "afe04867ec7a3845145579a95f72eca7" # MD4("hashcat")
    "b89eaac7e61417341b710b727768294d0e6a277b" # SHA1("hashcat")
    "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935" # SHA256("hashcat")
    "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f" # SHA512("hashcat")
    "b4b9b02e6f09a9bd760f388b67351e2b" # NTLM("hashcat")
  ) | Set-Content -LiteralPath $hashes -Encoding ascii

  @(
    '$shooter-mode$100$8743b52063cd84097a65d1633f5c74f5:wrong-cross-mode-result'
    '8743b52063cd84097a65d1633f5c74f5:wrong-untagged-result'
    '$shooter-mode$0$8743b52063cd84097a65d1633f5c74f5:hashcat'
    '$shooter-mode$900$afe04867ec7a3845145579a95f72eca7:hashcat'
    '$shooter-mode$100$b89eaac7e61417341b710b727768294d0e6a277b:hashcat'
    '$shooter-mode$1400$127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935:hashcat'
    '$shooter-mode$1700$82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f:hashcat'
    '$shooter-mode$1000$b4b9b02e6f09a9bd760f388b67351e2b:hashcat'
  ) | Set-Content -LiteralPath $pot -Encoding ascii

  & $Hashcat --show --multi-hash-modes=0,900,100,1400,1700,1000 $hashes --potfile-path $pot -o $out --outfile-format=1,2 --quiet
  if ($LASTEXITCODE -ne 0) { throw "native --show test exited with $LASTEXITCODE" }

  $actual = @(Get-Content -LiteralPath $out)
  $expected = @(
    "0:8743b52063cd84097a65d1633f5c74f5:hashcat"
    "900:afe04867ec7a3845145579a95f72eca7:hashcat"
    "100:b89eaac7e61417341b710b727768294d0e6a277b:hashcat"
    "1400:127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935:hashcat"
    "1700:82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f:hashcat"
    "1000:b4b9b02e6f09a9bd760f388b67351e2b:hashcat"
  )

  if (Compare-Object $expected $actual -SyncWindow 0) {
    throw "mode-tagged output or mode-isolated potfile behavior differed from the expected result. Actual: $($actual -join ' | ')"
  }

  $eHashes = Join-Path $root "e-hashes.txt"
  $ePot = Join-Path $root "e-hashcat.potfile"
  $eOut = Join-Path $root "e-found.txt"

  @(
    "8743b52063cd84097a65d1633f5c74f5"
    "afe04867ec7a3845145579a95f72eca7"
    "b89eaac7e61417341b710b727768294d0e6a277b"
    "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
    "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"
    "b4b9b02e6f09a9bd760f388b67351e2b"
  ) | Set-Content -LiteralPath $eHashes -Encoding ascii
  @(
    '$shooter-mode$e1$8743b52063cd84097a65d1633f5c74f5:hashcat'
    '$shooter-mode$e3$afe04867ec7a3845145579a95f72eca7:hashcat'
    '$shooter-mode$e8$b89eaac7e61417341b710b727768294d0e6a277b:hashcat'
    '$shooter-mode$e10$127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935:hashcat'
    '$shooter-mode$e12$82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f:hashcat'
    '$shooter-mode$e369$b4b9b02e6f09a9bd760f388b67351e2b:hashcat'
  ) | Set-Content -LiteralPath $ePot -Encoding ascii

  & $Hashcat --show --multi-hash-modes=e1,e3,e8,e10,e12,e369 $eHashes --potfile-path $ePot -o $eOut --outfile-format=1,2 --quiet
  if ($LASTEXITCODE -ne 0) { throw "mdxfind e-mode --show test exited with $LASTEXITCODE" }

  $eActual = @(Get-Content -LiteralPath $eOut)
  $eExpected = @(
    "e1:8743b52063cd84097a65d1633f5c74f5:hashcat"
    "e3:afe04867ec7a3845145579a95f72eca7:hashcat"
    "e8:b89eaac7e61417341b710b727768294d0e6a277b:hashcat"
    "e10:127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935:hashcat"
    "e12:82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f:hashcat"
    "e369:b4b9b02e6f09a9bd760f388b67351e2b:hashcat"
  )

  if (Compare-Object $eExpected $eActual -SyncWindow 0) {
    throw "mdxfind e-mode order/tagging differed from the expected result"
  }

  $mixedPot = Join-Path $root "mixed-hashcat.potfile"
  $mixedOut = Join-Path $root "mixed-found.txt"
  @(
    '$shooter-mode$0$8743b52063cd84097a65d1633f5c74f5:hashcat'
    '$shooter-mode$e3$afe04867ec7a3845145579a95f72eca7:hashcat'
    '$shooter-mode$100$b89eaac7e61417341b710b727768294d0e6a277b:hashcat'
  ) | Set-Content -LiteralPath $mixedPot -Encoding ascii
  & $Hashcat --show --multi-hash-modes=0,e3,100 $hashes --potfile-path $mixedPot -o $mixedOut --outfile-format=1,2 --quiet
  if ($LASTEXITCODE -ne 0) { throw "mixed native/e-mode --show test exited with $LASTEXITCODE" }
  $mixedExpected = @(
    "0:8743b52063cd84097a65d1633f5c74f5:hashcat"
    "e3:afe04867ec7a3845145579a95f72eca7:hashcat"
    "100:b89eaac7e61417341b710b727768294d0e6a277b:hashcat"
  )
  if (Compare-Object $mixedExpected @(Get-Content -LiteralPath $mixedOut) -SyncWindow 0) {
    throw "mixed native/e-mode sequential fallback differed from the expected result"
  }

  if ($RunGpuCrack) {
    $crackPot = Join-Path $root "crack.potfile"
    $crackOut = Join-Path $root "cracked.txt"
    $words = Join-Path $root "words.txt"
    "hashcat" | Set-Content -LiteralPath $words -Encoding ascii

    $sharedText = (& $Hashcat --multi-hash-modes=0,900,100,1400,1700,1000 -a 0 $hashes $words --potfile-path $crackPot -o $crackOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet 2>&1 | Out-String)
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw "native cracking test exited with $LASTEXITCODE" }
    if ($sharedText -notmatch "shared GPU session") { throw "compatible raw modes did not select the shared GPU path" }

    $cracked = @(Get-Content -LiteralPath $crackOut)
    if (Compare-Object $expected $cracked -SyncWindow 0) {
      throw "multi-mode cracking result differed from the expected result. Actual: $($cracked -join ' | ')"
    }

    # Exercise every GPU-compatible family together.  These values are the
    # upstream single-mode self-test hashes for the common password "hashcat",
    # so this also compares the fused implementation with each normal module.
    $expandedModes = @(70, 170, 1470, 1770, 2600, 3500, 4300, 4400, 4500, 4700, 18500, 20800, 20900, 21000, 21400, 32800, 34500)
    $expandedHashValues = @(
      "2303b15bfa48c74a74758135a0df1201"
      "b9798556b741befdbddcbf640d1dd59d19b1e193"
      "9e9283e633f4a7a42d3abc93701155be8afe5660da24c8758e7d3533e2f2dc82"
      "79bba09eb9354412d0f2c037c22a777b8bf549ab12d49b77d5b25faa839e4378d8f6fa11aceb6d9413977ae5ad5d011568bad2de4f998d75fd4ce916eda83697"
      "a936af92b0ae20b1ff6c3347a72e5fbe"
      "9882d0778518b095917eb589f6998441"
      "b8c385461bb9f9d733d3af832cf60b27"
      "288496df99b33f8f75a7ce4837d1b480"
      "3db9184f5da4e463832b086211af8d2314919951"
      "92d85978d884eb1d99a51652b1139c8279fa8663"
      "888a2ffcb3854fba0321110c5d0d434ad1aa2880"
      "74ee1fae245edd6f27bf36efc3604942479fceefbadab5dc5c0b538c196eb0f1"
      "100b3a4fc1dc8d60d9bf40688d8b740a"
      "caec04bdf7c17f763a9ec7439f7c9abda112f1bfc9b1bb684fef9b6142636979b9896cfc236896d821a69a961a143dd19c96d59777258201f1bbe5ecc2a2ecf5"
      "0cc1b58a543f372327aa0281e97ab56e345267ee46feabf7709515debb7ec43c"
      "7b4f60b54472980e922280e225150dfa"
      "10d302483c927df95abba98d69dcd9608365241d1523a8cc5fcbcedc"
    )
    $expandedHashes = Join-Path $root "expanded-hashes.txt"
    $expandedOut = Join-Path $root "expanded-found.txt"
    $expandedHashValues | Set-Content -LiteralPath $expandedHashes -Encoding ascii
    $expandedModeList = $expandedModes -join ','
    $expandedText = (& $Hashcat "--multi-hash-modes=$expandedModeList" -a 0 $expandedHashes $words --potfile-disable -o $expandedOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet 2>&1 | Out-String)
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw "expanded shared-family cracking test exited with $LASTEXITCODE`: $expandedText" }
    if ($expandedText -notmatch "shared GPU session") { throw "expanded compatible modes did not select the shared GPU path" }
    $expandedExpected = for ($i = 0; $i -lt $expandedModes.Count; $i++) {
      "$($expandedModes[$i]):$($expandedHashValues[$i]):hashcat"
    }
    $expandedActual = @(Get-Content -LiteralPath $expandedOut)
    if (Compare-Object ($expandedExpected | Sort-Object) ($expandedActual | Sort-Object) -SyncWindow 0) {
      throw "expanded shared-family results differed. Actual: $($expandedActual -join ' | ')"
    }

    $expandedAliases = @('e800', 'e727', 'e805', 'e808', 'e262', 'e178', 'e160', 'e287', 'e164', 'e442', 'e38', 'e36', 'e188', 'e766')
    $expandedAliasHashIndexes = @(0, 1, 2, 3, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16)
    $expandedAliasOut = Join-Path $root "expanded-alias-found.txt"
    $expandedAliasText = (& $Hashcat "--multi-hash-modes=$($expandedAliases -join ',')" -a 0 $expandedHashes $words --potfile-disable -o $expandedAliasOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet 2>&1 | Out-String)
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw "expanded mdxfind-alias cracking test exited with $LASTEXITCODE`: $expandedAliasText" }
    if ($expandedAliasText -notmatch "shared GPU session") { throw "expanded mdxfind aliases did not select the shared GPU path" }
    $expandedAliasExpected = for ($i = 0; $i -lt $expandedAliases.Count; $i++) {
      "$($expandedAliases[$i]):$($expandedHashValues[$expandedAliasHashIndexes[$i]]):hashcat"
    }
    $expandedAliasActual = @(Get-Content -LiteralPath $expandedAliasOut)
    if (Compare-Object ($expandedAliasExpected | Sort-Object) ($expandedAliasActual | Sort-Object) -SyncWindow 0) {
      throw "expanded mdxfind-alias results differed. Actual: $($expandedAliasActual -join ' | ')"
    }

    $uppercaseHashes = Join-Path $root "uppercase-hashes.txt"
    $jsonOut = Join-Path $root "uppercase-json.txt"
    @(
      "8743B52063CD84097A65D1633F5C74F5"
      "B89EAAC7E61417341B710B727768294D0E6A277B"
    ) | Set-Content -LiteralPath $uppercaseHashes -Encoding ascii
    & $Hashcat --multi-hash-modes=0,100 -O -a 0 $uppercaseHashes $words --potfile-disable -o $jsonOut --outfile-json --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw "uppercase/-O/JSON cracking test exited with $LASTEXITCODE" }
    $jsonRows = @((Get-Content -LiteralPath $jsonOut) | ForEach-Object { $_ | ConvertFrom-Json })
    if ($jsonRows.Count -ne 2 -or (($jsonRows.hash_mode | Sort-Object) -join ',') -ne "0,100") {
      throw "uppercase/-O cracking did not retain the two JSON hash_mode values"
    }

    $ruleHashes = Join-Path $root "rule-hashes.txt"
    $ruleFile = Join-Path $root "uppercase.rule"
    $ruleOut = Join-Path $root "rule-found.txt"
    @(
      "071a1a3f8a1438cef8dc228d5810b431"
      "bd093dcdd1831d71b813a940c1ce342c59dfd66f"
    ) | Set-Content -LiteralPath $ruleHashes -Encoding ascii
    "u" | Set-Content -LiteralPath $ruleFile -Encoding ascii
    & $Hashcat --multi-hash-modes=0,100 -a 0 $ruleHashes $words -r $ruleFile --potfile-disable -o $ruleOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw "shared rules test exited with $LASTEXITCODE" }
    if (@(Get-Content -LiteralPath $ruleOut).Count -ne 2) { throw "shared rules test did not crack both requested modes" }

    $maskOut = Join-Path $root "mask-found.txt"
    & $Hashcat --multi-hash-modes=0,100 -a 3 $hashes "hashca?l" --potfile-disable -o $maskOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw "shared mask test exited with $LASTEXITCODE" }
    if (@(Get-Content -LiteralPath $maskOut).Count -ne 2) { throw "shared mask test did not crack both requested modes" }

    $potRows = @(Get-Content -LiteralPath $crackPot)
    if ($potRows.Count -ne 6 -or @($potRows | Where-Object { $_ -notmatch '^\$shooter-mode\$(0|900|100|1400|1700|1000)\$' }).Count -ne 0) {
      throw "cracking test did not produce exactly six mode-tagged potfile rows"
    }

    $eCrackPot = Join-Path $root "e-crack.potfile"
    $eCrackOut = Join-Path $root "e-cracked.txt"

    & $Hashcat --multi-hash-modes=e1,e3,e8,e10,e12,e369 -a 0 $eHashes $words --potfile-path $eCrackPot -o $eCrackOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw "mdxfind alias cracking test exited with $LASTEXITCODE" }

    $eCracked = @(Get-Content -LiteralPath $eCrackOut)
    if (Compare-Object $eExpected $eCracked -SyncWindow 0) {
      throw "mdxfind alias cracking result differed from the expected result. Actual: $($eCracked -join ' | ')"
    }

    $wrongWords = Join-Path $root "wrong-words.txt"
    "not-the-password" | Set-Content -LiteralPath $wrongWords -Encoding ascii
    & $Hashcat --multi-hash-modes=e1,e3,e8,e10,e12,e369 -a 0 $eHashes $wrongWords --potfile-path $eCrackPot --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet
    if ($LASTEXITCODE -ne 0) { throw "shared session did not reuse mode-tagged potfile rows" }

    $fallbackHashes = Join-Path $root "fallback-hashes.txt"
    $fallbackOut = Join-Path $root "fallback-found.txt"
    $fallbackPot = Join-Path $root "fallback.potfile"
    @(
      "8743b52063cd84097a65d1633f5c74f5"
      "3d83c8e717ff0e7ecfe187f088d69954:343141"
    ) | Set-Content -LiteralPath $fallbackHashes -Encoding ascii
    $fallbackText = (& $Hashcat --multi-hash-modes=0,10 -a 0 $fallbackHashes $words --potfile-path $fallbackPot -o $fallbackOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "sequential fallback test exited with $LASTEXITCODE" }
    if ($fallbackText -notmatch "processed in command-line order") { throw "unsupported family did not use the sequential fallback" }
    $fallbackExpected = @(
      "0:8743b52063cd84097a65d1633f5c74f5:hashcat"
      "10:3d83c8e717ff0e7ecfe187f088d69954:343141:hashcat"
    )
    if (Compare-Object $fallbackExpected @(Get-Content -LiteralPath $fallbackOut) -SyncWindow 0) {
      throw "sequential fallback stopped before all requested modes completed"
    }

    $exhaustedFallbackHash = Join-Path $root "exhausted-fallback-hash.txt"
    $exhaustedFallbackOut = Join-Path $root "exhausted-fallback-found.txt"
    @(
      "d41d8cd98f00b204e9800998ecf8427e"
      "3d83c8e717ff0e7ecfe187f088d69954:343141"
    ) | Set-Content -LiteralPath $exhaustedFallbackHash -Encoding ascii
    & $Hashcat --multi-hash-modes=0,10 -a 0 $exhaustedFallbackHash $words --potfile-disable -o $exhaustedFallbackOut --outfile-format=1,2 --backend-ignore-opencl --backend-devices=1 --restore-disable --self-test-disable --hwmon-disable --quiet
    if ($LASTEXITCODE -ne 1) { throw "exhausted-first fallback test exited with $LASTEXITCODE instead of 1" }
    $exhaustedFallbackExpected = "10:3d83c8e717ff0e7ecfe187f088d69954:343141:hashcat"
    if ((Get-Content -LiteralPath $exhaustedFallbackOut) -ne $exhaustedFallbackExpected) {
      throw "sequential fallback stopped after the first mode exhausted"
    }

    $singleRestoreHash = Join-Path $root "single-restore-hash.txt"
    $singleRestore = Join-Path $root "single.restore"
    "d41d8cd98f00b204e9800998ecf8427e" | Set-Content -LiteralPath $singleRestoreHash -Encoding ascii
    & $Hashcat -m 0 -a 3 $singleRestoreHash "?a?a?a?a?a?a?a?a?a" --runtime=1 --session=single-restore-regression --restore-file-path=$singleRestore --potfile-disable --backend-ignore-opencl --backend-devices=1 --self-test-disable --hwmon-disable --quiet
    if ($LASTEXITCODE -ne 4 -or -not (Test-Path -LiteralPath $singleRestore)) {
      throw "initial ordinary restore test failed: exit $LASTEXITCODE"
    }
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $singleRestoreText = (& $Hashcat --restore --restore-file-path=$singleRestore 2>&1 | Out-String)
    $singleRestoreExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorActionPreference
    if ($singleRestoreExitCode -ne 4) { throw "ordinary restore regression test exited with $singleRestoreExitCode" }
    if ($singleRestoreText -match "Multi-hash") { throw "ordinary restore was incorrectly converted into a multi-hash session" }
  }

  $badCases = @(
    [pscustomobject]@{ Argument = "--multi-hash-modes=e1"; Expected = "requires at least two" }
    [pscustomobject]@{ Argument = "--multi-hash-modes=e425-e427"; Expected = "e426 is not a cracking mode" }
    [pscustomobject]@{ Argument = "--multi-hash-modes=0,,100"; Expected = "Invalid --multi-hash-modes" }
    [pscustomobject]@{ Argument = "--multi-hash-modes=0,79997"; Expected = "Invalid --multi-hash-modes" }
    [pscustomobject]@{ Argument = "-m79997"; Expected = "is internal" }
  )

  foreach ($case in $badCases) {
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $text = (& $Hashcat $case.Argument 2>&1 | Out-String)
    $badCaseExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorActionPreference
    if ($badCaseExitCode -eq 0) { throw "invalid case unexpectedly succeeded: $($case.Argument)" }
    if ($text -notmatch [regex]::Escape($case.Expected)) { throw "invalid case lacked expected diagnostic: $($case.Argument)" }
  }

  $scope = if ($RunGpuCrack) { "parser, GPU cracking, order, mode-tagged output, and potfile isolation" } else { "parser, order, mode-tagged output, and potfile isolation" }
  Write-Host "PASS: --multi-hash-modes $scope"
}
finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
