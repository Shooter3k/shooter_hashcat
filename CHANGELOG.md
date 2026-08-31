# shooter_hashcat release notes

## v7.1.2-shooter.20260831.59

Native Argon2 with an MD5-prehashed password input.

### Added

- Add hash mode `34900`, `Argon2(md5($pass))`. Candidate generation, masks,
  rules, hybrid attacks, and Shooter mode 13 continue to operate on the
  original plaintext. The GPU kernel converts the finished candidate to a
  lowercase 32-character MD5 hexadecimal string immediately before Argon2.
- Support standard PHC strings for Argon2d, Argon2i, and Argon2id, versions 16
  and 19, while preserving each hash's memory, iteration, parallelism, salt,
  and digest-length parameters.

### Verified

- Verify independently generated vectors for all three Argon2 variants and
  both supported versions on CUDA, including built-in self-test, mask, and
  rule-based recovery paths.
- Regression-test standard mode `34000` after sharing its host-side PHC parser
  and memory/tuning integration with the new mode.

## v7.1.2-shooter.20260824.58

Clean Windows rebuild and synchronized recovery release.

### Improved

- Publish this maintenance release through the clean Windows release workflow
  so every frontend, core, module, bridge, and feed is rebuilt together. Local
  incremental builds remain useful for development but are not deployment or
  release artifacts.

### Verified

- Rebuild the complete Windows x64 distribution from a clean object tree and
  verify its internal SHA-256 manifest, SBOM, executable version, module count,
  bridge set, and feed set before publication.
- Run representative known-answer attacks against the clean executable to
  confirm candidate generation and recovered plaintext remain correct.

## v7.1.2-shooter.20260824.57

Interactive forward seeking, cross-build autotune reuse, and redirected-output
formatting.

### Added

- Add interactive `[g]oto` forward seeking during running or paused attacks.
  Values from 0 through 100 select a percentage of the current base keyspace;
  values above 100 select an exact one-based line/base position. Already
  assigned GPU work finishes safely, skipped amplification is included in
  progress, and backward, stdin, `--stdout`, and out-of-range seeks are
  rejected without changing the attack.

### Improved

- Search all otherwise compatible RTX 4090 autotune values after a Hashcat
  rebuild, preferring a covering and then nearest salt/digest workload. Reused
  geometry is measured on the current kernel and real workload before use,
  promoted under the current build/workload key when accepted, and discarded
  in favor of normal autotune when validation fails.

### Fixed

- Preserve in-place progress replacement on interactive terminals while
  terminating each pending progress record when output is redirected. Startup,
  hash parsing, sorting, and similar messages no longer run together in logs
  or controller transcripts, including when logging switches between stdout
  and stderr.

## v7.1.2-shooter.20260820.55

Candidate generation, final-candidate policy, Unicode status output, and
mode-13 recovered-plaintext correctness.

### Added

- Add a native deterministic PCFG feed for attack mode 8 plus
  `tools/train_pcfg.py`. Models use probability-ordered class structures and
  terminal tables, exact 64-bit keyspace accounting, deterministic
  multi-device offsets, rules, skip/limit, and restore.
- Add independent, default-off `--require-upper`, `--require-lower`,
  `--require-digit`, and `--require-symbol` final-candidate policies, with
  numeric `--candidate-min-*=N` forms for larger minimums.
- Add comprehensive PCFG, candidate-policy, and six-method candidate roadmap
  documentation. Only PCFG is marked shipped; the remaining five generator
  proposals are explicitly planned.

### Fixed

- Render valid UTF-8 status and diagnostic text through the Windows Unicode
  console API. Multibyte candidate previews no longer depend on the active
  console code page; redirected output remains byte-for-byte UTF-8, and
  invalid candidate bytes retain the existing `$HEX[...]` representation.
- Reconstruct optimized mode-13 recovered plaintext from its synthesized GPU
  suffix rules. Fully GPU-amplified pipelines no longer report an empty plain,
  and partial GPU suffixes retain their complete host prefix.

### Verified

- Build the Windows core and PCFG feed, compare skip output with the suffix of
  a complete deterministic sequence, validate model-class errors, and verify
  rules transform complete PCFG candidates. A two-GPU run recovered all 21
  known candidates, and a runtime-aborted session restored at its saved PCFG
  offset.
- Verify final-candidate requirements with straight wordlists, post-rule
  output, masks, two-word combinations, both hybrid orders, PCFG plus rules,
  and an ordered mode-13 wordlist/mask/rule pipeline.
- Verify two-, three-, and four-byte UTF-8 candidate previews, including real
  Windows terminal runs under code page 437 in both editions and ordered mode
  13, plus redirected UTF-8 output and invalid-byte `$HEX[...]` fallback.
- Verify exact `hash:plain` output for every permutation of two distinct
  wordlists and a mask, leading/middle/trailing and repeated rule stages,
  optimized and pure kernels, complete/partial/disabled GPU amplification,
  crack positions, and wrong-order negative cases in both editions.

## v7.1.2-shooter.20260818.54

Mode-13 performance, optimized-kernel recovery, and opt-in timing diagnostics.

### Added

- Add `--task-time-breakdown`, disabled by default, to print the measured
  end-to-end preparation, attack, and cleanup report. Existing quiet,
  machine-readable, informational, and candidate-output modes remain clean.
- Add exhaustive mode-13 semantic validation for every one- through six-stage
  wordlist, mask, and rule type sequence, plus a 60-stage stress case and a
  reproducible all-order GPU benchmark harness.

### Improved

- Mode 13 now compiles the largest safe trailing product of wordlists, masks,
  and rules into as many as 65,536 native GPU rules. Indexed outer-wordlist
  dispatch, prefix reuse, resident small-wordlist caching, and forward cursors
  avoid redundant host candidate generation without changing left-to-right
  semantics, keyspace, restore positions, or output.
- `--stdout` uses the exact compressed host path without interactive prompts
  or automatic status output.

### Fixed

- When an optimized kernel actually selected by `-O` rejects every supplied
  hash during parsing and a pure kernel exists, Hashcat rebuilds the complete
  session once without `-O`. If the pure parser also rejects the input, its
  error is preserved and the job stops normally.

### Verified

- Exhaustively compared 1,092 structural mode-13 pipelines and 55,986 ordered
  candidates per semantic path against an independent left-to-right oracle.
- Benchmarked all 24 permutations of a large wordlist, ten-rule file, digit
  mask, and 100-line wordlist. Orders with the large source first formed a
  10,000-candidate GPU suffix and held twelve RTX 4090 GPUs at 99 to 100
  percent utilization; the original order reached 219.5 GH/s against one MD5.
- Retested the best order against 84,381,739 MD5 digests at 100.8 to 101.3
  GH/s with every GPU at 98 to 100 percent, and verified timing output is absent
  by default and present only with `--task-time-breakdown`.

## v7.1.2-shooter.20260817.53

Time-estimate corrective release for attack mode 13.

### Fixed

- Mode 13 now participates in Hashcat's normal ETA calculation. Once a speed
  sample is available, `Time.Estimated` uses the complete ordered-pipeline
  keyspace, current progress, ignored work, and aggregate device speed instead
  of remaining at the current time with `(0 secs)`.
- The automatic pre-attack status page still reports zero while speed is
  `0 H/s`; later automatic, periodic, and interactive status pages report the
  measured ETA.

### Verified

- Tested a real `wordlist -> rule -> mask -> wordlist` pipeline with
  651,605,000 candidates on a CPU-only OpenCL device in both editions.
- Confirmed nonzero ETAs after the first speed sample and confirmed the
  displayed remaining time matches remaining candidates divided by measured
  speed. The standard executable was also retested successfully by the user.

## v7.1.2-shooter.20260817.52

Interactive-control corrective release for attack mode 13.

### Fixed

- Mode 13 now starts the normal keyboard handler even though its ordered host
  pipeline does not use Hashcat's single mask or generic-feed source type.
- The interactive command menu is displayed during mode-13 attacks, and `s`,
  `p`, `b`, `c`, `f`, `q`, `e`, `l`, and `i` are handled normally when their
  corresponding features are available.
- The automatic full status pages at the beginning and end of a mode-13 attack
  remain enabled.

### Verified

- Reproduced the `.51` failure in a Windows console: the initial status page
  printed, but `s` was ignored because no keyboard thread existed.
- Built both Windows x64 editions as `.52` and verified that mode 13 displays
  its command menu, responds to `s`, and accepts `q` for a clean exit.

## v7.1.2-shooter.20260817.51

Corrective ordered-pipeline release for attack mode 13.

### Changed

- Mode 13 now accepts any number of wordlist, mask, and rule stages in any
  order and processes them from left to right.
- Each `-r` file is a stage at its exact command-line position. It transforms
  the complete candidate assembled to its left; later wordlists and masks
  append after that transformation.
- Positional files default to wordlists, tokens containing `?` are masks, and
  `.hcmask` files are mask-file stages. The explicit `wordlist:`, `mask:`, and
  `maskfile:` prefixes resolve ambiguous inputs.
- `?w` and `?q` remain mode-12 markers and are no longer part of mode-13
  syntax.
- The Shooter enhancement inventory counts only Shooter-authored changes;
  official mode 12, upstream maintenance fixes, and stock low-rate bypass
  flags are not presented as Shooter features.
- Keyspace, skip/limit, checkpoints, and restores use the complete ordered
  Cartesian product, including each rule stage. Restore files retain the
  original command-line stage order.

### Fixed

- Commands such as `wordlist -r rules ?d?d wordlist` no longer interpret the
  first wordlist as a mask or reject the later mask as a filename.

### Verified

- Built the affected Linux core and linked `hashcat.bin`.
- Built both Windows x64 editions as `.51`; verified wordlist/mask/rule
  permutations, adjacent and leading rules, hcmask/custom charsets, keyspace,
  257 rule stages, and a real mode-0 recovery.
- Confirmed automatic status pages report `Running` at startup and `Cracked`
  at completion.

## v7.1.2-shooter.20260817.50

> Superseded by `.51`: this release's fixed mask-first `?w` layout did not
> satisfy arbitrary left-to-right component ordering.

### Added

- Attack mode 13 accepts a mask plus any number of wordlists. Each `?w` marker
  maps to the next wordlist in command-line order, and every mask must contain
  exactly one marker per wordlist.
- Mode 13 supports hcmask files for ordered mask sequences and applies `-r` or
  `-g` rules only after the complete mask-and-wordlist candidate is assembled.
- Mode 13 works with normal cracking, `--stdout`, `--keyspace`,
  `--total-candidates`, skip/limit accounting, restore positions, status,
  potfiles, and outfiles.

### Verified

- Built the portable Windows x64 executable.
- Confirmed three wordlists retain command-line order, hcmask lines retain
  file order, reversing two `-r` options reverses their rule effect, marker
  count mismatches fail clearly, and a ruled mode-13 candidate cracks a known
  MD5 target.

## v7.1.2-shooter.20260817.49

Automatic endpoint-status and task-timing release.

### Added

- Every normal human-readable attack now ends with an automatic task-time
  breakdown. It separates preparation, cracking, and cleanup and itemizes
  backend discovery, GPU setup, hash loading/sorting/deduplication,
  potfile/outfile checks, rules, bitmaps, self-test, and autotune.
- Each timing line includes seconds and its share of measured end-to-end time;
  unclassified preparation remains visible so the report reconciles to the
  measured total.
- Normal human-readable attacks print the full interactive `s` status page
  once before cracking workers launch and again when the attack completes.
  Quiet, structured, benchmark, speed-only, progress-only, and `--stdout`
  output retain their existing formats.

### Changed

- Audited the public feature inventory against the official upstream hashcat
  commit merged into this branch. Inherited hashcat features are no longer
  counted as Shooter enhancements; the inventory now contains 51 local
  changes.

### Verified

- Built the portable Windows x64 executable and ran a real CUDA MD5 attack.
- Confirmed `BEFORE ATTACK`, `ATTACK`, and `AFTER ATTACK` reconcile to the
  displayed `MEASURED TOTAL`.
- Confirmed a real MD5 attack prints exactly two full status pages, starting
  with `Running` and ending with `Cracked`, while `--quiet` prints neither.

## v7.1.2-shooter.20260816.48

Standard-edition simplification release.

### Removed

- Removed the standalone `shooterctl` companion from standard
  `shooter_hashcat`, including its Rust source, default build target, CI checks,
  prebuilt executable, package requirement, SBOM entry, and current companion
  documentation.
- Removed companion-only claims for doctor/support bundles, rule reports,
  persistent line indexes, streaming pipelines, target manifests, adaptive GPU
  fleets, and local mode discovery from the standard feature inventory.

### Unchanged

- `hashcat.exe` does not link to or launch `shooterctl`, so the cracking engine
  and its native Shooter features are unchanged.
- Native stage profiling, automatic error reports, release SBOMs, and signed
  public-release attestations remain part of standard `shooter_hashcat`.

### Verified

- Built and validated the complete production Windows x64 archive without a
  `shooterctl` executable or source tree.
- Confirmed the packaged `hashcat.exe` reports this exact release version.

## v7.1.2-shooter.20260816.47

Immediate minute-rate and shorter interactive-prompt release.

### Changed

- `Recovered/Time` now reports numeric current and average minute values from
  the first status update instead of showing `N/A` for the first minute.
- The interactive outfile-directory command is now labeled
  `[i]gnore outfile`; its `i` key and `--outfile-check-dir` behavior are
  unchanged.
- Updated the README, complete feature inventory, change summary, and release
  notes to describe both changes.

### Verified

- Built the complete production Windows x64 program and module set.
- Confirmed live status output reports numeric minute values before 60 seconds.
- Confirmed active outfile-check prompts display `[i]gnore outfile`.

## v7.1.2-shooter.20260816.46

Consistent status-visibility release.

### Changed

- Normal human-readable status now always includes `Remaining` and
  `Recovered/Time`, including for jobs with 1,000 or fewer digests.
- Early recovery-rate windows remain explicit as `N/A`; minute, hour, and day
  values appear as enough run time becomes available.
- Documented the status guarantee and its scope in the README and complete
  Shooter feature inventory.

### Verified

- Built the production Windows x64 frontend and confirmed its version is
  `v7.1.2-shooter.20260816.46`.
- Confirmed a one-digest job includes both status lines in its final display.

## v7.1.2-shooter.20260815.45

Large-wordlist indexing and feed-throughput release.

### Changed

- Large wordlists now build their first-use seek database with up to 64 CPU
  workers and SIMD newline counting instead of one function call per line.
  The new byte-spaced `SHSEEK01` format is smaller, supports direct seeks, and
  continues to load existing line-spaced seek databases.
- The regular wordlist feed caches its selected line scanner and bypasses the
  full transform pipeline for ordinary candidates when autohex is the only
  possible transformation. Valid `$HEX[...]` candidates and every configured
  rule, encoding, hexadecimal, or uppercase transformation retain the full
  path.
- Renamed the README feature-list heading so visitors can immediately see
  that it compares Shooter with the original Hashcat baseline.

## v7.1.2-shooter.20260815.44

Release-attestation follow-up for the `.43` clean-runner build.

- Resolve and validate the single archive and SPDX SBOM after packaging, then
  pass their exact paths to GitHub's provenance, SBOM, and upload actions.

## v7.1.2-shooter.20260815.43

Clean-runner Rust setup follow-up for the `.42` reliability fixes.

- Preinstall the `rust-src` component in the same serialized Make prerequisite
  as the Windows GNU target, preventing parallel proc-macro builds from racing
  during Rust's first-use component installation.

## v7.1.2-shooter.20260815.42

Release-build reliability follow-up for the `.41` feature set.

- Serialized Windows Rust target setup so parallel clean builds cannot race
  while Rust is installing `rust-src`.
- Made the Rust formatting workflow honor each crate's declared edition,
  including the Rust 2024 `shooterctl` crate.
- Hardened tokenizer bounds handling for truncated configured-length fields,
  zero-length intermediate fields, and missing diagnostic snippet buffers.

## v7.1.2-shooter.20260815.41

The twelve-part reliability, observability, large-input, automation, fleet,
and release-security upgrade.

### Added

- The included, dependency-free `shooterctl` companion provides installation
  checks, privacy-limited support bundles, target manifests, rule reports,
  persistent line indexes, streaming, direct pipelines, multi-GPU fleet
  scheduling, and local hash-mode discovery.
- `shooterctl doctor` (also accepted as `shooterctl --doctor`) checks the
  executable, runtime directories, backend probe, and optional zstd support.
  `support-bundle` records those results without collecting hashes,
  candidates, potfiles, environment values, or command lines.
- `--stage-profile` and `--stage-profile-json` report pipeline-stage time,
  launch counts, and process peak memory in human-readable or stable
  `shooter-stage-profile-v1` JSON form.
- Existing records in `--outfile-check-dir` are now applied before bitmap
  creation, candidate-source setup, attack-kernel initialization, autotune,
  and attack-specific GPU and host-memory allocation. An all-found job exits
  at that point; a partial match sends only the remaining hashes to cracking.
- `shooterctl rule-report` (also accepted as `--rule-report`) inspects enormous
  rule sets with bounded memory, supports skip/limit ranges, recognizes
  multibyte content, and estimates duplicates. Manifest plans run multiple
  rule files sequentially instead of multiplying them together.
- `.hcidx` persistent indexes store sparse line offsets, source identity, and
  counts. Seekable streaming resumes use a matching index to jump close to the
  requested line instead of scanning from byte zero.
- Streaming accepts partial files, standard input, and zstd input, with line
  ranges, explicit progress counts, and source-position checkpoints. The
  pipeline command directly connects a Hashcat candidate producer to a
  cracking consumer without a shell or temporary candidate file.
- Versioned `shooter-target-v1` JSON manifests can be created directly or
  imported from existing Hashcat arguments, reviewed, planned, and run.
- Fleet mode distributes manifest work from a shared queue across up to 12 or
  more selected GPUs. It reassigns finished work, retries failed chunks,
  quarantines repeatedly failing devices, and writes JSON Lines telemetry.
- Installed standard and mdxfind hash modes can be searched, explained, or
  identified locally through `shooterctl mode`.
- Release packages contain an SPDX 2.3 SBOM. GitHub release workflows create
  cryptographically verifiable provenance and SBOM attestations for the one
  complete Windows archive.
- Linux Clang AddressSanitizer, UndefinedBehaviorSanitizer, and coverage-guided
  parser fuzzing run in CI and retain reproducing inputs after failures.

### Changed

- Merged official upstream Hashcat changes through commit
  `eba388d2ef8d2dc6f184cb2effdc1a99493d888d`, including shared parser/core
  refactoring and newer correctness and security fixes.
- Windows and Linux builds now include `shooterctl`; the complete Windows
  package treats it as a required prebuilt program.
- Renamed the final goodbye-summary label from `Total Time` to
  `Total Run Time` so its start-to-stop elapsed duration is immediately clear.
- The outfile-check preflight hands its file offsets to the normal live
  watcher, preventing an unchanged large result file from being reread
  immediately when some hashes still need cracking. The feature remains
  disabled when `--outfile-check-timer=0` or the selected module disables
  outfile checking.
- Replaced developer-specific absolute paths in public documentation with
  portable commands and clearly marked placeholder paths.

### Security

- Fixed an out-of-bounds read when the CPU rule parser receives a truncated
  character-class rule.
- Release archives can be checked against both their internal SHA-256 manifest
  and GitHub's signed build-provenance/SBOM attestations.

### Verified

- A clean portable Windows x64 production build completed successfully.
- The full no-device module/package suite passed all 1,601 module tests.
- Stage-profile JSON, rule reporting, indexing/resume, manifests, mode lookup,
  streaming, direct pipelines, doctor/support-bundle privacy, and SPDX output
  were exercised locally.
- A live GPU mask run with no recovered hashes confirmed that the paired
  bypass options stop the current queue entry after the configured window.
- Unsalted MD5 all-found and salted mode-10 all-found fixtures exited before
  bitmap, kernel, autotune, GPU attack-buffer, and host staging allocation. A
  mixed MD5 fixture removed one outfile result, initialized cracking only for
  the remaining digest, and recovered it normally. A timer-zero control run
  skipped the preflight and retained the original cracking behavior. A bare
  hash record was recognized, and `--remove` correctly rewrote an all-found
  target file to empty. The touched core sources also passed a Linux GCC
  syntax check.

## v7.1.2-shooter.20260815.40

Automatic support reports for easier troubleshooting, together with the
project-wide `shooter_hashcat` rename and public-documentation cleanup made
after the previous release.

### Added

- The first error sent through Hashcat's normal logger automatically creates
  one `shooter_hashcat-error-YYYYMMDD-HHMMSS-PID.log` file in the directory
  where the program was started. No new option is required.
- The report keeps every normal error from that process, all warnings emitted
  after the first error, and up to 64 recent warnings from before the error.
  This preserves preceding diagnostics such as `Hash parsing error` without
  creating files for successful or warning-only runs.
- Reports include timestamps, exact Shooter version, operating system,
  architecture, process ID, working directory, and bounded command-line
  arguments. Both forms of `--brain-password` are automatically redacted.
- A Windows-and-Linux CI regression verifies report creation, console path
  output, version/platform context, both password-redaction forms, the actual
  command-line error, and the absence of a report after a successful command.

### Changed

- Renamed the project and repository to `shooter_hashcat`, including clone
  URLs, example paths, generated help, release titles, packaging identifiers,
  and repository-local toolchain paths.
- Future complete Windows archives use the
  `shooter_hashcat-<version>-windows-x64-complete.7z` name.
- The optional fast-start and host-staging environment variables are now
  `SHOOTER_HASHCAT_FAST_START` and `SHOOTER_HASHCAT_HOST_STAGING_MB`.
- Removed public contest-specific guides, labels, credits, and generated
  documentation entries while retaining the underlying compatibility modules
  in the source tree.
- Command-line option parsing and several first-party allocation, network,
  session, and potfile-search failures now use the shared error logger so they
  are included in the automatic report instead of appearing only on stderr.

### Privacy and limitations

- Reports never attach input or output files. Normal diagnostics can quote an
  individual malformed hash, rule, or other input line, and arguments can
  contain private paths or values, so users are told to review the report
  before sharing it.
- A process killed by the operating system, a power loss, a crash before the
  logger is initialized, or an unwritable starting directory can prevent the
  report from being created or completed.

### Verified

- A portable Windows x64 production build completed and reported
  `v7.1.2-shooter.20260815.40`.
- An invalid-option regression created exactly one report, printed its path,
  included the expected error and environment context, redacted both supported
  brain-password forms, and left both secret values absent from the file.
- A malformed MD5 command-line hash placed the preceding parse warning and
  final `No hashes loaded` error in the same report.
- A successful `--version` command created no report. The report sources also
  compiled warning-free with the Linux GCC headers and feature configuration.

## v7.1.2-shooter.20260815.39

Faster `--show` and `--left` processing for very large hash lists and
potfiles, a clearer outfile-check command, and a repaired Linux build.

### Changed

- The interactive outfile-directory command is now
  `[i]gnore outfile` and uses the `i` key in every active and paused
  prompt.
- Large unsalted lists build a compact 16-bit range index so normal potfile
  entries are searched within a narrow slice of the sorted hash array.
- Salted modes locate the matching salt group first and search only that
  group's digests. Custom potfile validators and special keep-all-hashes jobs
  retain their existing paths.
- When `-o` is open, `--show` and `--left` no longer allocate, sort, and free a
  redundant in-memory copy of results that the stdout event handler will not
  consume.

### Fixed

- The mdxfind bridge's bundled static libraries are now compiled as
  position-independent code. Linux static and shared builds can link
  `bridge_mdxfind.so` instead of failing on `librhash.a` relocations.
- The privately linked mhash code no longer declares internal functions as
  Windows DLL exports, avoiding Clang's conflicting `dllexport` declaration
  errors in the supported-platform CI build.
- The primary build matrix now covers Shooter's supported Linux and Windows
  targets. The redundant combined cross-build and inherited macOS and BSD
  jobs were removed instead of presenting incomplete or unverified mdxfind
  targets as supported.
- The Linux build documentation now points to this repository and lists the
  compiler, OpenSSL, Python, and current stable Rust prerequisites needed by
  Shooter's additional bridges and feeds.
- The generated command-help and example-hash pages now include the current
  Shooter options and complete mode inventory. CI verifies those files are
  current instead of trying to push an unrequested bot commit from a
  read-only build job.

### Measured and verified

- On the supplied 84,381,739-entry mode-0 list and 41,948,260-byte potfile,
  `--left -o NUL` fell from 105.501 to 18.637 seconds: 5.66 times faster and
  82.3% less total process time.
- Alternating warm-cache `--show -o NUL` runs improved from 13.02/14.90
  seconds to 12.74/14.47 seconds. Hash parsing remains most of that runtime.
- The real 296,078-byte `--show` output was byte-identical to the previous
  release. Separate unsalted MD5 and salted mode-10 fixtures produced
  byte-identical `--show` and `--left` files.
- A live 12-GPU session displayed `[i]gnore outfile`; pressing `i`
  printed `Ignoring --outfile-check-dir for the rest of this run.` and the
  command disappeared from the next prompt.
- Clean Ubuntu 24.04 Clang builds completed with both `SHARED=0` and
  `SHARED=1`; the resulting executable and `bridge_mdxfind.so` were verified
  as x86-64 ELF binaries and the executable reported this release version.

## v7.1.2-shooter.20260815.38

Portable Windows release binaries, plus the large-rule and status improvements
introduced in the superseded `.37` build.

### Includes

- Huge plain rule files load across up to 64 CPU workers for every
  rule-capable hash algorithm.
- Per-device `Restore.Sub` status rows are hidden by default and can be shown
  with `--status-restore-sub`.

### Fixed

- The repository-local Windows wrapper and GitHub release workflow now build
  for the standard x64 instruction baseline instead of the build runner's CPU.
  This prevents a downloaded executable from terminating with Windows error
  `0xC000001D` (illegal instruction) on a different x64 processor.
- Rust bridge and feed DLLs now honor `MAINTAINER_MODE=1`, matching the portable
  C and C++ build instead of retaining `target-cpu=native`.
- GitHub release descriptions now include the matching version's complete
  changelog entry above the download and verification instructions.

### Verified

- A clean Windows rebuild completed with no `-march=native`, `-mtune=native`,
  `target-cpu=native`, or hard-coded AVX2 flags in the release build paths.
- The portable executable reports `v7.1.2-shooter.20260815.38`, exposes
  `--status-restore-sub`, and accepts the literal multibyte mask
  `?d?d№?d?d№?d?d№` on the Windows command line.
- The clean build produced all 1,601 module DLLs, seven bridge DLLs, and five
  feed DLLs.

## v7.1.2-shooter.20260815.37

Faster loading for very large rule files and cleaner multi-GPU status. This
build is superseded by `.38`, which rebuilds the same changes for portable x64.

### Added

- Plain rule files of at least 16 MiB are counted, validated, and compiled
  with up to 64 CPU workers. The shared loader benefits every rule-capable
  hash algorithm and preserves file order and warning order.
- `HASHCAT_RULE_PARSE_PARALLEL_DISABLE=1` forces the optimized serial path for
  comparison. `HASHCAT_RULE_PARSE_PARALLEL_MIN` changes the activation byte
  threshold for focused testing.
- Per-device `Restore.Sub` rows are now hidden from human-readable status by
  default. `--status-restore-sub` restores the original salt, amplifier, and
  iteration rows for manual, timed, and final status displays.

### Changed

- Ordinary rule validation no longer performs one heap allocation and free
  per line. Unusually long rules retain a heap fallback.
- Serial rule storage grows geometrically instead of by fixed 10,000-rule
  increments.
- A single `-r` file now returns its compiled buffer directly instead of
  allocating and copying a second complete array. Temporary per-file buffers
  are released after multi-file rule chaining.
- Compressed rule files and unusual inputs retain the original streaming
  behavior.

### Measured and verified

- The supplied 63,758,579-byte file containing 4,902,480 rules loaded in a
  seven-run median of 0.140 seconds, versus 26.235 seconds with the pre-change
  binary. The optimized serial fallback's median was 0.872 seconds.
- Applying the complete file through the parallel and forced-serial paths
  produced byte-identical 53,502,267-byte output with SHA-256
  `B10A2FA49C7C5E27E98BF41A6567C1A708D80F9C543DF0E380B804BCA2A9A18C`.
- Matching output and diagnostics were verified for invalid rules, UTF-8 BOM,
  CRLF, comments, blank lines, a final line without a newline, and chained
  rule files. A Windows production build and a one-GPU rule-loading smoke
  session completed successfully.
- Identical 12-GPU runtime-limited status tests emitted zero `Restore.Sub`
  rows by default and exactly rows `#01` through `#12` with
  `--status-restore-sub`. `Restore.Point` and the remaining status fields were
  still present in both outputs.

## v7.1.2-shooter.20260814.36

Reproducible complete Windows release versioning.

### Fixed

- Pinned the source tree's default production date and revision instead of
  deriving the release date from the build machine's local clock. Tagged
  builds, later source rebuilds, `hashcat.exe --version`, the package folder,
  and the archive filename now retain one identical version across time zones.
- Added an expected-version gate to `package-windows.ps1`. The release
  workflow passes its tag to this gate and refuses to upload or publish an
  archive whose executable version does not exactly match the tag.
- Superseded `.35`, whose first GitHub-hosted build crossed midnight UTC and
  consequently stamped its asset as `20260815.35` despite the `20260814.35`
  tag.

### Verified

- Repeated a clean source build and complete package validation with the
  pinned `.36` version before publication.
- The tag-triggered Windows workflow independently clean-builds all binaries,
  verifies the internal manifest and 7-Zip archive, and publishes exactly one
  `.7z` release asset.

## v7.1.2-shooter.20260814.35

Complete source and prebuilt Windows release archives.

### Added

- Added `package-windows.ps1`, a release packager that clean-builds by
  default, exports only committed source files, and overlays the ready-to-run
  Windows executable, all 1,601 module DLLs, bridge/feed DLLs, and required
  MinGW runtime DLLs.
- The package records its version, source commit, build counts, prerequisites,
  and rebuild commands in `BUILD-INFO.txt`. An internal `SHA256SUMS` manifest
  covers every other source and binary file.
- Added `verify-windows-package.ps1` so recipients can validate the complete
  extracted tree without installing another checksum utility.
- Added a tag-triggered GitHub Actions workflow that performs a clean Windows
  production build and publishes exactly one versioned
  `shooter_hashcat-<version>-windows-x64-complete.7z` release asset. Its
  SHA-256 is recorded in the
  release notes rather than adding a second asset.
- Added 7-Zip to the repository-local Windows toolchain bootstrap and exposed
  the same packaging flow for local maintainers.

### Package contents and prerequisites

- The archive is both a complete source distribution and a runnable Windows
  x64 distribution. No Git checkout is required to run or rebuild it.
- Rebuilding uses the included `build-windows.ps1`. Its first run downloads
  the checksum-pinned MSYS2 base and required packages into a local
  `.build-tools` cache, so it requires internet access and at least 5 GB of
  free disk space. The approximately 4 GB compiler cache is intentionally not
  embedded in every release asset.
- GPU vendor drivers remain external runtime prerequisites and are not
  redistributable as part of the archive.

### Verified

- Completed the package script's source/module completeness checks, internal
  manifest verification, and `7z t` archive-integrity test.
- Extracted the finished archive into a clean directory, reverified every
  manifest entry, loaded mode 0, and ran the packaged executable's self-test
  and UTF-8 mask smoke checks.
- Rebuilt the extracted source with the documented command and confirmed the
  resulting executable reports `v7.1.2-shooter.20260814.35`.

## v7.1.2-shooter.20260814.34

UTF-8 literal masks on Windows.

### Fixed

- Preserved native UTF-8 command-line masks containing `?d` or other mask
  tokens. MinGW's wildcard compatibility previously made Hashcat retain its
  ANSI `argv` whenever it saw `?`, replacing characters outside the active
  code page with `?` before mask parsing.
- Distinguished a real MinGW filesystem-wildcard expansion from a lossy ANSI
  conversion by comparing the CRT argument with the original wide argument's
  expected ANSI representation. Existing wildcard argument expansion remains
  enabled.
- The fix is in the shared Windows command-line path and therefore applies to
  every algorithm and mask-capable attack mode. Literal Unicode characters
  continue to expand to their UTF-8 bytes in Hashcat's byte-oriented mask
  engine; `--hex-charset` behavior is unchanged.

### Verified

- Completed a clean Windows production rebuild through the repository's
  self-bootstrapping `build-windows.ps1` entry point; the resulting executable
  reports `v7.1.2-shooter.20260814.34`.
- Passed the literal command-line mask `?d?d№?d?d№?d?d№` through the Windows
  UTF-8 path and confirmed candidates contain the exact `e2 84 96` byte
  sequence at all three literal positions.
- Rechecked two-, three-, and four-byte literals and both single- and
  multi-match wildcard expansion.

## v7.1.2-shooter.20260814.33

Parallel large-list parsing for compatible text hash modes.

### Added

- Generalized the memory-mapped large-list loader from mode 0 to native text
  hash formats. Each worker invokes the selected module's own decoder, so raw,
  salted, embedded-salt, extended-salt, hook-salt, original-hash-copy, and
  compatible postprocess modes retain their format-specific behavior.
- Mode 0 keeps the direct MD5 decoder introduced in `.32`.
- Inputs with at least 4,194,304 nonempty hashes use up to 64 CPU workers.
  Empty LF/CRLF lines are skipped as before. Malformed input automatically
  reruns through the original sequential parser so warnings and recovery
  behavior are preserved.
- Required binary containers, split-hash formats, non-native hash-list
  formats, compressed/BOM inputs, username/dynamic parsing, association
  autosplit, and postprocessors using external keyfiles or keyboard maps keep
  the original loader. Optional-binary modes can use the parallel path when
  their input is native text.
- Set `HASHCAT_HASH_PARSE_PARALLEL_DISABLE=1` to force the original loader.
  `HASHCAT_HASH_PARSE_MD5_DISABLE=1` remains a mode-0-compatible alias.
  `HASHCAT_HASH_PARSE_PARALLEL_MIN` can lower the activation count for focused
  testing and benchmarking.

### Measured and verified

- A 4,194,304-entry SHA-1 fixture (171.97 MB) completed `--left` in 0.57
  seconds versus 1.49 seconds with the original parser, a 61.7% reduction.
- A 4,194,304-entry salted mode-10 fixture (169.87 MB) completed `--left` in
  1.36 seconds versus 2.48 seconds, a 45.2% reduction.
- Mode 0 retained identical output and completed the 4,194,304-line regression
  fixture in 0.58 seconds versus 1.39 seconds with the original parser.
- BOM-free two-worker fixtures were compared with the forced original parser
  across all 854 modes exposing usable self-test examples. All 814 examples
  that loaded successfully matched. Another 39 failed identically because
  they require special files or options. Mode 32500 was excluded from output
  comparison because its encoder produces nondeterministic trailing bytes in
  repeated original-parser runs.
- Representative SHA-1, SHA-256, NTLM, salted MD5, and bcrypt fixtures with
  mixed LF/CRLF endings and an empty line produced identical output. Malformed
  MD5 and SHA-1 fixtures also produced identical automatic-fallback warnings
  and output.

## v7.1.2-shooter.20260814.32

Faster startup for very large plain MD5 hash lists.

### Added

- Plain native-format mode-0 lists with at least 4,194,304 hashes now use a
  memory-mapped parallel validation and decode path with up to 64 CPU workers.
- Empty lines retain the original parser's skip behavior. Compressed files,
  byte-order-marked files, non-native formats, malformed nonempty lines, and
  inputs needing username, dynamic, or original-hash metadata automatically
  retain the original line-by-line parser.
- Set `HASHCAT_HASH_PARSE_MD5_DISABLE=1` to force the original parser for an
  A/B test.

### Measured and verified

- On the intended Threadripper PRO 5995WX system, the supplied 2.87 GB file
  contained 84,381,740 physical lines, one empty line, and 84,381,739 MD5
  hashes. Parse plus sort fell from 33.56 seconds to 6.41 seconds, an 80.9%
  reduction. Preprocessing through duplicate removal fell from 48.12 seconds
  to 11.28 seconds, a 76.6% reduction.
- A 4,194,304-line mixed-LF/CRLF fixture produced byte-for-byte identical
  `--left` output with the original parser, the parallel parser, and the
  forced-fallback path. The complete supplied list retained the expected
  84,381,739 digest count after duplicate removal.

## v7.1.2-shooter.20260814.31

Native UTF-8 literal rules and reliable Windows loopback induction.

### Added

- Added native UTF-8 literals for the byte-emitting `$`, `^`, `i`, `v`, and
  `o` rule functions. Two-, three-, and four-byte UTF-8 characters are
  compiled into the equivalent existing byte instructions on both host and
  GPU rule paths.
- Accepted an optional UTF-8 BOM at the start of rule files and converted the
  native Windows wide command line to UTF-8 so literal `-j` and `-k` rules and
  Unicode paths reach the parser without ANSI code-page loss.
- Added `multibyte-test.rule` with 26 ready-to-run examples covering two-,
  three-, and four-byte UTF-8 operands, each supported emitting function, and
  chained rules.

### Compatibility

- Existing ASCII and `\xNN` rules are unchanged. Rule positions and all other
  transforms remain byte-oriented; this does not make case conversion,
  deletion, replacement, purge, or rejection Unicode-code-point operations.

### Fixed

- Closed per-round wordlist feeds before deleting consumed loopback induction
  files. Windows previously kept those files memory-mapped, so deletion failed
  silently and `--loopback` rediscovered the same files indefinitely.
- Made induction cleanup report and stop on deletion errors, release scan
  allocations between generations, remove unneeded files when every hash is
  cracked, and preserve the active induction file on abort or quit.

### Verified

- Completed a full Windows production build and confirmed the executable
  reports `v7.1.2-shooter.20260814.31`.
- Confirmed literal two-, three-, and four-byte operands on host and GPU rule
  paths, UTF-8 BOM input, Windows inline rules, legacy `\xNN` rules, and the
  existing Windows wildcard expansion behavior.
- Ran bounded ASCII (`seed` to `seed111`) and UTF-8 (`test` to `testééé`)
  loopback cascades. Both recovered three generations, exited normally, and
  left zero files in their induction directories.

## v7.1.2-shooter.20260814.30

Self-contained Windows build bootstrap for fresh clones.

### Added

- Added `build-windows.ps1`, a one-command PowerShell build entry point that
  downloads a checksum-verified official MSYS2 base into the repository's
  ignored `.build-tools` cache and performs the required full MSYS2 upgrade.
- Installed the complete repo-local Windows dependency set: GCC, Clang/LLVM,
  LLD, Rust, Make, Git, OpenSSL, and iconv. Nothing is installed into Windows
  and the system `PATH` is not changed.
- Added `Build`, `Rebuild`, and `Clean` actions, configurable parallel jobs,
  and an explicit toolchain-update option.

### Fixed

- Selected Rust's `x86_64-pc-windows-gnu` toolchain explicitly and kept its
  Cargo and rustup state inside the local MSYS2 tree. This avoids accidentally
  selecting the incompatible MSVC ABI or relying on a developer's global Rust
  installation.
- Invoked the stable Cargo toolchain directly and ordered MinGW ahead of Rust
  runtime DLLs so bindgen can load the repo-local `libclang.dll` and build the
  Rust bridges reliably.
- Copied the required MinGW runtime DLLs beside `hashcat.exe` after a build and
  made that operation safe when an identical DLL is temporarily locked by an
  endpoint-security product or another process.
- Updated the manual MSYS2 dependency list to match the wrapper and documented
  disk-space, execution-policy, and endpoint-security considerations.

### Verified

- Bootstrapped the toolchain from an absent `.build-tools` directory using
  only the files and commands documented in the repository.
- Completed a clean Windows production rebuild of the C core, modules,
  mdxfind bridge, Rust bridge DLLs, and Rust feed using the target-local
  toolchain.
- Confirmed the resulting executable reports
  `v7.1.2-shooter.20260814.30`.

## v7.1.2-shooter.20260814.29

High-throughput cracked-result streaming for very large result sets.

### Optimized

- Changed cracked-result outfile handling from one Windows
  open/lock/write/close cycle per result to bounded batches of 4,096 results.
  Full stdio buffers continue to reach `-o` while a batch is active, and each
  bounded batch is explicitly flushed and closed so the outfile remains a
  live stream and can still be moved or rotated during a run.
- Batched potfile locking and flushing over the same result windows and
  replaced formatted string output with length-aware writes. The potfile is
  still flushed at every batch boundary.
- Reconstructed cracked plaintexts from the retained host candidate batch
  that was uploaded for the active launch. This removes two device-to-host
  copies and two backend stream synchronizations per cracked result while
  preserving the device fallback used outside an active pipeline batch.
- Stopped shifting the ten-entry general event history for every cracked
  result. Event consumers still receive every cracked-result callback.

### Verified

- Rebuilt the Windows production executable and confirmed it reports
  `v7.1.2-shooter.20260814.29`.
- On one RTX 4090, a controlled mode-0 workload where all 100,000 candidates
  crack completed in 7.447 seconds and streamed all 100,000 lines to both the
  outfile and potfile. The previous executable produced only 1,757 lines in
  roughly 47 seconds before the baseline was stopped, an observed result-rate
  improvement of about 360x on this I/O-bound case.
- Recomputed MD5 for every emitted pair and confirmed 100,000 valid, unique
  lines with no missing, duplicate, or invalid results. Outfile and potfile
  content were byte-identical within the run.
- Confirmed plaintext reconstruction with straight rules, combinator,
  hybrid, and `--slow-candidates` attacks, and confirmed output with
  `--outfile-check-dir` enabled.

## v7.1.2-shooter.20260814.28

Portable Windows build setup for fresh third-party clones.

### Fixed

- Declared the `mingw-w64-x86_64-openssl` build dependency required by the
  mdxfind bridge in both Windows build guides and the GitHub Actions MSYS2
  environment. This resolves clean-build failures for missing
  `openssl/des.h`, `openssl/sha.h`, and the static crypto library.
- Replaced machine-specific absolute paths with reusable MSYS2 and PowerShell
  instructions that work with repositories on any drive.
- Corrected the MSYS2 guide to clone `Shooter3k/shooter_hashcat` instead of
  upstream hashcat, and corrected the documented MinGW runtime DLL name and
  location.
- Documented that OpenSSL is statically linked into the Windows mdxfind
  bridge, so the development package is required to build but no separate
  OpenSSL runtime DLL is required by the release package.

### Verified

- Rebuilt the Windows production executable and confirmed it reports
  `v7.1.2-shooter.20260814.28`.
- Confirmed the documented MSYS2 OpenSSL package exists and supplies the
  headers and static archive used by the bridge.
- Exercised the documented PowerShell-to-MSYS path conversion against a
  repository on a non-system drive.
- Confirmed the existing `bridge_mdxfind.dll` target is current and ran
  `git diff --check` successfully.

## v7.1.2-shooter.20260813.25

Visible Pure Kernel selection in the interactive status display.

### Added

- The complete `Kernel.Feature...: Pure Kernel (password length ... bytes)`
  status line is now rendered in bright yellow in interactive Windows
  consoles and ANSI-capable terminals.
- Optimized Kernel lines retain the normal status color, so the highlight
  specifically identifies use of a Pure Kernel.
- Color is applied only by the interactive renderer. Redirected output,
  logs, API event text, and machine-readable consumers receive the original
  plain status line without escape sequences or a changed event severity.

### Verified

- Rebuilt the Windows production executable as
  `v7.1.2-shooter.20260813.25`.
- Confirmed a CUDA `e355` run selects and reports the Pure Kernel path and
  cracks its known-answer vector.
- Confirmed an optimized CUDA MD5 control run selects and reports the
  Optimized Kernel path and cracks its known-answer vector.
- Captured the Pure Kernel status through redirected output and confirmed it
  contains zero escape bytes.

## v7.1.2-shooter.20260813.24

Documentation and release packaging for the completed mdxfind module
verification.

### Updated

- Added the aggregate validation result to the README: all 988 published
  Hashpipe examples and all 11 additional standalone known-answer vectors
  cracked successfully on CUDA, covering 999/999 self-contained hash modes.
- Clarified that `e426` is an mdxfind scheduler pseudo-entry rather than a
  hash, while `e535` requires external mdxfind custom-user/salt state and has
  no published standalone test vector.
- Advanced the production build identity to
  `v7.1.2-shooter.20260813.24` and repackaged the verified implementation with
  the updated README and changelog.

## v7.1.2-shooter.20260813.23

Complete functional verification for the mdxfind named-module layer.

### Fixed

- Replaced the incomplete compatibility-expression path with Hashpipe's
  tested in-process verifier implementations, retaining mdxfind's expression
  VM as a fallback. The bridge remains self-contained and launches no helper
  process.
- Routed 38 `eN` wrappers away from similarly named numeric hashcat modes
  whose parser or exact computation differs from mdxfind. Existing numeric
  hashcat modules remain unchanged.
- Added mdxfind `$HEX[...]` binary-salt decoding, the two capitalization steps
  required by `e355`, and compatibility with the documented 16-byte `e539`
  MYSQL5MD5 prefix.
- Expanded bridge results to preserve complete long-form targets such as
  `e943` WPA-EAPOL records. A new comparison-kernel ID prevents stale CUDA
  cache entries from using the previous temporary-buffer layout.
- Updated `e942` to the current hashcat mode 22000 WPA parser instead of the
  deprecated mode 16800 path.
- Made the vendored mhash integer-size configuration portable across Windows
  LLP64 and Unix LP64 builds and included the upstream license notices.

### Coverage

- The generated inventory now uses 264 isolated wrappers around exactly
  compatible numeric hashcat modes and 737 mdxfind compatibility-bridge
  modules.
- `e426` (`PARALLEL`) is an mdxfind scheduler pseudo-entry rather than a hash
  algorithm. `e535` (`SHA1-CUSTOMUSERSALT`) depends on mdxfind's external
  custom-user/salt state and has no published standalone test vector. Both
  names remain present without being redirected to an incorrect algorithm.

### Verified

- Forced a complete Windows production rebuild, including all 1,001 `eN`
  module DLLs, the bridge, its static dependency archives, and the new CUDA
  comparison kernel. The executable reports
  `v7.1.2-shooter.20260813.23`.
- Ran every one of the 988 test hashes in Hashpipe's `HASH_TYPES.md` as an
  independent CUDA straight-attack known-answer test. All 988 recovered the
  documented password with no initialization failures, parse errors,
  exhaustions, or timeouts.
- Re-ran the six edge vectors that exposed defects (`e283`, `e348`, `e349`,
  `e355`, `e539`, and `e943`) after rebuilding; all six passed on CUDA.
- Added direct CUDA known-answer runs for the four standalone pre-995 entries
  omitted from `HASH_TYPES.md` (`e429`, `e432`, `e433`, and `e676`) and for
  every post-document mode `e995` through `e1001`; all eleven passed. Together
  with the 988 documented vectors, this exercises all 999 standalone hash
  modes in the 1,001-entry registry.

## v7.1.2-shooter.20260813.22

Magento input compatibility for mdxfind `e987` Argon2.

### Fixed

- `e987` now accepts both standard `$argon2...` PHC strings and mdxfind's
  Magento `hex_digest:salt:2` /
  `hex_digest:salt:3_digest_length_iterations_memory_bytes` forms.
- Magento inputs are converted to hashcat mode 34000 parameters internally
  using mdxfind's version-19, single-lane, first-16-salt-character rules.
- The original Magento hash line is retained for potfiles, `--show`, `--left`,
  and cracked-output files rather than being replaced with the internal PHC
  representation.
- The module generator now records specialized compatibility aliases so
  regenerating all 1,001 wrappers preserves the `e987` parser.

### Verified

- Parsed all 31,161 hashes in the supplied Magento `e987` file with zero
  errors and confirmed `--left` returned every original line unchanged.
- Completed an `e987` benchmark with the CUDA backend across all 12 detected
  RTX 4090 devices. `-O` correctly reports that no optimized Argon2 kernel is
  required and uses `m34000-pure.cl`.
- Confirmed standard Argon2 PHC input and the existing numeric mode 34000
  remain unchanged.

## v7.1.2-shooter.20260813.21

Consistent public `eN` names throughout the hashcat interface.

### Fixed

- `-hh` now lists all 1,001 mdxfind modes as `e1` through `e1001` instead of
  exposing their private integer representations.
- `-H`, `-HH`, example-hash output, runtime status, benchmark headings and
  machine-readable rows, autodetect results, diagnostics, source-module hints,
  and session logs now use the same public `eN` spelling.
- The main help table now describes `-m` as a mode and includes `-m e987` as
  an example. Existing numeric modes keep their original output unchanged.

### Verified

- Confirmed `-hh` contains exactly 1,001 named rows and maps representative
  entries to `e1`, `e987`, and `e1001` without exposing `90001`
  through `91001` as public mode values.
- Confirmed human-readable and JSON hash information report `e987`, while
  representative numeric modes retain their original numeric identifiers.

## v7.1.2-shooter.20260813.20

Named hashcat modules for the complete mdxfind algorithm registry.

### Added

- Added `module_e1` through `module_e1001`, matching every live algorithm name
  in mdxfind's `Types[]` registry. Hashcat now accepts names such as `-m e987`
  and loads the corresponding `module_e987` plugin.
- Kept every existing numeric hashcat module unchanged. The generated layer
  uses 302 isolated aliases to compatible hashcat modules and 699 isolated
  front ends for mdxfind's checked-in expression VM.
- Added the native `bridge_mdxfind` CPU evaluator and a small OpenCL comparison
  kernel. The bridge is self-contained in the Windows package and does not
  require a separate OpenSSL runtime DLL.
- Added `tools/generate_mdxfind_modules.py`, which reads mdxfind's live
  `Types[]` and `Maphashcat[]` tables rather than the potentially older prose
  list, plus `docs/mdxfind-modules.json` as the complete generated inventory.

### Compatibility and diagnostics

- Existing numeric `-m` values and numeric module filenames retain their
  original parsing and loading behavior.
- Mapped algorithms retain the original hashcat parser, self-test, kernel, and
  hash syntax while reporting their mdxfind `eN` name.
- Expression algorithms accept `hash[:salt[:salt2[:pepper[:user]]]]`. If the
  checked-in mdxfind expression table marks an algorithm as an outlier or
  needs a primitive unavailable in this bridge build, startup reports that
  exact limitation instead of selecting a different algorithm.

### Verified

- Production-built representative native aliases `e536` and `e987`, the
  translated expression module `e996`, the mdxfind bridge, and the main
  executable with the MinGW64 toolchain.
- Confirmed `hashcat.exe -m e536 --example-hashes`, `-m e987`, and `-m e996`
  resolve their named module files and report internal names `mdxfind eN ...`.
- Loaded all 1,001 generated modules with `--example-hashes`; every `e1`
  through `e1001` module resolved successfully.
- Confirmed the e996 expression VM produces the independently calculated
  `md5(sha256(sha256("hashcat")))` known answer.

## v7.1.2-shooter.20260812.19

Faster preprocessing for very large unsalted hash lists.

### Added

- Lists with at least 4,194,304 unsalted hashes now use a stable, parallel
  least-significant-digit radix sort with up to 64 CPU workers. The byte-pass
  order exactly matches hashcat's existing digest comparator.
- Smaller lists and all salted lists retain the upstream comparison sorter.
  If scratch allocation is unavailable, the optimized path safely falls back
  to that sorter. Set `HASHCAT_HASH_SORT_RADIX_DISABLE=1` to force the legacy
  path for comparison or troubleshooting.
- If Windows cannot create one of the requested worker threads, that worker's
  range is processed synchronously so no hashes can be omitted.

### Measured and verified

- On the intended 64-core/128-thread Threadripper PRO 5995WX system, the
  supplied 1.33 GB mode-0 list contains about 40.3 million hashes. An identical
  `--left` preprocessing pass took 48.85 seconds with the parallel sorter and
  80.50 seconds with it disabled: 31.65 seconds saved, 39.3% less total time,
  or 1.65x faster overall.
- Parallel and legacy output was byte-for-byte identical on 300,000- and
  2,000,000-hash validation sets. The optimized full 40.3-million-hash pass
  also completed parsing, sorting, duplicate removal, and output successfully.

## v7.1.2-shooter.20260812.18

Official hashcat synchronization through August 12, 2026.

### Integrated from official hashcat

- Merged all twelve official commits after the Shooter baseline
  `fdad9f2f7` through official master `9c735bade`, preserving their commit
  ancestry in the local merge.
- Added official attack mode `12`, the general multi-hybrid mode introduced by
  `554c1207a`. Its mask uses `?w` for the first wordlist and optional `?q` for
  a second wordlist, allowing masks and literals on either side of the words.
- Included official feed-to-device mapping, yescrypt address-space and layout
  fixes, PDF mode 10500 empty-ID support, hash/salt pointer-overflow fixes,
  full-length combinator plaintext/status buffers, and rule-processor
  overflow, double-free, and out-of-bounds fixes.

### Shooter compatibility

- Preserved Shooter's three-or-more-file `-a 1` Cartesian combinator and its
  multi-GPU range seeking, while no-rule two-file `-a 1` now uses the official
  mode-12 alias path.
- Preserved whole-candidate `-r`/`-g` processing for modes `1`, `3`, `6`, and
  `7`. Rule-bearing commands stay on the Shooter paths instead of being
  rewritten to official mode 12.
- Preserved all 12 x RTX 4090 startup, staging, autotune-cache, checkpoint,
  outfile-retry, resumable-stdout, runtime-control, and custom hash-mode work.
- Restored the custom combinator's no-mask update path and host-to-device base
  upload around the upstream multi-hybrid refactor. This prevents a
  three-file `-a 1` access violation and incomplete `--stdout` candidates.
- Restored recovered-plaintext reconstruction for Shooter's multi-file
  combinator, so cracked `-a 1` candidates are written to the outfile instead
  of appearing with an empty plaintext after the upstream refactor.
- Restored the legacy hybrid argument slicing and mask initialization needed
  by Shooter's whole-candidate-rule `-a 6` and `-a 7` paths.
- Kept compatibility mode `67000` on the maintained yescrypt kernel used by
  mode `36100`, matching its documented alias behavior after the upstream
  yescrypt host/kernel layout change.
- Updated the README and `hashcat.exe -h` attack-mode table to identify rule
  support for modes `0`, `1`, `3`, `6`, `7`, `8`, and `9`, with the native
  versus whole-candidate rule behavior documented explicitly.

### Verified

- Built the merged sources with debug symbols while resolving integration
  issues and confirmed the three-file access violation is gone.
- Verified exact candidate sets for official one- and two-wordlist `-a 12`,
  the official no-rule two-file `-a 1` alias, Shooter three-file `-a 1`, and
  Shooter whole-candidate rules on modes `1`, `3`, `6`, and `7`.
- Verified three-file `-a 1` reports keyspace `4`, total candidates `8`, and
  outputs all eight expected candidates in command-line order.
- Verified GPU known-answer cracks for official mode `12`, Shooter multi-file
  and ruled mode `1`, custom modes `29950` and `29951`, yescrypt modes `36100`
  and `67000`, and gost-yescrypt mode `36200`.
- Verified mode `10500` accepts the newly supported empty PDF ID form.

## v7.1.2-shooter.20260812.17

Responsive RTX 4090 tuning for phpBB3 bcrypt-over-phpass modes.

### Fixed

- Modes `29950` and `29951` now cap automatic tuning at `Accel:8` and
  `Loops:8`. The generic staged autotuner measures their inexpensive first
  phpass-MD5 loop, so it previously selected as much as `Accel:488` and
  `Loops:1024` for the much slower bcrypt loop2 stage.
- The oversized selection created roughly 1.5 million bcrypt candidates in a
  single GPU batch on an RTX 4090. Status, `--runtime`, interactive quit, and
  checkpoints could then wait minutes for a launch boundary even though CUDA
  compute was active.
- The tuning-range change is part of the persisted-autotune cache key, so old
  mode-29950/29951 entries are ignored automatically; users do not need to
  delete cache files.

### Measured

- On one RTX 4090 against a real cost-10 record with phpass count character
  `9`, completed-candidate throughput measured 6,485 H/s at `Accel:1`,
  6,799 H/s at `Accel:2`, 6,967 H/s at `Accel:4`, 7,090 H/s at `Accel:8`, and
  7,078 H/s at `Accel:16`. `Accel:8` retained the best measured throughput.
- A twelve-GPU reproduction of the reported command showed 100% CUDA/SM
  utilization on all twelve RTX 4090s. The memory-controller metric remained
  near zero, which is expected for this compute/shared-memory-heavy Blowfish
  workload and is not an idle-GPU measurement.
- The supplied hash file contains 1,853 valid 73-character records and five
  malformed records (four length 70 and one length 71); malformed records
  remain rejected rather than being guessed or silently repaired.

## v7.1.2-shooter.20260812.16 (local source build)

Native GPU support for phpBB3 bcrypt-over-phpass legacy rehashes.

### Added

- Added mode `29950` for `bcrypt(phpass($pass))` hashes stored by phpBB3 in
  their original `$H\2*$...` legacy-rehash form.
- Added mode `29951` for the explicitly selected rare
  `bcrypt(phpass(md5($pass)))` pipeline. The two pipelines are separate modes
  so a candidate is never silently transformed with the wrong construction.
- Both modes accept the original 73-character phpBB form directly and the
  extracted `$2*$...:<count><phpass-salt>` representation. Recovered hashes
  are rendered in the original phpBB form.
- The parser carries the per-hash phpass count character, eight-character
  phpass salt, bcrypt variant, bcrypt cost, 22-character bcrypt salt, and
  31-character bcrypt digest into the normal hashcat salt/digest paths.

### Implementation

- The GPU pipeline uses hashcat's staged slow-hash scheduler: phpass MD5 runs
  in `init/loop`, its 16-byte result is encoded to the 22-character portable
  phpass checksum, and that checksum becomes the bcrypt password for
  `init2/loop2/comp`.
- Only the 22-character phpass checksum is passed to bcrypt; the `$H$`
  signature, count character, and phpass salt are not part of the outer
  bcrypt password.
- The normal and MD5-prehash modes use distinct kernel types and self-tests.
  Both retain standard attack modes, rules, restore, status, outfile, and
  multi-GPU scheduling behavior. `-O` safely falls back to the pure kernel.

### Verified

- Independently recomputed the supplied example: phpass count character `7`
  selects `2^9 = 512` iterations, salt `RsqOrLNk`, and plaintext `123456`
  produce checksum `cmD0qyV8sv/3sGcLRo8D31`.
- Cracked the supplied original hash as `123456` with mode 29950 on CUDA and
  repeated the crack from its extracted representation.
- Independently generated and cracked a mode-29951 test vector for
  `123456`; its inner MD5 text is
  `e10adc3949ba59abbe56e057f20f883e`, its phpass checksum is
  `B5k0g0vxFC8hKXhGxEITa0`, and both CUDA self-tests pass.
- Verified a nondefault phpass count (`8`, or 1024 iterations), bcrypt `$2b$`
  cost 04, mixed hashes with different salts/costs, same-salt hashes with
  different bcrypt costs, a 100-character plaintext, an ordinary rule attack,
  the `-O` fallback, and initialization across all twelve RTX 4090s.
- Confirmed invalid phpass counts and bcrypt costs are rejected before GPU
  work starts.

## v7.1.2-shooter.20260812.15

Mode-1 whole-candidate-rule status correction.

### Fixed

- A two-wordlist `-a 1` attack using `-r` or `-g` now reports the actual
  left-side wordlist in `Guess.Base` instead of `File ((null))`.
- The error was limited to status presentation: the combinator candidate
  pipeline already retained and processed both wordlists. Combinator status
  now resolves its dictionary names before consulting the generic feed label.

### Verification

- Rebuilt the Windows production executable and confirmed
  `hashcat.exe --version` reports `v7.1.2-shooter.20260812.15`.
- Reproduced the reported two-wordlist `-a 1 -r` layout with the same input
  wordlists and rule file. Interactive status reported the correct left and
  right paths with no `(null)` value.
- Verified deterministic `--stdout` candidates for the two-file final-rule,
  three-file final-rule, and unchanged two-file no-rule paths as
  `ShooterStatus!`, `ShooterStatusCheck!`, and `ShooterStatus` respectively.

## v7.1.2-shooter.20260812.14 (local source build)

Dynamic multi-file combination through attack mode 1.

### Added

- Attack mode 1 now accepts two or more wordlists and concatenates one word
  from every file in command-line order. There is no fixed six-file array in
  the implementation.
- Three-or-more-file attacks use the pipelined host producer for the first
  `N - 1` files and the existing GPU combinator amplifier for the final file.
- Multi-GPU range startup converts the assigned Cartesian offset directly to
  its mixed-radix wordlist positions. A later GPU no longer replays all base
  combinations assigned before its range.
- Whole-candidate `-r` and `-g` rules work with any supported number of mode-1
  files. `-j` applies to file 1, `-k` applies to files 2 through `N`, and the
  ordinary rule then applies after concatenation.

### Changed

- Removed private attack modes 11, 12, 13, and 14. Their fixed three- through
  six-file layouts are now written as `-a 1` with the same wordlists, and mode
  1 also permits more files.
- The original two-file, no-whole-rule mode-1 path remains unchanged and keeps
  the native optimized combinator behavior.
- Status reports every multi-file input as `Guess.File.#NN`; help and usage no
  longer list modes 11-14.
- Updated the README, Windows compilation notes, change summary, combination
  guide, and whole-candidate-rule guide for the new syntax and accounting.

### Compatibility

- Three-or-more-file mode 1 is rejected with `-S/--slow-candidates` and brain
  client operation. The unchanged two-file no-rule path retains its prior
  compatibility.
- The implementation detects 64-bit Cartesian-product overflow. Candidate
  length and Windows command-line length remain practical upper bounds on the
  number of inputs.
- Without whole-candidate rules, `--keyspace` and restore positions count the
  product of files 1 through `N - 1`; `--total-candidates` includes file `N`
  as the GPU amplifier. With whole-candidate rules, all files form the base and
  the loaded rules are the amplifier.

### Verified

- Forced a full Windows MSYS2/MinGW64 production rebuild after the structure
  changes and confirmed `hashcat.exe --version` reports
  `v7.1.2-shooter.20260812.14`.
- Confirmed modes 11-14 are absent from help and each is rejected as an invalid
  attack mode.
- Verified exact `--stdout` Cartesian ordering with two, three, and eight
  wordlists; repeated the three- and eight-file tests with a `$!`
  whole-candidate rule.
- Ran RTX 4090 MD5 known-answer cracks through the unchanged two-file path, the
  eight-file path, and the eight-file whole-rule path. Every expected plaintext
  was recovered. Also verified `-j`, `-k`, and final `-r` ordering as
  `a1b2c2d2!` across four files.
- Verified `--skip 3 --limit 2` resumes at the correct three-file base work
  unit and emits only its two final-word amplifications.
- Requested an interactive checkpoint at 47.19% of a three-file attack,
  restored the saved session, and verified it resumed from that base position
  and exhausted at exactly 100% without repeating the prefix.
- Ran a 1,000,000,000,000-candidate three-file MD5 attack on all twelve RTX
  4090s. All devices initialized and reported nonzero sustained speed; status
  listed all three files and the attack exhausted the exact total. The final
  short-run aggregate was 645.4 GH/s on that test workload.

## v7.1.2-shooter.20260812.13 (local source build)

Whole-candidate rules on existing attacks and visible quit progress.

### Added

- Added optional `-r`/`--rules-file` and `-g`/`--generate-rules` processing to
  attack modes 1, 3, 6, 7, and 11-14. The rule is applied after the mode has
  assembled its complete candidate, not to only one component.
- Attack mode 8 retains its upstream native rule support. Mode 9 also retains
  its existing native association-rule behavior.
- Whole-candidate rule runs preserve stacked rule files, generated rules,
  `--stdout`, keyspace/total-candidate accounting, skip/limit, status,
  checkpoint, and restore paths supported by the underlying attack.
- Standard combinator side rules keep their normal order: `-j` and `-k`
  transform their respective mode-1 inputs before concatenation, and `-r` or
  `-g` then transforms the completed candidate.
- Pressing `q` or `Q` now prints progress while shutdown proceeds: candidate
  dispatch/GPU-kernel drain, GPU-worker completion, session-service shutdown,
  GPU-resource release, and final restore/session-file finalization.

### Changed

- Removed the unreleased attack-mode-15 implementation. Its use case is now
  handled directly by `-a 1 ... -r rules`, so existing attack numbering and
  the optimized no-rule combinator path remain intact.
- Modes 1, 3, 6, 7, and 11-14 retain their original fast GPU paths whenever no
  ordinary rule file or generated-rule request is supplied. The new host-side
  complete-candidate producer is selected only for a whole-candidate rule run.
- Status identifies the native attack layout and separately reports the rule
  source as `Whole Candidate`, rather than presenting a synthetic attack mode.

### Compatibility

- `--slow-candidates` and brain-client operation are rejected for the new
  whole-candidate rule paths. The existing behavior without whole-candidate
  rules is unchanged.
- Candidate-length checks occur after the mode's inputs are assembled and
  before the GPU rule is applied, matching straight-kernel base-word behavior.

### Verified

- Clean-built and versioned the Windows production binary as
  `v7.1.2-shooter.20260812.13`.
- Ran RTX 4090 known-answer MD5/rules tests for modes 1, 3, 6, 7, 8, and 11-14.
  The recovered candidates confirmed that `$!` was applied to the completed
  candidate in every mode.
- Repeated known-answer tests without `-r` for the same nine modes, confirming
  the existing native paths and candidate layouts still work.
- Verified `--stdout` output for ruled modes 1, 3, 6, 7, 8, and 11-14 byte for
  byte; the emitted values ranged from `abcd!` for mode 1 through `abcdef!`
  for mode 14. Confirmed generated-rule accounting with `-g 3` as well.
- Ran a generated-rule mode-3 workload on all twelve RTX 4090 devices. Every
  GPU initialized, received work, and reported a nonzero speed until the
  intentional five-second runtime limit.
- Confirmed a live long-running GPU session accepts quit and prints each new
  shutdown-progress stage before its final Started/Stopped/Total Run Time
  summary.

## v7.1.2-shooter.20260812.10 (local source build)

Atomic CUDA startup retry for multi-GPU jobs.

### Changed

- Extended the existing CUDA startup recovery to `cuStreamCreate()` and CUDA
  event-creation failures. Stream and event creation retry in place on the
  affected context, avoiding the cost and state churn of rebuilding the attack.
- A failure on any selected CUDA device now rejects the complete startup
  attempt. Hashcat no longer continues a twelve-GPU command using only the
  subset whose contexts happened to initialize.
- Partial resources from a failed context-startup attempt are released before
  retrying, preventing the next clean attempt from inheriting memory pressure.
- Increased the delay between attempts from two to five seconds. Context,
  stream, and event creation each retain ten retries after the initial attempt.
  Exhaustion prints an explicit message and exits instead of falling through to
  a partial-GPU run.

### Verified

- Completed a forced full Windows MSYS2/MinGW64 production rebuild and
  confirmed `hashcat.exe --version` reports
  `v7.1.2-shooter.20260812.10`.
- Completed a normal mode-1800 benchmark on all 12 RTX 4090 devices.
- In a temporary test-only build, injected one context-creation-stage failure,
  one stream-creation failure, and one event-creation failure. Each retry path
  recovered, and the mode-1800 benchmark then completed on all 12 devices with
  exit code 0. The fault-injection hooks were removed before the final build.

## v7.1.2-shooter.20260812.9 (local source build)

Interactive ignore-outfile-check-dir control.

### Added

- Added `[i]gnore outfile` to the interactive menu whenever outfile-directory
  checking is active.
- Pressing `i` stops further `--outfile-check-dir` processing for the current
  run without deleting, truncating, or modifying anything in that directory.
- The checker and key handler synchronize at outfile-line boundaries. A line
  already being processed may finish, but after `i` takes effect no later line
  can mark another hash as cracked.

### Compatibility

- Hashes processed before `i` remain marked as cracked. The control applies to
  the current process only; a new run or `--restore` starts with the configured
  outfile checker enabled again.
- The key is hidden when outfile checking is disabled, unavailable for the
  selected mode, or already ignored.

### Verified

- Completed a forced full Windows MSYS2/MinGW64 production rebuild and
  confirmed `hashcat.exe --version` reports
  `v7.1.2-shooter.20260812.9`.
- On the target 12 x RTX 4090 system, pressed `i`, added a matching MD5 result
  to the watched directory, waited through multiple one-second check periods,
  and confirmed the attack remained `Running` with `Recovered: 0/1`.
- Repeated the same test without pressing `i` and confirmed the unchanged
  checker found the result after one second and completed as `Cracked` with
  `Recovered: 1/1`.

## v7.1.2-shooter.20260812.8

Resumable `--stdout` candidate-generation sessions.

### Added

- Enabled normal `.restore` checkpoints for `--stdout` sessions instead of
  forcibly disabling restore in stdout preprocessing.
- Added the normal interactive `[p]ause`, `[r]esume`, `[c]heckpoint`, and
  `[q]uit` menu to mask- and file-driven stdout sessions. Menu and event text
  are written to stderr so stdout remains a candidate-only stream.
- Added an exact outfile journal for `--stdout -o`: restore data now records
  both the committed candidate position and the matching byte boundary.
  `--restore` truncates any uncommitted tail before reopening the file in
  append mode.
- Ordered multi-GPU stdout batch commits by keyspace position. A restore file
  therefore always describes a contiguous output prefix even when later GPU
  batches finish first.
- Added pause/quit checks at buffered output boundaries, making host-side
  candidate generation responsive without adding a branch to every candidate.

### Compatibility

- Restore format version 721 reads existing version-720 cracking restore
  files. Exact stdout outfile restoration requires a version-721 restore file.
- Direct stdout and pipe sessions can resume their candidate position, but
  downstream bytes cannot be rolled back. Exact no-tail continuation requires
  a regular `-o/--outfile` file.
- A session that reads its candidate source from stdin cannot also use stdin
  for the interactive menu. File wordlists and masks use the menu normally.

### Verified

- Completed a clean Windows MSYS2/MinGW64 production build and confirmed
  `hashcat.exe --version` reports `v7.1.2-shooter.20260812.8`.
- Confirmed a 100-candidate mask run through `--stdout -o` wrote exactly 100
  candidates, wrote no candidate data to process stdout, and removed its
  restore file after successful exhaustion.
- Confirmed direct stdout still contains candidates only while warnings and
  the interactive menu are isolated on stderr.
- On the target Windows GPU system, confirmed `[p]ause` stopped outfile growth,
  a restore file was saved while paused, and `[r]esume` restarted generation.
- Appended an 8-byte uncommitted tail to a checkpointed 11,000,000,000-byte
  candidate file and confirmed `--restore` removed exactly those 8 bytes,
  logged the saved boundary, wrote nothing to process stdout, and completed
  without regenerating the exhausted keyspace.
- Enabled `[c]heckpoint` during a live stdout session and confirmed it exited
  at the coordinated multi-GPU boundary with an updated `.restore` file.

## v7.1.2-shooter.20260812.7

Transient Windows outfile-access recovery.

### Added

- Added bounded retry handling when the `-o` path temporarily returns
  `Permission denied`, `busy`, or another retryable access error. Startup path
  validation and result-time append opens retry for up to 5 seconds at 250 ms
  intervals.
- Added a 30-second retry cooldown after a full retry window is exhausted.
  Later recovered results still make one immediate open attempt, but persistent
  failures cannot impose another 5-second stall or duplicate the same error for
  every result. A timed retry window becomes eligible again after the cooldown.
- Added explicit recovery messages when the outfile becomes available and
  result writing resumes.

### Performance

- Successful outfile opens retain the original single-open fast path. They do
  not sleep, read a timer, or enter retry bookkeeping, so normal cracking and
  outfile performance are unchanged. Delays occur only after an actual outfile
  access failure.

### Verified

- Completed a clean Windows MSYS2/MinGW64 production build and confirmed
  `hashcat.exe --version` reports `v7.1.2-shooter.20260812.7`.
- A startup `Permission denied` caused by a read-only outfile recovered after
  9 retries when the file became writable; the attack cracked and the expected
  result was written.
- A result-time `Permission denied` caused by an exclusive Windows file lock
  recovered after 11 retries when the handle was released; the attack cracked
  and the expected result was written.
- A persistent exclusive lock during a three-hash test produced exactly one
  5-second retry window and one final error. Later results used immediate
  attempts instead of adding two more 5-second delays.
- An unlocked warm-cache control run cracked normally, wrote the expected
  result, and emitted zero outfile retry messages.

## v7.1.2-shooter.20260812.6

RTX 4090 persisted-autotune cache validation correctness.

### Fixed

- Initialized the same synthetic candidates and rule buffer before cached
  profile validation that full autotune uses. Rule attacks no longer compare
  an uninitialized approximately 15 ms validation launch with the properly
  initialized approximately 31 ms stored launch and retune every run.
- Made cache validation tolerate expected timing variance while 12 GPUs tune
  concurrently. Faster launches are accepted, while slower launches are
  rejected only after exceeding both four times the stored duration and the
  selected workload target, subject to the existing 2-second safety ceiling.
- Serialized concurrent log formatting and display with a dedicated mutex, so
  simultaneous per-GPU cache messages retain their correct device numbers and
  no longer appear duplicated or interleaved.
- Advanced the local build revision to `v7.1.2-shooter.20260812.6`.

### Verified

- Completed a clean Windows production build and confirmed
  `hashcat.exe --version` reports `v7.1.2-shooter.20260812.6`.
- Ran the reported NTLM (`-m 1000`), straight/rules (`-a 0`), `-w 4`
  command from an empty cache on all 12 RTX 4090s: status `Cracked`,
  `479.8 GH/s`, 14 seconds, and exactly one profile saved.
- Repeated the identical command twice: both runs reused the one profile on
  all 12 devices, produced zero rejection and save messages, kept exactly one
  cache record, cracked the target, and measured `479.2` and `479.1 GH/s`.

## v7.1.2-shooter.20260812.5

Multi-GPU checkpoint cancellation reliability, elapsed-time reporting, and
12 x RTX 4090 short-session startup improvements.

### Added

- Added `Total Run Time` to the final status summary, calculated from the
  displayed `Started` and `Stopped` timestamps.
- Added `SHOOTER_HASHCAT_HOST_STAGING_MB` for changing the automatic per-GPU
  host candidate-staging limit. Set it to `0` to restore the generic limit.

### Changed

- Changed checkpoint requests into a coordinated device barrier. GPUs that
  reach a restore boundary first now remain parked with their worker threads
  alive instead of exiting while slower GPUs finish their current work.
- Cancelling a pending checkpoint now releases every parked GPU, so all
  devices that participated in the attack resume—not only the GPUs that were
  still executing when cancellation was requested.
- Paused candidate producers together with their GPU consumers so prefetched
  work remains intact across checkpoint cancellation.
- Counted only live, non-skipped GPU workers in the barrier and accounted for
  devices that naturally finish near the end of the keyspace.
- Carried forward the missing parallel CUDA context initialization and
  per-device teardown work from the earlier Shooter development tree.
- Initialized host candidate-staging buffers concurrently and avoided
  zero-filling data that candidate construction overwrites before use.
- Replaced full candidate-buffer resets with the required metadata reset.
- Limited the two-slot host candidate staging to 3072 MiB per GPU on the exact
  Windows 12 x RTX 4090 configuration. This reduced the tested mode-0 host
  allocation from approximately 97.7 GB to 36.7 GB.

### Verification

- Clean Windows MSYS2/MinGW64 production build passed.
- Rapid checkpoint enable/disable on a 12 x RTX 4090 bcrypt/rule attack kept
  the session running and restored fresh nonzero speeds on all 12 GPUs.
- Leaving the checkpoint enabled produced a clean `Aborted (Checkpoint)` and
  a saved restore point.
- Starting with `--restore` resumed from that checkpoint with all 12 GPUs and
  reused the persisted RTX 4090 autotune settings on all devices.
- The short mode-0 known-answer run improved from approximately 18-23 seconds
  to 15.8-16.9 seconds cold and 7.6-10.1 seconds warm on the 12-card system.
- Normal dictionary candidate processing and attack modes 11, 12, 13, and 14
  completed known-answer tests successfully after the staging changes.
- A sustained mode-0 comparison measured 686.3 GH/s at the lower-memory
  geometry and 693.1 GH/s at acceleration 96 (approximately 1% difference).

## v7.1.2-shooter.20260811.4

Windows startup optimization for the intended 12 x RTX 4090 system.

### Added

- Added an automatic CUDA-only fast-start path for normal cracking sessions
  when CUDA reports exactly twelve `NVIDIA GeForce RTX 4090` devices.
- Added `SHOOTER_HASHCAT_FAST_START=0` as a per-process override that restores
  full HIP and OpenCL probing.
- Added startup behavior, measurements, and override instructions in
  `docs/startup-optimization.md`.

### Changed

- Kept `-I`/`--backend-info` comprehensive; diagnostic runs still enumerate
  CUDA, NVIDIA OpenCL, and Intel OpenCL.
- Updated the Windows instructions to use `make PRODUCTION=1`, ensuring local
  production binaries embed the dated shooter version.
- Advanced the build revision to `v7.1.2-shooter.20260811.4`.

### Verification

- Clean Windows MSYS2/MinGW64 production build passed.
- Automatic detection found all twelve RTX 4090 devices and enabled fast-start.
- The override restored full backend probing.
- MD5 and legacy yescrypt mode 67000 known-answer cracks passed.
- Alternating fixed-tuning MD5 runs measured 6.12/6.17 seconds with fast-start
  versus 6.69/6.76 seconds with all backends, approximately 8.6% faster for
  the tested short session.

## v7.1.2-shooter.20260811.3

Dated build identifiers, inverse runtime control, and legacy yescrypt
compatibility.

### Added

- Added date-and-revision version identifiers in the form
  `v7.1.2-shooter.YYYYMMDD.REVISION`.
- Added interactive `[l]ower` runtime control. It advances the countdown at
  twice normal speed and can switch directly to or from `[e]xtend`.
- Restored legacy yescrypt hash mode 67000 as a compatibility alias for the
  current optimized mode 36100 implementation.
- Added documentation for runtime controls, mode 67000, and Windows builds.

### Verification

- Clean Windows build passed.
- Direct lower, extend-to-lower transition, runtime abort, and standard
  known-answer tests passed.
- RTX 4090 GPU known-answer cracks passed for modes 67000 and 36100.

## v7.1.2-shooter.20260811.1

First dated release of the shooter customization ported onto the newer
hashcat master codebase.

### Added

- Added attack modes 11 through 14 and documented multi-way combination use.
- Added interactive `[e]xtend` runtime control.
- Added persisted autotune profiles for identical RTX 4090 devices, including
  safe profile validation and invalidation.
- Added grouped autotuning so matching devices can share measured settings.
- Added CUDA initialization retry handling and Windows runtime/build guidance.
- Added custom modes 29960, 29970, 29980, and 29990 with their GPU kernels and
  operating notes.
- Added the ported performance, dispatch, status, candidate-processing, and
  multi-device improvements from the beta development tree.

### Verification

- Built and tested on the 12 x RTX 4090 Windows system.
- RTX 4090 autotune-cache cold/warm validation covered attack modes 0, 1, 3,
  6, 7, 8, 9, and 11 through 14, plus slow-candidate operation.
- Standard known-answer and custom-mode checks passed during the port.

## Version numbering note

Revision `.2` was an intermediate local build and was not published as a
GitHub release. Published releases therefore proceed from `.1` to `.3`.
