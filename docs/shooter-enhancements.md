# Shooter enhancement details

This page explains every Shooter-specific change summarized at the beginning
of the main README. The comparison baseline is official upstream hashcat commit
[`eba388d2e`](https://github.com/hashcat/hashcat/commit/eba388d2ef8d2dc6f184cb2effdc1a99493d888d),
which is merged into this branch. Features inherited from official hashcat are
intentionally excluded. Upstream integration history, release-by-release
evidence, and test results are preserved in [CHANGELOG.md](../CHANGELOG.md).

## Performance and startup

### 1. Parallel hash-list parsing

Compatible native-text inputs containing at least 4,194,304 nonempty hashes
are memory-mapped and decoded with up to 64 CPU workers. Unsupported or
malformed inputs automatically use hashcat's original parser. On the measured
84,381,739-hash MD5 list, parsing plus sorting fell from 33.56 to 6.41 seconds.
See [startup optimization](startup-optimization.md).

### 2. Parallel hash-list sorting

Unsalted lists containing at least 4,194,304 hashes can use a stable parallel
radix sort with up to 64 CPU workers. Smaller, salted, or allocation-limited
jobs retain the original comparison sorter. See
[startup optimization](startup-optimization.md).

### 3. Automatic CUDA-only fast start

Normal Windows cracking sessions skip redundant HIP and OpenCL discovery when
CUDA confirms the intended system has exactly twelve RTX 4090 GPUs. Backend
diagnostics still inspect every backend, and an environment variable disables
the shortcut. See [startup optimization](startup-optimization.md).

### 4. Concurrent GPU setup and shutdown

CUDA contexts, memory queries, candidate-buffer preparation, and device
teardown can run concurrently on multi-GPU sessions instead of processing each
GPU one at a time. See [startup optimization](startup-optimization.md).

### 5. Lower host memory use

On the exact Windows 12 x RTX 4090 configuration, Shooter limits the two host
candidate-staging slots to 3072 MiB per GPU and avoids unnecessary buffer
initialization. The measured fast-hash host commitment fell from about 97.7 GB
to 36.7 GB. See [startup optimization](startup-optimization.md).

### 6. Reusable RTX 4090 autotuning

Shooter saves successful RTX 4090 workload settings, validates them before
reuse, and shares matching settings across identical cards. Explicit tuning
options still win, and unsupported jobs bypass the cache. See the
[RTX 4090 autotune-cache guide](../RTX_4090_AUTOTUNE_CACHE.md).

### 7. Blowfish kernel caching

Compiled kernels can be reused for Blowfish-based modes that would otherwise
be rebuilt. This covers modes 3200, 25600, 25800, 28400, 30600, 30601, 33800,
and 35500.

### 8. High-volume result streaming

Recovered plaintexts can be reconstructed from retained host candidates
instead of copied back from the GPU for every result. Outfile and potfile
writes are processed in bounded groups of 4,096 results while remaining live
and flushed. A controlled all-cracked workload improved by about 360 times;
that I/O-bound result is not a universal speed guarantee. See the
[release notes](../CHANGELOG.md#v712-shooter2026081429).

## Candidate generation

### 9. Multi-file combination attacks

Attack mode 1 accepts two or more wordlists and joins one entry from every
file in command-line order. This replaces the earlier fixed private modes for
three through six files and also permits additional files. See the
[multi-file combination guide](multi-file-combination.md).

### 10. Efficient multi-GPU combination starts

For three-or-more-file combination attacks, each GPU converts its assigned
Cartesian offset directly into wordlist positions. A later GPU does not replay
all combinations assigned to earlier devices. See the
[multi-file combination guide](multi-file-combination.md).

### 11. Whole-candidate rules

`-r` and `-g` can transform the fully assembled candidate in attack modes 1,
3, 6, and 7. Existing `-j` and `-k` side rules still run before assembly.
Mode 13 instead applies each rule at its exact pipeline position. See the
[whole-candidate rule guide](whole-candidate-rules.md).

### 12. Parallel stdout rule generation

High-volume straight wordlist-and-rule `--stdout` jobs use a reusable CPU
worker pool with up to 64 workers. Output remains deterministic, and the path
avoids GPU transfers that do not contribute to candidate generation.

### 13. Resumable stdout sessions

Mask- and file-driven `--stdout` sessions support pause, resume, checkpoint,
and quit. With a regular `-o` file, restore data binds the candidate position
to an exact byte boundary and removes an uncommitted tail before continuing.
See the [stdout session guide](stdout-sessions.md).

## Multibyte input

### 14. Multibyte masks work on Windows

Literal two-, three-, and four-byte UTF-8 characters work beside normal mask
tokens in every mask-capable hash mode. For example,
`?d?d№?d?d№?d?d№` reaches the mask engine without Windows replacing `№`.
See the [release notes](../CHANGELOG.md#v712-shooter2026081434).

### 15. Multibyte rules work on Windows

Rule files can use UTF-8 literals with the byte-emitting `$`, `^`, `i`, `v`,
and `o` operations. UTF-8 BOM-prefixed files, Unicode paths, and literal
Windows inline `-j` and `-k` rules are also supported. Existing rule positions
and non-emitting transforms remain byte-oriented. See the
[release notes](../CHANGELOG.md#v712-shooter2026081431).

## Long-job control and recovery

### 16. Interactive runtime controls

The interactive menu can extend a `--runtime` countdown or make it decrease at
twice normal speed. A running job can switch directly between the two modes.
See the [runtime-control guide](runtime-controls.md).

### 17. Coordinated multi-GPU checkpoints

A checkpoint request parks active GPUs at safe restore positions until every
participating device reaches the barrier. Cancelling the checkpoint releases
all parked devices and preserves prefetched candidate work. See the
[checkpoint-control guide](checkpoint-control.md).

### 18. Atomic CUDA startup retry

If context creation fails on any selected CUDA GPU, Shooter releases the
partial attempt and retries the complete session instead of continuing with a
subset of devices. Stream and event creation failures retry on the affected
context. Retries are bounded and end with an explicit error.

### 19. Windows outfile lock recovery

Startup validation and result-time append operations retry temporary Windows
outfile access failures every 250 milliseconds for up to five seconds. A
cooldown prevents persistent locks from adding the same long delay for every
later result. See the [release notes](../CHANGELOG.md#v712-shooter202608127).

### 20. Ignore outfile

When `--outfile-check-dir` is active, `[i]gnore outfile` stops further
directory checking for the current process without deleting or changing
files. Press `i` to activate it; the command then disappears from the prompt.
Hashes already processed remain recovered. See the
[release notes](../CHANGELOG.md#v712-shooter202608129-local-source-build).

### 21. Clear outfile-check completion status

When every recovered hash came from `--outfile-check-dir` rather than the
current attack, the final status says `cracked from outfile-check-dir`.

### 22. Reliable loopback cleanup

Windows loopback feeds release their file mappings before consumed induction
files are deleted. Cleanup failures are reported instead of letting the same
file be rediscovered indefinitely, and active files are preserved on abort or
quit. See the [release notes](../CHANGELOG.md#v712-shooter2026081431).

## Clearer status information

### 23. Visible quit progress

After `q` or `Q`, Shooter reports candidate and GPU drain, worker completion,
session-service shutdown, GPU-resource release, and final session-file work so
the console does not appear frozen. See the
[release notes](../CHANGELOG.md#v712-shooter2026081213-local-source-build).

### 24. Total run time

The final summary prints `Total Run Time`, calculated from the displayed
`Started` and `Stopped` timestamps. See the
[release notes](../CHANGELOG.md#v712-shooter202608125).

### 25. Correct combination status

A two-wordlist mode-1 attack using whole-candidate rules reports the real left
and right wordlist paths instead of a `(null)` feed label. See the
[release notes](../CHANGELOG.md#v712-shooter2026081215).

### 26. Visible Pure Kernel warning

Interactive terminals display the complete Pure Kernel status line in bright
yellow. Redirected, logged, and machine-readable output remains plain text.
See the [release notes](../CHANGELOG.md#v712-shooter2026081325).

## Hash formats and compatibility

### 27. Complete mdxfind namespace

Shooter exposes every name in mdxfind's live registry as `e1` through `e1001`.
Of those 1,001 entries, 999 are self-contained algorithms with passing test
vectors. `e426` is a scheduler pseudo-entry, and `e535` requires external
mdxfind custom-user/salt state. See the
[mdxfind compatibility guide](mdxfind-modules.md) and
[complete registry](mdxfind-modules.json).

### 28. Public mdxfind mode names

Help, hash information, examples, runtime status, benchmarks, autodetection,
diagnostics, and session logs show public `eN` names instead of private numeric
plugin identifiers. Existing standard numeric modes remain unchanged.

### 29. Magento Argon2 input

Mode `e987` accepts standard Argon2 PHC strings and mdxfind's Magento
`hex_digest:salt:2` and extended `:3_...` forms. The original Magento line is
retained for potfiles, `--show`, `--left`, and cracked output. See the
[release notes](../CHANGELOG.md#v712-shooter2026081322).

### 30. phpBB3 bcrypt-over-phpass modes

Mode `29950` handles `bcrypt(phpass($pass))`; mode `29951` explicitly handles
the rarer `bcrypt(phpass(md5($pass)))` construction. Both accept the original
phpBB3 record and run both stages through hashcat's GPU scheduler. See the
[mode 29950 guide](mode-29950.md).

### 31. Mode 29980

Mode `29980` implements the supported libxcrypt-style gost-yescrypt
`$gy$j9T$` profile on the GPU. See the
[gost-yescrypt notes](../GOST_YESCRYPT_GPU.md).

### 32. Mode 67000

Mode `67000` is a compatibility number for older yescrypt jobs and uses the
maintained implementation behind current mode `36100`. New jobs should use
`36100`. See the [mode 67000 guide](mode-67000.md).

## Downloads and builds

### 33. Complete Windows release archive

Each release publishes one `shooter_hashcat-<version>-windows-x64-complete.7z`
containing the complete
tagged source, the ready-to-run Windows x64 executable, module and bridge DLLs,
required runtime DLLs, build metadata, and rebuild tools.

### 34. Package integrity verification

The archive includes `SHA256SUMS` covering its source and binary contents plus
`verify-windows-package.ps1`, which checks every manifest entry after
extraction.

### 35. Self-bootstrapping Windows build

`build-windows.ps1` downloads a checksum-pinned MSYS2 toolchain into the local
`.build-tools` directory and builds Shooter without installing system-wide
software or changing the user or system `PATH`. See
[how_to_compile.txt](../how_to_compile.txt).

### 36. Portable Windows build instructions

Build commands work with a fresh clone on any drive and include all required
GCC, Clang, Rust, OpenSSL, iconv, bridge, feed, and runtime dependencies. No
developer-specific absolute paths are required. See
[how_to_compile.txt](../how_to_compile.txt).

### 37. Reproducible release versioning

Production source pins its release date and revision so later rebuilds retain
the same version across machines and time zones. Packaging and release
automation refuse to publish an executable that does not exactly match the
requested tag.

## Rule loading

### 38. Parallel rule-file loading

Plain rule files of at least 16 MiB are read once and validated with up to 64
CPU workers. This is part of the shared rule loader, so it benefits every hash
algorithm and attack that accepts `-r`; it is not limited to MD5. Rule order,
comments, blank lines, UTF-8 BOM handling, LF/CRLF input, invalid-rule
warnings, and chained rule files retain their existing behavior. Compressed
rule files and unusual inputs automatically keep the original streaming path.

The loader also avoids one allocation and free for every rule, grows its
serial fallback buffer geometrically, and no longer allocates and copies a
second complete compiled-rule array when one rule file is used. On the
measured 60.80 MiB file containing 4,902,480 rules, loader-only startup fell
from 26.235 seconds with the pre-change binary to a seven-run median of 0.140
seconds. See [startup optimization](startup-optimization.md#large-rule-file-parsing)
for controls, memory behavior, and verification details.

## Optional status detail

### 39. Optional Restore.Sub status lines

The per-device `Restore.Sub` rows are hidden from normal human-readable status
output by default, keeping a 12-GPU status screen twelve lines shorter. Add
`--status-restore-sub` to show the original salt, amplifier, and iteration
ranges:

```powershell
hashcat.exe ... --status-restore-sub
```

The switch covers manual status requests, automatic `--status` updates, final
summaries, every selected GPU, and bridge-backed modes. `Restore.Point` remains
visible either way, and hiding the rows does not change checkpoint or restore
behavior. JSON and machine-readable status formats are unchanged because they
did not emit these human-readable rows.

## Portable release binaries

### 40. Portable prebuilt Windows binaries

The one-file Windows release is compiled for the standard x64 baseline instead
of the particular CPU model used by GitHub Actions. This prevents a downloaded
`hashcat.exe`, bridge, or feed DLL from failing with an illegal-instruction
error on an older x64 processor. The repo-local `build-windows.ps1` wrapper
uses the same portable setting, while developers can still invoke make
directly when they intentionally want machine-specific optimization.

## Potfile reporting

### 41. Faster show and left

`--show` and `--left` use narrower searches when comparing a potfile with a
large hash list. Unsalted lists use a small 16-bit prefix index over the
already-sorted hashes. Salted lists first locate the matching salt group and
then search only that group's digests. Custom potfile validators and the
special keep-all-hashes path retain their original matching behavior.

When `-o` is supplied, each selected line is already written by Hashcat's
outfile writer. Shooter no longer makes a second heap-allocated copy of every
line, sorts all of those unused copies, and frees them one at a time. This is
especially important for `--left`, where nearly the complete input list may
need to be emitted. Standard-output mode retains original input ordering.

No new option is required. See
[startup optimization](startup-optimization.md#large-show-and-left-workloads)
for measured results, scope, and verification details.

## Linux builds

### 42. Linux-compatible mdxfind bridge

Shooter's bundled mdxfind libraries are compiled as position-independent code
before they are linked into `bridge_mdxfind.so`. This fixes the Linux linker
failure that previously reported an `R_X86_64_PC32` relocation in
`librhash.a` and requested a rebuild with `-fPIC`.

Both the normal `SHARED=0` build and the `SHARED=1` library build are covered.
See [BUILD.md](../BUILD.md) for the tested Ubuntu prerequisites and commands.

## Support and troubleshooting

### 43. Automatic error reports

The first normal Hashcat error in a process creates a uniquely named
`shooter_hashcat-error-YYYYMMDD-HHMMSS-PID.log` in the directory where the
program was started. Every later error and warning from the same run is
appended to that one file, including errors reported concurrently by different
GPU workers. Up to 64 recent warnings from before the first error are included
as context. This ensures messages such as `Hash parsing error`, which Hashcat
internally treats as warnings, are not lost. Successful runs and warning-only
runs do not create a report.

The report includes timestamps, the exact Shooter version, operating system,
architecture, process ID, working directory, and a bounded command-line
argument list. `--brain-password` values are automatically replaced with
`[REDACTED]`. Input and output files are not attached, but a normal diagnostic
can quote an individual malformed input line. Other arguments and paths may
also be private, so users should review the text file before sharing it. See
the [error-report guide](error-reports.md).

## Testing and observability

### 44. Sanitizers and parser fuzzing

The Security workflow compiles the shared parser core with AddressSanitizer
and UndefinedBehaviorSanitizer and runs a coverage-guided libFuzzer target over
the common tokenizer and multibyte rule compiler. Scheduled and change-based
runs retain any crash input as a workflow artifact. See
[security-testing.md](security-testing.md).

### 45. Stage time and peak memory

`--stage-profile` prints final time for feed, copy, initialization, temporary
transfer, main launch, and comparison stages together with measured launches
and peak process RAM. `--stage-profile-json` emits the same fields as one
`shooter-stage-profile-v1` object. Profiling is disabled by default. See
[stage-profile.md](stage-profile.md).

### 46. SBOM and signed release attestations

The Windows package contains an SPDX 2.3 inventory of the executables and
plugin DLLs with SHA-256 checksums and principal dependencies. The release
workflow creates Sigstore-backed GitHub attestations for both build provenance
and the SBOM while retaining one public `.7z` download asset. See
[release-security.md](release-security.md).

## Outfile-check startup

### 47. Outfile-check before cracking allocation

Before building bitmap tables, loading the candidate source, initializing
attack kernels, allocating attack-specific GPU and host buffers, or running
autotune, Shooter compares the loaded hashes with every existing result in
`--outfile-check-dir`. Matching hashes are marked recovered immediately. If
the directory accounts for the complete target list, Shooter exits without
starting the cracking allocation. If hashes remain, only those remaining
hashes continue into the normal attack.

The same file positions are handed to the live outfile watcher, so a partial
preflight does not immediately reread unchanged files from the beginning.
`--outfile-check-timer=0` disables both this preflight and the live watcher.
Modes that intentionally disable outfile checking retain that behavior.

The directory must contain only trusted recovered-result files. Hashcat's
existing outfile reader scans the files in that directory and intentionally
accepts entries with or without a plaintext, so a target hash list must not be
stored there.

Like Hashcat's existing all-found potfile shortcut, the check happens after
the lightweight backend-runtime and device-enumeration phase needed by the
current session architecture. It avoids the much larger per-attack GPU and
host allocation; it does not suppress the initial device list. See
[startup optimization](startup-optimization.md#existing-outfile-results-before-cracking-allocation).

## Wordlist I/O

### 48. Faster large-wordlist indexing and feed

The first time Shooter sees a wordlist, it builds the sparse line index used
for multi-GPU distribution, `--skip`, and restore. Very large files now use up
to 64 CPU workers and SIMD newline counting, allowing the storage queue and
the available processor cores to work together. The new byte-spaced index is
also much smaller. Existing seek databases still load, so no cache cleanup or
conversion step is required.

During cracking, each wordlist reader caches its selected SIMD line scanner.
The common path also avoids the complete candidate-transform function when no
inline rule, encoding conversion, hexadecimal input mode, or forced-uppercase
mode is active and an ordinary candidate cannot be `$HEX[...]`. Actual
`$HEX[...]` entries and every configured transformation retain their original
behavior.

No option is required. On the supplied 60,256,380,643-byte email list, the
first-use index pass fell from 57.376 seconds to 11.756 seconds, or 4.88 times
faster. The optimized pass read at 4.77 GiB/s, about 90 percent of a separate
5.28 GiB/s sequential-read measurement on the same system, while the index
shrank from 4,343,248 bytes to 229,904 bytes. A live 12-GPU mode-0 test with
112 loaded rules processed 4,060,086,272 base words in its 10-second cracking
window versus 2,919,628,800 before the final feed optimizations, a 39.1 percent
increase. See [startup optimization](startup-optimization.md#large-wordlist-indexing-and-feed-throughput)
for scope and verification details.

## Status visibility

### 49. Consistent remaining and recovery-rate status

Every normal human-readable status display includes both of these lines:

```text
Remaining........: 33473 (99.93%) Digests
Recovered/Time...: CUR:0,N/A,N/A AVG:0.00,N/A,N/A (Min,Hour,Day)
```

They are no longer suppressed when a job contains 1,000 or fewer digests.
`Remaining` reports the live digest count and percentage; jobs with multiple
salts continue to include the salt count and percentage on the same line.
`Recovered/Time` reports the minute columns immediately. During the first
minute, `CUR` is the recovered count so far and `AVG` is its live per-minute
pace. The hour and day columns use `N/A` until those windows have elapsed.

This affects the normal terminal display, including periodic and final status.
Machine-readable and JSON status formats keep their existing structured
fields and formats.

## Opt-in timing diagnostics

### 50. Task-time breakdown

Add `--task-time-breakdown` to a normal human-readable attack to print a `Task
Time Breakdown` that accounts for the measured end-to-end run. The option is
disabled by default. The three main totals are `BEFORE ATTACK`, `ATTACK`, and
`AFTER ATTACK`; every line includes seconds and its percentage of the complete
run.

The preparation section separately measures command/options setup, session
initialization, bridge/plugin initialization, backend runtime loading, GPU
device setup, hash-mode setup, hash line counting, hash and salt sorting,
duplicate removal, potfile checks, `--outfile-check-dir` checks, rule loading,
bitmap generation, bridge salts, per-attack GPU allocation, self-test, and
autotune. `Other session initialization` and `Other attack preparation` keep
unclassified coordination time visible instead of silently losing it.

The cleanup section separates the time used to finish monitors, output, and
the attack-specific GPU session from the time used to destroy the remaining
session contexts. Repeated stages show their run count, such as during a
benchmark or retry. If the potfile or outfile preflight resolves every hash,
the report says that the attack did not start.

Even when requested, the report is suppressed for `--quiet`, machine-readable
output, `--stdout`, `--show`, `--left`, `--identify`, `--keyspace`, help,
hash-info, and backend-info modes so existing scripts keep their established
output formats. This end-to-end report complements the opt-in
`--stage-profile`, which measures the lower-level candidate pipeline.

## Automatic endpoint status

### 51. Automatic start and finish status

Every normal human-readable attack prints the same full status page as the
interactive `s` command at both endpoints. The initial page appears after
attack preparation, self-test, and autotune have made live status available,
but before any cracking worker is launched. It therefore provides a complete
zero-progress view of the selected hashes, candidate source, devices, and
runtime estimate. The existing final page remains the matching completion
view with the terminal result and recovery totals.

Queued rounds share one initial page at the beginning and one final page after
the last round, avoiding duplicate pages between dictionaries or masks.
Automatic pages are suppressed for `--quiet`, machine-readable and JSON
output, benchmarks, speed-only and progress-only modes, and `--stdout`, so
their established output formats remain unchanged.

## Ordered component candidates

### 52. Ordered component pipeline mode 13

Attack mode 13 accepts any number of wordlists, masks, and rule stages in any
order. It processes them from left to right exactly as entered. Wordlist and
mask stages append to the candidate assembled so far. A rule stage transforms
the entire assembled prefix, and components to its right append afterward.

Each `-r` file is its own Cartesian stage at the option's command-line
position, so adjacent rule files apply sequentially. Positional files default
to wordlists, mask-looking tokens are inline masks, and `.hcmask` files are
mask-file stages. Explicit `wordlist:`, `mask:`, and `maskfile:` prefixes
handle ambiguous names. Mode-12 `?w` and `?q` markers are not reused.

The complete ordered product drives keyspace, skip/limit, checkpoints, and
restore positions. Original stage order is preserved in restore files.
`-j` transforms the first wordlist stage and `-k` transforms later wordlist
stages as they are read. Interactive attacks display the normal command menu
and accept the usual status and control keys. After the first speed sample,
status pages calculate `Time.Estimated` from the complete pipeline's remaining
candidates and aggregate device speed. See the
[attack-mode 13 guide](multi-hybrid-mode13.md) for syntax, examples, type
detection, counting, and limits.

The host generator reuses an assembled stage prefix until an outer Cartesian
position changes. For example, `wordlist -r rules ?d domains.txt` applies a
given rule to a word once, reuses that result for its digit/domain suffixes,
and regenerates only the suffix stage that advances. It also keeps small
wordlists in an 8 MiB per-device cache and advances large-wordlist cursors
across device work ranges instead of repeatedly restarting at the beginning.
These optimizations do not change candidate order, skip/limit positions, or
restore accounting.

Mode 13 also compiles the largest safe trailing product, up to 65,536
candidates, into native GPU rules. Wordlists, masks, and supported rule stages
may all occur inside that suffix and retain their original left-to-right
meaning. `Guess.GPU.Amp` shows the selected multiplier and stage range. On the
reference twelve-RTX-4090 system, a 100-candidate suffix was insufficient,
1,000 improved throughput but remained uneven, and the reported
`wordlist -r ten-rules ?d hundred-word-domain-list` shape produced a 10,000×
suffix that held all twelve GPUs at approximately 98-100 percent utilization.

The bounded exhaustive regression covers every wordlist/mask/rule structure
through six stages: 1,092 pipelines and 55,986 ordered candidates per host or
compiled semantic path. A separate benchmark covered all 24 permutations of
the production-shaped four-stage workload. Every order with the large
wordlist first produced a 10,000-candidate suffix and held all twelve GPUs at
99-100 percent; the original large-wordlist/rules/mask/domain order was fastest
at 219.5 GH/s against one MD5 target. Reproducible harnesses are in `tools/`.

On the actual 84,381,739-digest target with `--bitmap-max 26`, the same order
held all twelve GPUs at 98-100 percent and measured 100.8-101.3 GH/s. The
26-bit bitmap required about 17 seconds to build, so it improves the long
attack rather than startup time.

The first host-side wordlist uses the sparse indexed feed even if a mask or
rule appears before it, preventing distant device ranges from repeatedly
rescanning a large file. Unsupported or overlong suffix operations, products
above the cap, non-divisible skip/limit boundaries, old restore mappings, and
`--stdout` safely retain the exact host implementation. See the
[attack-mode 13 guide](multi-hybrid-mode13.md#gpu-batching-and-performance) for
the limits and ordering guidance.

## Automatic pure-kernel recovery

### 53. Automatic pure-kernel recovery

When `-O` selects an actual optimized kernel, the mode also provides a pure
kernel, and the optimized parser rejects every supplied hash, Shooter rebuilds
the complete session once without `-O`. Rebuilding at the process boundary
ensures that the second attempt receives the pure parser limits, password
limits, kernel choices, and restore metadata instead of retaining optimized
state from the first attempt.

The retry is intentionally narrow. A mixed file with at least one valid hash
continues normally, a run that is already using the pure kernel does not
retry, and a mode without a pure kernel preserves its normal error. If the
pure parser also rejects every hash, Shooter reports that parser error and
stops; it never retries a second time.

This fallback handles valid formats whose optimized parser imposes tighter
field limits. It cannot repair malformed input or a hash supplied to the
wrong mode. For example, mode 1800 requires sha512crypt input beginning with
`$6$`; a line without that structure is retried once but remains a
`Separator unmatched` error under the pure kernel.

## Statistical candidate generation

### 54. Native PCFG feed

Shooter ships a deterministic probabilistic context-free grammar generator as
the `pcfg` feed for attack mode 8. It is not a new attack number: run it as
`-a 8 pcfg MODEL`, so it inherits the generic feed interface's rule
amplification, per-device instances, keyspace, skip/limit, status, and restore
behavior.

`tools/train_pcfg.py` learns ASCII uppercase, lowercase, digit, and
symbol/other run structures plus terminal frequencies from an authorized
plaintext corpus. It stores integer negative-log scores in a versioned,
hex-safe model. The native feed globally merges every retained structure's
Cartesian product in probability order with deterministic tie breaking.

Model loading validates classes, lengths, references, hexadecimal data,
candidate limits, and 64-bit score/keyspace arithmetic. The distributed
source identity covers the complete model contents. Version 1 restores exact
candidate positions by deterministic replay, which can make a deep seek CPU
intensive without changing its result. See the comprehensive
[PCFG guide](pcfg-attack.md).

The other proposed candidate methods remain clearly labeled as planned in the
[candidate-generation roadmap](candidate-generation-roadmap.md); they are not
listed here as shipped enhancements.

## Candidate selection policy

### 55. Final-candidate class requirements

The independent `--require-upper`, `--require-lower`, `--require-digit`, and
`--require-symbol` flags require at least one byte from each selected class.
The numeric `--candidate-min-upper=N`, `--candidate-min-lower=N`,
`--candidate-min-digit=N`, and `--candidate-min-symbol=N` forms support larger
minimums. Every option is disabled by default.

The check runs after the complete supported candidate and its rules or ordered
mode-13 stages have been assembled. Rejected candidates retain their original
positions, so skip, restore, multi-GPU ranges, progress, and the `Rejected`
counter remain consistent. Status displays the active minimums on a
`Candidate.Policy` line.

Exact post-rule inspection selects host generation and can reduce fast-hash
throughput. Unsupported layouts are refused instead of checking an incomplete
prefix. Class byte definitions, examples, performance behavior, and current
compatibility limits are documented in
[Final-candidate requirements](candidate-requirements.md).

## Windows Unicode status output

### 56. Code-page-independent UTF-8 candidate display

Hashcat candidates are byte strings. When a candidate preview is valid,
printable UTF-8, status shows the text directly; candidates containing invalid
UTF-8 or control bytes continue to use the unambiguous `$HEX[...]` form. The
bytes tested by the hash kernel are never converted for display.

On Windows, human-readable status and diagnostic messages sent to a real
console are now converted from Hashcat's internal UTF-8 to UTF-16 and written
with the Windows Unicode console API. This fixes mojibake in `Candidates.#...`
without requiring `chcp 65001` and without changing the console's global code
page.

Redirection is deliberately different: output sent to a file, pipe, or capture
remains byte-for-byte UTF-8. Candidate-data streams such as `--stdout` also
remain raw, because converting those bytes would change the attack data. A
terminal font still needs a glyph for the requested character; a missing-glyph
box is a font limitation rather than an encoding conversion error.

## Interactive candidate-position control

### 57. Live forward seek

Pressing `g` during a running or paused attack prompts for a new forward
position. Whole numbers from 0 through 100 select that percentage of the
current unamplified base keyspace; numbers above 100 select an exact one-based
line/base position. The distinction is value based, so `100` is always 100
percent and `101` is always position 101.

The dispatcher moves only past work that has not yet been assigned. Existing
GPU batches finish, new batches start at the selected point, and the skipped
base positions plus their complete amplification are booked as rejected
progress. The restore boundary remains conservative until prior assignments
finish, preventing lost work after interruption. Backward requests and
nonseekable stdin or ordered `--stdout` sessions are refused without changing
the attack. See [Live forward seek](live-goto.md) for position semantics,
examples, limitations, and mode-13 behavior.
