# shooter_hashcat

`shooter_hashcat` is a Windows-focused version of hashcat 7.1.2. It keeps the
normal hashcat commands and features, then adds faster handling of very large
hash and rule lists, better multi-GPU behavior, more ways to build password
candidates, multibyte masks and rules on Windows, additional hash types, and a
ready-to-run release. If an error occurs, it also creates one support file that
can be reviewed and sent with a bug report.

It was developed for a Windows machine with 12 NVIDIA GeForce RTX 4090 GPUs,
but most of its additions also work on other hardware.

Use this software only on passwords and systems you own or are explicitly
authorized to audit.

## Shooter-specific enhancements

This public inventory lists changes maintained by Shooter relative to the
[official upstream hashcat commit merged into this branch](https://github.com/hashcat/hashcat/commit/eba388d2ef8d2dc6f184cb2effdc1a99493d888d).
Features inherited from official hashcat are intentionally excluded. Every
item links to a plain-language explanation.

1. **[Huge hash lists parse across CPU cores](docs/shooter-enhancements.md#1-parallel-hash-list-parsing)** — less time waiting at `Parsing Hashes`.
2. **[Huge unsalted hash lists sort across CPU cores](docs/shooter-enhancements.md#2-parallel-hash-list-sorting)** — preprocessing finishes sooner.
3. **[The 12-GPU system skips unnecessary backend scans](docs/shooter-enhancements.md#3-automatic-cuda-only-fast-start)** — short jobs begin faster.
4. **[Multiple GPUs start and stop concurrently](docs/shooter-enhancements.md#4-concurrent-gpu-setup-and-shutdown)** — devices no longer wait on one-at-a-time setup.
5. **[The 12-GPU system uses much less host memory](docs/shooter-enhancements.md#5-lower-host-memory-use)** — measured staging fell from about 97.7 GB to 36.7 GB.
6. **[RTX 4090 tuning is saved and reused](docs/shooter-enhancements.md#6-reusable-rtx-4090-autotuning)** — matching jobs can skip repeated tuning.
7. **[Blowfish kernels can be reused](docs/shooter-enhancements.md#7-blowfish-kernel-caching)** — supported Blowfish modes avoid needless recompilation.
8. **[Large cracked-result sets write much faster](docs/shooter-enhancements.md#8-high-volume-result-streaming)** — outfile and potfile results are batched safely.
9. **[Attack mode 1 joins three or more wordlists](docs/shooter-enhancements.md#9-multi-file-combination-attacks)** — no fixed three-to-six-file attack modes are needed.
10. **[Multi-GPU combination attacks seek directly to each GPU's work](docs/shooter-enhancements.md#10-efficient-multi-gpu-combination-starts)** — later GPUs do not replay earlier combinations.
11. **[Rules can modify the complete candidate](docs/shooter-enhancements.md#11-whole-candidate-rules)** — supported in attack modes 1, 3, 6, and 7; mode 13 instead applies rules at their ordered pipeline position.
12. **[`--stdout` rule generation uses multiple CPU cores](docs/shooter-enhancements.md#12-parallel-stdout-rule-generation)** — up to 64 workers retain deterministic order.
13. **[`--stdout` jobs can pause, checkpoint, and restore](docs/shooter-enhancements.md#13-resumable-stdout-sessions)** — file output resumes at the exact byte boundary.
14. **[Multibyte masks work on Windows](docs/shooter-enhancements.md#14-multibyte-masks-work-on-windows)** — literals such as `№` survive the command line.
15. **[Multibyte rules work on Windows](docs/shooter-enhancements.md#15-multibyte-rules-work-on-windows)** — rule files and inline rules accept UTF-8 literals.
16. **[A running time limit can be extended or shortened](docs/shooter-enhancements.md#16-interactive-runtime-controls)** — adjust `--runtime` without restarting.
17. **[Multi-GPU checkpoints keep every GPU coordinated](docs/shooter-enhancements.md#17-coordinated-multi-gpu-checkpoints)** — checkpoint cancellation safely resumes all devices.
18. **[CUDA startup failures retry without dropping GPUs](docs/shooter-enhancements.md#18-atomic-cuda-startup-retry)** — a failed device cannot silently produce a partial-GPU run.
19. **[Temporarily locked output files are retried](docs/shooter-enhancements.md#19-windows-outfile-lock-recovery)** — brief Windows locks do not immediately lose results.
20. **[`[i]gnore outfile` stops directory checking](docs/shooter-enhancements.md#20-ignore-outfile)** — stop checking `--outfile-check-dir` for the current run without changing the directory.
21. **[Outfile-check-only cracks are labeled clearly](docs/shooter-enhancements.md#21-clear-outfile-check-completion-status)** — the final status identifies where the result came from.
22. **[Loopback induction files clean up safely on Windows](docs/shooter-enhancements.md#22-reliable-loopback-cleanup)** — consumed files are not rediscovered forever.
23. **[Quit shows shutdown progress](docs/shooter-enhancements.md#23-visible-quit-progress)** — the console explains what hashcat is still finishing.
24. **[The final summary shows total run time](docs/shooter-enhancements.md#24-total-run-time)** — `Total Run Time` is calculated from start and stop timestamps.
25. **[Combination status shows the correct wordlist paths](docs/shooter-enhancements.md#25-correct-combination-status)** — ruled mode-1 jobs no longer show `(null)`.
26. **[Pure Kernel selection is highlighted](docs/shooter-enhancements.md#26-visible-pure-kernel-warning)** — interactive status displays the line in yellow.
27. **[The complete mdxfind `e1`-`e1001` namespace is available](docs/shooter-enhancements.md#27-complete-mdxfind-namespace)** — 999 standalone algorithms plus two documented special entries.
28. **[mdxfind names appear consistently throughout hashcat](docs/shooter-enhancements.md#28-public-mdxfind-mode-names)** — help, status, benchmarks, and logs show public `eN` names.
29. **[mdxfind `e987` accepts Magento Argon2 input](docs/shooter-enhancements.md#29-magento-argon2-input)** — original Magento lines remain intact in output and potfiles.
30. **[Modes 29950 and 29951 handle phpBB3 legacy rehashes](docs/shooter-enhancements.md#30-phpbb3-bcrypt-over-phpass-modes)** — the complete two-stage hashes run on the GPU.
31. **[Mode 29980 adds the supported gost-yescrypt profile](docs/shooter-enhancements.md#31-mode-29980)** — handles libxcrypt-style `$gy$j9T$` hashes.
32. **[Mode 67000 restores legacy yescrypt numbering](docs/shooter-enhancements.md#32-mode-67000)** — old jobs use the maintained mode-36100 implementation.
33. **[One `.7z` contains both source and a ready-to-run build](docs/shooter-enhancements.md#33-complete-windows-release-archive)** — download one file to run or rebuild Shooter.
34. **[Release contents can be verified locally](docs/shooter-enhancements.md#34-package-integrity-verification)** — an included script checks the complete SHA-256 manifest.
35. **[Windows builds bootstrap with one command](docs/shooter-enhancements.md#35-self-bootstrapping-windows-build)** — the compiler toolchain stays inside the repository.
36. **[Fresh clones build from any drive](docs/shooter-enhancements.md#36-portable-windows-build-instructions)** — no machine-specific absolute paths are required.
37. **[Release versions are reproducible](docs/shooter-enhancements.md#37-reproducible-release-versioning)** — tags, packages, rebuilds, and `--version` stay identical.
38. **[Huge rule files load across CPU cores](docs/shooter-enhancements.md#38-parallel-rule-file-loading)** — all rule-capable algorithms spend less time waiting at `Loading rules`.
39. **[`Restore.Sub` status lines are optional](docs/shooter-enhancements.md#39-optional-restoresub-status-lines)** — they stay hidden unless `--status-restore-sub` is requested.
40. **[Prebuilt releases run on standard x64 CPUs](docs/shooter-enhancements.md#40-portable-prebuilt-windows-binaries)** — release binaries do not inherit the GitHub runner's CPU-only instructions.
41. **[`--show` and `--left` finish faster on huge lists](docs/shooter-enhancements.md#41-faster-show-and-left)** — large potfiles use narrower lookups, and `-o` jobs skip a redundant full-result copy and sort.
42. **[Shooter's mdxfind bridge builds on Linux](docs/shooter-enhancements.md#42-linux-compatible-mdxfind-bridge)** — the added bridge links in both static and shared Linux builds.
43. **[Errors are saved in one support file](docs/shooter-enhancements.md#43-automatic-error-reports)** — the file records recent warnings, every normal error, later warnings, and the details needed to investigate the problem.
44. **[Parser bugs are hunted automatically](docs/shooter-enhancements.md#44-sanitizers-and-parser-fuzzing)** — scheduled sanitizer and coverage-guided fuzz tests retain crash inputs.
45. **[Pipeline time and peak RAM can be measured](docs/shooter-enhancements.md#45-stage-time-and-peak-memory)** — opt-in human and JSON reports show where a run spent its time.
46. **[Releases include an SBOM and signed attestations](docs/shooter-enhancements.md#46-sbom-and-signed-release-attestations)** — verify archive contents, provenance, and the software inventory.
47. **[Existing outfile results are removed before cracking starts](docs/shooter-enhancements.md#47-outfile-check-before-cracking-allocation)** — if every hash is already in `--outfile-check-dir`, the expensive attack-specific GPU and host-memory allocation is skipped.
48. **[Huge wordlists index and feed faster](docs/shooter-enhancements.md#48-faster-large-wordlist-indexing-and-feed)** — first-use line counting uses the CPU cores and ordinary candidates reach the GPUs with less per-word overhead.
49. **[Remaining hashes and recovery rates are always visible](docs/shooter-enhancements.md#49-consistent-remaining-and-recovery-rate-status)** — every normal status display includes `Remaining` and `Recovered/Time`, even for small hash lists, with live minute values from the first status update.
50. **[Attacks can explain where their time went](docs/shooter-enhancements.md#50-task-time-breakdown)** — opt-in `--task-time-breakdown` output separates preparation, cracking, and cleanup, then itemizes hash loading, sorting, potfile/outfile checks, rules, GPU setup, self-test, and autotune.
51. **[Full status appears at both ends of an attack](docs/shooter-enhancements.md#51-automatic-start-and-finish-status)** — the same human-readable page as interactive `s` prints once before cracking workers start and again when the attack completes.
52. **[Attack mode 13 runs an ordered component pipeline](docs/shooter-enhancements.md#52-ordered-component-pipeline-mode-13)** — any number of wordlists, masks, and rule stages run left-to-right in the exact order entered.
53. **[All-rejected optimized input retries with the pure kernel](docs/shooter-enhancements.md#53-automatic-pure-kernel-recovery)** — when `-O` parser limits reject every supplied hash, the complete session is rebuilt once without `-O`.
54. **[PCFG candidates run through a native deterministic feed](docs/shooter-enhancements.md#54-native-pcfg-feed)** — train a probability-ordered grammar, then run it as `-a 8 pcfg MODEL` with keyspace, rules, restore, and multi-GPU distribution.
55. **[Final candidates can require character classes](docs/shooter-enhancements.md#55-final-candidate-class-requirements)** — independent, default-off upper/lower/digit/symbol minimums are checked after supported rules and complete mode-13 pipelines.
56. **[Multibyte candidates display correctly on Windows](docs/shooter-enhancements.md#56-code-page-independent-utf-8-candidate-display)** — valid UTF-8 previews use the Unicode console without changing candidate bytes or redirected output.
57. **[A running attack can seek forward](docs/shooter-enhancements.md#57-live-forward-seek)** — press `g`; values through 100 mean percentage and larger values mean an exact one-based line/base position.

## Download and run

Download the single `shooter_hashcat-<version>-windows-x64-complete.7z` asset from the
[latest release](https://github.com/Shooter3k/shooter_hashcat/releases/latest)
and extract it. The archive contains the complete tagged source and the
already-built Windows x64 program.

Verify the package and check the version:

```powershell
.\verify-windows-package.ps1
.\hashcat.exe --version
```

If a run reports an error, look for `Error report saved to:` in the console.
Review that text file and send it with a short description of the problem; see
[Automatic error reports](docs/error-reports.md) for privacy details and
limitations.

Rebuild everything from the included source:

```powershell
.\build-windows.ps1 -Action Rebuild
```

The first rebuild downloads a checksum-pinned MSYS2 compiler toolchain into
the local `.build-tools` directory. Allow internet access and at least 5 GB of
free disk space. Nothing is installed system-wide, and the system or user
`PATH` is not changed. GPU vendor drivers remain an external requirement.

Tagged Windows releases are rebuilt on a clean GitHub runner. The release is
published only after the executable version, archive layout, source manifest,
and package-integrity checks pass. Separate CI jobs exercise static and shared
Windows and Linux builds, Rust crates, and the sanitizer-backed parser fuzzer.

## Technical details

| Topic | Documentation |
| --- | --- |
| Complete Shooter feature inventory | [docs/shooter-enhancements.md](docs/shooter-enhancements.md) |
| Startup, memory, parsing, and sorting | [docs/startup-optimization.md](docs/startup-optimization.md) |
| Large-wordlist indexing and feed speed | [wordlist I/O optimization](docs/startup-optimization.md#large-wordlist-indexing-and-feed-throughput) |
| Existing `--outfile-check-dir` results before cracking | [outfile-check startup](docs/startup-optimization.md#existing-outfile-results-before-cracking-allocation) |
| RTX 4090 autotune cache | [RTX_4090_AUTOTUNE_CACHE.md](RTX_4090_AUTOTUNE_CACHE.md) |
| Multi-file combinations and complete-candidate rules | [docs/multi-file-combination.md](docs/multi-file-combination.md) and [docs/whole-candidate-rules.md](docs/whole-candidate-rules.md) |
| Ordered component pipeline: attack mode 13 | [docs/multi-hybrid-mode13.md](docs/multi-hybrid-mode13.md) |
| Native PCFG training and attack feed | [docs/pcfg-attack.md](docs/pcfg-attack.md) |
| Final-candidate class requirements | [docs/candidate-requirements.md](docs/candidate-requirements.md) |
| Candidate methods 1-6 and implementation status | [docs/candidate-generation-roadmap.md](docs/candidate-generation-roadmap.md) |
| Runtime and checkpoint controls | [docs/runtime-controls.md](docs/runtime-controls.md) and [docs/checkpoint-control.md](docs/checkpoint-control.md) |
| Live forward seek by percentage or line | [docs/live-goto.md](docs/live-goto.md) |
| Interactive status output | [consistent remaining and recovery-rate lines](docs/shooter-enhancements.md#49-consistent-remaining-and-recovery-rate-status) |
| Resumable candidate output | [docs/stdout-sessions.md](docs/stdout-sessions.md) |
| mdxfind modes | [docs/mdxfind-modules.md](docs/mdxfind-modules.md) and the [complete JSON registry](docs/mdxfind-modules.json) |
| Windows builds | [how_to_compile.txt](how_to_compile.txt) |
| Linux builds | [BUILD.md](BUILD.md) |
| Error reports and privacy | [docs/error-reports.md](docs/error-reports.md) |
| Stage timing and peak memory | [docs/stage-profile.md](docs/stage-profile.md) |
| Sanitizers and parser fuzzing | [docs/security-testing.md](docs/security-testing.md) |
| SBOM and signed release attestations | [docs/release-security.md](docs/release-security.md) |
| Every release and verification result | [CHANGELOG.md](CHANGELOG.md) |
| Source comparison | [Feature origins](docs/shooter-enhancements.md) and the [complete Shooter delta from the merged upstream baseline](https://github.com/Shooter3k/shooter_hashcat/compare/eba388d2ef8d2dc6f184cb2effdc1a99493d888d...master) |

## Upstream hashcat and license

General hashcat help is available from the [Hashcat Wiki](https://hashcat.net/wiki/),
[`--help`](docs/hashcat-help.md), the
[Hashcat Forum](https://hashcat.net/forum/), and
[Discord](https://discord.gg/HFS523HGBT).

hashcat and the Shooter modifications are licensed under the MIT license. See
[docs/license.txt](docs/license.txt).
