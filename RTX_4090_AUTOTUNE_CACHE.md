# RTX 4090 persisted autotuning

This build automatically remembers successful autotune results for NVIDIA
GeForce RTX 4090 cards. On the first matching run, hashcat performs its normal
autotune and stores the selected kernel accel, loops, threads, and measured
kernel time in `hashcat.autotune-cache`. Later matching runs validate that
profile with two short kernel launches and reuse it, avoiding the full search.

Profiles also remain useful after rebuilding Hashcat. The build timestamp is
not trusted across executables: an otherwise identical prior-build entry only
supplies its learned acceleration, loops, and thread geometry. The current
kernel measures that geometry against the real workload before using it. A
successful validation writes a fresh current-build entry; a rejected value
falls through to normal autotune. The lookup searches every otherwise
compatible entry, preferring one that covers the current salt/digest counts
and then the nearest workload size. GPU, driver, hash/attack configuration,
optimization flags, and tuning limits must still match.

The twelve 4090s in one machine share a profile when their relevant limits are
identical, so the cache stores one entry rather than twelve duplicate entries.

## Safety and invalidation

A profile is reused only when all of these still match:

- hashcat executable build time
- CUDA driver version and CUDA architecture
- GPU processor count and vector width
- hash mode, kernel type, attack mode/kernel, and workload profile
- optimized/pure kernel flags and module option flags
- slow-candidate state and the loaded salt/digest counts
- current minimum and maximum accel, loops, and threads

The cached values must also remain within the current runtime limits. Hashcat
initializes the same synthetic candidates, rule buffer, and outside-kernel
preparation used by full autotune before measuring the cached profile. Two
timed launches must complete successfully and remain within a safe upper
bound: the larger of the selected workload target or four times the stored
runtime, capped at 2 seconds. Faster measurements are accepted. This tolerates
CUDA scheduling, clock, power, and thermal variance while 12 GPUs validate
concurrently, but still rejects a launch that has become materially too slow.

Per-device validation runs concurrently. Cache messages are serialized with a
dedicated log mutex so all device numbers remain correct on multi-GPU systems.

The cache never overrides explicit `-n`, `-u`, or `-T` values or `--force`.
It covers every GPU cracking attack mode, including modes 11 through 14 and
`--slow-candidates`; each distinct configuration receives its own key. It is
disabled for bridges, the non-cracking stdout mode, and private modes
29960/29970/29990. A configuration whose accel, loops, and threads are already
fully fixed is not written because it has no tuning search to avoid.

Set this environment variable to bypass the cache for a run:

```powershell
$env:HASHCAT_AUTOTUNE_CACHE_DISABLE = '1'
.\hashcat.exe ...
```

Remove it again with:

```powershell
Remove-Item Env:HASHCAT_AUTOTUNE_CACHE_DISABLE
```

To discard every saved profile and force fresh tuning, delete:

```powershell
Remove-Item .\hashcat.autotune-cache -Force
```

The cache file is generated runtime state and is ignored by Git. A clean
rebuild produces a new executable build identifier, so entries from the old
binary cannot be reused.

## Reapplying after an upstream update

Keep these files together when committing or reapplying this feature:

- `include/types.h` - per-device cache state
- `include/autotune.h` - finalization declaration
- `src/autotune.c` - keying, validation, loading, tuning fallback, and saving
- `src/hashcat.c` - saves results after all device autotune threads finish
- `.gitignore` - excludes the generated cache file
- `RTX_4090_AUTOTUNE_CACHE.md` and `how_to_compile.txt` - Windows operation and build notes

After resolving an upstream update, use `make clean && make -j`, then rerun a
cold and warm known-answer test. Changes to `include/types.h` must not be tested
with an incremental-only build.

The Windows validation performed for this version used MD5 known answers on
attack modes 0, 1, 3, 6, 7, 8, 9, and 11 through 14, plus `--slow-candidates`.
Every cold run saved a distinct profile and every warm run reused it while
recovering the expected plaintext. A mode-0 warm profile was also reused and
validated independently on all 12 RTX 4090 devices. A forced manual
`-n/-u/-T` run recovered the expected plaintext without reading or changing the
cache.
