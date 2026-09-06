# Multiple hash modes

Shooter Hashcat can apply one candidate attack to a file that contains hashes
from more than one algorithm:

```text
hashcat.exe --multi-hash-modes=0,1000,100 -a 0 mixed-hashes.txt words.txt
```

Use this only for hashes you are authorized to test. The option changes which
hash parsers and kernels receive the candidates; it does not identify an
unknown format with certainty.

## Mode-list syntax

The value is a comma-separated list of two or more modes. Numeric Hashcat
modes and mdxfind-compatible `eN` names are accepted:

```text
--multi-hash-modes=0,100,1400
--multi-hash-modes=e1,e3,e8,e10
--multi-hash-modes=100-101
--multi-hash-modes=e1-e25
```

Ranges are inclusive and must stay inside one spelling family. Exact
duplicates are removed while the first occurrence keeps its position. `e426`
is rejected because mdxfind defines it as a parallel throughput/counter mode,
not a digest algorithm. The current list limit is 4,096 distinct modes.
Every mode produced by a range must exist in the current build.

Do not combine `-m` with `--multi-hash-modes`. Benchmark, identify,
backend-information, hash-information, `--stdout`, keyspace-only,
total-candidate, and `--remove` sessions are also rejected. Removing hashes
from the source file would make later parsers miss input, so `--remove` is
intentionally fail-closed.

## Two execution paths

Shooter selects the path automatically.

The general path runs every existing hash mode from left to right in the order
listed. Each mode keeps its normal parser, optimized/pure-kernel choice,
bridge, device behavior, and candidate semantics. Lines that do not belong to
the current mode can produce the same parser warnings as an ordinary command
using that mode. A mode with no compatible lines is skipped. Slow hashes and
special formats use this path.

The shared path handles combinations drawn entirely from this table, provided
the list does not contain two aliases for the same digest:

| Formula | Numeric mode | mdxfind name |
| --- | ---: | ---: |
| `md5($pass)` | `0` | `e1` |
| `md4($pass)` | `900` | `e3` |
| `sha1($pass)` | `100` | `e8` |
| `sha256($pass)` | `1400` | `e10` |
| `sha512($pass)` | `1700` | `e12` |
| `md4(utf16le($pass))` (NTLM) | `1000` | `e369` |
| `md5(utf16le($pass))` | `70` | `e800` |
| `sha1(utf16le($pass))` | `170` | `e727` |
| `sha256(utf16le($pass))` | `1470` | `e805` |
| `sha512(utf16le($pass))` | `1770` | `e808` |
| `md5(md5($pass))` | `2600` | — |
| `md5(md5(md5($pass)))` | `3500` | — |
| `md5(uppercase(md5($pass)))` | `4300` | `e262` |
| `md5(sha1($pass))` | `4400` | `e178` |
| `sha1(sha1($pass))` | `4500` | — |
| `sha1(md5($pass))` | `4700` | `e160` |
| `sha1(md5(md5($pass)))` | `18500` | `e287` |
| `sha256(md5($pass))` | `20800` | `e164` |
| `md5(sha1($pass).md5($pass).sha1($pass))` | `20900` | `e442` |
| `sha512(sha512_bin($pass))` | `21000` | `e38` |
| `sha256(sha256_bin($pass))` | `21400` | `e36` |
| `md5(sha1(md5($pass)))` | `32800` | `e188` |
| `sha224(sha1($pass))` | `34500` | `e766` |

For example, `0,e3,100` is one valid shared run. `0,e1` names MD5 twice, so it
cannot be fused; it remains valid and automatically uses the ordered general
path. Other mixtures of native and `eN` modes behave the same way whenever a
shared kernel does not cover the complete list.

Every available numeric or mdxfind-compatible mode can still be requested in
one command. "One command" is not always one physical GPU kernel pass. Salted
hashes, bcrypt, Argon2, archives, wallets, and other schema- or cost-specific
algorithms need their normal parser, salt layout, memory allocation, and kernel
loop. Shooter therefore processes those modes through the ordered general path
instead of pretending that unlike work can safely share one kernel launch.

The shared kernel receives each fully generated candidate once, computes all
selected digests, canonicalizes them as lowercase hexadecimal text, and looks
them up in one target table. Wordlist rules and mask attacks work normally.
`-O` cannot make this internal family use the individual modes' optimized
kernels; the shared implementation deliberately uses its own pure kernel.

Status identifies this implementation as internal mode `79997` and names it
`Shooter shared unsalted hash family`. Do not select `-m 79997` directly. The mode
exists only as an implementation detail of `--multi-hash-modes`.

Shared results are reported as soon as the GPU finds them. That discovery
order can differ from the list order. The general path, `--show`, and `--left`
retain list order.

## Mixed input and output attribution

Put one hash per line in the input file. The shared family accepts lowercase
or uppercase raw hexadecimal strings of 32, 40, 56, 64, or 128 characters. A
value is intentionally tested by every selected algorithm with the same output
length because the hexadecimal text alone cannot identify its formula.

Every text outfile row begins with the public mode:

```text
0:8743b52063cd84097a65d1633f5c74f5:hashcat
100:b89eaac7e61417341b710b727768294d0e6a277b:hashcat
```

JSON output adds a `hash_mode` property. Shooter potfile rows use a private
prefix such as:

```text
$shooter-mode$0$8743b52063cd84097a65d1633f5c74f5:hashcat
```

The tag is required in multi-mode sessions. Untagged entries and entries for
another mode are ignored, which prevents identical-length raw formats from
cross-crediting a result. Existing single-mode potfile rows are left intact
but are not assumed to have reliable algorithm attribution.

Use the same list to display saved results:

```text
hashcat.exe --show --multi-hash-modes=0,1000,100 mixed-hashes.txt
```

## Restore and completion

The general path stores the current list position in restore format 723. When
one mode cracks every line it can parse, Shooter resets only that mode's stop
condition and continues with the remaining modes. User quit, checkpoint,
finish, runtime, and error states still stop the whole session.

The shared path stores the ordinary candidate position and rebuilds the same
selected kernel on restore. Mode-tagged potfile rows are loaded before work is
resumed, so already recovered targets are not retested as remaining hashes.

Restore files older than format 723 do not contain a mode-list position. They
predate this option and therefore resume at list position zero if reused with
a multi-mode command.

## Verification

The regression script checks parsing, ordered `--show`, potfile isolation,
numeric and `eN` attribution, all 23 shared algorithm families, uppercase
input, JSON attribution, `-O` pure-kernel fallback, wordlist rules, masks,
shared potfile reuse, the sequential fallback, and ordinary single-mode
restore:

```powershell
.\tools\test_multi_hash_modes.ps1
.\tools\test_multi_hash_modes.ps1 -RunGpuCrack
```

The GPU form defaults to device 1 and uses only tiny known-answer fixtures.
