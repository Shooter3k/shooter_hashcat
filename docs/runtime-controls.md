# Interactive runtime controls

These controls are available during an attack started with a positive
`--runtime` value. They do not appear when no runtime limit was requested.

- Press `e` to enable extend mode. The runtime countdown freezes while extend
  is active, allowing one additional second of wall time for every second it
  remains enabled. Press `e` again to return to the normal countdown.
- Press `l` to subtract 1% of the originally configured `--runtime` value from
  the remaining runtime. Every press is cumulative: ten presses subtract
  exactly 10%, and the reduction is capped at 100%. Hashcat immediately prints
  an updated status page showing the changed runtime clock and the cumulative
  `Runtime.Reduced.` percentage.

Extend and lower are independent. Pressing `l` while extend is active applies
the fixed reduction but leaves the runtime countdown paused; pressing `e`
again resumes it from the reduced value. Pausing the cracking devices with `p`
continues to pause the ordinary runtime countdown.

Example prompt:

```text
[s]tatus [p]ause [b]ypass [g]oto [c]heckpoint [f]inish [q]uit [e]xtend [l]ower 1% =>
```

The always-available `g` key is separate from runtime extension. It seeks new
dispatch forward by percentage or one-based line/base position; see
[Live forward seek](live-goto.md).
