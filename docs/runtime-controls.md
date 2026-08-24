# Interactive runtime controls

These controls are available during an attack started with a positive
`--runtime` value. They do not appear when no runtime limit was requested.

- Press `e` to enable extend mode. The runtime countdown freezes while extend
  is active, allowing one additional second of wall time for every second it
  remains enabled. Press `e` again to return to the normal countdown.
- Press `l` to enable lower mode. The runtime countdown runs at 2x speed while
  lower is active: normal elapsed time continues to count down and an equal
  amount is also subtracted. Press `l` again to return to normal speed.

Extend and lower are mutually exclusive. Pressing `l` while extend is active
switches directly to lower; pressing `e` while lower is active switches
directly to extend. Pausing the cracking devices with `p` also pauses either
runtime adjustment so a device pause does not silently change the limit.

Example prompt:

```text
[s]tatus [p]ause [b]ypass [g]oto [c]heckpoint [f]inish [q]uit [e]xtend [l]ower =>
```

The always-available `g` key is separate from runtime extension. It seeks new
dispatch forward by percentage or one-based line/base position; see
[Live forward seek](live-goto.md).
