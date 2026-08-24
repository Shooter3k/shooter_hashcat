# Live forward seek with `[g]oto`

During a running or paused attack, press `g` and enter one whole number. The
number is interpreted by value:

- `0` through `100`, inclusive, is a percentage of the current base keyspace.
- Any number above `100` is an exact one-based line/base position.
- Press Enter without a value to cancel.

For example, on a 1,000,000-line base wordlist, `25` selects 25 percent and
makes line 250,001 the next new dispatch position. Entering `500001` selects
line 500,001 exactly. `100` always means 100 percent, not line 100, and moves
new dispatch to the end of the current keyspace.

## Forward-only safety

Go-to moves only the first position that has not already been assigned to a
GPU. It never cancels an active kernel or reuses a completed position.
Consequently:

- The requested position must be ahead of the next undispatched position.
- GPU batches assigned before `g` was pressed finish normally. Their results
  may appear briefly after the go-to acceptance message.
- New batches begin at the requested position.
- The intentionally skipped interval is booked as rejected progress, including
  its rule, mask, combination, or other amplification. Progress and ETA can
  still reach their correct final totals.
- The restore point remains conservative until already-assigned work finishes.
  A crash in that short interval can repeat work but cannot omit work that was
  neither completed nor intentionally skipped.

Backward seeking is rejected because already-cracked output, potfile state,
debug/loopback output, and per-device progress cannot be undone safely inside a
live session. To revisit an earlier position, stop the attack and start or
restore a new session at the desired `--skip` value.

## What a position means

The target addresses the current attack round's unamplified base keyspace:

- In a normal wordlist attack, it is the wordlist line before rules are
  expanded. All rule candidates belonging to skipped base lines are skipped.
- When multiple wordlists form one feed, it is the global base position across
  those wordlists in their configured order.
- For a mask or another generated source, it is a generated base position, not
  a physical file line.
- In attack mode 13, it is the current base pipeline position. A mask,
  wordlist, or rule suffix compiled as GPU amplification remains attached to
  that position, so this is not necessarily the final candidate number.
- With increment mode, mask files, or another queue of rounds, percentages and
  positions apply to the round currently displayed by Hashcat.

The status page's progress can be slightly ahead of visible cracked output
because work is assigned to GPUs in batches. Go-to deliberately uses the next
*undispatched* position, which is the only boundary that prevents duplicate GPU
assignment.

## Limits

Live go-to is unavailable for stdin candidate streams because they have no
seekable position. It is also unavailable with `--stdout`, where skipping live
positions would break the ordered candidate-output contract. Invalid values,
out-of-range line positions, and requests at or behind current dispatch are
reported without changing the attack.
