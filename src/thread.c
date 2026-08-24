/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include <inttypes.h>
#include "event.h"
#include "timer.h"
#include "user_options.h"
#include "thread.h"

/*
#if defined (_WIN)

BOOL WINAPI sigHandler_default (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

       *
       * special case see: https://stackoverflow.com/questions/3640633/c-setconsolectrlhandler-routine-issue/5610042#5610042
       * if the user interacts w/ the user-interface (GUI/cmd), we need to do the finalization job within this signal handler
       * function otherwise it is too late (e.g. after returning from this function)
       *

      myabort (hashcat_ctx->status_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myabort (hashcat_ctx->status_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

BOOL WINAPI sigHandler_benchmark (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

      myquit (hashcat_ctx->status_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myquit (hashcat_ctx->status_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

void hc_signal (BOOL WINAPI (callback) (DWORD))
{
  if (callback == NULL)
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, FALSE);
  }
  else
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, TRUE);
  }
}

#else

void sigHandler_default (int sig)
{
  myabort (hashcat_ctx->status_ctx);

  signal (sig, NULL);
}

void sigHandler_benchmark (int sig)
{
  myquit (hashcat_ctx->status_ctx);

  signal (sig, NULL);
}

void hc_signal (void (callback) (int))
{
  if (callback == NULL) callback = SIG_DFL;

  signal (SIGINT,  callback);
  signal (SIGTERM, callback);
  signal (SIGABRT, callback);
}

#endif
*/

int mycracked (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_CRACKED;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort_checkpoint (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_ABORTED_CHECKPOINT;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort_finish (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_ABORTED_FINISH;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort_runtime (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_ABORTED_RUNTIME;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  //those checks create problems in benchmark mode, it's simply too short of a timeframe where it's running as STATUS_RUNNING
  // not sure if this is still valid, but abort is also called by gpu temp monitor
  //if (status_ctx->devices_status != STATUS_RUNNING) return;

  status_ctx->devices_status = STATUS_ABORTED;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myquit (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const bool running = ((status_ctx->devices_status == STATUS_RUNNING) || (status_ctx->devices_status == STATUS_PAUSED));

  // A session that has already failed still has to be quittable.
  //
  // A device thread that gives up sets STATUS_ERROR and returns, and every other device thread keeps
  // running, because nothing clears the run flags on that path. The guard here used to refuse any
  // status but the two above, so q cleared nothing and returned -1, and the caller does not look at
  // the return value. The session was then unquittable and only a signal ended it. What made this
  // reachable was a bridge losing its last board: the status line said Error and the remaining
  // devices carried on with a keyspace 29 days wide.
  //
  // The error status is kept rather than replaced with STATUS_QUIT, because the session really did
  // fail and the exit code has to keep saying so.

  const bool failed = (status_ctx->devices_status == STATUS_ERROR);

  if ((running == false) && (failed == false)) return -1;

  if (running == true) status_ctx->devices_status = STATUS_QUIT;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

static bool live_seek_parse (const char *request, u64 *value)
{
  const u8 *ptr = (const u8 *) request;

  while ((*ptr == ' ') || (*ptr == '\t')) ptr++;

  if ((*ptr < '0') || (*ptr > '9')) return false;

  u64 parsed = 0;

  const u64 max_u64 = -1ULL;

  while ((*ptr >= '0') && (*ptr <= '9'))
  {
    const u64 digit = *ptr - '0';

    if (parsed > ((max_u64 - digit) / 10)) return false;

    parsed = (parsed * 10) + digit;

    ptr++;
  }

  while ((*ptr == ' ') || (*ptr == '\t')) ptr++;

  if (*ptr != 0) return false;

  *value = parsed;

  return true;
}

int live_seek (hashcat_ctx_t *hashcat_ctx, const char *request)
{
  hashes_t             *hashes             = hashcat_ctx->hashes;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  const user_options_t *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  u64 requested = 0;

  if (live_seek_parse (request, &requested) == false)
  {
    event_log_warning (hashcat_ctx, "Go-to needs one whole number: 0 through 100 is a percentage; anything above 100 is a one-based line/base position.");

    return -1;
  }

  if (user_options->stdout_flag == true)
  {
    event_log_warning (hashcat_ctx, "Go-to is unavailable with --stdout because skipping would break ordered candidate output.");

    return -1;
  }

  if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    event_log_warning (hashcat_ctx, "Go-to is unavailable for candidates read from stdin because that stream cannot seek forward by position.");

    return -1;
  }

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  const bool active = ((status_ctx->devices_status == STATUS_RUNNING) || (status_ctx->devices_status == STATUS_PAUSED));

  if ((status_ctx->accessible == false) || (active == false))
  {
    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    event_log_warning (hashcat_ctx, "Go-to is available only while an attack is running or paused.");

    return -1;
  }

  const u64 end = (status_ctx->words_limit == 0)
                ? status_ctx->words_base
                : MIN (status_ctx->words_limit, status_ctx->words_base);

  if ((end == 0) || (end == -1ULL))
  {
    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    event_log_warning (hashcat_ctx, "Go-to cannot be used because the current base keyspace size is unknown.");

    return -1;
  }

  const bool percentage = (requested <= 100);

  u64 target;

  if (percentage == true)
  {
    target = ((end / 100) * requested) + (((end % 100) * requested) / 100);
  }
  else
  {
    target = requested - 1;

    if (target >= end)
    {
      hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

      event_log_warning (hashcat_ctx, "Go-to line/base position is outside the current keyspace (maximum: %" PRIu64 ").", end);

      return -1;
    }
  }

  const u64 from = status_ctx->words_off;

  if (target <= from)
  {
    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    const double current_percent = ((double) from / (double) end) * 100.0;

    event_log_warning (hashcat_ctx, "Go-to is forward-only. The next undispatched line/base position is %" PRIu64 " of %" PRIu64 " (%.2f%%).", MIN (from + 1, end), end, current_percent);

    return -1;
  }

  const u64 skipped = target - from;
  const u64 amplifier = user_options_extra_amplifier (hashcat_ctx);

  // Keep dispatch stopped until its skipped range is visible in progress. In
  // particular, a 100-percent seek can make the device threads finish as soon
  // as this mutex is released, so publishing the counters afterwards could
  // leave the final status one interval short.
  hc_thread_mutex_lock (status_ctx->mux_counter);

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    const u64 salt_end = MIN (target, hashes->salts_cnt);

    for (u64 salt_pos = from; salt_pos < salt_end; salt_pos++)
    {
      status_ctx->words_progress_rejected[salt_pos] += amplifier;
    }
  }
  else
  {
    for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
    {
      status_ctx->words_progress_rejected[salt_pos] += skipped * amplifier;
    }
  }

  hc_thread_mutex_unlock (status_ctx->mux_counter);

  if (user_options->slow_candidates == true) status_ctx->words_seek_guard = target;

  status_ctx->words_off = target;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  if (target == end)
  {
    event_log_info (hashcat_ctx, "Go-to accepted: %" PRIu64 "%% selected the end of the current base keyspace (%" PRIu64 " positions).", requested, end);
    event_log_info (hashcat_ctx, "Skipped %" PRIu64 " undispatched base positions; already-assigned GPU work will finish before the attack completes.", skipped);
  }
  else if (percentage == true)
  {
    event_log_info (hashcat_ctx, "Go-to accepted: %" PRIu64 "%% maps to line/base position %" PRIu64 " of %" PRIu64 ".", requested, target + 1, end);
    event_log_info (hashcat_ctx, "Skipped %" PRIu64 " undispatched base positions; new GPU dispatch starts there after already-assigned work.", skipped);
  }
  else
  {
    event_log_info (hashcat_ctx, "Go-to accepted: line/base position %" PRIu64 " of %" PRIu64 ".", requested, end);
    event_log_info (hashcat_ctx, "Skipped %" PRIu64 " undispatched base positions; new GPU dispatch starts there after already-assigned work.", skipped);
  }

  return 0;
}

// Move the dispatcher to the first word of the next source the feed was given, and say whether there
// was one.
//
// Bypass means "skip the wordlist I am on". Several dictionaries used to be several attacks, so ending
// the attack was the same thing as moving to the next one. A feed lays them end to end into a single
// keyspace, so ending the attack there skips every remaining dictionary at once, which is not what the
// key means and is what a user reported. The offsets of the sources are already known, because the
// status display uses them to say which one the run has reached.
//
// The words in between are booked as rejected. Progress counts everything that has been decided, not
// only what was hashed, and without booking them the run can never reach its keyspace and never ends.
//
// Returns false when there is nothing to move to, and then the caller bypasses the way it always did.
// That covers a single source, the last source, and every attack mode not reading from a feed.

static bool bypass_to_next_source (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options_extra->base_source != BASE_SOURCE_FEED) return false;

  const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

  if (generic_ctx->enabled == false) return false;

  const generic_global_ctx_t *global_ctx = &generic_ctx->global_ctx;

  if (global_ctx->segments_cnt < 2) return false;

  hashes_t     *hashes     = hashcat_ctx->hashes;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  const u64 words_off = status_ctx->words_off;

  bool found = false;

  u64 next_first = 0;

  for (u64 i = 0; i < global_ctx->segments_cnt; i++)
  {
    if (global_ctx->segment_first[i] <= words_off) continue;

    next_first = global_ctx->segment_first[i];

    found = true;

    break;
  }

  if (found == false)
  {
    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    return false;
  }

  const u64 skipped = next_first - words_off;

  status_ctx->words_off = next_first;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  const u64 amplifier = user_options_extra_amplifier (hashcat_ctx);

  hc_thread_mutex_lock (status_ctx->mux_counter);

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    status_ctx->words_progress_rejected[salt_pos] += skipped * amplifier;
  }

  hc_thread_mutex_unlock (status_ctx->mux_counter);

  return true;
}

int bypass (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (bypass_to_next_source (hashcat_ctx) == true) return 0;

  status_ctx->devices_status = STATUS_BYPASS;

  status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  status_ctx->checkpoint_shutdown = false;
  status_ctx->finish_shutdown     = false;

  return 0;
}

int SuspendThreads (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status != STATUS_RUNNING) return -1;

  hc_timer_set (&status_ctx->timer_paused);

  status_ctx->devices_status = STATUS_PAUSED;

  return 0;
}

int ResumeThreads (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status != STATUS_PAUSED) return -1;

  const double msec_paused = hc_timer_get (status_ctx->timer_paused);

  status_ctx->msec_paused += msec_paused;

  status_ctx->devices_status = STATUS_RUNNING;

  return 0;
}

int SuspendRuntime (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_timer_set (&status_ctx->timer_runtime_paused);

  status_ctx->runtime_status = STATUS_PAUSED;

  return 0;
}

int ResumeRuntime (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const double msec_runtime_paused = hc_timer_get (status_ctx->timer_runtime_paused);

  status_ctx->msec_runtime_paused += msec_runtime_paused;

  status_ctx->runtime_status = STATUS_RUNNING;

  return 0;
}

int StartLowerRuntime (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_timer_set (&status_ctx->timer_runtime_lowered);

  status_ctx->runtime_lower_enabled = true;

  return 0;
}

int StopLowerRuntime (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const double msec_runtime_lowered = hc_timer_get (status_ctx->timer_runtime_lowered);

  status_ctx->msec_runtime_lowered += msec_runtime_lowered;

  status_ctx->runtime_lower_enabled = false;

  return 0;
}

int stop_at_checkpoint (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // this feature only makes sense if --restore-disable was not specified

  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false)
  {
    event_log_warning (hashcat_ctx, "This feature is disabled when --restore-disable is specified.");

    return -1;
  }

  // Enable or Disable. A checkpoint request is deliberately separate from a hard worker stop.
  // Workers park at their next completed launch and remain alive until either every worker has
  // arrived (a real checkpoint exit) or the request is cancelled. This distinction is what lets
  // GPUs that reached the checkpoint first resume along with the slower GPUs.

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  if (status_ctx->checkpoint_shutdown == false)
  {
    if ((status_ctx->devices_status != STATUS_RUNNING) && (status_ctx->devices_status != STATUS_PAUSED))
    {
      hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

      return -1;
    }

    status_ctx->checkpoint_shutdown = true;

    status_ctx->run_main_level1   = false;
    status_ctx->run_main_level2   = false;
    status_ctx->run_main_level3   = false;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }
  else
  {
    if ((status_ctx->devices_status != STATUS_RUNNING) && (status_ctx->devices_status != STATUS_PAUSED))
    {
      hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

      return -1;
    }

    status_ctx->checkpoint_shutdown = false;

    status_ctx->run_main_level1   = true;
    status_ctx->run_main_level2   = true;
    status_ctx->run_main_level3   = true;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  return 0;
}

int finish_after_attack (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // Enable or Disable

  if (status_ctx->finish_shutdown == false)
  {
    status_ctx->finish_shutdown = true;

    status_ctx->run_main_level1   = false;
    status_ctx->run_main_level2   = false;
    status_ctx->run_main_level3   = false;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }
  else
  {
    status_ctx->finish_shutdown = false;

    status_ctx->run_main_level1   = true;
    status_ctx->run_main_level2   = true;
    status_ctx->run_main_level3   = true;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }

  return 0;
}
