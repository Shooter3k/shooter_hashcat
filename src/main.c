/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <getopt.h>
#include <unistd.h>

#if defined (_WIN)
#include <windows.h>
#include <shellapi.h>
#endif

#include "types.h"
#include "user_options.h"
#include "usage.h"
#include "memory.h"
#include "hashcat.h"
#include "terminal.h"
#include "thread.h"
#include "status.h"
#include "shared.h"
#include "system.h"
#include "timer.h"
#include "event.h"
#include "hwmon.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

#if defined (__MINGW64__) || defined (__MINGW32__)
int _dowildcard = -1;
#endif

#if defined (_WIN)

static int    main_argc_utf8 = 0;
static char **main_argv_utf8 = NULL;

// MinGW presents main() with arguments converted through the active ANSI code
// page and may also expand wildcards. A command-line mask contains '?' tokens,
// so a UTF-8 mask can differ from argv even when no filesystem expansion took
// place. Compare against the expected ANSI conversion to tell those cases
// apart: equality means only the encoding changed and the UTF-8 argument is the
// one to keep; inequality means MinGW replaced the wildcard with a path.

static bool main_arg_wildcard_was_expanded (const wchar_t *arg_wide, const char *arg_crt)
{
  const int ansi_size = WideCharToMultiByte (CP_ACP, 0, arg_wide, -1, NULL, 0, NULL, NULL);

  if (ansi_size == 0) return true;

  char *arg_ansi = (char *) malloc (ansi_size);

  if (arg_ansi == NULL) return true;

  const int rc = WideCharToMultiByte (CP_ACP, 0, arg_wide, -1, arg_ansi, ansi_size, NULL, NULL);

  const bool expanded = (rc == 0) || (strcmp (arg_ansi, arg_crt) != 0);

  free (arg_ansi);

  return expanded;
}

static void main_argv_utf8_destroy (void)
{
  for (int i = 0; i < main_argc_utf8; i++) free (main_argv_utf8[i]);

  free (main_argv_utf8);
}

static int main_argv_utf8_init (int *argc, char ***argv)
{
  int argc_wide = 0;

  LPWSTR *argv_wide = CommandLineToArgvW (GetCommandLineW (), &argc_wide);

  if (argv_wide == NULL) return -1;

  char **argv_utf8 = (char **) calloc (argc_wide + 1, sizeof (char *));

  if (argv_utf8 == NULL)
  {
    LocalFree (argv_wide);

    return -1;
  }

  for (int i = 0; i < argc_wide; i++)
  {
    const int utf8_size = WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, argv_wide[i], -1, NULL, 0, NULL, NULL);

    if (utf8_size == 0)
    {
      for (int j = 0; j < i; j++) free (argv_utf8[j]);

      free (argv_utf8);

      LocalFree (argv_wide);

      return -1;
    }

    argv_utf8[i] = (char *) malloc (utf8_size);

    if (argv_utf8[i] == NULL)
    {
      for (int j = 0; j < i; j++) free (argv_utf8[j]);

      free (argv_utf8);

      LocalFree (argv_wide);

      return -1;
    }

    if (WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, argv_wide[i], -1, argv_utf8[i], utf8_size, NULL, NULL) == 0)
    {
      for (int j = 0; j <= i; j++) free (argv_utf8[j]);

      free (argv_utf8);

      LocalFree (argv_wide);

      return -1;
    }
  }

  // MinGW expands wildcard arguments before main(). CommandLineToArgvW() does
  // not, so retain the CRT argv when replacing it would undo that expansion.
  bool keep_crt_argv = (argc_wide != *argc);

  if (keep_crt_argv == false)
  {
    for (int i = 0; i < argc_wide; i++)
    {
      bool has_wildcard = false;

      for (const wchar_t *ptr = argv_wide[i]; *ptr != 0; ptr++)
      {
        if ((*ptr == L'*') || (*ptr == L'?'))
        {
          has_wildcard = true;

          break;
        }
      }

      if ((has_wildcard == true)
       && (strcmp (argv_utf8[i], (*argv)[i]) != 0)
       && (main_arg_wildcard_was_expanded (argv_wide[i], (*argv)[i]) == true))
      {
        keep_crt_argv = true;

        break;
      }
    }
  }

  if (keep_crt_argv == true)
  {
    for (int i = 0; i < argc_wide; i++) free (argv_utf8[i]);

    free (argv_utf8);

    LocalFree (argv_wide);

    return 0;
  }

  LocalFree (argv_wide);

  main_argc_utf8 = argc_wide;
  main_argv_utf8 = argv_utf8;

  if (atexit (main_argv_utf8_destroy) != 0)
  {
    main_argv_utf8_destroy ();

    main_argc_utf8 = 0;
    main_argv_utf8 = NULL;

    return -1;
  }

  *argc = argc_wide;
  *argv = argv_utf8;

  return 0;
}

#endif

// Build the argument vector for the one automatic pure-kernel retry. The strings remain owned by
// the original command line; only the pointer array is new. Forcing the parsed option off as well
// covers an unusual clustered short option while the ordinary -O and long spelling are omitted
// from restore metadata and diagnostics.

static char **main_pure_kernel_argv (const int argc, char **argv, int *pure_argc)
{
  char **pure_argv = (char **) hccalloc (argc + 1, sizeof (char *));

  int out = 0;

  for (int i = 0; i < argc; i++)
  {
    if (strcmp (argv[i], "-O") == 0) continue;
    if (strcmp (argv[i], "--optimized-kernel-enable") == 0) continue;

    pure_argv[out++] = argv[i];
  }

  pure_argv[out] = NULL;

  *pure_argc = out;

  return pure_argv;
}

static int main_user_options_reload (hashcat_ctx_t *hashcat_ctx, const int argc, char **argv, const bool force_pure_kernel)
{
  memset (hashcat_ctx->user_options, 0, sizeof (user_options_t));

  if (user_options_init (hashcat_ctx) == -1) return -1;

  if (user_options_getopt (hashcat_ctx, argc, argv) == -1)
  {
    user_options_destroy (hashcat_ctx);

    return -1;
  }

  if (force_pure_kernel == true) hashcat_ctx->user_options->optimized_kernel = false;

  if (user_options_sanity (hashcat_ctx) == -1)
  {
    user_options_destroy (hashcat_ctx);

    return -1;
  }

  return 0;
}

// Most attacks with an interactive prompt read their base candidates through the mask or generic
// feed. Host-produced multi-input attacks keep wordlist_mode at NONE even though they need the
// same keyboard/status handling.

static bool main_has_terminal_prompt (const hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // --stdout is a candidate stream, not an interactive attack. In particular, mode 13 must not
  // start the keyboard thread merely because its normal cracking path has a prompt: doing so can
  // delay process exit while the thread waits for console input and can mix a prompt with scripts'
  // diagnostic streams.

  if (user_options->stdout_flag == true) return false;

  if (user_options_extra->wordlist_mode == WL_MODE_MASK)    return true;
  if (user_options_extra->wordlist_mode == WL_MODE_GENERIC) return true;
  if ((user_options->attack_mode == ATTACK_MODE_COMBI) && (user_options_extra->hc_workc > 2)) return true;
  if (user_options->attack_mode == ATTACK_MODE_MULTI_HYBRID) return true;

  return false;
}

static void main_log_clear_line (MAYBE_UNUSED const size_t prev_len, MAYBE_UNUSED FILE *fp)
{
  const bool is_terminal = (fp == stderr) ? is_stderr_terminal () : is_stdout_terminal ();

  if (is_terminal == false) return;

  #if defined (_WIN)

  fputc ('\r', fp);

  for (size_t i = 0; i < prev_len; i++) fputc (' ', fp);

  fputc ('\r', fp);

  #else

  fputs ("\033[2K\r", fp);

  #endif
}

static bool main_log_is_pure_kernel_feature (const char *msg_buf, const size_t msg_len)
{
  static const char pure_kernel_prefix[] = "Kernel.Feature...: Pure Kernel ";

  const size_t prefix_len = sizeof (pure_kernel_prefix) - 1;

  if (msg_len < prefix_len) return false;

  return (memcmp (msg_buf, pure_kernel_prefix, prefix_len) == 0);
}

#if defined (_WIN)
static void main_log_write_utf8 (FILE *fp, HANDLE hConsole, const bool is_terminal, const char *buf, const size_t len)
{
  // Internally Hashcat keeps paths, status text, and printable candidates as UTF-8. fwrite() sends
  // those bytes through the console's active OEM/ANSI code page, which corrupts valid multibyte
  // candidate previews unless the user happened to select code page 65001. Write UTF-16 directly
  // to a real Windows console instead. Redirected output deliberately stays byte-for-byte UTF-8.

  if ((is_terminal == false) || (len == 0) || (len > INT_MAX))
  {
    fwrite (buf, len, 1, fp);

    return;
  }

  const int wide_len = MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, buf, (int) len, NULL, 0);

  if (wide_len <= 0)
  {
    // Candidate display hexifies invalid UTF-8 before it reaches this point. Keep a byte-preserving
    // fallback for other diagnostics that may intentionally contain arbitrary input bytes.

    fwrite (buf, len, 1, fp);

    return;
  }

  wchar_t *wide_buf = (wchar_t *) malloc ((size_t) wide_len * sizeof (wchar_t));

  if (wide_buf == NULL)
  {
    fwrite (buf, len, 1, fp);

    return;
  }

  if (MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, buf, (int) len, wide_buf, wide_len) != wide_len)
  {
    free (wide_buf);

    fwrite (buf, len, 1, fp);

    return;
  }

  int wide_pos = 0;

  while (wide_pos < wide_len)
  {
    const DWORD wide_left = (DWORD) MIN (wide_len - wide_pos, 16384);

    DWORD wide_written = 0;

    if (WriteConsoleW (hConsole, wide_buf + wide_pos, wide_left, &wide_written, NULL) == 0)
    {
      // Falling back is safe only before WriteConsoleW has emitted anything; otherwise it would
      // duplicate the already-visible prefix.

      if (wide_pos == 0) fwrite (buf, len, 1, fp);

      break;
    }

    if (wide_written == 0)
    {
      if (wide_pos == 0) fwrite (buf, len, 1, fp);

      break;
    }

    wide_pos += (int) wide_written;
  }

  free (wide_buf);
}
#endif

static void main_log (hashcat_ctx_t *hashcat_ctx, FILE *fp, const int loglevel)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  const char  *msg_buf     = event_ctx->msg_buf;
  const size_t msg_len     = event_ctx->msg_len;
  const bool   msg_newline = event_ctx->msg_newline;

  // handle last_len

  const size_t prev_len = event_ctx->prev_len;

  if (prev_len)
  {
    FILE *prev_fp = (event_ctx->prev_on_stderr == true) ? stderr : stdout;

    const bool prev_is_terminal = (prev_fp == stderr) ? is_stderr_terminal () : is_stdout_terminal ();

    if (prev_is_terminal == true)
    {
      main_log_clear_line (prev_len, prev_fp);
    }
    else
    {
      // No-newline events are progress-line replacements on an interactive terminal. Redirected
      // streams cannot erase that previous text, so terminate the pending record before emitting
      // the replacement. Without this, worker/transcript output becomes e.g.
      // "Please be patient...Counted lines" and several parse/sort events run together.

      fwrite (EOL, strlen (EOL), 1, prev_fp);

      fflush (prev_fp);
    }
  }

  if (msg_newline == true)
  {
    event_ctx->prev_len = 0;
  }
  else
  {
    event_ctx->prev_len       = msg_len;
    event_ctx->prev_on_stderr = (fp == stderr);
  }

  #if defined (_WIN)
  HANDLE hConsole = GetStdHandle ((fp == stderr) ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);

  CONSOLE_SCREEN_BUFFER_INFO con_info;

  GetConsoleScreenBufferInfo (hConsole, &con_info);

  const int orig = con_info.wAttributes;
  #endif

  // color stuff pre
  const bool is_terminal = (fp == stderr) ? is_stderr_terminal () : is_stdout_terminal ();
  const bool highlight_pure_kernel = main_log_is_pure_kernel_feature (msg_buf, msg_len);

  if (is_terminal == true)
  {
  #if defined (_WIN)
    if (highlight_pure_kernel == true)
    {
      SetConsoleTextAttribute (hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }
    else switch (loglevel)
    {
      case LOGLEVEL_INFO:
        break;
      case LOGLEVEL_WARNING: SetConsoleTextAttribute (hConsole, 6);
        break;
      case LOGLEVEL_ERROR:   SetConsoleTextAttribute (hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        break;
      case LOGLEVEL_ADVICE:  SetConsoleTextAttribute (hConsole, 6);
        break;
    }

  #else
    if (highlight_pure_kernel == true)
    {
      fwrite ("\033[1;33m", 7, 1, fp);
    }
    else switch (loglevel)
    {
      case LOGLEVEL_INFO:                                   break;
      case LOGLEVEL_WARNING: fwrite ("\033[33m", 5, 1, fp); break;
      case LOGLEVEL_ERROR:   fwrite ("\033[31m", 5, 1, fp); break;
      case LOGLEVEL_ADVICE:  fwrite ("\033[33m", 5, 1, fp); break;
    }
  #endif
  }

  // finally, print

  #if defined (_WIN)
  main_log_write_utf8 (fp, hConsole, is_terminal, msg_buf, msg_len);
  #else
  fwrite (msg_buf, msg_len, 1, fp);
  #endif

  // color stuff post
  if (is_terminal == true)
  {
  #if defined (_WIN)
    if (highlight_pure_kernel == true)
    {
      SetConsoleTextAttribute (hConsole, orig);
    }
    else switch (loglevel)
    {
      case LOGLEVEL_INFO:                                              break;
      case LOGLEVEL_WARNING: SetConsoleTextAttribute (hConsole, orig); break;
      case LOGLEVEL_ERROR:   SetConsoleTextAttribute (hConsole, orig); break;
      case LOGLEVEL_ADVICE:  SetConsoleTextAttribute (hConsole, orig); break;
    }
  #else
    if (highlight_pure_kernel == true)
    {
      fwrite ("\033[0m", 4, 1, fp);
    }
    else switch (loglevel)
    {
      case LOGLEVEL_INFO:                                  break;
      case LOGLEVEL_WARNING: fwrite ("\033[0m", 4, 1, fp); break;
      case LOGLEVEL_ERROR:   fwrite ("\033[0m", 4, 1, fp); break;
      case LOGLEVEL_ADVICE:  fwrite ("\033[0m", 4, 1, fp); break;
    }
  #endif
  }

  // eventual newline

  if (msg_newline == true)
  {
    fwrite (EOL, strlen (EOL), 1, fp);

    // on error, add another newline

    if (loglevel == LOGLEVEL_ERROR)
    {
      fwrite (EOL, strlen (EOL), 1, fp);
    }
  }

  fflush (fp);
}

static void main_log_advice (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->advice == false) return;

  FILE *fp = ((user_options->stdout_flag == true) || (user_options->restore == true)) ? stderr : stdout;

  main_log (hashcat_ctx, fp, LOGLEVEL_ADVICE);
}

static void main_log_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  FILE *fp = ((user_options->stdout_flag == true) || (user_options->restore == true)) ? stderr : stdout;

  main_log (hashcat_ctx, fp, LOGLEVEL_INFO);
}

static void main_log_warning (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  FILE *fp = ((user_options->stdout_flag == true) || (user_options->restore == true)) ? stderr : stdout;

  main_log (hashcat_ctx, fp, LOGLEVEL_WARNING);
}

static void main_log_error (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  main_log (hashcat_ctx, stderr, LOGLEVEL_ERROR);
}

static void main_outerloop_starting (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  hashcat_user_t *hashcat_user = hashcat_ctx->hashcat_user;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  /**
   * keypress thread
   */

  hashcat_user->outer_threads_cnt = 0;

  hashcat_user->outer_threads = (hc_thread_t *) hccalloc (2, sizeof (hc_thread_t)); if (hashcat_user->outer_threads == NULL) return;

  status_ctx->shutdown_outer = false;

  if (user_options->backend_info  > 0)    return;
  if (user_options->hash_info     > 0)    return;

  if (user_options->keyspace     == true) return;
  if (user_options->speed_only   == true) return;
  if (user_options->identify     == true) return;

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    // see thread_keypress() how to access status information

    hc_thread_create (hashcat_user->outer_threads[hashcat_user->outer_threads_cnt], thread_keypress, hashcat_ctx);

    hashcat_user->outer_threads_cnt++;
  }
}

static void main_outerloop_finished (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  hashcat_user_t *hashcat_user = hashcat_ctx->hashcat_user;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  // we should never stop hashcat with STATUS_INIT:
  // keypress thread blocks on STATUS_INIT forever!

  if (status_ctx->devices_status == STATUS_INIT)
  {
    status_ctx->devices_status = STATUS_ERROR;
  }

  // wait for outer threads

  status_ctx->shutdown_outer = true;

  for (int thread_idx = 0; thread_idx < hashcat_user->outer_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &hashcat_user->outer_threads[thread_idx]);
  }

  hcfree (hashcat_user->outer_threads);

  hashcat_user->outer_threads_cnt = 0;
}

static void main_clear_event_line (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if ((user_options->quiet == true) && (user_options->stdout_flag == false)) return;

  event_log_info_nn (hashcat_ctx, NULL);
}

static void main_cracker_starting (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  const bool show_prompt = (user_options->quiet == false) || (user_options->stdout_flag == true);

  const bool show_initial_status = (user_options->quiet            == false)
                                && (user_options->machine_readable == false)
                                && (user_options->status_json      == false)
                                && (user_options->benchmark        == false)
                                && (user_options->progress_only    == false)
                                && (user_options->speed_only       == false)
                                && (user_options->stdout_flag      == false);

  if (show_prompt == false) return;

  // Tell the user we're about to start

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    if ((show_prompt == true) && (user_options->speed_only == false))
    {
      event_log_info_nn (hashcat_ctx, NULL);

      clear_prompt (hashcat_ctx);

      if (show_initial_status == true)
      {
        status_display (hashcat_ctx);

        event_log_info (hashcat_ctx, NULL);
      }

      send_prompt (hashcat_ctx);
    }
  }
  else
  {
    if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
    {
      event_log_info (hashcat_ctx, "Starting attack in stdin mode");
      event_log_info (hashcat_ctx, NULL);
    }

    if (show_initial_status == true)
    {
      status_display (hashcat_ctx);

      event_log_info (hashcat_ctx, NULL);
    }
  }
}

static void main_cracker_finished (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->backend_info  > 0)    return;
  if (user_options->hash_info     > 0)    return;

  if (user_options->keyspace     == true) return;
  if (user_options->stdout_flag == true)
  {
    if (main_has_terminal_prompt (hashcat_ctx) == true)
    {
      if (user_options->speed_only == false) clear_prompt (hashcat_ctx);
    }

    return;
  }

  // if we had a prompt, clear it

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    if ((user_options->speed_only == false) && (user_options->quiet == false))
    {
      clear_prompt (hashcat_ctx);
    }
  }

  // print final status

  if (user_options->benchmark == true)
  {
    status_benchmark (hashcat_ctx);

    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
  else if (user_options->progress_only == true)
  {
    status_progress (hashcat_ctx);

    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
  else if (user_options->speed_only == true)
  {
    status_speed (hashcat_ctx);

    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
  else if (user_options->machine_readable == true)
  {
    status_display (hashcat_ctx);
  }
  else if (user_options->status == true)
  {
    status_display (hashcat_ctx);
  }
  else if (user_options->status_json == true)
  {
    status_display (hashcat_ctx);
  }
  else
  {
    if (user_options->quiet == false)
    {
      if (hashes->digests_saved != hashes->digests_done) event_log_info (hashcat_ctx, NULL);

      status_display (hashcat_ctx);

      event_log_info (hashcat_ctx, NULL);
    }
  }
}

static void main_cracker_hash_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  outfile_ctx_t  *outfile_ctx  = hashcat_ctx->outfile_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (outfile_ctx->fp.pfp != NULL) return; // cracked hash was not written to an outfile

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    if (outfile_ctx->filename == NULL) if (user_options->quiet == false) clear_prompt (hashcat_ctx);
  }

  // color option for cracked hashes
  if (user_options->color_cracked == true && is_stdout_terminal()) fputs("\033[0;36m", stdout);
  fwrite (buf, len,          1, stdout);
  if (user_options->color_cracked == true && is_stdout_terminal()) fwrite("\033[0m", 4, 1, stdout);
  fwrite (EOL, strlen (EOL), 1, stdout);

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    if (status_ctx->devices_status != STATUS_CRACKED)
    {
      if (outfile_ctx->filename == NULL) if (user_options->quiet == false) send_prompt (hashcat_ctx);
    }
  }
}

static void main_calculated_words_base (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->keyspace == false) return;
  if (user_options->total_candidates == true) return;

  event_log_info (hashcat_ctx, "%" PRIu64 "", status_ctx->words_base);
}

static void main_calculated_words_cnt (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->keyspace == false) return;
  if (user_options->total_candidates == false) return;

  event_log_info (hashcat_ctx, "%" PRIu64 "", status_ctx->words_cnt);
}

static void main_potfile_remove_parse_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Comparing hashes with potfile entries. Please be patient...");
}

static void main_potfile_remove_parse_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Compared hashes with potfile entries");
}

static void main_outfile_check_parse_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Comparing hashes with outfile-check entries. Please be patient...");
}

static void main_outfile_check_parse_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Compared hashes with outfile-check entries");
}

static void main_rulesfiles_parse_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Loading rules. Please be patient...");
}

static void main_rulesfiles_parse_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Loading rules finished");
}

static void main_potfile_hash_show (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  if (outfile_ctx->fp.pfp != NULL) return; // cracked hash was not written to an outfile

  fwrite (buf, len,          1, stdout);
  fwrite (EOL, strlen (EOL), 1, stdout);
}

static void main_potfile_hash_left (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  if (outfile_ctx->fp.pfp != NULL) return; // cracked hash was not written to an outfile

  fwrite (buf, len, 1, stdout);
}

static void main_potfile_num_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;
  hashes_t             *hashes       = hashcat_ctx->hashes;
  outcheck_ctx_t       *outcheck_ctx = hashcat_ctx->outcheck_ctx;

  if (user_options->quiet == true) return;

  if (hashes->digests_done_zero == 1)
  {
    event_log_info (hashcat_ctx, "INFO: Removed hash found as empty hash.");
    event_log_info (hashcat_ctx, NULL);
  }
  else if (hashes->digests_done_zero > 1)
  {
    event_log_info (hashcat_ctx, "INFO: Removed %d hashes found as empty hashes.", hashes->digests_done_zero);
    event_log_info (hashcat_ctx, NULL);
  }

  if (hashes->digests_done_pot == 1)
  {
    event_log_info (hashcat_ctx, "INFO: Removed hash found as potfile entry.");
    event_log_info (hashcat_ctx, NULL);
  }
  else if (hashes->digests_done_pot > 1)
  {
    event_log_info (hashcat_ctx, "INFO: Removed %d hashes found as potfile entries.", hashes->digests_done_pot);
    event_log_info (hashcat_ctx, NULL);
  }

  if (outcheck_ctx->digests_done == 1)
  {
    event_log_info (hashcat_ctx, "INFO: Removed hash found in outfile-check entries.");
    event_log_info (hashcat_ctx, NULL);
  }
  else if (outcheck_ctx->digests_done > 1)
  {
    event_log_info (hashcat_ctx, "INFO: Removed %u hashes found in outfile-check entries.", outcheck_ctx->digests_done);
    event_log_info (hashcat_ctx, NULL);
  }
}

static void main_potfile_all_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;
  const outcheck_ctx_t *outcheck_ctx = hashcat_ctx->outcheck_ctx;

  if (user_options->quiet == true) return;

  if (outcheck_ctx->digests_done > 0)
  {
    event_log_info (hashcat_ctx, "INFO: All hashes already found in potfile, outfile-check, and/or empty entries.");
    event_log_info (hashcat_ctx, "      No cracking backend allocation is needed.");
  }
  else
  {
    event_log_info (hashcat_ctx, "INFO: All hashes found as potfile and/or empty entries! Use --show to display them.");
    event_log_info (hashcat_ctx, "      For more information, see https://hashcat.net/faq/potfile");
  }
  event_log_info (hashcat_ctx, NULL);
}

static void main_outerloop_mainscreen (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const bitmap_ctx_t         *bitmap_ctx         = hashcat_ctx->bitmap_ctx;
  const hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  const hashes_t             *hashes             = hashcat_ctx->hashes;
  const hwmon_ctx_t          *hwmon_ctx          = hashcat_ctx->hwmon_ctx;
  const straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  /**
   * In benchmark-mode, inform user which algorithm is checked
   */

  if (user_options->benchmark == true)
  {
    if (user_options->machine_readable == false)
    {
      char buf[HCBUFSIZ_TINY] = { 0 };
      char hash_mode_buf[16] = { 0 };

      size_t len = 0;

      hash_mode_to_string (hashconfig->hash_mode, hash_mode_buf, sizeof (hash_mode_buf));

      if ((hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL) && (hashconfig->is_salted == true))
      {
        len = snprintf (buf, sizeof (buf), "* Hash-Mode %s (%s) [Iterations: %d]", hash_mode_buf, hashconfig->hash_name, hashes[0].salts_buf[0].salt_iter);
      }
      else
      {
        len = snprintf (buf, sizeof (buf), "* Hash-Mode %s (%s)", hash_mode_buf, hashconfig->hash_name);
      }

      char line[HCBUFSIZ_TINY] = { 0 };

      memset (line, '-', len);

      line[len] = 0;

      event_log_info (hashcat_ctx, "%s", line);
      event_log_info (hashcat_ctx, "%s", buf);
      event_log_info (hashcat_ctx, "%s", line);
      event_log_info (hashcat_ctx, NULL);
    }
  }

  if (user_options->quiet == true) return;

  event_log_info (hashcat_ctx, "Hashes: %u digests; %u unique digests, %u unique salts", hashes->hashes_cnt_orig, hashes->digests_cnt, hashes->salts_cnt);
  event_log_info (hashcat_ctx, "Bitmaps: %u bits, %u entries, 0x%08x mask, %u bytes, %u/%u rotates", bitmap_ctx->bitmap_bits, bitmap_ctx->bitmap_nums, bitmap_ctx->bitmap_mask, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_shift1, bitmap_ctx->bitmap_shift2);

  if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
  {
    event_log_info (hashcat_ctx, "Rules: %u", straight_ctx->kernel_rules_cnt);
  }

  if (user_options->quiet == false) event_log_info (hashcat_ctx, NULL);

  if (hashconfig->opti_type)
  {
    event_log_info (hashcat_ctx, "Optimizers applied:");

    for (u32 i = 0; i < 32; i++)
    {
      const u32 opti_bit = 1U << i;

      if (hashconfig->opti_type & opti_bit) event_log_info (hashcat_ctx, "* %s", stroptitype (opti_bit));
    }
  }

  event_log_info (hashcat_ctx, NULL);

  if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0)
  {
    if (hashconfig->has_optimized_kernel == true)
    {
      event_log_advice (hashcat_ctx, "ATTENTION! Pure (unoptimized) backend kernels selected.");
      event_log_advice (hashcat_ctx, "Pure kernels can crack longer passwords, but drastically reduce performance.");
      event_log_advice (hashcat_ctx, "If you want to switch to optimized kernels, append -O to your commandline.");
      event_log_advice (hashcat_ctx, "See the above message to find out about the exact limits.");
      event_log_advice (hashcat_ctx, NULL);
    }
  }

  if (user_options->keep_guessing == true)
  {
    event_log_advice (hashcat_ctx, "ATTENTION! --keep-guessing mode is enabled.");
    event_log_advice (hashcat_ctx, "This tells hashcat to continue attacking all target hashes until exhaustion.");
    event_log_advice (hashcat_ctx, "hashcat will NOT check for or remove targets present in the potfile, and");
    event_log_advice (hashcat_ctx, "will add ALL plains/collisions found, even duplicates, to the potfile.");
    event_log_advice (hashcat_ctx, NULL);
  }

  if (hashconfig->potfile_disable == true && user_options->attack_mode != ATTACK_MODE_ASSOCIATION)
  {
    event_log_advice (hashcat_ctx, "ATTENTION! Potfile storage is disabled for this hash mode.");
    event_log_advice (hashcat_ctx, "Passwords cracked during this session will NOT be stored to the potfile.");

    if(user_options->outfile_chgd == false)
    {
      event_log_advice (hashcat_ctx, "Consider using -o to save cracked passwords.");
    }

    event_log_advice (hashcat_ctx, NULL);
  }

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    event_log_advice (hashcat_ctx, "ATTENTION! Potfile read/write is disabled for this attack mode.");
    event_log_advice (hashcat_ctx, "Passwords cracked during this session will NOT be stored to the potfile.");

    if(user_options->outfile_chgd == false)
    {
      event_log_advice (hashcat_ctx, "Consider using -o to save cracked passwords.");
    }

    event_log_advice (hashcat_ctx, NULL);
  }
  /**
   * Watchdog and Temperature balance
   */

  if (hwmon_ctx->enabled == false)
  {
    event_log_info (hashcat_ctx, "Watchdog: Hardware monitoring interface not found on your system.");
  }

  hm_temperature_abort_banner (hashcat_ctx);

  event_log_info (hashcat_ctx, NULL);
}

static void main_backend_session_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initializing device kernels and memory. Please be patient...");
}

static void main_backend_session_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initialized device kernels and memory");
}

static void main_backend_session_hostmem (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const u64 *hostmem = (const u64 *) buf;

  u64 free_memory = 0;

  if (get_free_memory (&free_memory) == false)
  {
    event_log_info (hashcat_ctx, "Host memory allocated for this attack: %" PRIu64 " MB", *hostmem / (1024 * 1024));
  }
  else
  {
    event_log_info (hashcat_ctx, "Host memory allocated for this attack: %" PRIu64 " MB (%" PRIu64 " MB free)", *hostmem / (1024 * 1024), free_memory / (1024 * 1024));
  }

  event_log_info (hashcat_ctx, NULL);
}

static void main_backend_device_init_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const u32 *device_id = (const u32 *) buf;

  event_log_info_nn (hashcat_ctx, "Initializing backend runtime for device #%u. Please be patient...", *device_id + 1);
}

static void main_backend_device_init_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const u32 *device_id = (const u32 *) buf;

  event_log_info_nn (hashcat_ctx, "Initialized backend runtime for device #%u", *device_id + 1);
}

static void main_bitmap_init_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Generating bitmap tables...");
}

static void main_bitmap_init_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Generated bitmap tables");
}

static void main_bitmap_final_overflow (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_advice (hashcat_ctx, "Bitmap table overflowed at %d bits.", user_options->bitmap_max);
  event_log_advice (hashcat_ctx, "This typically happens with too many hashes and reduces your performance.");
  event_log_advice (hashcat_ctx, "You can increase the bitmap table size with --bitmap-max, but");
  event_log_advice (hashcat_ctx, "this creates a trade-off between L2-cache and bitmap efficiency.");
  event_log_advice (hashcat_ctx, "It is therefore not guaranteed to restore full performance.");
  event_log_advice (hashcat_ctx, NULL);
}

static void main_set_kernel_power_final (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  clear_prompt (hashcat_ctx);

  event_log_advice (hashcat_ctx, "Approaching final keyspace - workload adjusted.");
  event_log_advice (hashcat_ctx, NULL);

  send_prompt (hashcat_ctx);
}

static void main_monitor_throttle1 (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    clear_prompt (hashcat_ctx);
  }

  const u32 *device_id = (const u32 *) buf;

  event_log_warning (hashcat_ctx, "Driver temperature threshold met on GPU #%u. Expect reduced performance.", *device_id + 1);

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    send_prompt (hashcat_ctx);
  }
}

static void main_monitor_throttle2 (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    clear_prompt (hashcat_ctx);
  }

  const u32 *device_id = (const u32 *) buf;

  event_log_warning (hashcat_ctx, "Driver temperature threshold met on GPU #%u. Expect reduced performance.", *device_id + 1);

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    send_prompt (hashcat_ctx);
  }
}

static void main_monitor_throttle3 (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    clear_prompt (hashcat_ctx);
  }

  const u32 *device_id = (const u32 *) buf;

  event_log_warning (hashcat_ctx, "Driver temperature threshold met on GPU #%u. Expect reduced performance.", *device_id + 1);
  event_log_warning (hashcat_ctx, NULL);

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    send_prompt (hashcat_ctx);
  }
}

static void main_monitor_performance_hint (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const backend_ctx_t        *backend_ctx        = hashcat_ctx->backend_ctx;
  const hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  if (backend_ctx->kernel_power_final > 0) return;

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    clear_prompt (hashcat_ctx);
  }

  event_log_advice (hashcat_ctx, "Cracking performance lower than expected?");
  event_log_advice (hashcat_ctx, NULL);

  if (user_options->optimized_kernel == false)
  {
    if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0)
    {
      if (hashconfig->has_optimized_kernel == true)
      {
        event_log_advice (hashcat_ctx, "* Append -O to the commandline.");
        event_log_advice (hashcat_ctx, "  This lowers the maximum supported password/salt length (usually down to 32).");
        event_log_advice (hashcat_ctx, NULL);
      }
    }
  }

  if (user_options->workload_profile < 3)
  {
    event_log_advice (hashcat_ctx, "* Append -w 3 to the commandline.");
    event_log_advice (hashcat_ctx, "  This can cause your screen to lag.");
    event_log_advice (hashcat_ctx, NULL);
  }

  if (user_options->slow_candidates == false)
  {
    if ((user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      if ((user_options->attack_mode != ATTACK_MODE_HYBRID)
       && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
       && (user_options->attack_mode != ATTACK_MODE_HYBRID2)
       && (user_options->attack_mode != ATTACK_MODE_ASSOCIATION))
      {
        event_log_advice (hashcat_ctx, "* Append -S to the commandline.");
        event_log_advice (hashcat_ctx, "  This has a drastic speed impact but can be better for specific attacks.");
        event_log_advice (hashcat_ctx, "  Typical scenarios are a small wordlist but a large ruleset.");
        event_log_advice (hashcat_ctx, NULL);
      }
    }
  }

  event_log_advice (hashcat_ctx, "* Update your backend API runtime / driver the right way:");
  event_log_advice (hashcat_ctx, "  https://hashcat.net/faq/wrongdriver");
  event_log_advice (hashcat_ctx, NULL);
  event_log_advice (hashcat_ctx, "* Create more work items to make use of your parallelization power:");
  event_log_advice (hashcat_ctx, "  https://hashcat.net/faq/morework");
  event_log_advice (hashcat_ctx, NULL);

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    send_prompt (hashcat_ctx);
  }
}

static void main_monitor_noinput_hint (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_advice (hashcat_ctx, "ATTENTION! Read timeout in stdin mode. Password candidates input is too slow:");
  event_log_advice (hashcat_ctx, "* Are you sure you are using the correct attack mode (--attack-mode or -a)?");
  event_log_advice (hashcat_ctx, "* Are you sure you want to use input from standard input (stdin)?");
  event_log_advice (hashcat_ctx, "* If using stdin, are you sure it is working correctly, and is fast enough?");
  event_log_advice (hashcat_ctx, NULL);
}

static void main_monitor_noinput_abort (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  event_log_error (hashcat_ctx, "No password candidates received in stdin mode, aborting");
}

// The candidate generator, not the unit. Worth its own message because the device number in the
// payload is a VIRTUAL one belonging to a bridge unit, so reporting it the usual way would name the
// unit, which is running perfectly well, while the GPU beside it is the thing overheating.

static void main_monitor_temp_abort_feeder (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if ((main_has_terminal_prompt (hashcat_ctx) == true) && (user_options->quiet == false))
  {
    clear_prompt (hashcat_ctx);
  }

  event_log_error (hashcat_ctx, "Temperature limit on the candidate generator reached, aborting");
}

static void main_monitor_temp_abort (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;


  if ((main_has_terminal_prompt (hashcat_ctx) == true) && (user_options->quiet == false))
  {
    clear_prompt (hashcat_ctx);
  }

  const u32 *device_id = (const u32 *) buf;

  event_log_error (hashcat_ctx, "Temperature limit on GPU #%u reached, aborting", *device_id + 1);
}

static void main_monitor_runtime_limit (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    clear_prompt (hashcat_ctx);
  }

  event_log_warning (hashcat_ctx, "Runtime limit reached, aborting");
}

static void main_monitor_status_refresh (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  if (status_ctx->accessible == false) return;

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    if (user_options->quiet == false)
    {
      //clear_prompt (hashcat_ctx);

      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, NULL);
    }
  }

  status_display (hashcat_ctx);

  if (main_has_terminal_prompt (hashcat_ctx) == true)
  {
    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, NULL);

      send_prompt (hashcat_ctx);
    }
  }

  if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
}

static void main_wordlist_cache_hit (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const cache_hit_t *cache_hit = (const cache_hit_t *) buf;

  event_log_info (hashcat_ctx, "Dictionary cache hit:");
  event_log_info (hashcat_ctx, "* Filename..: %s", cache_hit->dictfile);
  event_log_info (hashcat_ctx, "* Passwords.: %" PRIu64, cache_hit->cached_cnt);
  event_log_info (hashcat_ctx, "* Bytes.....: %" PRId64, cache_hit->stat.st_size);
  event_log_info (hashcat_ctx, "* Keyspace..: %" PRIu64, cache_hit->keyspace);
  event_log_info (hashcat_ctx, NULL);
}

static void main_wordlist_cache_generate (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const cache_generate_t *cache_generate = (const cache_generate_t *) buf;

  if (cache_generate->percent < 100)
  {
    const u64 speed = cache_generate->comp / cache_generate->runtime;

    event_log_info_nn (hashcat_ctx, "Dictionary cache building %s: %" PRIu64 " bytes (%.2f%%), %" PRIu64 " MiB/s", cache_generate->dictfile, cache_generate->comp, cache_generate->percent, speed / 1024);
  }
  else
  {
    char *runtime = (char *) hcmalloc (HCBUFSIZ_TINY);

    event_log_info (hashcat_ctx, "Dictionary cache built:");
    event_log_info (hashcat_ctx, "* Filename..: %s", cache_generate->dictfile);
    event_log_info (hashcat_ctx, "* Passwords.: %" PRIu64, cache_generate->cnt2);
    event_log_info (hashcat_ctx, "* Bytes.....: %" PRId64, cache_generate->comp);
    event_log_info (hashcat_ctx, "* Keyspace..: %" PRIu64, cache_generate->cnt);
    event_log_info (hashcat_ctx, "* Speed.....: %" PRIu64 " MiB/s", (u64) (cache_generate->comp / cache_generate->runtime) / 1024);
    event_log_info (hashcat_ctx, "* Runtime...: %.2fs", cache_generate->runtime / 1000);
    event_log_info (hashcat_ctx, NULL);

    hcfree (runtime);
  }
}

static void main_hashconfig_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
}

static void main_hashconfig_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  /**
   * Optimizer constraints
   */

  event_log_info (hashcat_ctx, "Minimum password length supported by kernel: %u", hashconfig->pw_min);
  event_log_info (hashcat_ctx, "Maximum password length supported by kernel: %u", hashconfig->pw_max);

  if (hashconfig->is_salted == true)
  {
    if (hashconfig->opti_type & OPTI_TYPE_RAW_HASH || hashconfig->salt_type & SALT_TYPE_GENERIC)
    {
      event_log_info (hashcat_ctx, "Minimum salt length supported by kernel: %u", hashconfig->salt_min);
      event_log_info (hashcat_ctx, "Maximum salt length supported by kernel: %u", hashconfig->salt_max);
    }
  }

  event_log_info (hashcat_ctx, NULL);
}

static void main_hashlist_count_lines_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const char *hashfile = (const char *) buf;

  event_log_info_nn (hashcat_ctx, "Counting lines in %s. Please be patient...", hashfile);
}

static void main_hashlist_count_lines_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const char *hashfile = (const char *) buf;

  event_log_info_nn (hashcat_ctx, "Counted lines in %s", hashfile);
}

static void main_hashlist_parse_hash (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const hashlist_parse_t *hashlist_parse = (const hashlist_parse_t *) buf;

  const u64 hashes_cnt   = hashlist_parse->hashes_cnt;
  const u64 hashes_avail = hashlist_parse->hashes_avail;

  if (hashes_cnt < hashes_avail)
  {
    event_log_info_nn (hashcat_ctx, "Parsing Hashes: %" PRIu64 "/%" PRIu64 " (%0.2f%%)...", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100.0);
  }
  else
  {
    event_log_info_nn (hashcat_ctx, "Parsed Hashes: %" PRIu64 "/%" PRIu64 " (%0.2f%%)", hashes_cnt, hashes_avail, 100.0);
  }
}

static void main_hashlist_sort_hash_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorting hashes. Please be patient...");
}

static void main_hashlist_sort_hash_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorted hashes");
}

static void main_hashlist_unique_hash_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Removing duplicate hashes. Please be patient...");
}

static void main_hashlist_unique_hash_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Removed duplicate hashes");
}

static void main_hashlist_sort_salt_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorting salts. Please be patient...");
}

static void main_hashlist_sort_salt_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorted salts");
}

static void main_autodetect_starting (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Autodetecting hash-modes. Please be patient...");
}

static void main_autodetect_finished (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Autodetected hash-modes");
}

static void main_selftest_starting (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Starting self-test. Please be patient...");
}

static void main_selftest_finished (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Finished self-test");
}

static void main_autotune_starting (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Starting autotune. Please be patient...");
}

static void main_autotune_finished (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Finished autotune");
}

static void main_backend_runtimes_init_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initializing backend runtimes. Please be patient...");
}

static void main_backend_runtimes_init_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initialized backend runtimes");
}

static void main_backend_devices_init_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initializing backend devices. Please be patient...");
}

static void main_backend_devices_init_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initialized backend devices");
}

static void main_bridges_init_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initializing bridges. Please be patient...");
}

static void main_bridges_init_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initialized bridges");
}

static void main_generic_init_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  // the name comes with the event because a run can bring up more than one instance, and the one
  // being initialised is the one worth naming

  const char *plugin_name = (const char *) buf;

  event_log_info_nn (hashcat_ctx, "Initializing feed plugin %s. Please be patient...", plugin_name);
}

static void main_generic_init_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  const char *plugin_name = (const char *) buf;

  event_log_info_nn (hashcat_ctx, "Initialized feed plugin %s", plugin_name);
}

static void main_bridges_salt_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initializing bridge salts. Please be patient...");
}

static void main_bridges_salt_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initialized bridge salts");
}

typedef enum main_timing_stage
{
  MAIN_TIMING_TOTAL = 0,
  MAIN_TIMING_BEFORE_ATTACK,
  MAIN_TIMING_ATTACK,
  MAIN_TIMING_AFTER_ATTACK,
  MAIN_TIMING_COMMAND_SETUP,
  MAIN_TIMING_SESSION_INIT,
  MAIN_TIMING_RETRY_WAIT,
  MAIN_TIMING_EXECUTE,
  MAIN_TIMING_SESSION_DESTROY,
  MAIN_TIMING_BRIDGES_INIT,
  MAIN_TIMING_BACKEND_RUNTIMES,
  MAIN_TIMING_BACKEND_DEVICES,
  MAIN_TIMING_AUTODETECT,
  MAIN_TIMING_HASHCONFIG,
  MAIN_TIMING_HASH_PARSE,
  MAIN_TIMING_HASH_COUNT,
  MAIN_TIMING_HASH_SORT,
  MAIN_TIMING_SALT_SORT,
  MAIN_TIMING_HASH_UNIQUE,
  MAIN_TIMING_POTFILE,
  MAIN_TIMING_OUTFILE_CHECK,
  MAIN_TIMING_RULES,
  MAIN_TIMING_CANDIDATE_SOURCE,
  MAIN_TIMING_BITMAP,
  MAIN_TIMING_BRIDGE_SALTS,
  MAIN_TIMING_BACKEND_SESSION,
  MAIN_TIMING_SELFTEST,
  MAIN_TIMING_AUTOTUNE,
  MAIN_TIMING_STAGE_MAX
} main_timing_stage_t;

typedef struct main_timing_entry
{
  hc_timer_t timer;
  double msec;
  u64 calls;
  bool running;
} main_timing_entry_t;

typedef struct main_timing_profile
{
  main_timing_entry_t entries[MAIN_TIMING_STAGE_MAX];
  bool attack_seen;
  bool initialized;
  bool finalized;
} main_timing_profile_t;

static main_timing_profile_t main_timing_profile;

static void main_timing_start (const main_timing_stage_t stage)
{
  main_timing_entry_t *entry = &main_timing_profile.entries[stage];

  if (entry->running == true) return;

  hc_timer_set (&entry->timer);

  entry->running = true;
}

static void main_timing_stop (const main_timing_stage_t stage)
{
  main_timing_entry_t *entry = &main_timing_profile.entries[stage];

  if (entry->running == false) return;

  entry->msec += hc_timer_get (entry->timer);
  entry->calls++;
  entry->running = false;
}

static void main_timing_reset (void)
{
  memset (&main_timing_profile, 0, sizeof (main_timing_profile));

  main_timing_profile.initialized = true;

  main_timing_start (MAIN_TIMING_TOTAL);
  main_timing_start (MAIN_TIMING_BEFORE_ATTACK);
  main_timing_start (MAIN_TIMING_COMMAND_SETUP);
}

static void main_timing_event (const u32 id)
{
  if (main_timing_profile.initialized == false) return;

  switch (id)
  {
    case EVENT_BRIDGES_INIT_PRE:          main_timing_start (MAIN_TIMING_BRIDGES_INIT);     break;
    case EVENT_BRIDGES_INIT_POST:         main_timing_stop  (MAIN_TIMING_BRIDGES_INIT);     break;
    case EVENT_BACKEND_RUNTIMES_INIT_PRE: main_timing_start (MAIN_TIMING_BACKEND_RUNTIMES); break;
    case EVENT_BACKEND_RUNTIMES_INIT_POST:main_timing_stop  (MAIN_TIMING_BACKEND_RUNTIMES); break;
    case EVENT_BACKEND_DEVICES_INIT_PRE:  main_timing_start (MAIN_TIMING_BACKEND_DEVICES);  break;
    case EVENT_BACKEND_DEVICES_INIT_POST: main_timing_stop  (MAIN_TIMING_BACKEND_DEVICES);  break;
    case EVENT_AUTODETECT_STARTING:       main_timing_start (MAIN_TIMING_AUTODETECT);       break;
    case EVENT_AUTODETECT_FINISHED:       main_timing_stop  (MAIN_TIMING_AUTODETECT);       break;
    case EVENT_HASHCONFIG_PRE:            main_timing_start (MAIN_TIMING_HASHCONFIG);       break;
    case EVENT_HASHCONFIG_POST:           main_timing_stop  (MAIN_TIMING_HASHCONFIG);       break;
    case EVENT_HASHLIST_PARSE_INPUT_PRE:  main_timing_start (MAIN_TIMING_HASH_PARSE);       break;
    case EVENT_HASHLIST_PARSE_INPUT_POST: main_timing_stop  (MAIN_TIMING_HASH_PARSE);       break;
    case EVENT_HASHLIST_COUNT_LINES_PRE:  main_timing_start (MAIN_TIMING_HASH_COUNT);       break;
    case EVENT_HASHLIST_COUNT_LINES_POST: main_timing_stop  (MAIN_TIMING_HASH_COUNT);       break;
    case EVENT_HASHLIST_SORT_HASH_PRE:    main_timing_start (MAIN_TIMING_HASH_SORT);        break;
    case EVENT_HASHLIST_SORT_HASH_POST:   main_timing_stop  (MAIN_TIMING_HASH_SORT);        break;
    case EVENT_HASHLIST_SORT_SALT_PRE:    main_timing_start (MAIN_TIMING_SALT_SORT);        break;
    case EVENT_HASHLIST_SORT_SALT_POST:   main_timing_stop  (MAIN_TIMING_SALT_SORT);        break;
    case EVENT_HASHLIST_UNIQUE_HASH_PRE:  main_timing_start (MAIN_TIMING_HASH_UNIQUE);      break;
    case EVENT_HASHLIST_UNIQUE_HASH_POST: main_timing_stop  (MAIN_TIMING_HASH_UNIQUE);      break;
    case EVENT_POTFILE_REMOVE_PARSE_PRE:  main_timing_start (MAIN_TIMING_POTFILE);          break;
    case EVENT_POTFILE_REMOVE_PARSE_POST: main_timing_stop  (MAIN_TIMING_POTFILE);          break;
    case EVENT_OUTFILE_CHECK_PARSE_PRE:   main_timing_start (MAIN_TIMING_OUTFILE_CHECK);    break;
    case EVENT_OUTFILE_CHECK_PARSE_POST:  main_timing_stop  (MAIN_TIMING_OUTFILE_CHECK);    break;
    case EVENT_RULESFILES_PARSE_PRE:      main_timing_start (MAIN_TIMING_RULES);            break;
    case EVENT_RULESFILES_PARSE_POST:     main_timing_stop  (MAIN_TIMING_RULES);            break;
    case EVENT_CANDIDATE_SOURCE_PRE:      main_timing_start (MAIN_TIMING_CANDIDATE_SOURCE); break;
    case EVENT_CANDIDATE_SOURCE_POST:     main_timing_stop  (MAIN_TIMING_CANDIDATE_SOURCE); break;
    case EVENT_BITMAP_INIT_PRE:           main_timing_start (MAIN_TIMING_BITMAP);           break;
    case EVENT_BITMAP_INIT_POST:          main_timing_stop  (MAIN_TIMING_BITMAP);           break;
    case EVENT_BRIDGES_SALT_PRE:          main_timing_start (MAIN_TIMING_BRIDGE_SALTS);     break;
    case EVENT_BRIDGES_SALT_POST:         main_timing_stop  (MAIN_TIMING_BRIDGE_SALTS);     break;
    case EVENT_BACKEND_SESSION_PRE:       main_timing_start (MAIN_TIMING_BACKEND_SESSION);  break;
    case EVENT_BACKEND_SESSION_POST:      main_timing_stop  (MAIN_TIMING_BACKEND_SESSION);  break;
    case EVENT_SELFTEST_STARTING:         main_timing_start (MAIN_TIMING_SELFTEST);         break;
    case EVENT_SELFTEST_FINISHED:         main_timing_stop  (MAIN_TIMING_SELFTEST);         break;
    case EVENT_AUTOTUNE_STARTING:         main_timing_start (MAIN_TIMING_AUTOTUNE);         break;
    case EVENT_AUTOTUNE_FINISHED:         main_timing_stop  (MAIN_TIMING_AUTOTUNE);         break;

    case EVENT_CRACKER_STARTING:
      main_timing_stop (MAIN_TIMING_BEFORE_ATTACK);
      main_timing_stop (MAIN_TIMING_AFTER_ATTACK);
      main_timing_start (MAIN_TIMING_ATTACK);
      main_timing_profile.attack_seen = true;
      break;

    case EVENT_CRACKER_FINISHED:
      main_timing_stop (MAIN_TIMING_ATTACK);
      main_timing_start (MAIN_TIMING_AFTER_ATTACK);
      break;
  }
}

static void main_timing_finalize (void)
{
  if ((main_timing_profile.initialized == false) || (main_timing_profile.finalized == true)) return;

  for (int stage = 0; stage < MAIN_TIMING_STAGE_MAX; stage++)
  {
    main_timing_stop ((main_timing_stage_t) stage);
  }

  main_timing_profile.finalized = true;
}

static double main_timing_msec (const main_timing_stage_t stage)
{
  return main_timing_profile.entries[stage].msec;
}

static double main_timing_other (const double total, const double known)
{
  return (total > known) ? total - known : 0;
}

static double main_timing_percent (const double part, const double total)
{
  return (total > 0) ? (part * 100.0) / total : 0;
}

static void main_timing_line (hashcat_ctx_t *hashcat_ctx, const char *label, const double msec, const double total_msec, const int indent)
{
  event_log_info (hashcat_ctx, "%*s%-35s %12.3f s  %6.2f%%", indent, "", label, msec / 1000.0, main_timing_percent (msec, total_msec));
}

static void main_timing_detail_line (hashcat_ctx_t *hashcat_ctx, const char *label, const main_timing_stage_t stage, const double total_msec, const int indent)
{
  const main_timing_entry_t *entry = &main_timing_profile.entries[stage];

  if (entry->calls == 0) return;

  char display_label[80];

  if (entry->calls > 1)
  {
    snprintf (display_label, sizeof (display_label), "%s (%" PRIu64 " runs)", label, entry->calls);
  }
  else
  {
    snprintf (display_label, sizeof (display_label), "%s", label);
  }

  main_timing_line (hashcat_ctx, display_label, entry->msec, total_msec, indent);
}

static void main_timing_report (hashcat_ctx_t *hashcat_ctx, const bool enabled)
{
  main_timing_finalize ();

  if (enabled == false) return;

  const double total          = main_timing_msec (MAIN_TIMING_TOTAL);
  const double before         = main_timing_msec (MAIN_TIMING_BEFORE_ATTACK);
  const double attack         = main_timing_msec (MAIN_TIMING_ATTACK);
  const double after          = main_timing_msec (MAIN_TIMING_AFTER_ATTACK);
  const double command_setup  = main_timing_msec (MAIN_TIMING_COMMAND_SETUP);
  const double session_init   = main_timing_msec (MAIN_TIMING_SESSION_INIT);
  const double retry_wait     = main_timing_msec (MAIN_TIMING_RETRY_WAIT);
  const double session_close  = main_timing_msec (MAIN_TIMING_SESSION_DESTROY);

  const double init_detail = main_timing_msec (MAIN_TIMING_BRIDGES_INIT)
                           + main_timing_msec (MAIN_TIMING_BACKEND_RUNTIMES)
                           + main_timing_msec (MAIN_TIMING_BACKEND_DEVICES);

  const double prep_detail = main_timing_msec (MAIN_TIMING_AUTODETECT)
                           + main_timing_msec (MAIN_TIMING_HASHCONFIG)
                           + main_timing_msec (MAIN_TIMING_HASH_PARSE)
                           + main_timing_msec (MAIN_TIMING_HASH_SORT)
                           + main_timing_msec (MAIN_TIMING_SALT_SORT)
                           + main_timing_msec (MAIN_TIMING_HASH_UNIQUE)
                           + main_timing_msec (MAIN_TIMING_POTFILE)
                           + main_timing_msec (MAIN_TIMING_OUTFILE_CHECK)
                           + main_timing_msec (MAIN_TIMING_CANDIDATE_SOURCE)
                           + main_timing_msec (MAIN_TIMING_BITMAP)
                           + main_timing_msec (MAIN_TIMING_BRIDGE_SALTS)
                           + main_timing_msec (MAIN_TIMING_BACKEND_SESSION)
                           + main_timing_msec (MAIN_TIMING_SELFTEST)
                           + main_timing_msec (MAIN_TIMING_AUTOTUNE);

  const double preparation_total = main_timing_other (before, command_setup + session_init + retry_wait);
  const double execution_cleanup = main_timing_other (after, session_close);

  event_log_info (hashcat_ctx, NULL);
  event_log_info (hashcat_ctx, "Task Time Breakdown");
  event_log_info (hashcat_ctx, "===================");
  event_log_info (hashcat_ctx, "Each percentage is part of the measured end-to-end run.");
  event_log_info (hashcat_ctx, NULL);

  main_timing_line (hashcat_ctx, "BEFORE ATTACK", before, total, 0);
  main_timing_line (hashcat_ctx, "Program/options setup", command_setup, total, 2);
  main_timing_line (hashcat_ctx, "Session initialization", session_init, total, 2);
  main_timing_detail_line (hashcat_ctx, "Bridge/plugin initialization", MAIN_TIMING_BRIDGES_INIT, total, 4);
  main_timing_detail_line (hashcat_ctx, "Backend runtime loading", MAIN_TIMING_BACKEND_RUNTIMES, total, 4);
  main_timing_detail_line (hashcat_ctx, "Backend device/GPU setup", MAIN_TIMING_BACKEND_DEVICES, total, 4);
  main_timing_line (hashcat_ctx, "Other session initialization", main_timing_other (session_init, init_detail), total, 4);
  if (retry_wait > 0) main_timing_line (hashcat_ctx, "CUDA retry waiting", retry_wait, total, 2);
  main_timing_line (hashcat_ctx, "Attack preparation", preparation_total, total, 2);
  main_timing_detail_line (hashcat_ctx, "Hash-mode autodetection", MAIN_TIMING_AUTODETECT, total, 4);
  main_timing_detail_line (hashcat_ctx, "Hash-mode/module setup", MAIN_TIMING_HASHCONFIG, total, 4);
  if (main_timing_profile.entries[MAIN_TIMING_HASH_PARSE].calls > 0)
  {
    const double hash_parse = main_timing_msec (MAIN_TIMING_HASH_PARSE);
    const double hash_count = main_timing_msec (MAIN_TIMING_HASH_COUNT);

    main_timing_detail_line (hashcat_ctx, "Read and parse hash input", MAIN_TIMING_HASH_PARSE, total, 4);
    main_timing_detail_line (hashcat_ctx, "Count hash input lines", MAIN_TIMING_HASH_COUNT, total, 6);
    main_timing_line (hashcat_ctx, "Other hash parsing", main_timing_other (hash_parse, hash_count), total, 6);
  }
  main_timing_detail_line (hashcat_ctx, "Sort hashes", MAIN_TIMING_HASH_SORT, total, 4);
  main_timing_detail_line (hashcat_ctx, "Sort salts", MAIN_TIMING_SALT_SORT, total, 4);
  main_timing_detail_line (hashcat_ctx, "Remove duplicate hashes", MAIN_TIMING_HASH_UNIQUE, total, 4);
  main_timing_detail_line (hashcat_ctx, "Check potfile", MAIN_TIMING_POTFILE, total, 4);
  main_timing_detail_line (hashcat_ctx, "Check outfile-check-dir", MAIN_TIMING_OUTFILE_CHECK, total, 4);
  if (main_timing_profile.entries[MAIN_TIMING_CANDIDATE_SOURCE].calls > 0)
  {
    const double candidate_source = main_timing_msec (MAIN_TIMING_CANDIDATE_SOURCE);
    const double rules = main_timing_msec (MAIN_TIMING_RULES);

    main_timing_detail_line (hashcat_ctx, "Prepare wordlists/masks/rules", MAIN_TIMING_CANDIDATE_SOURCE, total, 4);
    main_timing_detail_line (hashcat_ctx, "Load and validate rules", MAIN_TIMING_RULES, total, 6);
    main_timing_line (hashcat_ctx, "Other candidate-source setup", main_timing_other (candidate_source, rules), total, 6);
  }
  main_timing_detail_line (hashcat_ctx, "Build hash lookup bitmaps", MAIN_TIMING_BITMAP, total, 4);
  main_timing_detail_line (hashcat_ctx, "Prepare bridge salts", MAIN_TIMING_BRIDGE_SALTS, total, 4);
  main_timing_detail_line (hashcat_ctx, "Allocate attack/GPU session", MAIN_TIMING_BACKEND_SESSION, total, 4);
  main_timing_detail_line (hashcat_ctx, "Kernel self-test", MAIN_TIMING_SELFTEST, total, 4);
  main_timing_detail_line (hashcat_ctx, "Kernel autotune", MAIN_TIMING_AUTOTUNE, total, 4);
  main_timing_line (hashcat_ctx, "Other attack preparation", main_timing_other (preparation_total, prep_detail), total, 4);

  if (main_timing_profile.attack_seen == true)
  {
    main_timing_line (hashcat_ctx, "ATTACK", attack, total, 0);
    main_timing_line (hashcat_ctx, "AFTER ATTACK", after, total, 0);
    main_timing_line (hashcat_ctx, "Finish monitors/output/GPU session", execution_cleanup, total, 2);
    main_timing_line (hashcat_ctx, "Destroy remaining session contexts", session_close, total, 2);
  }
  else
  {
    event_log_info (hashcat_ctx, "ATTACK                              not started (all hashes may already be resolved)");
  }

  event_log_info (hashcat_ctx, NULL);
  main_timing_line (hashcat_ctx, "MEASURED TOTAL", total, total, 0);
  event_log_info (hashcat_ctx, NULL);
}

static bool main_timing_report_enabled (const user_options_t *user_options)
{
  if (user_options->task_time_breakdown == false) return false;

  if (user_options->quiet            == true) return false;
  if (user_options->machine_readable == true) return false;
  if (user_options->keyspace         == true) return false;
  if (user_options->stdout_flag      == true) return false;
  if (user_options->show             == true) return false;
  if (user_options->left             == true) return false;
  if (user_options->identify         == true) return false;
  if (user_options->usage             > 0)    return false;
  if (user_options->hash_info         > 0)    return false;
  if (user_options->backend_info      > 0)    return false;

  return true;
}

static void event (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  main_timing_event (id);

  switch (id)
  {
    case EVENT_AUTOTUNE_FINISHED:         main_autotune_finished         (hashcat_ctx, buf, len); break;
    case EVENT_AUTOTUNE_STARTING:         main_autotune_starting         (hashcat_ctx, buf, len); break;
    case EVENT_SELFTEST_FINISHED:         main_selftest_finished         (hashcat_ctx, buf, len); break;
    case EVENT_SELFTEST_STARTING:         main_selftest_starting         (hashcat_ctx, buf, len); break;
    case EVENT_AUTODETECT_FINISHED:       main_autodetect_finished       (hashcat_ctx, buf, len); break;
    case EVENT_AUTODETECT_STARTING:       main_autodetect_starting       (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_RUNTIMES_INIT_POST:main_backend_runtimes_init_post(hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_RUNTIMES_INIT_PRE: main_backend_runtimes_init_pre (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_DEVICES_INIT_POST: main_backend_devices_init_post (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_DEVICES_INIT_PRE:  main_backend_devices_init_pre  (hashcat_ctx, buf, len); break;
    case EVENT_BITMAP_INIT_POST:          main_bitmap_init_post          (hashcat_ctx, buf, len); break;
    case EVENT_BITMAP_INIT_PRE:           main_bitmap_init_pre           (hashcat_ctx, buf, len); break;
    case EVENT_BITMAP_FINAL_OVERFLOW:     main_bitmap_final_overflow     (hashcat_ctx, buf, len); break;
    case EVENT_BRIDGES_INIT_POST:         main_bridges_init_post         (hashcat_ctx, buf, len); break;
    case EVENT_BRIDGES_INIT_PRE:          main_bridges_init_pre          (hashcat_ctx, buf, len); break;
    case EVENT_BRIDGES_SALT_POST:         main_bridges_salt_post         (hashcat_ctx, buf, len); break;
    case EVENT_BRIDGES_SALT_PRE:          main_bridges_salt_pre          (hashcat_ctx, buf, len); break;
    case EVENT_CALCULATED_WORDS_BASE:     main_calculated_words_base     (hashcat_ctx, buf, len); break;
    case EVENT_CALCULATED_WORDS_CNT:      main_calculated_words_cnt      (hashcat_ctx, buf, len); break;
    case EVENT_CLEAR_EVENT_LINE:          main_clear_event_line          (hashcat_ctx, buf, len); break;
    case EVENT_CRACKER_FINISHED:          main_cracker_finished          (hashcat_ctx, buf, len); break;
    case EVENT_CRACKER_HASH_CRACKED:      main_cracker_hash_cracked      (hashcat_ctx, buf, len); break;
    case EVENT_CRACKER_STARTING:          main_cracker_starting          (hashcat_ctx, buf, len); break;
    case EVENT_GENERIC_INIT_POST:         main_generic_init_post         (hashcat_ctx, buf, len); break;
    case EVENT_GENERIC_INIT_PRE:          main_generic_init_pre          (hashcat_ctx, buf, len); break;
    case EVENT_HASHCONFIG_PRE:            main_hashconfig_pre            (hashcat_ctx, buf, len); break;
    case EVENT_HASHCONFIG_POST:           main_hashconfig_post           (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_COUNT_LINES_POST: main_hashlist_count_lines_post (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_COUNT_LINES_PRE:  main_hashlist_count_lines_pre  (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_PARSE_HASH:       main_hashlist_parse_hash       (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_HASH_POST:   main_hashlist_sort_hash_post   (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_HASH_PRE:    main_hashlist_sort_hash_pre    (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_SALT_POST:   main_hashlist_sort_salt_post   (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_SALT_PRE:    main_hashlist_sort_salt_pre    (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_UNIQUE_HASH_POST: main_hashlist_unique_hash_post (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_UNIQUE_HASH_PRE:  main_hashlist_unique_hash_pre  (hashcat_ctx, buf, len); break;
    case EVENT_LOG_ERROR:                 main_log_error                 (hashcat_ctx, buf, len); break;
    case EVENT_LOG_INFO:                  main_log_info                  (hashcat_ctx, buf, len); break;
    case EVENT_LOG_WARNING:               main_log_warning               (hashcat_ctx, buf, len); break;
    case EVENT_LOG_ADVICE:                main_log_advice                (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_RUNTIME_LIMIT:     main_monitor_runtime_limit     (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_STATUS_REFRESH:    main_monitor_status_refresh    (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_TEMP_ABORT:        main_monitor_temp_abort        (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_TEMP_ABORT_FEEDER: main_monitor_temp_abort_feeder (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_THROTTLE1:         main_monitor_throttle1         (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_THROTTLE2:         main_monitor_throttle2         (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_THROTTLE3:         main_monitor_throttle3         (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_PERFORMANCE_HINT:  main_monitor_performance_hint  (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_NOINPUT_HINT:      main_monitor_noinput_hint      (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_NOINPUT_ABORT:     main_monitor_noinput_abort     (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_SESSION_POST:      main_backend_session_post      (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_SESSION_PRE:       main_backend_session_pre       (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_SESSION_HOSTMEM:   main_backend_session_hostmem   (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_DEVICE_INIT_POST:  main_backend_device_init_post  (hashcat_ctx, buf, len); break;
    case EVENT_BACKEND_DEVICE_INIT_PRE:   main_backend_device_init_pre   (hashcat_ctx, buf, len); break;
    case EVENT_OUTERLOOP_FINISHED:        main_outerloop_finished        (hashcat_ctx, buf, len); break;
    case EVENT_OUTERLOOP_MAINSCREEN:      main_outerloop_mainscreen      (hashcat_ctx, buf, len); break;
    case EVENT_OUTERLOOP_STARTING:        main_outerloop_starting        (hashcat_ctx, buf, len); break;
    case EVENT_OUTFILE_CHECK_PARSE_POST:  main_outfile_check_parse_post  (hashcat_ctx, buf, len); break;
    case EVENT_OUTFILE_CHECK_PARSE_PRE:   main_outfile_check_parse_pre   (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_ALL_CRACKED:       main_potfile_all_cracked       (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_HASH_LEFT:         main_potfile_hash_left         (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_HASH_SHOW:         main_potfile_hash_show         (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_NUM_CRACKED:       main_potfile_num_cracked       (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_REMOVE_PARSE_POST: main_potfile_remove_parse_post (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_REMOVE_PARSE_PRE:  main_potfile_remove_parse_pre  (hashcat_ctx, buf, len); break;
    case EVENT_RULESFILES_PARSE_POST:     main_rulesfiles_parse_post     (hashcat_ctx, buf, len); break;
    case EVENT_RULESFILES_PARSE_PRE:      main_rulesfiles_parse_pre      (hashcat_ctx, buf, len); break;
    case EVENT_SET_KERNEL_POWER_FINAL:    main_set_kernel_power_final    (hashcat_ctx, buf, len); break;
    case EVENT_WORDLIST_CACHE_GENERATE:   main_wordlist_cache_generate   (hashcat_ctx, buf, len); break;
    case EVENT_WORDLIST_CACHE_HIT:        main_wordlist_cache_hit        (hashcat_ctx, buf, len); break;
  }
}

int main (int argc, char **argv)
{
#if defined (_WIN)
  if (main_argv_utf8_init (&argc, &argv) == -1)
  {
    fprintf (stderr, "Failed to convert the Windows command line to UTF-8.\n");

    return -1;
  }
#endif

  main_timing_reset ();

  // this increases the size on windows dos boxes

  setup_console ();

  const time_t proc_start = time (NULL);

  // hashcat main context

  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));

  if (hashcat_init (hashcat_ctx, event) == -1)
  {
    hcfree (hashcat_ctx);

    return -1;
  }

  event_error_report_init (hashcat_ctx, VERSION_TAG, argc, argv);

  // install and shared folder need to be set to recognize "make install" use

  const char *install_folder = NULL;
  const char *shared_folder  = NULL;

  #if defined (INSTALL_FOLDER)
  install_folder = INSTALL_FOLDER;
  #endif

  #if defined (SHARED_FOLDER)
  shared_folder = SHARED_FOLDER;
  #endif

  // initialize the user options with some defaults (you can override them later)

  if (user_options_init (hashcat_ctx) == -1)
  {
    hashcat_destroy (hashcat_ctx);

    hcfree (hashcat_ctx);

    return -1;
  }

  // parse commandline parameters and check them

  if (user_options_getopt (hashcat_ctx, argc, argv) == -1)
  {
    user_options_destroy (hashcat_ctx);

    hashcat_destroy (hashcat_ctx);

    hcfree (hashcat_ctx);

    return -1;
  }

  if (user_options_sanity (hashcat_ctx) == -1)
  {
    user_options_destroy (hashcat_ctx);

    hashcat_destroy (hashcat_ctx);

    hcfree (hashcat_ctx);

    return -1;
  }

  // some early exits

  user_options_t *user_options = hashcat_ctx->user_options;

  #ifdef WITH_BRAIN
  if (user_options->brain_feed == true)
  {
    const int rc = brain_feed (hashcat_ctx);

    hcfree (hashcat_ctx);

    return rc;
  }

  if (user_options->brain_server == true)
  {
    const int rc = brain_server (user_options->brain_host, user_options->brain_port, user_options->brain_password, user_options->brain_session_whitelist, user_options->brain_server_timer);

    hcfree (hashcat_ctx);

    return rc;
  }
  #endif

  if (user_options->version == true)
  {
    printf ("%s\n", VERSION_TAG);

    user_options_destroy (hashcat_ctx);

    hashcat_destroy (hashcat_ctx);

    hcfree (hashcat_ctx);

    return 0;
  }

  // init a hashcat session; this initializes backend devices, hwmon, etc

  welcome_screen (hashcat_ctx, VERSION_TAG);

  int rc_final = -1;

  const bool timing_report_enabled = main_timing_report_enabled (user_options);

  main_timing_stop (MAIN_TIMING_COMMAND_SETUP);

  #define CUDA_STARTUP_RETRY_MAX   10
  #define CUDA_STARTUP_RETRY_DELAY 5000000  /* 5 seconds in microseconds */

  int active_argc = argc;
  char **active_argv = argv;
  char **pure_argv = NULL;

  bool pure_kernel_retry_done = false;

  int cuda_retry = 0;

  while (true)
  {
    if (cuda_retry > 0)
    {
      fprintf (stderr, "\nNOTICE: CUDA context startup failed. Partial resources were released; retrying in 5 seconds (%d/%d) ...\n\n", cuda_retry, CUDA_STARTUP_RETRY_MAX);

      main_timing_start (MAIN_TIMING_RETRY_WAIT);

      usleep (CUDA_STARTUP_RETRY_DELAY);

      main_timing_stop (MAIN_TIMING_RETRY_WAIT);
    }

    main_timing_start (MAIN_TIMING_SESSION_INIT);

    const int session_init_rc = hashcat_session_init (hashcat_ctx, install_folder, shared_folder, active_argc, active_argv, COMPTIME);

    main_timing_stop (MAIN_TIMING_SESSION_INIT);

    bool should_retry_pure_kernel = false;

    if (session_init_rc == 0)
    {
      if (user_options->usage > 0)
      {
        usage_big_print (hashcat_ctx);

        rc_final = 0;
      }
      else if (user_options->hash_info > 0)
      {
        hash_info (hashcat_ctx);

        rc_final = 0;
      }
      else if (user_options->backend_info > 0)
      {
        // if this is just backend_info, no need to execute some real cracking session

        backend_info (hashcat_ctx);

        rc_final = 0;
      }
      else
      {
        // now execute hashcat

        backend_info_compact (hashcat_ctx);

        user_options_info (hashcat_ctx);

        main_timing_start (MAIN_TIMING_EXECUTE);

        rc_final = hashcat_session_execute (hashcat_ctx);

        main_timing_stop (MAIN_TIMING_EXECUTE);

        should_retry_pure_kernel = (pure_kernel_retry_done == false)
                                && (hashcat_ctx->status_ctx->optimized_kernel_parse_all_failed == true);
      }
    }

    // finish the hashcat session, this shuts down backend devices, hwmon, etc

    const bool should_retry_cuda = ((backend_ctx_t *) hashcat_ctx->backend_ctx)->cuda_startup_error;

    main_timing_start (MAIN_TIMING_SESSION_DESTROY);

    hashcat_session_destroy (hashcat_ctx);

    main_timing_stop (MAIN_TIMING_SESSION_DESTROY);

    if (should_retry_pure_kernel == true)
    {
      pure_kernel_retry_done = true;

      pure_argv = main_pure_kernel_argv (argc, argv, &active_argc);
      active_argv = pure_argv;

      fprintf (stderr, "\nNOTICE: 100%% of input hashes were rejected with -O; rebuilding the session with the pure kernel.\n\n");

      if (main_user_options_reload (hashcat_ctx, active_argc, active_argv, true) == -1) break;

      cuda_retry = 0;

      continue;
    }

    if (should_retry_cuda == false) break;

    if (cuda_retry == CUDA_STARTUP_RETRY_MAX)
    {
      fprintf (stderr, "\nNOTICE: CUDA startup still failed after %d retries; giving up with no partial-GPU run.\n\n", CUDA_STARTUP_RETRY_MAX);

      break;
    }

    cuda_retry++;

    if (main_user_options_reload (hashcat_ctx, active_argc, active_argv, pure_kernel_retry_done) == -1) break;
  }

  hcfree (pure_argv);

  // finished with hashcat, clean up

  main_timing_report (hashcat_ctx, timing_report_enabled);

  const time_t proc_stop = time (NULL);

  goodbye_screen (hashcat_ctx, proc_start, proc_stop);

  hashcat_destroy (hashcat_ctx);

  hcfree (hashcat_ctx);

  return rc_final;
}
