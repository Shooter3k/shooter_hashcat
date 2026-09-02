/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "thread.h"
#include "filehandling.h"
#include "event.h"

#ifndef __MINGW_PRINTF_FORMAT
#define __MINGW_PRINTF_FORMAT printf
#endif

static void event_error_report_timestamp (char *timestamp, const size_t timestamp_sz)
{
  const time_t now = time (NULL);

  struct tm tm;

  if (localtime_r (&now, &tm) == NULL)
  {
    snprintf (timestamp, timestamp_sz, "unknown");

    return;
  }

  strftime (timestamp, timestamp_sz, "%Y-%m-%d %H:%M:%S %z", &tm);
}

static void event_error_report_write_argument (HCFILE *fp, const char *argument)
{
  // Keep every argument on one physical line so malformed input cannot forge report fields.

  const size_t argument_len = strlen (argument);
  const size_t argument_max = 4096;
  const size_t write_len = MIN (argument_len, argument_max);

  for (size_t i = 0; i < write_len; i++)
  {
    const u8 c = (const u8) argument[i];

    if      (c == '\r') hc_fwrite ("\\r", 2, 1, fp);
    else if (c == '\n') hc_fwrite ("\\n", 2, 1, fp);
    else if (c == '\t') hc_fwrite ("\\t", 2, 1, fp);
    else if ((c < 0x20) || (c == 0x7f)) hc_fprintf (fp, "\\x%02x", c);
    else hc_fputc (c, fp);
  }

  if (argument_len > argument_max) hc_fprintf (fp, "... [truncated]");
}

static bool event_error_report_argument_is_secret (char **argv, const int argument_pos)
{
  const char *argument = argv[argument_pos];

  if (strncmp (argument, "--brain-password=", 17) == 0) return true;

  if ((argument_pos > 0) && (strcmp (argv[argument_pos - 1], "--brain-password") == 0)) return true;

  return false;
}

static void event_error_report_write_header (hashcat_ctx_t *hashcat_ctx, HCFILE *fp)
{
  const event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  char timestamp[64];

  event_error_report_timestamp (timestamp, sizeof (timestamp));

  #if defined (_WIN)
  static const char platform[] = "Windows";
  #elif defined (__APPLE__)
  static const char platform[] = "macOS";
  #elif defined (__linux__)
  static const char platform[] = "Linux";
  #else
  static const char platform[] = "Unix";
  #endif

  #if defined (__x86_64__) || defined (_M_X64)
  static const char architecture[] = "x86-64";
  #elif defined (__aarch64__) || defined (_M_ARM64)
  static const char architecture[] = "ARM64";
  #elif defined (__i386__) || defined (_M_IX86)
  static const char architecture[] = "x86";
  #else
  static const char architecture[] = "unknown";
  #endif

  #if defined (_WIN)
  const unsigned long process_id = (unsigned long) GetCurrentProcessId ();
  #else
  const unsigned long process_id = (unsigned long) getpid ();
  #endif

  char cwd[HCBUFSIZ_TINY] = { 0 };

  if (getcwd (cwd, sizeof (cwd) - 1) == NULL) snprintf (cwd, sizeof (cwd), "unavailable: %s", strerror (errno));

  hc_fprintf (fp, "shooter_hashcat automatic error report" EOL);
  hc_fprintf (fp, "Generated: %s" EOL, timestamp);
  hc_fprintf (fp, "Version: %s" EOL, event_ctx->error_report_version ? event_ctx->error_report_version : "unknown");
  hc_fprintf (fp, "Platform: %s %s" EOL, platform, architecture);
  hc_fprintf (fp, "Process ID: %lu" EOL, process_id);
  hc_fprintf (fp, "Working directory: %s" EOL, cwd);
  hc_fprintf (fp, "Privacy: review paths, arguments, and quoted input before sharing this file." EOL);
  hc_fprintf (fp, "The report does not attach input or output files, but diagnostics can quote individual input lines." EOL);
  hc_fprintf (fp, EOL "Arguments:" EOL);

  const int argument_count = MIN (event_ctx->error_report_argc, 256);

  for (int i = 0; i < argument_count; i++)
  {
    hc_fprintf (fp, "  [%d] ", i);

    if (event_error_report_argument_is_secret (event_ctx->error_report_argv, i) == true)
    {
      hc_fprintf (fp, "[REDACTED]");
    }
    else
    {
      event_error_report_write_argument (fp, event_ctx->error_report_argv[i]);
    }

    hc_fwrite (EOL, strlen (EOL), 1, fp);
  }

  if (event_ctx->error_report_argc > argument_count)
  {
    hc_fprintf (fp, "  ... %d additional arguments omitted" EOL, event_ctx->error_report_argc - argument_count);
  }
}

static void event_error_report_write_message (HCFILE *fp, event_ctx_t *event_ctx, const u32 id, const bool newline, const char *message, const size_t message_len)
{
  if ((event_ctx->error_report_line_open == true) && (event_ctx->error_report_line_id != id))
  {
    hc_fwrite (EOL, strlen (EOL), 1, fp);

    event_ctx->error_report_line_open = false;
  }

  if (message_len > 0)
  {
    if (event_ctx->error_report_line_open == false)
    {
      char timestamp[64];

      event_error_report_timestamp (timestamp, sizeof (timestamp));

      const char *level = (id == EVENT_LOG_WARNING) ? "WARNING" : "ERROR";

      hc_fprintf (fp, "[%s] %s: ", timestamp, level);
    }

    hc_fwrite (message, message_len, 1, fp);

    event_ctx->error_report_line_id = id;
  }

  if (newline == true)
  {
    hc_fwrite (EOL, strlen (EOL), 1, fp);

    event_ctx->error_report_line_open = false;
  }
  else if (message_len > 0)
  {
    event_ctx->error_report_line_open = true;
  }
}

static void event_error_report_remember_warning (event_ctx_t *event_ctx, const bool newline, const char *message, const size_t message_len)
{
  if (message_len == 0) return;

  const u32 warning_pos = event_ctx->error_report_warning_next;

  const size_t copy_len = MIN (message_len, sizeof (event_ctx->error_report_warnings[warning_pos]) - 1);

  memcpy (event_ctx->error_report_warnings[warning_pos], message, copy_len);

  event_ctx->error_report_warnings[warning_pos][copy_len] = 0;
  event_ctx->error_report_warning_len[warning_pos] = copy_len;
  event_ctx->error_report_warning_newline[warning_pos] = newline;
  event_ctx->error_report_warning_next = (warning_pos + 1) % MAX_ERROR_REPORT_WARNINGS;

  if (event_ctx->error_report_warning_count < MAX_ERROR_REPORT_WARNINGS)
  {
    event_ctx->error_report_warning_count++;
  }
}

static void event_error_report_write_warnings (event_ctx_t *event_ctx, HCFILE *fp)
{
  hc_fprintf (fp, EOL "Recent warnings before the first error (up to %u retained):" EOL, MAX_ERROR_REPORT_WARNINGS);

  if (event_ctx->error_report_warning_count == 0)
  {
    hc_fprintf (fp, "  (none)" EOL);
  }
  else
  {
    const u32 warning_first = (event_ctx->error_report_warning_count == MAX_ERROR_REPORT_WARNINGS)
                            ? event_ctx->error_report_warning_next
                            : 0;

    for (u32 i = 0; i < event_ctx->error_report_warning_count; i++)
    {
      const u32 warning_pos = (warning_first + i) % MAX_ERROR_REPORT_WARNINGS;

      event_error_report_write_message (fp,
                                        event_ctx,
                                        EVENT_LOG_WARNING,
                                        event_ctx->error_report_warning_newline[warning_pos],
                                        event_ctx->error_report_warnings[warning_pos],
                                        event_ctx->error_report_warning_len[warning_pos]);
    }

    if (event_ctx->error_report_line_open == true)
    {
      hc_fwrite (EOL, strlen (EOL), 1, fp);

      event_ctx->error_report_line_open = false;
    }
  }

  hc_fprintf (fp, EOL "Errors and later warnings:" EOL);
}

static bool event_error_report_append (hashcat_ctx_t *hashcat_ctx, const u32 id, const bool newline, const char *message, const size_t message_len)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  if ((id == EVENT_LOG_WARNING) && (event_ctx->error_report_created == false))
  {
    event_error_report_remember_warning (event_ctx, newline, message, message_len);

    return false;
  }

  if ((message_len == 0) && (event_ctx->error_report_created == false)) return false;

  if (event_ctx->error_report_configured == false)
  {
    event_error_report_init (hashcat_ctx, NULL, 0, NULL);
  }

  if (event_ctx->error_report_failed == true) return false;

  HCFILE fp;

  const char *mode = (event_ctx->error_report_created == true) ? "ab" : "wb";

  if (hc_fopen (&fp, event_ctx->error_report_path, mode) == false)
  {
    event_ctx->error_report_failed = true;

    fprintf (stderr, "WARNING: Could not create error report '%s': %s\n", event_ctx->error_report_path, strerror (errno));

    return false;
  }

  if (event_ctx->error_report_created == false)
  {
    event_error_report_write_header (hashcat_ctx, &fp);

    event_error_report_write_warnings (event_ctx, &fp);

    event_ctx->error_report_created = true;
  }

  event_error_report_write_message (&fp, event_ctx, id, newline, message, message_len);

  hc_fflush (&fp);

  hc_fclose (&fp);

  if ((id == EVENT_LOG_ERROR) && (newline == true) && (event_ctx->error_report_announced == false))
  {
    event_ctx->error_report_announced = true;

    return true;
  }

  return false;
}

void event_error_report_init (hashcat_ctx_t *hashcat_ctx, const char *version_tag, const int argc, char **argv)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  if (event_ctx->error_report_configured == true) return;

  char timestamp[32];

  const time_t now = time (NULL);

  struct tm tm;

  if (localtime_r (&now, &tm) == NULL)
  {
    snprintf (timestamp, sizeof (timestamp), "unknown-time");
  }
  else
  {
    strftime (timestamp, sizeof (timestamp), "%Y%m%d-%H%M%S", &tm);
  }

  #if defined (_WIN)
  const unsigned long process_id = (unsigned long) GetCurrentProcessId ();
  #else
  const unsigned long process_id = (unsigned long) getpid ();
  #endif

  char filename[256];

  snprintf (filename, sizeof (filename), "shooter_hashcat-error-%s-%lu.log", timestamp, process_id);

  char cwd[HCBUFSIZ_TINY] = { 0 };

  if (getcwd (cwd, sizeof (cwd) - 1) == NULL)
  {
    snprintf (event_ctx->error_report_path, sizeof (event_ctx->error_report_path), "%s", filename);
  }
  else
  {
    const size_t cwd_len = strlen (cwd);
    const size_t filename_len = strlen (filename);
    const bool cwd_has_separator = (cwd[cwd_len - 1] == '/') || (cwd[cwd_len - 1] == '\\');
    const size_t path_len = cwd_len + (cwd_has_separator ? 0 : 1) + filename_len;

    #if defined (_WIN)
    const char path_separator = '\\';
    #else
    const char path_separator = '/';
    #endif

    if (path_len >= sizeof (event_ctx->error_report_path))
    {
      // A relative filename still points at the starting directory and is more useful than a
      // silently truncated absolute path that cannot be opened.

      snprintf (event_ctx->error_report_path, sizeof (event_ctx->error_report_path), "%s", filename);
    }
    else
    {
      size_t path_pos = 0;

      memcpy (event_ctx->error_report_path + path_pos, cwd, cwd_len);

      path_pos += cwd_len;

      if (cwd_has_separator == false) event_ctx->error_report_path[path_pos++] = path_separator;

      memcpy (event_ctx->error_report_path + path_pos, filename, filename_len + 1);
    }
  }

  event_ctx->error_report_version    = version_tag;
  event_ctx->error_report_argc       = argc;
  event_ctx->error_report_argv       = argv;
  event_ctx->error_report_configured = true;
}

void event_call (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  bool is_log = false;

  switch (id)
  {
    case EVENT_LOG_INFO:    is_log = true; break;
    case EVENT_LOG_WARNING: is_log = true; break;
    case EVENT_LOG_ERROR:   is_log = true; break;
    case EVENT_LOG_ADVICE:  is_log = true; break;
  }

  if (is_log == false)
  {
    hc_thread_mutex_lock (event_ctx->mux_event);
  }

  hashcat_ctx->event (id, hashcat_ctx, buf, len);

  // add more back logs in case user wants to access them. Cracked-result
  // events are deliberately excluded: callers still receive every callback,
  // but retaining and shifting ten prior results for every crack adds a hot
  // O(MAX_OLD_EVENTS) memory path to very large result sets.
  //
  // Keep this update under mux_event as well. Parallel per-GPU session setup
  // dispatches device events from twelve threads. Releasing the mutex before
  // shifting old_buf/old_len allowed those threads to overlap memcpy calls and
  // corrupt the event history (and occasionally adjacent process state), which
  // surfaced later as an ntdll access violation in a resident worker.

  if (is_log == false && id != EVENT_CRACKER_HASH_CRACKED)
  {
    for (int i = MAX_OLD_EVENTS - 1; i >= 1; i--)
    {
      memcpy (event_ctx->old_buf[i], event_ctx->old_buf[i - 1], event_ctx->old_len[i - 1]);

      event_ctx->old_len[i] = event_ctx->old_len[i - 1];
    }

    size_t copy_len = 0;

    if (buf)
    {
      // truncate the whole buffer if needed (such that it fits into the old_buf):

      const size_t max_buf_len = sizeof (event_ctx->old_buf[0]);

      copy_len = MIN (len, max_buf_len - 1);

      memcpy (event_ctx->old_buf[0], buf, copy_len);
    }

    event_ctx->old_len[0] = copy_len;
  }

  if (is_log == false)
  {
    hc_thread_mutex_unlock (event_ctx->mux_event);
  }
}

__attribute__ ((format (__MINGW_PRINTF_FORMAT, 1, 0)))
static int event_log (const char *fmt, va_list ap, char *s, const size_t sz)
{
  size_t length;

  length = vsnprintf (s, sz, fmt, ap);
  length = MIN (length, sz);

  s[length] = 0;

  return (int) length;
}

static size_t event_log_dispatch (hashcat_ctx_t *hashcat_ctx, const u32 id, const bool newline, const size_t max_len, const char *fmt, va_list ap)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  // Every log level shares msg_buf, msg_len, msg_newline, prev_len and prev_on_stderr. Autotune runs
  // one thread per physical GPU, so formatting and printing must be one atomic operation or one
  // device can publish another device's message. A separate mutex is required because non-log event
  // callbacks hold mux_event and are allowed to log without recursively locking that same mutex.

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, max_len);
  }

  event_ctx->msg_newline = newline;

  bool announce_error_report = false;

  if ((id == EVENT_LOG_ERROR) || (id == EVENT_LOG_WARNING))
  {
    announce_error_report = event_error_report_append (hashcat_ctx, id, newline, event_ctx->msg_buf, event_ctx->msg_len);
  }

  event_call (id, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  if (announce_error_report == true)
  {
    event_log_info (hashcat_ctx, "Error report saved to: %s", event_ctx->error_report_path);
  }

  return msg_len;
}

size_t event_log_advice_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_ADVICE, false, HCBUFSIZ_SMALL - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

size_t event_log_info_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_INFO, false, HCBUFSIZ_SMALL - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

size_t event_log_warning_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_WARNING, false, HCBUFSIZ_SMALL - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

size_t event_log_error_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_ERROR, false, HCBUFSIZ_SMALL - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

size_t event_log_advice (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_ADVICE, true, HCBUFSIZ_SMALL - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

size_t event_log_info (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_INFO, true, HCBUFSIZ_LARGE - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_WARNING, true, HCBUFSIZ_SMALL - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

size_t event_log_error (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const size_t msg_len = event_log_dispatch (hashcat_ctx, EVENT_LOG_ERROR, true, HCBUFSIZ_SMALL - 1, fmt, ap);

  va_end (ap);

  return msg_len;
}

int event_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  // mux_log is initialized by hashcat_init() and survives across session retries. Clear only the
  // per-session data here; memset() of the full structure would destroy a live critical section.

  memset (event_ctx->old_buf, 0, sizeof (event_ctx->old_buf));
  memset (event_ctx->old_len, 0, sizeof (event_ctx->old_len));

  event_ctx->old_cnt = 0;

  event_ctx->msg_buf[0] = 0;
  event_ctx->msg_len = 0;
  event_ctx->msg_newline = false;

  event_ctx->prev_len       = 0;
  event_ctx->prev_on_stderr = false;

  hc_thread_mutex_init (event_ctx->mux_event);

  return 0;
}

void event_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_delete (event_ctx->mux_event);
}
