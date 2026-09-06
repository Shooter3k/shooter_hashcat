/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "mdxfind_modes.h"
#include <stddef.h>
#include "memory.h"
#include "event.h"
#include "locking.h"
#include "thread.h"
#include "user_options.h"
#include "shared.h"
#include "filehandling.h"
#include "path.h"
#include "pidfile.h"
#include "folder.h"
#include "restore.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#if defined (_WIN)
#include <io.h>
#endif

static int init_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  restore_data_t *rd = (restore_data_t *) hcmalloc (sizeof (restore_data_t));

  restore_ctx->rd = rd;

  rd->version = RESTORE_VERSION_CUR;

  rd->argc = restore_ctx->argc;
  rd->argv = restore_ctx->argv;

  if (getcwd (rd->cwd, 255) == NULL)
  {
    event_log_error (hashcat_ctx, "getcwd(): %s", strerror (errno));

    return -1;
  }

  return 0;
}

static int read_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t   *restore_ctx   = hashcat_ctx->restore_ctx;
  folder_config_t *folder_config = hashcat_ctx->folder_config;

  if (restore_ctx->enabled == false) return 0;

  char *eff_restore_file = restore_ctx->eff_restore_file;

  HCFILE fp;

  if (hc_fopen (&fp, eff_restore_file, "rb") == false)
  {
    event_log_error (hashcat_ctx, "Restore file '%s': %s", eff_restore_file, strerror (errno));

    return -1;
  }

  restore_data_t *rd = restore_ctx->rd;

  int restore_version = 0;

  if (hc_fread (&restore_version, sizeof (restore_version), 1, &fp) != 1)
  {
    event_log_error (hashcat_ctx, "Cannot read %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  if ((restore_version < RESTORE_VERSION_MIN) || (restore_version > RESTORE_VERSION_CUR))
  {
    event_log_error (hashcat_ctx, "Incompatible restore-file version.");

    hc_fclose (&fp);

    return -1;
  }

  if (hc_fseek (&fp, 0, SEEK_SET) == -1)
  {
    event_log_error (hashcat_ctx, "Cannot seek %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  memset (rd, 0, sizeof (restore_data_t));

  const size_t restore_data_size = (restore_version >= 723)
                                 ? sizeof (restore_data_t)
                                 : (restore_version >= 722)
                                 ? offsetof (restore_data_t, multi_hash_modes_pos)
                                 : (restore_version >= 721)
                                 ? offsetof (restore_data_t, attack13_amplifier)
                                 : offsetof (restore_data_t, stdout_output_size);

  if (hc_fread (rd, restore_data_size, 1, &fp) != 1)
  {
    event_log_error (hashcat_ctx, "Cannot read %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  // we only use these 2 checks to avoid "tainted string" warnings

  if (rd->argc < 1)
  {
    event_log_error (hashcat_ctx, "Unusually low number of arguments (argc) within restore file %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  if (rd->argc > 250) // some upper bound check is always good (with some dirs/dicts it could be a large string)
  {
    event_log_error (hashcat_ctx, "Unusually high number of arguments (argc) within restore file %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  rd->argv = (char **) hccalloc (rd->argc, sizeof (char *));

  char *buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  if (buf == NULL)
  {
    event_log_error(hashcat_ctx, "hcmalloc: %s", strerror(errno));
    hc_fclose(&fp);
    hcfree(rd->argv);
    return -1;
  }

  for (u32 i = 0; i < rd->argc; i++)
  {
    if (hc_fgets (buf, HCBUFSIZ_LARGE - 1, &fp) == NULL)
    {
      event_log_error (hashcat_ctx, "Cannot read %s", eff_restore_file);

      hc_fclose (&fp);

      hcfree (buf);

      return -1;
    }

    size_t len = strlen (buf);

    if (len) buf[len - 1] = 0;

    rd->argv[i] = hcstrdup (buf);
  }

  hcfree (buf);

  hc_fclose (&fp);

  if (hc_path_exist (rd->cwd) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", rd->cwd, strerror (errno));

    return -1;
  }

  if (hc_path_is_directory (rd->cwd) == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", rd->cwd, strerror (errno));

    return -1;
  }

  if (strncmp (rd->cwd, folder_config->cwd, sizeof (rd->cwd)) != 0) // check if we need to change the current working directory
  {
    event_log_warning (hashcat_ctx, "Changing current working directory to '%s'", rd->cwd);
    event_log_warning (hashcat_ctx, NULL);

    if (chdir (rd->cwd))
    {
      event_log_error (hashcat_ctx, "Directory '%s' needed to restore the session was not found.", rd->cwd);

      event_log_warning (hashcat_ctx, "Either create the directory, or update the directory within the .restore file.");
      event_log_warning (hashcat_ctx, "Restore files can be analyzed and modified with analyze_hc_restore.pl:");
      event_log_warning (hashcat_ctx, "    https://github.com/philsmd/analyze_hc_restore");
      event_log_warning (hashcat_ctx, "Directory must contain all files and folders from the original command line.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    // if we are here, we also need to update the folder_config and .pid file:

    /**
     * updated folders
     */

    // copy the paths of INSTALL_FOLDER and SHARED_FOLDER from the folder config:

    char *install_folder = hcstrdup (folder_config->install_dir);
    char *shared_folder  = hcstrdup (folder_config->shared_dir);

    folder_config_destroy (hashcat_ctx);

    const int rc_folder_config_init = folder_config_init (hashcat_ctx, install_folder, shared_folder);

    hcfree (install_folder);
    hcfree (shared_folder);

    if (rc_folder_config_init == -1) return -1;

    /**
     * updated pidfile
     */

    pidfile_ctx_destroy (hashcat_ctx);

    if (pidfile_ctx_init (hashcat_ctx) == -1) return -1;
  }

  return 0;
}

static int write_restore (hashcat_ctx_t *hashcat_ctx)
{
  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const restore_ctx_t  *restore_ctx  = hashcat_ctx->restore_ctx;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  if (restore_ctx->enabled == false) return 0;

  restore_data_t *rd = restore_ctx->rd;

  rd->masks_pos = mask_ctx->masks_pos;
  rd->dicts_pos = straight_ctx->dicts_pos;
  rd->multi_hash_modes_pos = hashcat_ctx->user_options->multi_hash_modes_pos;

  if (hashcat_ctx->user_options->stdout_flag == true)
  {
    rd->words_cur          = restore_ctx->stdout_committed_words;
    rd->stdout_output_size = restore_ctx->stdout_output_size;
    rd->stdout_flags       = (restore_ctx->stdout_output_size_valid == true)
                           ? RESTORE_DATA_STDOUT_FILE
                           : 0;
  }
  else
  {
    rd->words_cur          = status_ctx->words_cur;
    rd->stdout_output_size = 0;
    rd->stdout_flags       = (mask_ctx->attack13_gpu_amplified == true)
                           ? RESTORE_DATA_ATTACK13_AMPLIFIED
                           : 0;
    rd->attack13_amplifier = mask_ctx->attack13_amplifier;
  }

  char *new_restore_file = restore_ctx->new_restore_file;

  HCFILE fp;

  if (hc_fopen (&fp, new_restore_file, "wb") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", new_restore_file, strerror (errno));

    return -1;
  }

  if (setvbuf (fp.pfp, NULL, _IONBF, 0))
  {
    event_log_error (hashcat_ctx, "setvbuf file '%s': %s", new_restore_file, strerror (errno));

    hc_fclose (&fp);

    return -1;
  }

  hc_fwrite (rd, sizeof (restore_data_t), 1, &fp);

  for (u32 i = 0; i < rd->argc; i++)
  {
    hc_fprintf (&fp, "%s", rd->argv[i]);

    hc_fputc ('\n', &fp);
  }

  hc_fflush (&fp);

  hc_fsync (&fp);

  hc_fclose (&fp);

  rd->masks_pos = 0;
  rd->dicts_pos = 0;
  rd->words_cur = 0;
  rd->stdout_output_size = 0;
  rd->stdout_flags = 0;
  rd->attack13_amplifier = 0;
  rd->multi_hash_modes_pos = 0;

  return 0;
}

int cycle_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false) return 0;

  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  const bool stdout_session = user_options->stdout_flag;

  if (stdout_session == true) hc_thread_mutex_lock (outfile_ctx->mux_outfile);

  const u64 words_cur = (stdout_session == true)
                      ? restore_ctx->stdout_committed_words
                      : status_ctx->words_cur;

  // no updates, no need to write
  if ((restore_ctx->masks_pos_prev == mask_ctx->masks_pos)
   && (restore_ctx->dicts_pos_prev == straight_ctx->dicts_pos)
   && (restore_ctx->words_cur_prev == words_cur))
  {
    if (stdout_session == true) hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

    return 0;
  }

  restore_ctx->masks_pos_prev = mask_ctx->masks_pos;
  restore_ctx->dicts_pos_prev = straight_ctx->dicts_pos;
  restore_ctx->words_cur_prev = words_cur;

  const char *eff_restore_file = restore_ctx->eff_restore_file;
  const char *new_restore_file = restore_ctx->new_restore_file;

  if ((stdout_session == true)
   && (restore_ctx->stdout_output_size_valid == true)
   && (outfile_ctx->filename != NULL))
  {
    const int fd = open (outfile_ctx->filename, O_WRONLY | O_BINARY);

    if (fd == -1)
    {
      event_log_error (hashcat_ctx, "Cannot synchronize --stdout outfile '%s': %s", outfile_ctx->filename, strerror (errno));

      hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

      return -1;
    }

    #if defined (_WIN)
    const int sync_rc = _commit (fd);
    #else
    const int sync_rc = fsync (fd);
    #endif

    close (fd);

    if (sync_rc == -1)
    {
      event_log_error (hashcat_ctx, "Cannot synchronize --stdout outfile '%s': %s", outfile_ctx->filename, strerror (errno));

      hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

      return -1;
    }
  }

  if (write_restore (hashcat_ctx) == -1)
  {
    if (stdout_session == true) hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

    return -1;
  }

  if (hc_path_exist (eff_restore_file) == true)
  {
    if (unlink (eff_restore_file) == -1)
    {
      event_log_warning (hashcat_ctx, "Unlink file '%s': %s", eff_restore_file, strerror (errno));
    }
  }

  if (rename (new_restore_file, eff_restore_file) == -1)
  {
    event_log_warning (hashcat_ctx, "Rename file '%s' to '%s': %s", new_restore_file, eff_restore_file, strerror (errno));
  }

  if (stdout_session == true) hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

  return 0;
}

int restore_stdout_output_init (hashcat_ctx_t *hashcat_ctx)
{
  outfile_ctx_t  *outfile_ctx  = hashcat_ctx->outfile_ctx;
  restore_ctx_t  *restore_ctx  = hashcat_ctx->restore_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->stdout_flag == false) return 0;

  restore_ctx->stdout_output_size       = 0;
  restore_ctx->stdout_output_size_valid = false;

  if ((outfile_ctx->filename == NULL) || (outfile_ctx->is_fifo == true))
  {
    if (restore_ctx->enabled == true)
    {
      event_log_warning (hashcat_ctx, "Resumable --stdout is enabled, but an exact output rollback requires a regular file supplied with -o/--outfile.");
      event_log_warning (hashcat_ctx, "A restored pipe or console stream resumes the candidate position only; already-consumed downstream data cannot be retracted.");
      event_log_warning (hashcat_ctx, NULL);
    }

    return 0;
  }

  u64 current_size = 0;

  struct stat st;

  if (stat (outfile_ctx->filename, &st) == 0)
  {
    current_size = (u64) st.st_size;
  }
  else if (errno != ENOENT)
  {
    event_log_error (hashcat_ctx, "Cannot inspect --stdout outfile '%s': %s", outfile_ctx->filename, strerror (errno));

    return -1;
  }

  if (restore_ctx->restore_execute == true)
  {
    restore_data_t *rd = restore_ctx->rd;

    if ((rd->stdout_flags & RESTORE_DATA_STDOUT_FILE) == 0)
    {
      event_log_error (hashcat_ctx, "The restore file does not contain an exact --stdout outfile boundary.");

      return -1;
    }

    if (current_size < rd->stdout_output_size)
    {
      event_log_error (hashcat_ctx, "The --stdout outfile '%s' is smaller than its saved restore boundary (%" PRIu64 " < %" PRIu64 ").", outfile_ctx->filename, current_size, rd->stdout_output_size);

      return -1;
    }

    if (current_size > rd->stdout_output_size)
    {
      const int fd = open (outfile_ctx->filename, O_WRONLY | O_BINARY);

      if (fd == -1)
      {
        event_log_error (hashcat_ctx, "Cannot open --stdout outfile '%s' for restore: %s", outfile_ctx->filename, strerror (errno));

        return -1;
      }

      const int rc_truncate = ftruncate (fd, (off_t) rd->stdout_output_size);

      if (rc_truncate == 0)
      {
        #if defined (_WIN)
        _commit (fd);
        #else
        fsync (fd);
        #endif
      }

      close (fd);

      if (rc_truncate == -1)
      {
        event_log_error (hashcat_ctx, "Cannot roll back --stdout outfile '%s' to byte %" PRIu64 ": %s", outfile_ctx->filename, rd->stdout_output_size, strerror (errno));

        return -1;
      }

      event_log_info (hashcat_ctx, "Restored --stdout outfile '%s' to byte %" PRIu64 ".", outfile_ctx->filename, rd->stdout_output_size);
    }

    current_size = rd->stdout_output_size;
  }

  restore_ctx->stdout_output_size       = current_size;
  restore_ctx->stdout_output_size_valid = true;

  return 0;
}

void unlink_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;
  status_ctx_t  *status_ctx  = hashcat_ctx->status_ctx;

  if (restore_ctx->enabled == false) return;

  if ((status_ctx->devices_status == STATUS_EXHAUSTED) && (status_ctx->run_thread_level1 == true)) // this is to check for [c]heckpoint
  {
    unlink (restore_ctx->eff_restore_file);
    unlink (restore_ctx->new_restore_file);
  }

  if (status_ctx->devices_status == STATUS_CRACKED)
  {
    unlink (restore_ctx->eff_restore_file);
    unlink (restore_ctx->new_restore_file);
  }
}

int restore_ctx_init (hashcat_ctx_t *hashcat_ctx, int argc, char **argv)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  restore_ctx_t   *restore_ctx   = hashcat_ctx->restore_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  restore_ctx->enabled = false;

  if (user_options->usage            > 0)     return 0;
  if (user_options->backend_info     > 0)     return 0;
  if (user_options->hash_info        > 0)     return 0;

  if (user_options->benchmark       == true)  return 0;
  if (user_options->keyspace        == true)  return 0;
  if (user_options->left            == true)  return 0;
  if (user_options->show            == true)  return 0;
  if (user_options->speed_only      == true)  return 0;
  if (user_options->progress_only   == true)  return 0;
  if (user_options->version         == true)  return 0;
  if (user_options->identify        == true)  return 0;
  if (user_options->restore_enable  == false) return 0;

  if (argc ==    0) return 0;
  if (argv == NULL) return 0;

  if (user_options->restore_file_path == NULL)
  {
    hc_asprintf (&restore_ctx->eff_restore_file, "%s/%s.restore",     folder_config->session_dir, user_options->session);
    hc_asprintf (&restore_ctx->new_restore_file, "%s/%s.restore.new", folder_config->session_dir, user_options->session);
  }
  else
  {
    restore_ctx->eff_restore_file = hcstrdup (user_options->restore_file_path);
    hc_asprintf (&restore_ctx->new_restore_file, "%s.new", user_options->restore_file_path);
  }

  restore_ctx->argc = argc;
  restore_ctx->argv = argv;

  // getopt permutes argv. Mode 13 assigns semantic meaning to where every -r and positional stage
  // originally appeared, so persist the untouched pointer order or a resumed run would reorder the
  // pipeline.

  if ((user_options->attack_mode == ATTACK_MODE_MULTI_HYBRID)
   && (user_options->hc_argv_original_cnt == argc)
   && (user_options->hc_argv_original != NULL))
  {
    restore_ctx->argv = user_options->hc_argv_original;
  }

  if (init_restore (hashcat_ctx) == -1) return -1;

  restore_ctx->enabled = true;

  restore_ctx->restore_execute = false;

  if (user_options->restore == true)
  {
    if (read_restore (hashcat_ctx) == -1) return -1;

    restore_data_t *rd = restore_ctx->rd;

    if (rd->version < RESTORE_VERSION_MIN)
    {
      event_log_error (hashcat_ctx, "Incompatible restore-file version.");

      return -1;
    }

    hcfree (user_options->multi_hash_modes_buf);

    user_options_init (hashcat_ctx);

    if (user_options_getopt (hashcat_ctx, rd->argc, rd->argv) == -1) return -1;
    if (user_options_sanity (hashcat_ctx) == -1) return -1;

    if ((user_options->multi_hash_modes_chgd == true) && (rd->multi_hash_modes_pos >= user_options->multi_hash_modes_cnt))
    {
      event_log_error (hashcat_ctx, "Restore file refers to --multi-hash-modes entry %u, but the restored command only has %u entries.", rd->multi_hash_modes_pos + 1, user_options->multi_hash_modes_cnt);

      return -1;
    }

    user_options->multi_hash_modes_pos = rd->multi_hash_modes_pos;

    if (user_options->multi_hash_modes_chgd == true)
    {
      user_options->hash_mode = (user_options->multi_hash_modes_shared == true)
                            ? SHOOTER_MULTI_HASH_SHARED_MODE
                            : user_options->multi_hash_modes_buf[user_options->multi_hash_modes_pos];
    }

    restore_ctx->restore_execute = true;
  }

  restore_ctx->masks_pos_prev = -1;
  restore_ctx->dicts_pos_prev = -1;
  restore_ctx->words_cur_prev = -1;

  return 0;
}

void restore_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false) return;

  hcfree (restore_ctx->eff_restore_file);
  hcfree (restore_ctx->new_restore_file);
  hcfree (restore_ctx->rd);

  memset (restore_ctx, 0, sizeof (restore_ctx_t));
}
