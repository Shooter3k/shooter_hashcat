/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "backend.h"
#include "mpsp.h"
#include "wordlist.h"
#include "shared.h"
#include "thread.h"
#include "timer.h"
#include "pwpipe.h"
#include "filehandling.h"
#include "rp.h"
#include "rp_cpu.h"
#include "emu_inc_rp.h"
#include "slow_candidates.h"
#include "candidate_policy.h"
#include "dispatch.h"
#include "generic.h"
#include "convert.h"
#include "user_options.h"
#include "stdout.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

static u64 get_highest_words_done (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64 words_cur = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    const u64 words_done = device_param->words_done;

    if (words_done > words_cur) words_cur = words_done;
  }

  return words_cur;
}

static u64 get_lowest_words_done (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64 words_cur = 0xffffffffffffffff;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    const u64 words_done = device_param->words_done;

    if (words_done < words_cur) words_cur = words_done;
  }

  // It's possible that a device's workload isn't finished right after a restore-case.
  // In that case, this function would return 0 and overwrite the real restore point

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (words_cur < status_ctx->words_cur) words_cur = status_ctx->words_cur;

  return words_cur;
}

static int set_kernel_power_final (hashcat_ctx_t *hashcat_ctx, const u64 kernel_power_final)
{
  EVENT (EVENT_SET_KERNEL_POWER_FINAL);

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  backend_ctx->kernel_power_final = kernel_power_final;

  return 0;
}

static u64 get_power (backend_ctx_t *backend_ctx, hc_device_param_t *device_param)
{
  const u64 kernel_power_final = backend_ctx->kernel_power_final;

  if (kernel_power_final)
  {
    const double device_factor = (double) device_param->hardware_power / backend_ctx->hardware_power_all;

    const u64 words_left_device = (u64) CEIL (kernel_power_final * device_factor);

    // work should be at least the hardware power available without any accelerator

    const u64 work = MAX (words_left_device, device_param->hardware_power);

    // we need to make sure the value is not larger than the regular kernel_power

    const u64 work_final = MIN (work, device_param->kernel_power);

    return work_final;
  }

  return device_param->kernel_power;
}

static u64 get_work (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 max)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  // words_limit is this round's share of --limit and not --limit itself. --increment and a mask file
  // are a queue of rounds and the queue is one keyspace, so a round that starts part way into the
  // window stops part way into it as well.

  const u64 words_off  = status_ctx->words_off;
  const u64 words_base = (status_ctx->words_limit == 0) ? status_ctx->words_base : MIN (status_ctx->words_limit, status_ctx->words_base);

  device_param->words_off = words_off;

  const u64 kernel_power_all = backend_ctx->kernel_power_all;

  // words_off can start beyond the keyspace. The brain sets it to the highest position the session
  // has already reached, and a later run of the same attack can have a smaller keyspace: fewer rules,
  // a tighter --limit, a wordlist that shrank. Unsigned subtraction then wraps to about 1.8e19, work
  // never runs out and the attack never finishes.

  const u64 words_left = (words_off < words_base) ? words_base - words_off : 0;

  if (words_left < kernel_power_all)
  {
    if (backend_ctx->kernel_power_final == 0)
    {
      set_kernel_power_final (hashcat_ctx, words_left);
    }
  }

  const u64 kernel_power = get_power (backend_ctx, device_param);

  u64 work = MIN (words_left, kernel_power);

  work = MIN (work, max);

  status_ctx->words_off += work;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  return work;
}

// Everything the slow-candidate producer carries between batches. The three slow-candidate modes
// build their candidates from different sources but drive them through the same loop, so they share
// one producer and hand it pointers into whichever extra_info struct they own.

typedef struct slow_fill_state
{
  void *extra_info;

  u64       *pos;
  const u8  *out_buf;
  const u32 *out_len;

  const u8  *base_buf;         // NULL when the mode has no base word
  const u32 *base_len;
  const u64 *rule_pos;         // NULL when the mode applies no rule

  bool seek;                   // a generated candidate is addressed by index and needs no seek
  bool reject_len;             // a mask produces one fixed length, checked once by the caller
  bool keep_base;              // only the modes --debug-mode can report have to keep the base word

  const bool *reject;          // NULL when the mode can never refuse a candidate it was asked for

  u64 words_cur;

  #ifdef WITH_BRAIN
  u64 brain_highest;
  #endif

} slow_fill_state_t;

static int fill_slow (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  // every use of this is inside a WITH_BRAIN block, so a build without the brain has none

  MAYBE_UNUSED user_options_t *user_options = hashcat_ctx->user_options;

  slow_fill_state_t *sc = (slow_fill_state_t *) state;

  hc_timer_t timer_feed;

  pipe_mark (&timer_feed);

  u64 pre_rejects = -1;

  // this greatly reduces spam on hashcat console

  const u64 pre_rejects_ignore = get_power (backend_ctx, device_param) / 2;

  while (pre_rejects > pre_rejects_ignore)
  {
    u64 words_extra_total = 0;

    u64 words_extra = pre_rejects;

    pre_rejects = 0;

    #ifdef WITH_BRAIN
    u64 brain_rejects_attacks = 0;
    u64 brain_rejects_hashes  = 0;
    #endif

    memset (device_param->pws_pre_buf, 0, device_param->size_pws_pre);

    device_param->pws_pre_cnt = 0;

    while (words_extra)
    {
      u64 work = get_work (hashcat_ctx, device_param, words_extra);

      if (work == 0) break;

      // cleared here rather than after the brain block, so a reserve that skips part of the range can
      // set it and have this loop fetch that much again. Otherwise every skipped word is a word the
      // batch never gets back and the device runs a short batch.

      words_extra = 0;

      u64 words_off = device_param->words_off;

      #ifdef WITH_BRAIN
      if (user_options->brain_client == true)
      {
        if (device_param->brain_link_client_fd == -1)
        {
          const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

          if (brain_client_connect (hashcat_ctx, device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, user_options->brain_session, user_options->brain_attack, passwords_max, &sc->brain_highest) == false)
          {
            brain_client_disconnect (device_param);
          }
        }

        if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
        {
          u64 overlap = 0;

          if (brain_client_reserve (device_param, status_ctx, words_off, work, &overlap) == false)
          {
            brain_client_disconnect (device_param);
          }

          words_extra        = overlap;
          words_extra_total += overlap;
          words_off         += overlap;
          work              -= overlap;

          brain_rejects_attacks += overlap;
        }
      }
      #endif

      const u64 words_fin = words_off + work;

      batch->words_fin = words_fin;

      if (sc->seek == true) slow_candidates_seek (hashcat_ctx, sc->extra_info, sc->words_cur, words_off);

      sc->words_cur = words_off;

      for (u64 i = sc->words_cur; i < words_fin; i++)
      {
        sc->pos[0] = i;

        slow_candidates_next (hashcat_ctx, sc->extra_info);

        // The source refused this one. It still occupies its offset, so the loop moves on rather
        // than fetching a replacement, and the caller counts it the way it counts a length reject.

        if ((sc->reject != NULL) && (*sc->reject == true))
        {
          pre_rejects++;

          continue;
        }

        // Candidate class requirements are deliberately checked here, after the host has assembled
        // the complete password and applied its rules. A rejected candidate keeps its original
        // keyspace position so --skip, --restore and progress accounting remain stable.

        if (candidate_policy_accept (user_options, sc->out_buf, sc->out_len[0]) == false)
        {
          pre_rejects++;

          continue;
        }

        if (sc->reject_len == true)
        {
          if ((sc->out_len[0] < hashconfig->pw_min) || (sc->out_len[0] > hashconfig->pw_max))
          {
            pre_rejects++;

            continue;
          }
        }

        #ifdef WITH_BRAIN
        if (user_options->brain_client == true)
        {
          u32 hash[2];

          brain_client_generate_hash ((u64 *) hash, (const char *) sc->out_buf, sc->out_len[0]);

          u32 *ptr = device_param->brain_link_out_buf;

          ptr[(device_param->pws_pre_cnt * 2) + 0] = hash[0];
          ptr[(device_param->pws_pre_cnt * 2) + 1] = hash[1];
        }
        #endif

        if (sc->base_buf)
        {
          pw_pre_add (device_param, sc->out_buf, sc->out_len[0], sc->base_buf, sc->base_len[0], (sc->rule_pos) ? (int) sc->rule_pos[0] : 0);
        }
        else
        {
          pw_pre_add (device_param, sc->out_buf, sc->out_len[0], NULL, 0, 0);
        }

        if (status_ctx->run_thread_level1 == false) break;
      }

      sc->words_cur = words_fin;

      if (status_ctx->run_thread_level1 == false) break;
    }

    #ifdef WITH_BRAIN
    if (user_options->brain_client == true)
    {
      if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_HASHES)
      {
        if (brain_client_lookup (device_param, status_ctx) == false)
        {
          brain_client_disconnect (device_param);
        }
      }

      const u64 pws_pre_cnt = device_param->pws_pre_cnt;

      for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
      {
        if (device_param->brain_link_in_buf[pws_pre_idx] == 1)
        {
          pre_rejects++;

          brain_rejects_hashes++;
        }
        else
        {
          pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

          if (sc->keep_base == true) pw_base_add (batch, device_param->kernel_power, pw_pre);

          pw_add (batch, device_param->kernel_power, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
        }
      }
    }
    else
    {
      const u64 pws_pre_cnt = device_param->pws_pre_cnt;

      for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
      {
        pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

        if (sc->keep_base == true) pw_base_add (batch, device_param->kernel_power, pw_pre);

        pw_add (batch, device_param->kernel_power, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
      }
    }
    #else
    const u64 pws_pre_cnt = device_param->pws_pre_cnt;

    for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
    {
      pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

      if (sc->keep_base == true) pw_base_add (batch, device_param->kernel_power, pw_pre);

      pw_add (batch, device_param->kernel_power, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
    }
    #endif

    words_extra_total += pre_rejects;

    if (status_ctx->run_thread_level1 == false) break;

    if (words_extra_total > 0)
    {
      hc_thread_mutex_lock (status_ctx->mux_counter);

      for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        status_ctx->words_progress_rejected[salt_pos] += words_extra_total;
      }

      #ifdef WITH_BRAIN
      status_ctx->brain_rejects_attacks += brain_rejects_attacks;
      status_ctx->brain_rejects_hashes  += brain_rejects_hashes;
      #endif

      hc_thread_mutex_unlock (status_ctx->mux_counter);
    }
  }

  pipe_acc (PIPE_FEED, &timer_feed);

  return 0;
}


// Book one base word that produced no candidate. It stays booked against its own offset rather than
// being replaced, so --skip, --restore and the brain all keep counting the same positions. Both
// producers share this, because both count their base words the same way: a source holds as many base
// words as it holds lines, and one that cannot be turned into a candidate is a rejected word rather
// than a word that was never there.
//
// -a 9 cannot do even that. Word N is the guess for salt N, so a missing candidate would move every
// later word onto the previous hash, and there is nothing to put in its place. The run stops instead
// and says which word it was.

static int fill_reject (hashcat_ctx_t *hashcat_ctx, const bool reject_fatal, pw_batch_t *batch, u64 *words_extra, const u64 word_pos)
{
  if (reject_fatal == true)
  {
    event_log_error (hashcat_ctx, "Word %" PRIu64 " of the wordlist cannot be used as a candidate", word_pos + 1);
    event_log_error (hashcat_ctx, "Attack mode 9 pairs word N with salt N, so it has nothing to put in its place");

    return -1;
  }

  batch->words_extra++;

  words_extra[0]++;

  return 0;
}

// Everything the generic-feed producer carries between batches. The feed plugin keeps its own
// per-device cursor, so only one thread may drive it.

typedef struct generic_fill_state
{
  // Everything that happens to a base word between the feed handing it over and the device receiving
  // it, in the order every other producer uses it in. See pw_transform_t.

  pw_transform_t transform;

  // Which of the hash mode's length bounds apply to a base word, which is the one thing the attack
  // modes genuinely disagree about here.

  u32 length_policy;

  // Whether a base word that cannot be turned into a candidate ends the run. -a 9 is the mode that
  // cannot absorb one: word N belongs to salt N, so dropping one moves every later word onto the
  // previous hash.

  bool reject_fatal;

  // The feed writes the candidate straight into the buffer that gets uploaded, which holds exactly
  // PW_MAX per candidate. That is what makes the feed zero copy and it is the whole reader advantage
  // over -a 0, so it has to stay the normal path.
  //
  // A hex wordlist, a $HEX[] wrapper and an encoding change all shorten a candidate, so one can
  // arrive too long for that buffer and still finish inside it: a 256 byte password written as hex
  // is a 512 byte line. When that happens the word is read a second time into scratch, which is
  // large enough, and only the finished candidate is copied over. It costs a seek and a re-read, and
  // it only happens for a candidate that would otherwise have been thrown away.

  bool  can_shrink;
  bool  transform_simple;
  int   scratch_size;
  u8   *scratch;

  // Where the feed's own cursor is, so that a seek that would not move it can be skipped. A feed
  // that cannot seek has to implement seek by generating from the start again, which is the shape a
  // probabilistic generator has, and seeking it once per batch to the place it already sits turns a
  // linear attack into a quadratic one.

  bool seek_known;
  u64  seek_pos;

} generic_fill_state_t;

static int fill_generic (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  generic_fill_state_t *gf = (generic_fill_state_t *) state;

  hc_timer_t timer_feed;

  pipe_mark (&timer_feed);

  u64 words_extra = -1U;

  bool feed_dry = false;

  while (words_extra)
  {
    const u64 work_cnt = get_work (hashcat_ctx, device_param, words_extra);

    if (work_cnt == 0) break;

    words_extra = 0;

    const u64 words_off = device_param->words_off;

    batch->words_off = words_off;

    if ((gf->seek_known == false) || (gf->seek_pos != words_off))
    {
      if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_BASE, device_param->device_id, words_off) != 0) return -1;

      gf->seek_known = true;
      gf->seek_pos   = words_off;
    }

    u64 work_cur = 0;

    for (work_cur = 0; work_cur < work_cnt; work_cur++)
    {
      pw_idx_t *pw_idx = batch->pws_idx + batch->pws_cnt;

      u8 *pw_buf = (u8 *) (batch->pws_comp + pw_idx->off);

      // the candidate lands in the upload buffer directly, which is what makes the feed zero copy

      u8 *work_buf = pw_buf;

      int pw_len = generic_thread_next (hashcat_ctx, GENERIC_ROLE_BASE, device_param->device_id, pw_buf, PW_MAX);

      // the feed is dry. Whatever it produced before this call still has to be launched, so the
      // batch is finished rather than thrown away, and the pipeline is told on the next one

      if (pw_len == GENERIC_RC_EOF)
      {
        feed_dry = true;

        break;
      }

      // the feed failed. That is not the end of the attack, it is the end of the session, and it has
      // to reach the caller as an error or the run reports Exhausted and an exit status that says
      // everything went fine

      if (pw_len == GENERIC_RC_ERROR) return -1;

      gf->seek_pos++;

      // A feed reports the true length even when the candidate did not fit and it only wrote the
      // first PW_MAX bytes. If nothing in this run can shorten it then it is simply too long, and
      // -a 0 would have dropped it too.

      if (pw_len > PW_MAX)
      {
        if (gf->can_shrink == false)
        {
          if (fill_reject (hashcat_ctx, gf->reject_fatal, batch, &words_extra, words_off + work_cur) == -1) return -1;

          continue;
        }

        // It might still finish short enough, so read it again somewhere it fits. The feed is one
        // candidate past it now, so it has to be sent back.

        if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_BASE, device_param->device_id, words_off + work_cur) != 0) return -1;

        pw_len = generic_thread_next (hashcat_ctx, GENERIC_ROLE_BASE, device_param->device_id, gf->scratch, gf->scratch_size);

        if (pw_len == GENERIC_RC_EOF)
        {
          feed_dry = true;

          break;
        }

        if (pw_len == GENERIC_RC_ERROR) return -1;

        if (pw_len > gf->scratch_size)
        {
          if (fill_reject (hashcat_ctx, gf->reject_fatal, batch, &words_extra, words_off + work_cur) == -1) return -1;

          continue;
        }

        work_buf = gf->scratch;
      }

      // Everything that happens to a base word, in the one order every producer uses.

      bool transform_needed = true;

      if (gf->transform_simple == true)
      {
        transform_needed = false;

        // The normal MD5 wordlist path has no inline rule, case conversion or encoding conversion.
        // Autohex is its only possible transform, and almost every real candidate can reject that
        // possibility from the six-byte prefix. Avoid two core calls for every ordinary email or
        // password while still sending actual $HEX[...] entries through the complete transform.

        if ((gf->transform.wordlist_autohex == true)
         && (pw_len >= 6)
         && ((pw_len & 1) == 0)
         && (work_buf[0] == '$')
         && (work_buf[1] == 'H')
         && (work_buf[2] == 'E')
         && (work_buf[3] == 'X')
         && (work_buf[4] == '['))
        {
          transform_needed = true;
        }
      }

      if (transform_needed == true)
      {
        pw_len = pw_transform_apply (&gf->transform, work_buf, pw_len, (work_buf == pw_buf) ? PW_MAX : gf->scratch_size);
      }

      if (pw_len < 0)
      {
        if (fill_reject (hashcat_ctx, gf->reject_fatal, batch, &words_extra, words_off + work_cur) == -1) return -1;

        continue;
      }

      // Only now is the length final, so only now can it be judged. Rejecting before the transforms
      // would throw away a hex line that decodes to a candidate of a perfectly legal length: a 256
      // byte password written as hex arrives as 512 bytes.

      if (pw_len > PW_MAX)
      {
        if (fill_reject (hashcat_ctx, gf->reject_fatal, batch, &words_extra, words_off + work_cur) == -1) return -1;

        continue;
      }

      if (work_buf != pw_buf) memcpy (pw_buf, work_buf, pw_len);

      if (gf->length_policy != BASE_LENGTH_NONE)
      {
        const bool too_short = (gf->length_policy == BASE_LENGTH_BOTH) && (pw_len < (int) hashconfig->pw_min);
        const bool too_long  = (pw_len > (int) hashconfig->pw_max);

        if ((too_short == true) || (too_long == true))
        {
          if (fill_reject (hashcat_ctx, gf->reject_fatal, batch, &words_extra, words_off + work_cur) == -1) return -1;

          continue;
        }
      }

      pw_add_zerocopy (batch, device_param->kernel_power, pw_buf, pw_len);
    }

    // How far into the keyspace this batch reached. It is the restore point, so it has to be a
    // position and not a count of the words this one device happened to see.
    //
    // It is also what tells the pipeline whether the source is finished: a batch with no candidates
    // and no words_fin is the end. Leaving it at zero whenever nothing was accepted made a batch in
    // which every candidate was rejected on length look like the end of the feed, which ended the
    // attack and lost the rejects with it. Only a batch the feed refused to fill at all is the end.

    if (work_cur > 0) batch->words_fin = words_off + work_cur;

    if (feed_dry == true) break;

    if (status_ctx->run_thread_level1 == false) break;
  }

  pipe_acc (PIPE_FEED, &timer_feed);

  return 0;
}

typedef struct multi_fill_state
{
  HCFILE *fps;
  int opened;
  int base_cnt;
  u32 length_policy;

  pw_transform_t *transforms;
  int transforms_cnt;

  u64 *words_cnt;
  u64 *strides;
  u64 position;
  bool positioned;

  u8  *word_buf;
  int *word_len;
  char *line_buf;

} multi_fill_state_t;

static int multi_fill_store_line (hashcat_ctx_t *hashcat_ctx, multi_fill_state_t *mf, const int i)
{
  int line_len = fgetl (&mf->fps[i], mf->line_buf, HCBUFSIZ_LARGE);

  if (line_len == -1) return -1;

  if (i < mf->transforms_cnt)
  {
    line_len = pw_transform_apply (&mf->transforms[i], (u8 *) mf->line_buf, line_len, HCBUFSIZ_LARGE);
  }
  else
  {
    line_len = convert_from_hex (hashcat_ctx, mf->line_buf, line_len);
  }

  mf->word_len[i] = line_len;

  if ((line_len >= 0) && (line_len <= PW_MAX)) memcpy (mf->word_buf + (i * (PW_MAX + 1)), mf->line_buf, line_len);

  return 0;
}

static int multi_fill_step (hashcat_ctx_t *hashcat_ctx, multi_fill_state_t *mf, const u64 pos)
{
  for (int i = 0; i < mf->base_cnt; i++)
  {
    if ((pos % mf->strides[i]) != 0) continue;

    if (multi_fill_store_line (hashcat_ctx, mf, i) == -1) return -1;

    for (int j = i + 1; j < mf->base_cnt; j++) hc_rewind (&mf->fps[j]);
  }

  return 0;
}

// A device may receive a range far into the Cartesian product. Walking every earlier combination
// would make startup scale with the product and is especially damaging on many GPUs. Position each
// wordlist directly at its mixed-radix digit instead. Subsequent candidates retain the inexpensive
// sequential stepping path above.

static int multi_fill_seek_position (hashcat_ctx_t *hashcat_ctx, multi_fill_state_t *mf, const u64 pos)
{
  for (int i = 0; i < mf->base_cnt; i++)
  {
    const u64 line_idx = (pos / mf->strides[i]) % mf->words_cnt[i];

    hc_rewind (&mf->fps[i]);

    for (u64 line_pos = 0; line_pos <= line_idx; line_pos++)
    {
      if (multi_fill_store_line (hashcat_ctx, mf, i) == -1) return -1;
    }
  }

  return 0;
}

static int multi_fill_position (hashcat_ctx_t *hashcat_ctx, multi_fill_state_t *mf, const u64 pos)
{
  // Mode 13 emits every mask value for one word tuple before advancing the tuple. Reuse the cached
  // words while only the mask position changes.

  if ((mf->positioned == true) && (pos == mf->position)) return 0;

  int rc = 0;

  if ((mf->positioned == true) && (pos == mf->position + 1))
  {
    rc = multi_fill_step (hashcat_ctx, mf, pos);
  }
  else
  {
    rc = multi_fill_seek_position (hashcat_ctx, mf, pos);
  }

  if (rc == -1) return -1;

  mf->position   = pos;
  mf->positioned = true;

  return 0;
}

static int multi_fill_init (hashcat_ctx_t *hashcat_ctx, multi_fill_state_t *mf, const int base_cnt, const u32 length_policy, const bool transform_wordlists)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  memset (mf, 0, sizeof (*mf));

  mf->base_cnt      = base_cnt;
  mf->length_policy = length_policy;
  mf->fps           = (HCFILE *) hccalloc (base_cnt, sizeof (HCFILE));
  mf->words_cnt     = (u64 *)    hccalloc (base_cnt, sizeof (u64));
  mf->strides       = (u64 *)    hccalloc (base_cnt, sizeof (u64));
  mf->word_buf      = (u8 *)     hccalloc (base_cnt, PW_MAX + 1);
  mf->word_len      = (int *)    hccalloc (base_cnt, sizeof (int));

  if (transform_wordlists == true) mf->transforms = (pw_transform_t *) hccalloc (base_cnt, sizeof (pw_transform_t));

  for (int i = 0; i < mf->base_cnt; i++)
  {
    mf->words_cnt[i] = combinator_ctx->combs_counts[i];

    if (hc_fopen (&mf->fps[i], combinator_ctx->dicts[i], "rb") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", combinator_ctx->dicts[i], strerror (errno));

      return -1;
    }

    mf->opened++;
  }

  if (transform_wordlists == true)
  {
    for (int i = 0; i < mf->base_cnt; i++)
    {
      const int   rule_len = (i == 0) ? (int) user_options_extra->rule_len_l : (int) user_options_extra->rule_len_r;
      const char *rule_buf = (i == 0) ?       user_options->rule_buf_l :       user_options->rule_buf_r;

      if (pw_transform_init_wordlist (&mf->transforms[i], hashcat_ctx, rule_len, rule_buf) == -1) return -1;

      mf->transforms_cnt++;
    }
  }

  for (int i = 0; i < mf->base_cnt; i++) mf->strides[i] = 1;

  for (int i = mf->base_cnt - 2; i >= 0; i--) mf->strides[i] = mf->strides[i + 1] * mf->words_cnt[i + 1];

  mf->line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  return 0;
}

static void multi_fill_destroy (multi_fill_state_t *mf)
{
  for (int i = 0; i < mf->opened; i++) hc_fclose (&mf->fps[i]);

  for (int i = 0; i < mf->transforms_cnt; i++) pw_transform_term (&mf->transforms[i]);

  hcfree (mf->fps);
  hcfree (mf->transforms);
  hcfree (mf->words_cnt);
  hcfree (mf->strides);
  hcfree (mf->word_buf);
  hcfree (mf->word_len);
  hcfree (mf->line_buf);
}

static int fill_multi (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  multi_fill_state_t *mf = (multi_fill_state_t *) state;

  u64 words_extra = -1U;

  while (words_extra)
  {
    const u64 work_cnt = get_work (hashcat_ctx, device_param, words_extra);

    if (work_cnt == 0) break;

    words_extra = 0;

    const u64 words_off = device_param->words_off;

    batch->words_off = words_off;

    u64 work_cur = 0;

    for (work_cur = 0; work_cur < work_cnt; work_cur++)
    {
      if (multi_fill_position (hashcat_ctx, mf, words_off + work_cur) == -1)
      {
        event_log_error (hashcat_ctx, "Unexpected end of multi-way combination wordlist.");

        return -1;
      }

      int combined_len = 0;
      bool invalid = false;

      for (int i = 0; i < mf->base_cnt; i++)
      {
        if (mf->word_len[i] < 0)
        {
          invalid = true;

          break;
        }

        combined_len += mf->word_len[i];
      }

      const bool too_short = (mf->length_policy == BASE_LENGTH_BOTH) && (combined_len < (int) hashconfig->pw_min);
      const bool too_long  = (combined_len > (int) hashconfig->pw_max);

      if ((invalid == true) || (too_short == true) || (too_long == true))
      {
        if (fill_reject (hashcat_ctx, false, batch, &words_extra, words_off + work_cur) == -1) return -1;

        continue;
      }

      u8 combined_buf[PW_MAX + 1];
      int combined_pos = 0;

      for (int i = 0; i < mf->base_cnt; i++)
      {
        memcpy (combined_buf + combined_pos, mf->word_buf + (i * (PW_MAX + 1)), mf->word_len[i]);

        combined_pos += mf->word_len[i];
      }

      pw_add (batch, device_param->kernel_power, combined_buf, combined_len);

      if (status_ctx->run_thread_level1 == false) break;
    }

    if (work_cur > 0) batch->words_fin = words_off + work_cur;

    if (status_ctx->run_thread_level1 == false) break;
  }

  return 0;
}

typedef struct attack13_fill_state
{
  hashcat_ctx_t *hashcat_ctx;
  int device_id;
  bool indexed_first_wordlist;

  HCFILE *fps;
  int opened;

  u32 wordlists_cnt;
  u32 stages_cnt;

  pw_transform_t *transforms;
  int transforms_cnt;

  u64  *cached_indices;
  bool *cached;
  u8   *word_buf;
  int  *word_len;

  u8  **resident_word_buf;
  int **resident_word_len;
  u64  *resident_word_cnt;

  u64  *stage_indices;
  bool *prefix_cached;
  u8   *prefix_buf;
  int  *prefix_len;

  u64  candidate_pos;
  bool candidate_pos_cached;

  char *line_buf;

} attack13_fill_state_t;

#define ATTACK13_RESIDENT_CACHE_BYTES (8U * 1024U * 1024U)

static int attack13_fill_store_line (attack13_fill_state_t *state, const u32 wordlist_pos)
{
  int line_len = fgetl (&state->fps[wordlist_pos], state->line_buf, HCBUFSIZ_LARGE);

  if (line_len == -1) return -1;

  line_len = pw_transform_apply (&state->transforms[wordlist_pos], (u8 *) state->line_buf, line_len, HCBUFSIZ_LARGE);

  state->word_len[wordlist_pos] = line_len;

  if ((line_len >= 0) && (line_len <= RP_PASSWORD_SIZE))
  {
    memcpy (state->word_buf + (wordlist_pos * RP_PASSWORD_SIZE), state->line_buf, line_len);
  }

  return 0;
}

static int attack13_fill_word (attack13_fill_state_t *state, const attack13_stage_t *stage, const u64 line_idx, const u8 **word_buf, int *word_len)
{
  const u32 wordlist_pos = stage->wordlist_ordinal;

  if ((wordlist_pos == 0) && (state->indexed_first_wordlist == true))
  {
    if ((state->cached[wordlist_pos] == false) || (state->cached_indices[wordlist_pos] != line_idx))
    {
      if ((state->cached[wordlist_pos] == false) || (state->cached_indices[wordlist_pos] + 1 != line_idx))
      {
        if (generic_thread_seek (state->hashcat_ctx, GENERIC_ROLE_BASE, state->device_id, line_idx) == GENERIC_RC_ERROR) return -1;
      }

      int line_len = generic_thread_next (state->hashcat_ctx, GENERIC_ROLE_BASE, state->device_id, (u8 *) state->line_buf, HCBUFSIZ_LARGE);

      if (line_len < 0) return -1;

      line_len = pw_transform_apply (&state->transforms[wordlist_pos], (u8 *) state->line_buf, line_len, HCBUFSIZ_LARGE);

      state->word_len[wordlist_pos] = line_len;

      if ((line_len >= 0) && (line_len <= RP_PASSWORD_SIZE))
      {
        memcpy (state->word_buf + (wordlist_pos * RP_PASSWORD_SIZE), state->line_buf, line_len);
      }

      state->cached_indices[wordlist_pos] = line_idx;
      state->cached[wordlist_pos]         = true;
    }

    *word_buf = state->word_buf + (wordlist_pos * RP_PASSWORD_SIZE);
    *word_len = state->word_len[wordlist_pos];

    return 0;
  }

  if (state->resident_word_buf[wordlist_pos] != NULL)
  {
    if (line_idx >= state->resident_word_cnt[wordlist_pos]) return -1;

    *word_buf = state->resident_word_buf[wordlist_pos] + (line_idx * RP_PASSWORD_SIZE);
    *word_len = state->resident_word_len[wordlist_pos][line_idx];

    return 0;
  }

  if ((state->cached[wordlist_pos] == true) && (state->cached_indices[wordlist_pos] == line_idx))
  {
    *word_buf = state->word_buf + (wordlist_pos * RP_PASSWORD_SIZE);
    *word_len = state->word_len[wordlist_pos];

    return 0;
  }

  if ((state->cached[wordlist_pos] == true) && (state->cached_indices[wordlist_pos] < line_idx))
  {
    for (u64 i = state->cached_indices[wordlist_pos] + 1; i <= line_idx; i++)
    {
      if (attack13_fill_store_line (state, wordlist_pos) == -1) return -1;
    }
  }
  else
  {
    hc_rewind (&state->fps[wordlist_pos]);

    for (u64 i = 0; i <= line_idx; i++)
    {
      if (attack13_fill_store_line (state, wordlist_pos) == -1) return -1;
    }
  }

  state->cached_indices[wordlist_pos] = line_idx;
  state->cached[wordlist_pos]         = true;

  *word_buf = state->word_buf + (wordlist_pos * RP_PASSWORD_SIZE);
  *word_len = state->word_len[wordlist_pos];

  return 0;
}

static int attack13_fill_cache_wordlist (hashcat_ctx_t *hashcat_ctx, attack13_fill_state_t *state, const attack13_stage_t *stage, u64 *resident_bytes)
{
  const u32 wordlist_pos = stage->wordlist_ordinal;

  if (stage->candidates > (u64) (ATTACK13_RESIDENT_CACHE_BYTES / RP_PASSWORD_SIZE)) return 0;

  const u64 buf_bytes = stage->candidates * RP_PASSWORD_SIZE;
  const u64 len_bytes = stage->candidates * sizeof (int);
  const u64 new_bytes = buf_bytes + len_bytes;

  if (new_bytes > ATTACK13_RESIDENT_CACHE_BYTES - *resident_bytes) return 0;

  u8  *cache_buf = (u8 *) hccalloc ((size_t) stage->candidates, RP_PASSWORD_SIZE);
  int *cache_len = (int *) hccalloc ((size_t) stage->candidates, sizeof (int));

  for (u64 line_idx = 0; line_idx < stage->candidates; line_idx++)
  {
    int line_len = fgetl (&state->fps[wordlist_pos], state->line_buf, HCBUFSIZ_LARGE);

    if (line_len == -1)
    {
      event_log_error (hashcat_ctx, "Unexpected end of attack-mode 13 wordlist: %s", stage->source);

      hcfree (cache_buf);
      hcfree (cache_len);

      return -1;
    }

    line_len = pw_transform_apply (&state->transforms[wordlist_pos], (u8 *) state->line_buf, line_len, HCBUFSIZ_LARGE);

    cache_len[line_idx] = line_len;

    if ((line_len >= 0) && (line_len <= RP_PASSWORD_SIZE))
    {
      memcpy (cache_buf + (line_idx * RP_PASSWORD_SIZE), state->line_buf, line_len);
    }
  }

  hc_rewind (&state->fps[wordlist_pos]);

  state->resident_word_buf[wordlist_pos] = cache_buf;
  state->resident_word_len[wordlist_pos] = cache_len;
  state->resident_word_cnt[wordlist_pos] = stage->candidates;

  *resident_bytes += new_bytes;

  return 0;
}

static int attack13_markov_key (const mask_ctx_t *mask_ctx, const attack13_mask_t *attack_mask, const u32 pos, const u32 previous, const u32 ordinal)
{
  bool allowed[CHARSIZ] = { false };

  for (u32 i = 0; i < attack_mask->css_buf[pos].cs_len; i++)
  {
    allowed[attack_mask->css_buf[pos].cs_buf[i] & 0xff] = true;
  }

  const hcstat_table_t *table = mask_ctx->markov_table_buf + ((((u64) pos - 1) * CHARSIZ + previous) * CHARSIZ);

  u32 seen = 0;

  for (u32 i = 0; i < CHARSIZ; i++)
  {
    const u32 key = table[i].key;

    if (allowed[key] == false) continue;

    if (seen++ == ordinal) return (int) key;
  }

  return -1;
}

int attack13_mask_append (const mask_ctx_t *mask_ctx, const attack13_stage_t *stage, u64 mask_idx, char *candidate, int *candidate_len)
{
  const attack13_mask_t *attack_mask = NULL;

  for (u32 i = 0; i < stage->masks_cnt; i++)
  {
    const attack13_mask_t *entry = &stage->masks[i];

    if (mask_idx < entry->offset) continue;
    if (mask_idx >= entry->offset + entry->candidates) continue;

    attack_mask = entry;
    mask_idx -= entry->offset;

    break;
  }

  if (attack_mask == NULL) return -1;
  if (*candidate_len + (int) attack_mask->css_cnt > RP_PASSWORD_SIZE) return -1;

  u32 previous = 0;

  for (u32 pos = 0; pos < attack_mask->css_cnt; pos++)
  {
    const u32 radix   = attack_mask->root_css_buf[pos].cs_len;
    const u32 ordinal = (u32) (mask_idx % radix);

    mask_idx /= radix;

    int key;

    if (pos == 0)
    {
      key = (int) attack_mask->root_css_buf[pos].cs_buf[ordinal];
    }
    else
    {
      key = attack13_markov_key (mask_ctx, attack_mask, pos, previous, ordinal);
    }

    if (key < 0) return -1;

    candidate[(*candidate_len)++] = (char) key;
    previous = (u32) key;
  }

  return 0;
}

static int attack13_fill_init (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, attack13_fill_state_t *state)
{
  const mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  memset (state, 0, sizeof (*state));

  state->hashcat_ctx = hashcat_ctx;
  state->device_id   = device_param->device_id;

  state->indexed_first_wordlist = ((mask_ctx->attack13_gpu_amplified == true)
                                && (mask_ctx->attack13_host_wordlists_cnt > 0)
                                && (hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE].enabled == true));

  const u32 wordlists_cnt = mask_ctx->attack13_host_wordlists_cnt;
  const u32 stages_cnt    = mask_ctx->attack13_host_stages_cnt;

  state->wordlists_cnt = wordlists_cnt;
  state->stages_cnt    = stages_cnt;

  state->fps            = (HCFILE *)        hccalloc (wordlists_cnt, sizeof (HCFILE));
  state->transforms     = (pw_transform_t *) hccalloc (wordlists_cnt, sizeof (pw_transform_t));
  state->cached_indices = (u64 *)           hccalloc (wordlists_cnt, sizeof (u64));
  state->cached         = (bool *)          hccalloc (wordlists_cnt, sizeof (bool));
  state->word_buf       = (u8 *)            hccalloc (wordlists_cnt, RP_PASSWORD_SIZE);
  state->word_len       = (int *)           hccalloc (wordlists_cnt, sizeof (int));
  state->resident_word_buf = (u8 **)  hccalloc (wordlists_cnt, sizeof (u8 *));
  state->resident_word_len = (int **) hccalloc (wordlists_cnt, sizeof (int *));
  state->resident_word_cnt = (u64 *)   hccalloc (wordlists_cnt, sizeof (u64));
  state->stage_indices  = (u64 *)           hccalloc (stages_cnt, sizeof (u64));
  state->prefix_cached  = (bool *)          hccalloc (stages_cnt, sizeof (bool));
  state->prefix_buf     = (u8 *)            hccalloc (stages_cnt, RP_PASSWORD_SIZE);
  state->prefix_len     = (int *)           hccalloc (stages_cnt, sizeof (int));
  state->line_buf       = (char *)          hcmalloc (HCBUFSIZ_LARGE);

  u64 resident_bytes = 0;

  for (u32 i = 0; i < stages_cnt; i++)
  {
    const attack13_stage_t *stage = &mask_ctx->attack13_stages[i];

    if (stage->type != ATTACK13_STAGE_WORDLIST) continue;

    const u32 wordlist_pos = stage->wordlist_ordinal;

    if (hc_fopen (&state->fps[wordlist_pos], stage->source, "rb") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", stage->source, strerror (errno));

      return -1;
    }

    state->opened++;

    const int   rule_len = (wordlist_pos == 0) ? user_options_extra->rule_len_l : user_options_extra->rule_len_r;
    const char *rule_buf = (wordlist_pos == 0) ? user_options->rule_buf_l       : user_options->rule_buf_r;

    if (pw_transform_init_wordlist (&state->transforms[wordlist_pos], hashcat_ctx, rule_len, rule_buf) == -1) return -1;

    state->transforms_cnt++;

    if (attack13_fill_cache_wordlist (hashcat_ctx, state, stage, &resident_bytes) == -1) return -1;
  }

  return 0;
}

static void attack13_fill_destroy (attack13_fill_state_t *state)
{
  for (int i = 0; i < state->opened; i++) hc_fclose (&state->fps[i]);
  for (int i = 0; i < state->transforms_cnt; i++) pw_transform_term (&state->transforms[i]);

  for (u32 i = 0; i < state->wordlists_cnt; i++)
  {
    hcfree (state->resident_word_buf[i]);
    hcfree (state->resident_word_len[i]);
  }

  hcfree (state->fps);
  hcfree (state->transforms);
  hcfree (state->cached_indices);
  hcfree (state->cached);
  hcfree (state->word_buf);
  hcfree (state->word_len);
  hcfree (state->resident_word_buf);
  hcfree (state->resident_word_len);
  hcfree (state->resident_word_cnt);
  hcfree (state->stage_indices);
  hcfree (state->prefix_cached);
  hcfree (state->prefix_buf);
  hcfree (state->prefix_len);
  hcfree (state->line_buf);
}

static int fill_attack13 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state_ptr)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  const mask_ctx_t   *mask_ctx   = hashcat_ctx->mask_ctx;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  attack13_fill_state_t *state = (attack13_fill_state_t *) state_ptr;

  u64 words_extra = -1U;

  while (words_extra)
  {
    const u64 work_cnt = get_work (hashcat_ctx, device_param, words_extra);

    if (work_cnt == 0) break;

    words_extra = 0;

    const u64 words_off = device_param->words_off;

    batch->words_off = words_off;

    u64 work_cur = 0;

    for (work_cur = 0; work_cur < work_cnt; work_cur++)
    {
      const u64 candidate_pos = words_off + work_cur;
      const u64 pipeline_pos  = candidate_pos * mask_ctx->attack13_amplifier;

      u32 first_changed = 0;

      if ((state->candidate_pos_cached == true) && (candidate_pos == state->candidate_pos + 1))
      {
        first_changed = state->stages_cnt;

        for (u32 stage_pos = state->stages_cnt; stage_pos > 0; stage_pos--)
        {
          const u32 i = stage_pos - 1;
          const attack13_stage_t *stage = &mask_ctx->attack13_stages[i];

          state->stage_indices[i]++;
          first_changed = i;

          if (state->stage_indices[i] < stage->candidates) break;

          state->stage_indices[i] = 0;
        }
      }
      else if (state->candidate_pos_cached == true)
      {
        first_changed = state->stages_cnt;

        for (u32 i = 0; i < state->stages_cnt; i++)
        {
          const attack13_stage_t *stage = &mask_ctx->attack13_stages[i];
          const u64 stage_idx = (pipeline_pos / stage->stride) % stage->candidates;

          if ((first_changed == state->stages_cnt) && (state->stage_indices[i] != stage_idx)) first_changed = i;

          state->stage_indices[i] = stage_idx;
        }

        if (first_changed == state->stages_cnt) first_changed = state->stages_cnt - 1;
      }
      else
      {
        for (u32 i = 0; i < state->stages_cnt; i++)
        {
          const attack13_stage_t *stage = &mask_ctx->attack13_stages[i];

          state->stage_indices[i] = (pipeline_pos / stage->stride) % stage->candidates;
        }
      }

      state->candidate_pos        = candidate_pos;
      state->candidate_pos_cached = true;

      for (u32 i = first_changed; i + 1 < state->stages_cnt; i++) state->prefix_cached[i] = false;

      u32 candidate_words[(RP_PASSWORD_SIZE + 3) / 4] = { 0 };
      char *candidate = (char *) candidate_words;
      int candidate_len = 0;
      bool reject = false;

      u32 stage_start = first_changed;

      while ((stage_start > 0) && (state->prefix_cached[stage_start - 1] == false)) stage_start--;

      if (stage_start > 0)
      {
        candidate_len = state->prefix_len[stage_start - 1];

        if (candidate_len < 0)
        {
          reject = true;
        }
        else
        {
          memcpy (candidate, state->prefix_buf + ((stage_start - 1) * RP_PASSWORD_SIZE), candidate_len);
        }
      }

      for (u32 i = stage_start; (i < state->stages_cnt) && (reject == false); i++)
      {
        const attack13_stage_t *stage = &mask_ctx->attack13_stages[i];
        const u64 stage_idx = state->stage_indices[i];

        if (stage->type == ATTACK13_STAGE_WORDLIST)
        {
          const u8 *word_buf = NULL;
          int word_len = 0;

          if (attack13_fill_word (state, stage, stage_idx, &word_buf, &word_len) == -1)
          {
            event_log_error (hashcat_ctx, "Unexpected end of attack-mode 13 wordlist: %s", stage->source);

            return -1;
          }

          if ((word_len < 0) || (candidate_len + word_len > RP_PASSWORD_SIZE))
          {
            reject = true;
          }
          else
          {
            memcpy (candidate + candidate_len, word_buf, word_len);

            candidate_len += word_len;
          }
        }
        else if (stage->type == ATTACK13_STAGE_MASK)
        {
          if (attack13_mask_append (mask_ctx, stage, stage_idx, candidate, &candidate_len) == -1)
          {
            reject = true;
          }
        }
        else if (stage->generated == true)
        {
          memset (candidate + candidate_len, 0, RP_PASSWORD_SIZE - candidate_len);

          candidate_len = (int) apply_rules (stage->generated_rules[stage_idx].cmds, candidate_words, candidate_len);

          if ((candidate_len < 0) || (candidate_len > RP_PASSWORD_SIZE))
          {
            reject = true;
          }
        }
        else
        {
          char ruled[RP_PASSWORD_SIZE] = { 0 };

          const int ruled_len = _old_apply_rule (stage->rules[stage_idx], stage->rule_lens[stage_idx], candidate, candidate_len, ruled);

          if (ruled_len < 0)
          {
            reject = true;
          }
          else
          {
            memcpy (candidate, ruled, ruled_len);

            candidate_len = ruled_len;
          }
        }

        if (i + 1 < state->stages_cnt)
        {
          state->prefix_len[i]    = (reject == true) ? -1 : candidate_len;
          state->prefix_cached[i] = true;

          if (reject == false)
          {
            memcpy (state->prefix_buf + (i * RP_PASSWORD_SIZE), candidate, candidate_len);
          }
        }
      }

      if ((reject == true)
       || ((mask_ctx->attack13_gpu_amplified == false) && (candidate_len < (int) hashconfig->pw_min))
       || (candidate_len > (int) hashconfig->pw_max)
       || (candidate_policy_accept (user_options, (const u8 *) candidate, (u32) candidate_len) == false))
      {
        if (fill_reject (hashcat_ctx, false, batch, &words_extra, candidate_pos) == -1) return -1;

        continue;
      }

      pw_add (batch, device_param->kernel_power, (u8 *) candidate, candidate_len);

      if (status_ctx->run_thread_level1 == false) break;
    }

    if (work_cur > 0) batch->words_fin = words_off + work_cur;

    if (status_ctx->run_thread_level1 == false) break;
  }

  return 0;
}

typedef struct mask_rule_fill_state
{
  u64 words_cur;

} mask_rule_fill_state_t;

static int fill_mask_rules (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  const mask_ctx_t   *mask_ctx   = hashcat_ctx->mask_ctx;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  mask_rule_fill_state_t *mr = (mask_rule_fill_state_t *) state;

  u64 words_extra = -1U;

  while (words_extra)
  {
    const u64 work_cnt = get_work (hashcat_ctx, device_param, words_extra);

    if (work_cnt == 0) break;

    words_extra = 0;

    const u64 words_off = device_param->words_off;

    batch->words_off = words_off;

    mr->words_cur = words_off;

    u64 work_cur = 0;

    for (work_cur = 0; work_cur < work_cnt; work_cur++, mr->words_cur++)
    {
      u8 candidate[PW_MAX + 1] = { 0 };

      sp_exec (mr->words_cur, (char *) candidate, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, 0, mask_ctx->css_cnt);

      pw_add (batch, device_param->kernel_power, candidate, mask_ctx->css_cnt);

      if (status_ctx->run_thread_level1 == false) break;
    }

    if (work_cur > 0) batch->words_fin = words_off + work_cur;

    if (status_ctx->run_thread_level1 == false) break;
  }

  return 0;
}

typedef struct hybrid_rule_fill_state
{
  int device_id;
  bool mask_left;

  u64 words_cur;
  u64 words_cnt;
  u64 mask_cnt;
  u64 word_cached;
  u64 word_cursor;

  bool word_valid;

  pw_transform_t transform;

  u8 word_buf[PW_MAX + 1];
  int word_len;

} hybrid_rule_fill_state_t;

static int hybrid_rule_word (hashcat_ctx_t *hashcat_ctx, hybrid_rule_fill_state_t *hr, const u64 word_idx)
{
  if ((hr->word_valid == true) && (hr->word_cached == word_idx)) return 0;

  if (hr->word_cursor != word_idx)
  {
    if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_BASE, hr->device_id, word_idx) != 0) return -1;

    hr->word_cursor = word_idx;
  }

  const int line_len = generic_thread_next (hashcat_ctx, GENERIC_ROLE_BASE, hr->device_id, hr->word_buf, PW_MAX);

  hr->word_cursor = word_idx + 1;
  hr->word_cached = word_idx;
  hr->word_valid  = false;

  if ((line_len < 0) || (line_len > PW_MAX)) return 0;

  hr->word_len = pw_transform_apply (&hr->transform, hr->word_buf, line_len, PW_MAX);

  if (hr->word_len < 0) return 0;

  hr->word_valid = true;

  return 0;
}

static int fill_hybrid_rules (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  const mask_ctx_t   *mask_ctx   = hashcat_ctx->mask_ctx;
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hybrid_rule_fill_state_t *hr = (hybrid_rule_fill_state_t *) state;

  u64 words_extra = -1U;

  while (words_extra)
  {
    const u64 work_cnt = get_work (hashcat_ctx, device_param, words_extra);

    if (work_cnt == 0) break;

    words_extra = 0;

    const u64 words_off = device_param->words_off;

    batch->words_off = words_off;

    hr->words_cur = words_off;

    u64 work_cur = 0;

    for (work_cur = 0; work_cur < work_cnt; work_cur++, hr->words_cur++)
    {
      const u64 word_idx = (hr->mask_left == true) ? (hr->words_cur % hr->words_cnt) : (hr->words_cur / hr->mask_cnt);
      const u64 mask_idx = (hr->mask_left == true) ? (hr->words_cur / hr->words_cnt) : (hr->words_cur % hr->mask_cnt);

      if (hybrid_rule_word (hashcat_ctx, hr, word_idx) == -1) return -1;

      const int combined_len = hr->word_len + (int) mask_ctx->css_cnt;

      if ((hr->word_valid == false) || (combined_len < (int) hashconfig->pw_min) || (combined_len > (int) hashconfig->pw_max))
      {
        if (fill_reject (hashcat_ctx, false, batch, &words_extra, words_off + work_cur) == -1) return -1;

        continue;
      }

      u8 mask_buf[PW_MAX + 1] = { 0 };
      u8 combined_buf[PW_MAX + 1] = { 0 };

      sp_exec (mask_idx, (char *) mask_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, 0, mask_ctx->css_cnt);

      if (hr->mask_left == true)
      {
        memcpy (combined_buf, mask_buf, mask_ctx->css_cnt);
        memcpy (combined_buf + mask_ctx->css_cnt, hr->word_buf, hr->word_len);
      }
      else
      {
        memcpy (combined_buf, hr->word_buf, hr->word_len);
        memcpy (combined_buf + hr->word_len, mask_buf, mask_ctx->css_cnt);
      }

      pw_add (batch, device_param->kernel_power, combined_buf, combined_len);

      if (status_ctx->run_thread_level1 == false) break;
    }

    if (work_cur > 0) batch->words_fin = words_off + work_cur;

    if (status_ctx->run_thread_level1 == false) break;
  }

  return 0;
}

// Take batches off the pipeline and launch them until the producer runs dry. Every attack mode does
// this the same way, which is what pwpipe.h means by the producer being a callback: the mode chooses
// what fills a batch, not what happens to it afterwards.
//
// Two things genuinely differ, and both are constant for a whole attack rather than per batch.
//
// slow_candidates rejects candidates the host has already built, so a device's words_done is not a
// prefix of the keyspace and the restore point has to come from the device that got furthest. It also
// passes no position to run_cracker, because the candidate was built on the host and the kernel is
// not deriving it from an offset. The fast path is the other way round on both counts.
//
// reject_amplifier is how many candidates one rejected base word stood for, so the rejects can be
// booked against the salts. A producer that books its own passes 0: fill_slow does, because only it
// knows how many words it had to skip to fill the batch.

// A checkpoint is a barrier between completed kernel launches. Workers wait here without returning
// from calc(), which preserves their CUDA/HIP context, autotuning values and any prefetched batches.
// Cancelling the request releases every waiter. The final live worker to arrive converts the request
// into the normal checkpoint abort and releases the waiters to tear down normally.

static bool checkpoint_wait_worker (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  if (status_ctx->checkpoint_shutdown == false)
  {
    const bool keep_running = status_ctx->run_thread_level1;

    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    return keep_running;
  }

  if ((status_ctx->devices_status != STATUS_RUNNING) && (status_ctx->devices_status != STATUS_PAUSED))
  {
    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    return false;
  }

  status_ctx->checkpoint_threads_waiting++;

  if (status_ctx->checkpoint_threads_waiting >= status_ctx->checkpoint_threads_active)
  {
    myabort_checkpoint (hashcat_ctx);

    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    return false;
  }

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  while (true)
  {
    usleep (10000);

    hc_thread_mutex_lock (status_ctx->mux_dispatcher);

    if (status_ctx->checkpoint_shutdown == false)
    {
      if (status_ctx->checkpoint_threads_waiting > 0) status_ctx->checkpoint_threads_waiting--;

      const bool keep_running = status_ctx->run_thread_level1;

      hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

      return keep_running;
    }

    if ((status_ctx->devices_status != STATUS_RUNNING) && (status_ctx->devices_status != STATUS_PAUSED))
    {
      hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

      return false;
    }

    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
  }
}

static void checkpoint_retire_worker (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  if (status_ctx->checkpoint_threads_active > 0) status_ctx->checkpoint_threads_active--;

  // A worker can finish naturally at the edge of the keyspace while another worker is already at
  // the checkpoint barrier. Retiring it can therefore complete the barrier just like arriving does.

  if ((status_ctx->checkpoint_shutdown == true)
   && ((status_ctx->devices_status == STATUS_RUNNING) || (status_ctx->devices_status == STATUS_PAUSED))
   && (status_ctx->checkpoint_threads_waiting >= status_ctx->checkpoint_threads_active))
  {
    myabort_checkpoint (hashcat_ctx);
  }

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
}

static int pipe_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_pipe_t *pipe, const bool slow, const u64 reject_amplifier)
{
  hashes_t     *hashes     = hashcat_ctx->hashes;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // only read inside a WITH_BRAIN block, so a build without the brain has no use for it

  MAYBE_UNUSED user_options_t *user_options = hashcat_ctx->user_options;

  int rc_final = 0;

  while (true)
  {
    if (checkpoint_wait_worker (hashcat_ctx) == false) break;

    pw_batch_t *batch = pw_pipe_take (pipe);

    if (batch == NULL) break;

    if ((reject_amplifier > 0) && (batch->words_extra > 0))
    {
      hc_thread_mutex_lock (status_ctx->mux_counter);

      for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        status_ctx->words_progress_rejected[salt_pos] += batch->words_extra * reject_amplifier;
      }

      hc_thread_mutex_unlock (status_ctx->mux_counter);
    }

    //
    // flush
    //

    const u64 pws_cnt   = batch->pws_cnt;
    const u64 words_off = batch->words_off;
    const u64 words_fin = batch->words_fin;

    device_param->pws_idx  = batch->pws_idx;
    device_param->pws_comp = batch->pws_comp;
    device_param->pws_cnt  = pws_cnt;

    // Where this batch starts, for whatever the launch reports about it. The producer has already
    // moved device_param->words_off on to the batch it is filling next, so that field cannot answer
    // for the one being launched here.

    device_param->words_off_launch = words_off;
    device_param->words_fin_launch = words_fin;

    if (slow == true) device_param->pws_base_buf = batch->pws_base;

    if (pws_cnt)
    {
      hc_timer_t timer_copy;

      if (slow == false) pipe_mark (&timer_copy);

      if (run_copy (hashcat_ctx, device_param, pws_cnt) == -1)
      {
        rc_final = -1;

        break;
      }

      if (slow == false) pipe_acc (PIPE_COPY, &timer_copy);

      const u64 pws_pos = (slow == true) ? (u64) -1 : words_off;

      if (run_cracker (hashcat_ctx, device_param, pws_pos, pws_cnt) == -1)
      {
        rc_final = -1;

        break;
      }

      #ifdef WITH_BRAIN
      if ((slow == true) && (user_options->brain_client == true))
      {
        if ((status_ctx->devices_status != STATUS_ABORTED)
         && (status_ctx->devices_status != STATUS_ABORTED_RUNTIME)
         && (status_ctx->devices_status != STATUS_QUIT)
         && (status_ctx->devices_status != STATUS_BYPASS)
         && (status_ctx->devices_status != STATUS_ERROR))
        {
          if (brain_client_commit (device_param, status_ctx) == false)
          {
            brain_client_disconnect (device_param);
          }
        }
      }
      #endif

      device_param->pws_cnt = 0;
    }
    else if (user_options->stdout_flag == true)
    {
      if (stdout_restore_skip (hashcat_ctx, words_off, words_fin) == -1)
      {
        rc_final = -1;

        break;
      }
    }

    // the launch is complete, so the slot may go back to the producer

    pw_pipe_release (pipe, batch);

    if (device_param->speed_only_finish == true) break;

    if (status_ctx->run_thread_level2 == true)
    {
      device_param->words_done = MAX (device_param->words_done, words_fin);

      if (slow == true)
      {
        // Slow-candidate restore normally follows the furthest device. A live
        // seek creates an intentional hole, so keep the old safe point until
        // every device has crossed the new dispatch position. If a short tail
        // never reaches that barrier, restore stays conservative and may
        // repeat work, but it cannot omit an unfinished pre-seek batch.
        hc_thread_mutex_lock (status_ctx->mux_dispatcher);

        if (status_ctx->words_seek_guard > 0)
        {
          if (get_lowest_words_done (hashcat_ctx) >= status_ctx->words_seek_guard)
          {
            status_ctx->words_seek_guard = 0;
            status_ctx->words_cur = get_highest_words_done (hashcat_ctx);
          }
        }
        else
        {
          status_ctx->words_cur = get_highest_words_done (hashcat_ctx);
        }

        hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
      }
      else
      {
        status_ctx->words_cur = get_lowest_words_done (hashcat_ctx);
      }
    }

    if (checkpoint_wait_worker (hashcat_ctx) == false) break;
  }

  pw_pipe_stop (pipe);

  if (pw_pipe_failed (pipe) == true) rc_final = -1;

  return rc_final;
}

static int calc (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  const u32 attack_mode = user_options->attack_mode;
  const u32 attack_kern = user_options_extra->attack_kern;
  const u32 base_source = user_options_extra->base_source;

  if (user_options->slow_candidates == true)
  {
    #ifdef WITH_BRAIN
    const u32 brain_session = user_options->brain_session;
    const u32 brain_attack  = user_options->brain_attack;

    u64 highest = 0;

    brain_client_disconnect (device_param);

    if (user_options->brain_client == true)
    {
      const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

      // this is the first connect of the run. A brain that is not there now means the whole attack
      // runs with no dedup at all, which is what the user asked for by passing -z, so it is an error
      // rather than a degradation. A link that drops later is different: the work already deduped
      // stays deduped, so that one only warns and keeps going.

      if (brain_client_connect (hashcat_ctx, device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, brain_session, brain_attack, passwords_max, &highest) == false)
      {
        brain_client_disconnect (device_param);

        return -1;
      }

      if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
      {
        hc_thread_mutex_lock (status_ctx->mux_dispatcher);

        if (status_ctx->words_off == 0)
        {
          status_ctx->words_off = highest;

          for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
          {
            status_ctx->words_progress_rejected[salt_pos] = status_ctx->words_off;
          }

          // the brain reported a contiguous prefix of the keyspace as already done, so the run starts
          // past it. Those words are rejected by the same mechanism as an overlap and belong in the
          // same counter, or the attacks total is short by the whole prefix on any resumed session.

          status_ctx->brain_rejects_attacks = status_ctx->words_off;
        }

        hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
      }
    }
    #endif

    // attack modes from here. -a 12 is asked about before the feed, because its base words come from
    // one and it would answer to that test as well.

    if (attack_mode == ATTACK_MODE_HYBRID)
    {
      extra_info_combi_t extra_info_combi;

      memset (&extra_info_combi, 0, sizeof (extra_info_combi));

      extra_info_combi.scratch_buf = device_param->scratch_buf;

      extra_info_combi.device_id = device_param->device_id;

      if (pw_transform_init (&extra_info_combi.transform_base, hashcat_ctx, GENERIC_ROLE_BASE, (int) user_options_extra->rule_len_base, user_options_extra->rule_buf_base) == -1) return -1;

      if (pw_transform_init (&extra_info_combi.transform_amp, hashcat_ctx, GENERIC_ROLE_AMP, (int) user_options_extra->rule_len_amp, user_options_extra->rule_buf_amp) == -1) return -1;

      slow_fill_state_t sc;

      sc.extra_info = &extra_info_combi;
      sc.pos        = &extra_info_combi.pos;
      sc.out_buf    = extra_info_combi.out_buf;
      sc.out_len    = &extra_info_combi.out_len;
      sc.base_buf   = NULL;
      sc.base_len   = NULL;
      sc.rule_pos   = NULL;
      sc.reject     = &extra_info_combi.reject;
      sc.seek       = true;
      sc.reject_len = true;
      sc.keep_base  = true;
      sc.words_cur  = 0;

      bool pipe_serial = false;

      #ifdef WITH_BRAIN
      sc.brain_highest = highest;

      pipe_serial = user_options->brain_client;
      #endif

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_slow, &sc, pipe_serial);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, true, 0);

      pw_transform_term (&extra_info_combi.transform_base);
      pw_transform_term (&extra_info_combi.transform_amp);

      if (rc_final == -1) return -1;
    }
    else if (base_source == BASE_SOURCE_FEED)
    {
      extra_info_generic_t extra_info_generic;

      memset (&extra_info_generic, 0, sizeof (extra_info_generic));

      // The feed keeps one generator per device and hashcat addresses it by device id, so unlike the
      // wordlist reader there is no private copy of hashcat_ctx to make here.

      extra_info_generic.device_id = device_param->device_id;

      if (pw_transform_init (&extra_info_generic.transform, hashcat_ctx, GENERIC_ROLE_BASE, (int) user_options_extra->rule_len_base, user_options_extra->rule_buf_base) == -1) return -1;

      slow_fill_state_t sc;

      sc.extra_info = &extra_info_generic;
      sc.pos        = &extra_info_generic.pos;
      sc.out_buf    = extra_info_generic.out_buf;
      sc.out_len    = &extra_info_generic.out_len;
      sc.base_buf   = extra_info_generic.base_buf;
      sc.base_len   = &extra_info_generic.base_len;
      sc.rule_pos   = &extra_info_generic.rule_pos_prev;
      sc.reject     = &extra_info_generic.reject;
      sc.seek       = true;
      sc.reject_len = true;
      sc.keep_base  = true;
      sc.words_cur  = 0;

      bool pipe_serial = false;

      #ifdef WITH_BRAIN
      sc.brain_highest = highest;

      pipe_serial = user_options->brain_client;
      #endif

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_slow, &sc, pipe_serial);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, true, 0);

      pw_transform_term (&extra_info_generic.transform);

      if (rc_final == -1) return -1;
    }
    else if (attack_mode == ATTACK_MODE_BF)
    {
      extra_info_mask_t extra_info_mask;

      memset (&extra_info_mask, 0, sizeof (extra_info_mask));

      extra_info_mask.out_len = mask_ctx->css_cnt;

      slow_fill_state_t sc;

      sc.extra_info = &extra_info_mask;
      sc.pos        = &extra_info_mask.pos;
      sc.out_buf    = extra_info_mask.out_buf;
      sc.out_len    = &extra_info_mask.out_len;
      sc.base_buf   = NULL;
      sc.base_len   = NULL;
      sc.rule_pos   = NULL;
      sc.reject     = NULL;
      sc.seek       = false;
      sc.reject_len = false;
      sc.keep_base  = false;
      sc.words_cur  = 0;

      bool pipe_serial = false;

      #ifdef WITH_BRAIN
      sc.brain_highest = highest;

      pipe_serial = user_options->brain_client;
      #endif

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_slow, &sc, pipe_serial);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, true, 0);

      if (rc_final == -1) return -1;
    }

    #ifdef WITH_BRAIN
    if (user_options->brain_client == true)
    {
      brain_client_disconnect (device_param);
    }
    #endif
  }
  else
  {
    // The producers left build candidates from a mask or from one or more wordlists outside the
    // ordinary feed path. -a 3, -a 7 under the pure kernel, and -a 12 under the pure kernel when its
    // mask ends in ?w use the mask as their base source. Shooter's multi-file -a 1 path is handled
    // explicitly below.

    if (attack_mode == ATTACK_MODE_MULTI_HYBRID)
    {
      attack13_fill_state_t attack13;

      if (attack13_fill_init (hashcat_ctx, device_param, &attack13) == -1)
      {
        attack13_fill_destroy (&attack13);

        return -1;
      }

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_attack13, &attack13, false);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, straight_ctx->kernel_rules_cnt);

      attack13_fill_destroy (&attack13);

      if (rc_final == -1) return -1;
    }
    else if ((user_options_extra->whole_candidate_rules == true) && (attack_mode == ATTACK_MODE_COMBI))
    {
      multi_fill_state_t mf;

      const int dicts_cnt = combinator_ctx->dicts_cnt;

      if (multi_fill_init (hashcat_ctx, &mf, dicts_cnt, BASE_LENGTH_BOTH, true) == -1)
      {
        multi_fill_destroy (&mf);

        return -1;
      }

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_multi, &mf, false);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, straight_ctx->kernel_rules_cnt);

      multi_fill_destroy (&mf);

      if (rc_final == -1) return -1;
    }
    else if ((user_options_extra->whole_candidate_rules == true) && (attack_mode == ATTACK_MODE_BF))
    {
      mask_rule_fill_state_t mr;

      memset (&mr, 0, sizeof (mr));

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_mask_rules, &mr, false);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, straight_ctx->kernel_rules_cnt);

      if (rc_final == -1) return -1;
    }
    else if ((user_options_extra->whole_candidate_rules == true)
          && ((attack_mode == ATTACK_MODE_HYBRID1) || (attack_mode == ATTACK_MODE_HYBRID2)))
    {
      const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

      hybrid_rule_fill_state_t hr;

      memset (&hr, 0, sizeof (hr));

      hr.device_id   = device_param->device_id;
      hr.mask_left   = (attack_mode == ATTACK_MODE_HYBRID2);
      hr.words_cnt   = generic_ctx->keyspace;
      hr.mask_cnt    = mask_ctx->bfs_cnt;
      hr.word_cached = -1;
      hr.word_cursor = -1;

      if (pw_transform_init (&hr.transform, hashcat_ctx, GENERIC_ROLE_BASE, (int) user_options_extra->rule_len_base, user_options_extra->rule_buf_base) == -1) return -1;

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_hybrid_rules, &hr, false);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, straight_ctx->kernel_rules_cnt);

      pw_transform_term (&hr.transform);

      if (rc_final == -1) return -1;
    }
    else if ((attack_mode == ATTACK_MODE_COMBI) && (combinator_ctx->dicts_cnt > 2))
    {
      multi_fill_state_t mf;

      if (multi_fill_init (hashcat_ctx, &mf, combinator_ctx->dicts_cnt - 1, BASE_LENGTH_MAX, true) == -1)
      {
        multi_fill_destroy (&mf);

        return -1;
      }

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_multi, &mf, false);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, combinator_ctx->combs_cnt);

      multi_fill_destroy (&mf);

      if (rc_final == -1) return -1;
    }
    else if (base_source == BASE_SOURCE_MASK)
    {
      while (true)
      {
        if (checkpoint_wait_worker (hashcat_ctx) == false) break;

        const u64 work = get_work (hashcat_ctx, device_param, -1);

        if (work == 0) break;

        const u64 words_off = device_param->words_off;
        const u64 words_fin = words_off + work;

        device_param->pws_cnt = work;

        // The mask producer is not pipelined, so the two are the same batch here. It is still set
        // rather than left behind, because what reads it cannot tell the two paths apart.

        device_param->words_off_launch = words_off;
        device_param->words_fin_launch = words_fin;

        if (run_copy    (hashcat_ctx, device_param, device_param->pws_cnt) == -1) return -1;
        if (run_cracker (hashcat_ctx, device_param, -1, device_param->pws_cnt) == -1) return -1;

        device_param->pws_cnt = 0;

        if (device_param->speed_only_finish == true) break;

        if (status_ctx->run_thread_level2 == true)
        {
          device_param->words_done = MAX (device_param->words_done, words_fin);

          status_ctx->words_cur = get_lowest_words_done (hashcat_ctx);
        }
      }
    }
    else if (base_source == BASE_SOURCE_FEED)
    {
      generic_fill_state_t gf;

      if (pw_transform_init (&gf.transform, hashcat_ctx, GENERIC_ROLE_BASE, (int) user_options_extra->rule_len_base, user_options_extra->rule_buf_base) == -1) return -1;

      gf.length_policy = user_options_extra_base_length (hashcat_ctx);
      gf.reject_fatal  = (user_options->attack_mode == ATTACK_MODE_ASSOCIATION);

      gf.can_shrink   = pw_transform_shrinks (&gf.transform);
      gf.transform_simple = ((gf.transform.pt_uppercase == false)
                          && (gf.transform.pt_hex == false)
                          && (gf.transform.rule_len == 0)
                          && (gf.transform.iconv_enabled == false));
      gf.scratch_size = HCBUFSIZ_TINY;
      gf.scratch      = (gf.can_shrink == true) ? (u8 *) hcmalloc (gf.scratch_size) : NULL;

      gf.seek_known = false;
      gf.seek_pos   = 0;

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_generic, &gf, false);

      // One rejected base word stood for a whole amplifier's worth of candidates, and which amplifier
      // depends on the kernel exactly as it does for the wordlist reader.

      u64 reject_amplifier = 0;

      if (attack_kern == ATTACK_KERN_STRAIGHT) reject_amplifier = straight_ctx->kernel_rules_cnt;
      if (attack_kern == ATTACK_KERN_COMBI)    reject_amplifier = combinator_ctx->combs_cnt;

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, reject_amplifier);

      hcfree (gf.scratch);

      pw_transform_term (&gf.transform);

      if (rc_final == -1) return -1;
    }
  }

  device_param->kernel_accel_prev   = device_param->kernel_accel;
  device_param->kernel_loops_prev   = device_param->kernel_loops;
  device_param->kernel_threads_prev = device_param->kernel_threads;

  device_param->kernel_accel   = 0;
  device_param->kernel_loops   = 0;
  device_param->kernel_threads = 0;

  return 0;
}

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD thread_calc (void *p)
#else
HC_API_CALL void *thread_calc (void *p)
#endif
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  bridge_ctx_t  *bridge_ctx  = hashcat_ctx->bridge_ctx;
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;

  if (backend_ctx->enabled == false) return 0;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped) return 0;
  if (device_param->skipped_warning == true) return 0;

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_init != BRIDGE_DEFAULT)
    {
      if (bridge_ctx->thread_init (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes) == false)
      {
        checkpoint_retire_worker (hashcat_ctx);

        return 0;
      }
    }
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1)
    {
      checkpoint_retire_worker (hashcat_ctx);

      return 0;
    }
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1)
    {
      checkpoint_retire_worker (hashcat_ctx);

      return 0;
    }
  }

  if (calc (hashcat_ctx, device_param) == -1)
  {
    status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

    status_ctx->devices_status = STATUS_ERROR;
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1)
    {
      checkpoint_retire_worker (hashcat_ctx);

      return 0;
    }
  }

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_term != BRIDGE_DEFAULT)
    {
      bridge_ctx->thread_term (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes);
    }
  }

  checkpoint_retire_worker (hashcat_ctx);

  return 0;
}
