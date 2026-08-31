/**
 * Author......: Shooter3k
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct argon2_tmp
{
  u32 state[4];

} argon2_tmp_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;

} merged_options_t;

DECLSPEC u32 argon2_md5_hex_byte (const u32 v)
{
  const u32 hi = (v >> 4) & 15;
  const u32 lo = (v >> 0) & 15;

  const u32 hi_ascii = (hi < 10) ? '0' + hi : 'a' - 10 + hi;
  const u32 lo_ascii = (lo < 10) ? '0' + lo : 'a' - 10 + lo;

  return (hi_ascii << 0) | (lo_ascii << 8);
}

KERNEL_FQ KERNEL_FA void m34900_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);
  md5_update_global (&md5_ctx, pws[gid].i, pws[gid].pw_len);
  md5_final (&md5_ctx);

  pw_t md5_hex;

  md5_hex.i[0] = argon2_md5_hex_byte ((md5_ctx.h[0] >>  0) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[0] >>  8) & 255) << 16;
  md5_hex.i[1] = argon2_md5_hex_byte ((md5_ctx.h[0] >> 16) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[0] >> 24) & 255) << 16;
  md5_hex.i[2] = argon2_md5_hex_byte ((md5_ctx.h[1] >>  0) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[1] >>  8) & 255) << 16;
  md5_hex.i[3] = argon2_md5_hex_byte ((md5_ctx.h[1] >> 16) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[1] >> 24) & 255) << 16;
  md5_hex.i[4] = argon2_md5_hex_byte ((md5_ctx.h[2] >>  0) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[2] >>  8) & 255) << 16;
  md5_hex.i[5] = argon2_md5_hex_byte ((md5_ctx.h[2] >> 16) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[2] >> 24) & 255) << 16;
  md5_hex.i[6] = argon2_md5_hex_byte ((md5_ctx.h[3] >>  0) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[3] >>  8) & 255) << 16;
  md5_hex.i[7] = argon2_md5_hex_byte ((md5_ctx.h[3] >> 16) & 255) <<  0
               | argon2_md5_hex_byte ((md5_ctx.h[3] >> 24) & 255) << 16;

  md5_hex.pw_len = 32;

  argon2_init_pg (&md5_hex, &salt_bufs[SALT_POS_HOST], &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m34900_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #ifdef ARGON2_PARALLELISM
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].argon2_options;

  #ifdef IS_APPLE
  // it doesn't work on Apple, so we won't set it up
  #else
  #ifdef ARGON2_PARALLELISM
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < argon2_options.parallelism; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &argon2_options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m34900_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  u32 out[8];

  argon2_final (argon2_block, &argon2_options, out);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #include COMPARE_M
}
