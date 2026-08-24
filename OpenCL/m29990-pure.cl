/**
 * Private Hashcat kernel for the KoreLogic CMIYC 2026 memory-hard SHA-512 KDF.
 * One scalar work-item owns one 64 MiB job for the official memlog=20 format.
 *
 * All intermediate data is kept as u32 word arrays (LE native) and converted
 * to BE only when feeding sha512_update_swap.  Memory (global) uses u32[16]
 * per 64-byte block with native LE ordering.
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct cmiyc_tmp
{
  u32 chain[16];  // 64 bytes as LE u32s
} cmiyc_tmp_t;

/**
 * Compute SHA-512 of `len` bytes stored in LE u32 array `w` (up to 40 words).
 * Result is written to `out` as 16 LE u32s (64 bytes).
 */
DECLSPEC void cmiyc_sha512_w (PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *out)
{
  sha512_ctx_t ctx;
  sha512_init (&ctx);
  sha512_update_swap (&ctx, w, len);
  sha512_final (&ctx);

  // Store h[0..7] (u64) into out[0..15] as LE u32s matching SHA-512 byte output.
  // SHA-512 h[i] is stored big-endian: h32 = bytes[0..3], l32 = bytes[4..7]
  // As LE u32: bytes[0..3] → swap32(h32), bytes[4..7] → swap32(l32)
  for (u32 i = 0; i < 8; i++)
  {
    out[i * 2 + 0] = hc_swap32_S (h32_from_64_S (ctx.h[i]));
    out[i * 2 + 1] = hc_swap32_S (l32_from_64_S (ctx.h[i]));
  }
}

/**
 * Pack a u64 value into a LE u32 word array at byte offset `off`.
 * Handles the case where `off` is u32-aligned (which it always is in our usage).
 */
DECLSPEC void cmiyc_pack_le64 (PRIVATE_AS u32 *w, const u32 word_off, const u64 value)
{
  w[word_off + 0] = (u32) (value      );
  w[word_off + 1] = (u32) (value >> 32);
}

/**
 * Read a LE u64 from global u32 memory at word offset.
 */
DECLSPEC u64 cmiyc_read_le64_global (GLOBAL_AS const u32 *mem, const u32 word_off)
{
  return (u64) mem[word_off] | ((u64) mem[word_off + 1] << 32);
}

/**
 * Get pointer to this work-item's memory region.
 */
DECLSPEC GLOBAL_AS u32 *cmiyc_memory (GLOBAL_AS u32 *d_extra0_buf, GLOBAL_AS u32 *d_extra1_buf, GLOBAL_AS u32 *d_extra2_buf, GLOBAL_AS u32 *d_extra3_buf, const u64 gid)
{
  const u64 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS u32 *base;

  switch (gm4)
  {
    case 0: base = d_extra0_buf; break;
    case 1: base = d_extra1_buf; break;
    case 2: base = d_extra2_buf; break;
    default: base = d_extra3_buf; break;
  }

  return base + gd4 * (u64) CMIYC_STRIDE_BLOCKS * 16;
}

/**
 * HMAC-SHA512(key=salt, msg=password || LE32(rounds) || LE32(memlog))
 * Result stored in chain[0..15] as LE u32s.
 */
DECLSPEC void cmiyc_hmac_seed (GLOBAL_AS const pw_t *pw, GLOBAL_AS const salt_t *salt, PRIVATE_AS u32 *chain)
{
  // Key = salt bytes (16 bytes), stored in salt_buf as LE u32s
  u32 key[32] = { 0 };
  key[0] = salt->salt_buf[0];
  key[1] = salt->salt_buf[1];
  key[2] = salt->salt_buf[2];
  key[3] = salt->salt_buf[3];

  sha512_hmac_ctx_t ctx;
  sha512_hmac_init_swap (&ctx, key, 16);
  sha512_hmac_update_global_swap (&ctx, pw->i, pw->pw_len);

  // config = LE32(rounds) || LE32(memlog) = 8 bytes
  const u32 config[32] = { salt->scrypt_p, salt->scrypt_r };
  sha512_hmac_update_swap (&ctx, config, 8);
  sha512_hmac_final (&ctx);

  // ctx.opad.h[i] are BE u64 values representing the hash output.
  // We need to store as LE u32s matching the byte sequence.
  // h[0] = 0xAABBCCDDEEFF0011 means bytes [AA BB CC DD EE FF 00 11]
  // As LE u32s: word0 = 0xDDCCBBAA (bytes 0-3), word1 = 0x1100FFEE (bytes 4-7)
  for (u32 i = 0; i < 8; i++)
  {
    const u64 h = ctx.opad.h[i];
    chain[i * 2 + 0] = hc_swap32_S (h32_from_64_S (h));  // bytes [0..3] as LE u32
    chain[i * 2 + 1] = hc_swap32_S (l32_from_64_S (h));  // bytes [4..7] as LE u32
  }
}

/**
 * fill_hash: SHA-512(chain || "cmiyc-fill" || LE64(index))
 * chain and output are u32[16] in LE format.
 * Message is 82 bytes = 21 u32s (last partial).
 */
DECLSPEC void cmiyc_fill_hash (PRIVATE_AS const u32 *chain, const u64 index, PRIVATE_AS u32 *output)
{
  u32 w[32] = { 0 };

  // bytes 0-63: chain (16 LE u32s)
  for (u32 i = 0; i < 16; i++) w[i] = chain[i];

  // bytes 64-73: "cmiyc-fill" (10 bytes)
  // "cmiy" = 0x79696D63, "c-fi" = 0x69662D63, "ll" = 0x00006C6C
  w[16] = 0x79696D63;  // 'c','m','i','y' as LE u32
  w[17] = 0x69662D63;  // 'c','-','f','i' as LE u32
  // bytes 72-73: 'l','l' + bytes 74-75 from index
  // bytes 72 = 'l' = 0x6C, byte 73 = 'l' = 0x6C
  // bytes 74..81 = LE64(index)
  // w[18] contains bytes 72-75: 'll' + low 2 bytes of index
  w[18] = 0x6C6C | (((u32)(index & 0xFFFF)) << 16);
  // w[19] = bytes 76-79 = idx[2..5]
  w[19] = (u32)(index >> 16);
  // w[20] = bytes 80-81 = idx[6..7] + padding zeros
  w[20] = (u32)(index >> 48);

  cmiyc_sha512_w (w, 82, output);
}

/**
 * mix_hash: SHA-512(current || other || LE64(round) || LE64(index) || tag)
 * current/other are global u32[16] in LE format.
 * Message is 145 bytes = 37 u32s (last partial: 1 byte in word 36).
 */
DECLSPEC void cmiyc_mix_hash (GLOBAL_AS const u32 *current, GLOBAL_AS const u32 *other, const u64 round, const u64 index, const u32 tag, PRIVATE_AS u32 *output)
{
  u32 w[64] = { 0 };

  // bytes 0-63: current (16 LE u32s)
  for (u32 i = 0; i < 16; i++) w[i] = current[i];

  // bytes 64-127: other (16 LE u32s)
  for (u32 i = 0; i < 16; i++) w[16 + i] = other[i];

  // bytes 128-135: LE64(round)
  w[32] = (u32)(round);
  w[33] = (u32)(round >> 32);

  // bytes 136-143: LE64(index)
  w[34] = (u32)(index);
  w[35] = (u32)(index >> 32);

  // byte 144: tag
  w[36] = tag & 0xFF;

  cmiyc_sha512_w (w, 145, output);
}

KERNEL_FQ KERNEL_FA void m29990_init (KERN_ATTR_TMPS (cmiyc_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 chain[16];

  cmiyc_hmac_seed (&pws[gid], &salt_bufs[SALT_POS_HOST], chain);

  for (u32 i = 0; i < 16; i++) tmps[gid].chain[i] = chain[i];
}

KERNEL_FQ KERNEL_FA void m29990_loop (KERN_ATTR_TMPS (cmiyc_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  GLOBAL_AS u32 *memory = cmiyc_memory ((GLOBAL_AS u32 *) d_extra0_buf, (GLOBAL_AS u32 *) d_extra1_buf, (GLOBAL_AS u32 *) d_extra2_buf, (GLOBAL_AS u32 *) d_extra3_buf, gid);

  const u64 blocks = (u64) salt_bufs[SALT_POS_HOST].scrypt_N * 2;

  u32 chain[16];

  for (u32 i = 0; i < 16; i++) chain[i] = tmps[gid].chain[i];

  for (u32 step = 0; step < LOOP_CNT; step++)
  {
    const u64 position = (u64) LOOP_POS + step;

    if (position < blocks)
    {
      u32 digest[16];

      cmiyc_fill_hash (chain, position, digest);

      GLOBAL_AS u32 *dst = memory + position * 16;

      for (u32 i = 0; i < 16; i++)
      {
        dst[i] = digest[i];
        chain[i] = digest[i];
      }
    }
    else
    {
      const u64 mix_position = position - blocks;
      const u64 round_span = blocks * 2;
      const u64 round = (u64) (mix_position / round_span) + 1;
      const u64 within = mix_position % round_span;

      u64 index;
      u64 other_index;
      u32 tag;

      if (within < blocks)
      {
        index = within;
        tag = 'A';

        GLOBAL_AS const u32 *cur = memory + index * 16;
        // other_index from bytes 0-7 of current block = LE u64 from words 0,1
        other_index = cmiyc_read_le64_global (cur, 0) & (blocks - 1);
      }
      else
      {
        index = blocks - 1 - (within - blocks);
        tag = 'B';

        GLOBAL_AS const u32 *cur = memory + index * 16;
        // other_index from bytes 8-15 of current block = LE u64 from words 2,3
        other_index = cmiyc_read_le64_global (cur, 2) & (blocks - 1);
      }

      GLOBAL_AS u32 *current = memory + index * 16;
      GLOBAL_AS const u32 *other = memory + other_index * 16;

      u32 digest[16];

      cmiyc_mix_hash (current, other, round, index, tag, digest);

      for (u32 i = 0; i < 16; i++) current[i] = digest[i];
    }
  }

  if ((u64) LOOP_POS < blocks)
  {
    for (u32 i = 0; i < 16; i++) tmps[gid].chain[i] = chain[i];
  }
}

KERNEL_FQ KERNEL_FA void m29990_comp (KERN_ATTR_TMPS (cmiyc_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  GLOBAL_AS const u32 *memory = cmiyc_memory ((GLOBAL_AS u32 *) d_extra0_buf, (GLOBAL_AS u32 *) d_extra1_buf, (GLOBAL_AS u32 *) d_extra2_buf, (GLOBAL_AS u32 *) d_extra3_buf, gid);

  const u64 blocks = (u64) salt_bufs[SALT_POS_HOST].scrypt_N * 2;

  u32 accumulator[32] = { 0 };

  for (u64 block = 0; block < blocks; block++)
  {
    GLOBAL_AS const u32 *src = memory + block * 16;

    for (u32 i = 0; i < 16; i++) accumulator[i] ^= src[i];
  }

  u32 digest[16];

  cmiyc_sha512_w (accumulator, 64, digest);

  const u32 r0 = digest[0];
  const u32 r1 = digest[1];
  const u32 r2 = digest[2];
  const u32 r3 = digest[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
