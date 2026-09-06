/**
 * One-pass raw hash family for Shooter --multi-hash-modes.
 *
 * Every enabled algorithm hashes the same candidate.  Its lowercase textual
 * digest is then MD4-indexed so differently sized raw targets can share one
 * normal hashcat digest table.  The public mode is returned in plain.extra1.
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha224.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#ifndef SHOOTER_MULTI_MD5_MODE
#define SHOOTER_MULTI_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD4_MODE
#define SHOOTER_MULTI_MD4_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA1_MODE
#define SHOOTER_MULTI_SHA1_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA256_MODE
#define SHOOTER_MULTI_SHA256_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA512_MODE
#define SHOOTER_MULTI_SHA512_MODE 0
#endif
#ifndef SHOOTER_MULTI_NTLM_MODE
#define SHOOTER_MULTI_NTLM_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD5_UTF16LE_MODE
#define SHOOTER_MULTI_MD5_UTF16LE_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA1_UTF16LE_MODE
#define SHOOTER_MULTI_SHA1_UTF16LE_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA256_UTF16LE_MODE
#define SHOOTER_MULTI_SHA256_UTF16LE_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA512_UTF16LE_MODE
#define SHOOTER_MULTI_SHA512_UTF16LE_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD5_MD5_MODE
#define SHOOTER_MULTI_MD5_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD5_MD5_MD5_MODE
#define SHOOTER_MULTI_MD5_MD5_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD5_UC_MD5_MODE
#define SHOOTER_MULTI_MD5_UC_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD5_SHA1_MODE
#define SHOOTER_MULTI_MD5_SHA1_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA1_SHA1_MODE
#define SHOOTER_MULTI_SHA1_SHA1_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA1_MD5_MODE
#define SHOOTER_MULTI_SHA1_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA1_MD5_MD5_MODE
#define SHOOTER_MULTI_SHA1_MD5_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA256_MD5_MODE
#define SHOOTER_MULTI_SHA256_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD5_SHA1_MIX_MODE
#define SHOOTER_MULTI_MD5_SHA1_MIX_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA512_RAW2_MODE
#define SHOOTER_MULTI_SHA512_RAW2_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA256_RAW2_MODE
#define SHOOTER_MULTI_SHA256_RAW2_MODE 0
#endif
#ifndef SHOOTER_MULTI_MD5_SHA1_MD5_MODE
#define SHOOTER_MULTI_MD5_SHA1_MD5_MODE 0
#endif
#ifndef SHOOTER_MULTI_SHA224_SHA1_MODE
#define SHOOTER_MULTI_SHA224_SHA1_MODE 0
#endif

typedef struct shooter_multi_tmp
{
  u32 pw_buf[64];
  u32 pw_len;

} shooter_multi_tmp_t;

DECLSPEC u32 shooter_hex_char (const u32 nibble)
{
  return (nibble < 10) ? ('0' + nibble) : ('a' + nibble - 10);
}

DECLSPEC u32 shooter_hex_char_upper (const u32 nibble)
{
  return (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
}

DECLSPEC void shooter_hex_put_char (PRIVATE_AS u32 *buf, const u32 pos, const u32 value)
{
  buf[pos >> 2] |= value << ((pos & 3) * 8);
}

DECLSPEC void shooter_hex_put_byte (PRIVATE_AS u32 *buf, const u32 byte_pos, const u32 value)
{
  shooter_hex_put_char (buf, byte_pos * 2 + 0, shooter_hex_char ((value >> 4) & 15));
  shooter_hex_put_char (buf, byte_pos * 2 + 1, shooter_hex_char ((value >> 0) & 15));
}

DECLSPEC void shooter_hex_put_byte_upper (PRIVATE_AS u32 *buf, const u32 byte_pos, const u32 value)
{
  shooter_hex_put_char (buf, byte_pos * 2 + 0, shooter_hex_char_upper ((value >> 4) & 15));
  shooter_hex_put_char (buf, byte_pos * 2 + 1, shooter_hex_char_upper ((value >> 0) & 15));
}

DECLSPEC void shooter_hex_clear (PRIVATE_AS u32 *buf)
{
  for (u32 i = 0; i < 32; i++) buf[i] = 0;
}

DECLSPEC void shooter_hex_le32 (PRIVATE_AS u32 *buf, PRIVATE_AS const u32 *digest, const u32 words)
{
  shooter_hex_clear (buf);

  for (u32 word = 0; word < words; word++)
  {
    const u32 value = digest[word];

    for (u32 byte = 0; byte < 4; byte++)
    {
      shooter_hex_put_byte (buf, word * 4 + byte, (value >> (byte * 8)) & 0xff);
    }
  }
}

DECLSPEC void shooter_hex_le32_upper (PRIVATE_AS u32 *buf, PRIVATE_AS const u32 *digest, const u32 words)
{
  shooter_hex_clear (buf);

  for (u32 word = 0; word < words; word++)
  {
    const u32 value = digest[word];

    for (u32 byte = 0; byte < 4; byte++)
    {
      shooter_hex_put_byte_upper (buf, word * 4 + byte, (value >> (byte * 8)) & 0xff);
    }
  }
}

DECLSPEC void shooter_hex_be32 (PRIVATE_AS u32 *buf, PRIVATE_AS const u32 *digest, const u32 words)
{
  shooter_hex_clear (buf);

  for (u32 word = 0; word < words; word++)
  {
    const u32 value = digest[word];

    for (u32 byte = 0; byte < 4; byte++)
    {
      shooter_hex_put_byte (buf, word * 4 + byte, (value >> (24 - byte * 8)) & 0xff);
    }
  }
}

DECLSPEC void shooter_hex_be64 (PRIVATE_AS u32 *buf, PRIVATE_AS const u64 *digest, const u32 words)
{
  shooter_hex_clear (buf);

  for (u32 word = 0; word < words; word++)
  {
    const u64 value = digest[word];

    for (u32 byte = 0; byte < 8; byte++)
    {
      shooter_hex_put_byte (buf, word * 8 + byte, (u32) ((value >> (56 - byte * 8)) & 0xff));
    }
  }
}

DECLSPEC u32 shooter_buf_get_char (PRIVATE_AS const u32 *buf, const u32 pos)
{
  return (buf[pos >> 2] >> ((pos & 3) * 8)) & 0xff;
}

#define SHOOTER_COMPARE_TEXT(hex_buf, hex_len, output_mode)                                      \
  do                                                                                              \
  {                                                                                               \
    md4_ctx_t lookup_ctx;                                                                         \
    md4_init (&lookup_ctx);                                                                        \
    md4_update (&lookup_ctx, (hex_buf), (hex_len));                                                \
    md4_final (&lookup_ctx);                                                                       \
    u32 digest_tp[4];                                                                              \
    digest_tp[0] = lookup_ctx.h[0];                                                                \
    digest_tp[1] = lookup_ctx.h[1];                                                                \
    digest_tp[2] = lookup_ctx.h[2];                                                                \
    digest_tp[3] = lookup_ctx.h[3];                                                                \
    if (check (digest_tp,                                                                          \
               bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,            \
               bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,            \
               BITMAP_MASK, BITMAP_SHIFT1, BITMAP_SHIFT2))                                        \
    {                                                                                              \
      const int digest_pos = find_hash (digest_tp, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]); \
      if (digest_pos != -1)                                                                        \
      {                                                                                            \
        const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;                               \
        if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                   \
        {                                                                                          \
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT,                         \
                     digest_pos, final_hash_pos, gid, 0, (output_mode), 0);                         \
        }                                                                                          \
      }                                                                                            \
    }                                                                                              \
  } while (0)

KERNEL_FQ KERNEL_FA void m79997_init (KERN_ATTR_TMPS (shooter_multi_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  for (u32 i = 0; i < 64; i++) tmps[gid].pw_buf[i] = pws[gid].i[i];

  tmps[gid].pw_len = pws[gid].pw_len;
}

KERNEL_FQ KERNEL_FA void m79997_loop (KERN_ATTR_TMPS (shooter_multi_tmp_t))
{
}

KERNEL_FQ KERNEL_FA void m79997_comp (KERN_ATTR_TMPS (shooter_multi_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  PRIVATE_AS const u32 *pw_buf = tmps[gid].pw_buf;
  const u32 pw_len = tmps[gid].pw_len;

  u32 hex_buf[32];

  #if SHOOTER_MULTI_MD5_MODE > 0
  {
    md5_ctx_t ctx;

    md5_init (&ctx);
    md5_update (&ctx, pw_buf, pw_len);
    md5_final (&ctx);

    shooter_hex_le32 (hex_buf, ctx.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD4_MODE > 0
  {
    md4_ctx_t ctx;

    md4_init (&ctx);
    md4_update (&ctx, pw_buf, pw_len);
    md4_final (&ctx);

    shooter_hex_le32 (hex_buf, ctx.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD4_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA1_MODE > 0
  {
    sha1_ctx_t ctx;

    sha1_init (&ctx);
    sha1_update_swap (&ctx, pw_buf, pw_len);
    sha1_final (&ctx);

    shooter_hex_be32 (hex_buf, ctx.h, 5);

    SHOOTER_COMPARE_TEXT (hex_buf, 40, SHOOTER_MULTI_SHA1_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA256_MODE > 0
  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);
    sha256_update_swap (&ctx, pw_buf, pw_len);
    sha256_final (&ctx);

    shooter_hex_be32 (hex_buf, ctx.h, 8);

    SHOOTER_COMPARE_TEXT (hex_buf, 64, SHOOTER_MULTI_SHA256_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA512_MODE > 0
  {
    sha512_ctx_t ctx;

    sha512_init (&ctx);
    sha512_update_swap (&ctx, pw_buf, pw_len);
    sha512_final (&ctx);

    shooter_hex_be64 (hex_buf, ctx.h, 8);

    SHOOTER_COMPARE_TEXT (hex_buf, 128, SHOOTER_MULTI_SHA512_MODE);
  }
  #endif

  #if SHOOTER_MULTI_NTLM_MODE > 0
  {
    md4_ctx_t ctx;

    md4_init (&ctx);
    md4_update_utf16le (&ctx, pw_buf, pw_len);
    md4_final (&ctx);

    shooter_hex_le32 (hex_buf, ctx.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_NTLM_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD5_UTF16LE_MODE > 0
  {
    md5_ctx_t ctx;

    md5_init (&ctx);
    md5_update_utf16le (&ctx, pw_buf, pw_len);
    md5_final (&ctx);

    shooter_hex_le32 (hex_buf, ctx.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_UTF16LE_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA1_UTF16LE_MODE > 0
  {
    sha1_ctx_t ctx;

    sha1_init (&ctx);
    sha1_update_utf16le_swap (&ctx, pw_buf, pw_len);
    sha1_final (&ctx);

    shooter_hex_be32 (hex_buf, ctx.h, 5);

    SHOOTER_COMPARE_TEXT (hex_buf, 40, SHOOTER_MULTI_SHA1_UTF16LE_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA256_UTF16LE_MODE > 0
  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);
    sha256_update_utf16le_swap (&ctx, pw_buf, pw_len);
    sha256_final (&ctx);

    shooter_hex_be32 (hex_buf, ctx.h, 8);

    SHOOTER_COMPARE_TEXT (hex_buf, 64, SHOOTER_MULTI_SHA256_UTF16LE_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA512_UTF16LE_MODE > 0
  {
    sha512_ctx_t ctx;

    sha512_init (&ctx);
    sha512_update_utf16le_swap (&ctx, pw_buf, pw_len);
    sha512_final (&ctx);

    shooter_hex_be64 (hex_buf, ctx.h, 8);

    SHOOTER_COMPARE_TEXT (hex_buf, 128, SHOOTER_MULTI_SHA512_UTF16LE_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD5_MD5_MODE > 0
  {
    md5_ctx_t inner;
    md5_ctx_t outer;

    md5_init (&inner);
    md5_update (&inner, pw_buf, pw_len);
    md5_final (&inner);
    shooter_hex_le32 (hex_buf, inner.h, 4);

    md5_init (&outer);
    md5_update (&outer, hex_buf, 32);
    md5_final (&outer);
    shooter_hex_le32 (hex_buf, outer.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD5_MD5_MD5_MODE > 0
  {
    md5_ctx_t ctx0;
    md5_ctx_t ctx1;
    md5_ctx_t ctx2;

    md5_init (&ctx0);
    md5_update (&ctx0, pw_buf, pw_len);
    md5_final (&ctx0);
    shooter_hex_le32 (hex_buf, ctx0.h, 4);

    md5_init (&ctx1);
    md5_update (&ctx1, hex_buf, 32);
    md5_final (&ctx1);
    shooter_hex_le32 (hex_buf, ctx1.h, 4);

    md5_init (&ctx2);
    md5_update (&ctx2, hex_buf, 32);
    md5_final (&ctx2);
    shooter_hex_le32 (hex_buf, ctx2.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_MD5_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD5_UC_MD5_MODE > 0
  {
    md5_ctx_t inner;
    md5_ctx_t outer;

    md5_init (&inner);
    md5_update (&inner, pw_buf, pw_len);
    md5_final (&inner);
    shooter_hex_le32_upper (hex_buf, inner.h, 4);

    md5_init (&outer);
    md5_update (&outer, hex_buf, 32);
    md5_final (&outer);
    shooter_hex_le32 (hex_buf, outer.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_UC_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD5_SHA1_MODE > 0
  {
    sha1_ctx_t inner;
    md5_ctx_t outer;

    sha1_init (&inner);
    sha1_update_swap (&inner, pw_buf, pw_len);
    sha1_final (&inner);
    shooter_hex_be32 (hex_buf, inner.h, 5);

    md5_init (&outer);
    md5_update (&outer, hex_buf, 40);
    md5_final (&outer);
    shooter_hex_le32 (hex_buf, outer.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_SHA1_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA1_SHA1_MODE > 0
  {
    sha1_ctx_t inner;
    sha1_ctx_t outer;

    sha1_init (&inner);
    sha1_update_swap (&inner, pw_buf, pw_len);
    sha1_final (&inner);
    shooter_hex_be32 (hex_buf, inner.h, 5);

    sha1_init (&outer);
    sha1_update_swap (&outer, hex_buf, 40);
    sha1_final (&outer);
    shooter_hex_be32 (hex_buf, outer.h, 5);

    SHOOTER_COMPARE_TEXT (hex_buf, 40, SHOOTER_MULTI_SHA1_SHA1_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA1_MD5_MODE > 0
  {
    md5_ctx_t inner;
    sha1_ctx_t outer;

    md5_init (&inner);
    md5_update (&inner, pw_buf, pw_len);
    md5_final (&inner);
    shooter_hex_le32 (hex_buf, inner.h, 4);

    sha1_init (&outer);
    sha1_update_swap (&outer, hex_buf, 32);
    sha1_final (&outer);
    shooter_hex_be32 (hex_buf, outer.h, 5);

    SHOOTER_COMPARE_TEXT (hex_buf, 40, SHOOTER_MULTI_SHA1_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA1_MD5_MD5_MODE > 0
  {
    md5_ctx_t ctx0;
    md5_ctx_t ctx1;
    sha1_ctx_t ctx2;

    md5_init (&ctx0);
    md5_update (&ctx0, pw_buf, pw_len);
    md5_final (&ctx0);
    shooter_hex_le32 (hex_buf, ctx0.h, 4);

    md5_init (&ctx1);
    md5_update (&ctx1, hex_buf, 32);
    md5_final (&ctx1);
    shooter_hex_le32 (hex_buf, ctx1.h, 4);

    sha1_init (&ctx2);
    sha1_update_swap (&ctx2, hex_buf, 32);
    sha1_final (&ctx2);
    shooter_hex_be32 (hex_buf, ctx2.h, 5);

    SHOOTER_COMPARE_TEXT (hex_buf, 40, SHOOTER_MULTI_SHA1_MD5_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA256_MD5_MODE > 0
  {
    md5_ctx_t inner;
    sha256_ctx_t outer;

    md5_init (&inner);
    md5_update (&inner, pw_buf, pw_len);
    md5_final (&inner);
    shooter_hex_le32 (hex_buf, inner.h, 4);

    sha256_init (&outer);
    sha256_update_swap (&outer, hex_buf, 32);
    sha256_final (&outer);
    shooter_hex_be32 (hex_buf, outer.h, 8);

    SHOOTER_COMPARE_TEXT (hex_buf, 64, SHOOTER_MULTI_SHA256_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD5_SHA1_MIX_MODE > 0
  {
    u32 sha1_hex[32];
    u32 md5_hex[32];
    u32 mix_buf[32];
    sha1_ctx_t sha1_ctx;
    md5_ctx_t md5_ctx;
    md5_ctx_t outer;

    sha1_init (&sha1_ctx);
    sha1_update_swap (&sha1_ctx, pw_buf, pw_len);
    sha1_final (&sha1_ctx);
    shooter_hex_be32 (sha1_hex, sha1_ctx.h, 5);

    md5_init (&md5_ctx);
    md5_update (&md5_ctx, pw_buf, pw_len);
    md5_final (&md5_ctx);
    shooter_hex_le32 (md5_hex, md5_ctx.h, 4);

    shooter_hex_clear (mix_buf);
    for (u32 i = 0; i < 40; i++) shooter_hex_put_char (mix_buf, i, shooter_buf_get_char (sha1_hex, i));
    for (u32 i = 0; i < 32; i++) shooter_hex_put_char (mix_buf, 40 + i, shooter_buf_get_char (md5_hex, i));
    for (u32 i = 0; i < 40; i++) shooter_hex_put_char (mix_buf, 72 + i, shooter_buf_get_char (sha1_hex, i));

    md5_init (&outer);
    md5_update (&outer, mix_buf, 112);
    md5_final (&outer);
    shooter_hex_le32 (hex_buf, outer.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_SHA1_MIX_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA512_RAW2_MODE > 0
  {
    u32 raw[32] = { 0 };
    sha512_ctx_t inner;
    sha512_ctx_t outer;

    sha512_init (&inner);
    sha512_update_swap (&inner, pw_buf, pw_len);
    sha512_final (&inner);

    for (u32 i = 0; i < 8; i++)
    {
      raw[i * 2 + 0] = h32_from_64_S (inner.h[i]);
      raw[i * 2 + 1] = l32_from_64_S (inner.h[i]);
    }

    sha512_init (&outer);
    sha512_update (&outer, raw, 64);
    sha512_final (&outer);
    shooter_hex_be64 (hex_buf, outer.h, 8);

    SHOOTER_COMPARE_TEXT (hex_buf, 128, SHOOTER_MULTI_SHA512_RAW2_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA256_RAW2_MODE > 0
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };
    sha256_ctx_t inner;
    sha256_ctx_t outer;

    sha256_init (&inner);
    sha256_update_swap (&inner, pw_buf, pw_len);
    sha256_final (&inner);

    for (u32 i = 0; i < 4; i++) w0[i] = inner.h[i];
    for (u32 i = 0; i < 4; i++) w1[i] = inner.h[i + 4];

    sha256_init (&outer);
    sha256_update_64 (&outer, w0, w1, w2, w3, 32);
    sha256_final (&outer);
    shooter_hex_be32 (hex_buf, outer.h, 8);

    SHOOTER_COMPARE_TEXT (hex_buf, 64, SHOOTER_MULTI_SHA256_RAW2_MODE);
  }
  #endif

  #if SHOOTER_MULTI_MD5_SHA1_MD5_MODE > 0
  {
    md5_ctx_t ctx0;
    sha1_ctx_t ctx1;
    md5_ctx_t ctx2;

    md5_init (&ctx0);
    md5_update (&ctx0, pw_buf, pw_len);
    md5_final (&ctx0);
    shooter_hex_le32 (hex_buf, ctx0.h, 4);

    sha1_init (&ctx1);
    sha1_update_swap (&ctx1, hex_buf, 32);
    sha1_final (&ctx1);
    shooter_hex_be32 (hex_buf, ctx1.h, 5);

    md5_init (&ctx2);
    md5_update (&ctx2, hex_buf, 40);
    md5_final (&ctx2);
    shooter_hex_le32 (hex_buf, ctx2.h, 4);

    SHOOTER_COMPARE_TEXT (hex_buf, 32, SHOOTER_MULTI_MD5_SHA1_MD5_MODE);
  }
  #endif

  #if SHOOTER_MULTI_SHA224_SHA1_MODE > 0
  {
    sha1_ctx_t inner;
    sha224_ctx_t outer;

    sha1_init (&inner);
    sha1_update_swap (&inner, pw_buf, pw_len);
    sha1_final (&inner);
    shooter_hex_be32 (hex_buf, inner.h, 5);

    sha224_init (&outer);
    sha224_update_swap (&outer, hex_buf, 40);
    sha224_final (&outer);
    shooter_hex_be32 (hex_buf, outer.h, 7);

    SHOOTER_COMPARE_TEXT (hex_buf, 56, SHOOTER_MULTI_SHA224_SHA1_MODE);
  }
  #endif
}
