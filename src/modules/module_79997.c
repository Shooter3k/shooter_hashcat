/**
 * Shooter shared unsalted-hash family used internally by --multi-hash-modes.
 *
 * Targets are normalized to lowercase hexadecimal text and indexed by MD4 of
 * that text.  The GPU computes each requested raw digest for a candidate,
 * converts it to the same canonical text, and performs one normal hashcat
 * multi-hash lookup.  plain_t.extra1 carries the public mode back to the host.
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "emu_inc_hash_md4.h"
#include "mdxfind_modes.h"

#define SHOOTER_MULTI_TARGET_MAX 128

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH;
static const char *HASH_NAME      = "Shooter shared unsalted hash family";
static const u64   KERN_TYPE      = SHOOTER_MULTI_HASH_SHARED_MODE;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_AUTODETECT_DISABLE
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_SELF_TEST_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "8743b52063cd84097a65d1633f5c74f5";

typedef struct shooter_multi_tmp
{
  u32 pw_buf[64];
  u32 pw_len;

} shooter_multi_tmp_t;

typedef struct shooter_multi_esalt
{
  u8  target_buf[SHOOTER_MULTI_TARGET_MAX + 1];
  u32 target_len;

} shooter_multi_esalt_t;

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC; }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0; }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1; }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2; }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3; }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE; }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY; }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE; }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE; }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH; }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS; }

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return sizeof (shooter_multi_tmp_t);
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return sizeof (shooter_multi_esalt_t);
}

static int shooter_multi_mode_define (const int mode)
{
  return mode + 1;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  int md5 = 0;
  int md4 = 0;
  int sha1 = 0;
  int sha256 = 0;
  int sha512 = 0;
  int ntlm = 0;
  int md5_utf16le = 0;
  int sha1_utf16le = 0;
  int sha256_utf16le = 0;
  int sha512_utf16le = 0;
  int md5_md5 = 0;
  int md5_md5_md5 = 0;
  int md5_uc_md5 = 0;
  int md5_sha1 = 0;
  int sha1_sha1 = 0;
  int sha1_md5 = 0;
  int sha1_md5_md5 = 0;
  int sha256_md5 = 0;
  int md5_sha1_mix = 0;
  int sha512_raw2 = 0;
  int sha256_raw2 = 0;
  int md5_sha1_md5 = 0;
  int sha224_sha1 = 0;

  for (u32 i = 0; i < user_options->multi_hash_modes_cnt; i++)
  {
    const int mode = user_options->multi_hash_modes_buf[i];
    const int value = shooter_multi_mode_define (mode);

    switch (mode)
    {
      case 0:
      case MDXFIND_HASH_MODE_FROM_ID (1):   md5 = value; break;
      case 900:
      case MDXFIND_HASH_MODE_FROM_ID (3):   md4 = value; break;
      case 100:
      case MDXFIND_HASH_MODE_FROM_ID (8):   sha1 = value; break;
      case 1400:
      case MDXFIND_HASH_MODE_FROM_ID (10):  sha256 = value; break;
      case 1700:
      case MDXFIND_HASH_MODE_FROM_ID (12):  sha512 = value; break;
      case 1000:
      case MDXFIND_HASH_MODE_FROM_ID (369): ntlm = value; break;
      case 70:
      case MDXFIND_HASH_MODE_FROM_ID (800): md5_utf16le = value; break;
      case 170:
      case MDXFIND_HASH_MODE_FROM_ID (727): sha1_utf16le = value; break;
      case 1470:
      case MDXFIND_HASH_MODE_FROM_ID (805): sha256_utf16le = value; break;
      case 1770:
      case MDXFIND_HASH_MODE_FROM_ID (808): sha512_utf16le = value; break;
      case 2600: md5_md5 = value; break;
      case 3500: md5_md5_md5 = value; break;
      case 4300:
      case MDXFIND_HASH_MODE_FROM_ID (262): md5_uc_md5 = value; break;
      case 4400:
      case MDXFIND_HASH_MODE_FROM_ID (178): md5_sha1 = value; break;
      case 4500: sha1_sha1 = value; break;
      case 4700:
      case MDXFIND_HASH_MODE_FROM_ID (160): sha1_md5 = value; break;
      case 18500:
      case MDXFIND_HASH_MODE_FROM_ID (287): sha1_md5_md5 = value; break;
      case 20800:
      case MDXFIND_HASH_MODE_FROM_ID (164): sha256_md5 = value; break;
      case 20900:
      case MDXFIND_HASH_MODE_FROM_ID (442): md5_sha1_mix = value; break;
      case 21000:
      case MDXFIND_HASH_MODE_FROM_ID (38): sha512_raw2 = value; break;
      case 21400:
      case MDXFIND_HASH_MODE_FROM_ID (36): sha256_raw2 = value; break;
      case 32800:
      case MDXFIND_HASH_MODE_FROM_ID (188): md5_sha1_md5 = value; break;
      case 34500:
      case MDXFIND_HASH_MODE_FROM_ID (766): sha224_sha1 = value; break;
    }
  }

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options,
    "-D SHOOTER_MULTI_MD5_MODE=%d -D SHOOTER_MULTI_MD4_MODE=%d -D SHOOTER_MULTI_SHA1_MODE=%d -D SHOOTER_MULTI_SHA256_MODE=%d -D SHOOTER_MULTI_SHA512_MODE=%d -D SHOOTER_MULTI_NTLM_MODE=%d "
    "-D SHOOTER_MULTI_MD5_UTF16LE_MODE=%d -D SHOOTER_MULTI_SHA1_UTF16LE_MODE=%d -D SHOOTER_MULTI_SHA256_UTF16LE_MODE=%d -D SHOOTER_MULTI_SHA512_UTF16LE_MODE=%d "
    "-D SHOOTER_MULTI_MD5_MD5_MODE=%d -D SHOOTER_MULTI_MD5_MD5_MD5_MODE=%d -D SHOOTER_MULTI_MD5_UC_MD5_MODE=%d -D SHOOTER_MULTI_MD5_SHA1_MODE=%d "
    "-D SHOOTER_MULTI_SHA1_SHA1_MODE=%d -D SHOOTER_MULTI_SHA1_MD5_MODE=%d -D SHOOTER_MULTI_SHA1_MD5_MD5_MODE=%d "
    "-D SHOOTER_MULTI_SHA256_MD5_MODE=%d -D SHOOTER_MULTI_MD5_SHA1_MIX_MODE=%d -D SHOOTER_MULTI_SHA512_RAW2_MODE=%d -D SHOOTER_MULTI_SHA256_RAW2_MODE=%d "
    "-D SHOOTER_MULTI_MD5_SHA1_MD5_MODE=%d -D SHOOTER_MULTI_SHA224_SHA1_MODE=%d",
    md5, md4, sha1, sha256, sha512, ntlm,
    md5_utf16le, sha1_utf16le, sha256_utf16le, sha512_utf16le,
    md5_md5, md5_md5_md5, md5_uc_md5, md5_sha1,
    sha1_sha1, sha1_md5, sha1_md5_md5,
    sha256_md5, md5_sha1_mix, sha512_raw2, sha256_raw2,
    md5_sha1_md5, sha224_sha1);

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, void *digest_buf, salt_t *salt, void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, const int line_len)
{
  if ((line_len != 32) && (line_len != 40) && (line_len != 56) && (line_len != 64) && (line_len != 128)) return PARSER_HASH_LENGTH;
  if (is_valid_hex_string ((const u8 *) line_buf, line_len) == false) return PARSER_HASH_ENCODING;

  shooter_multi_esalt_t *esalt = (shooter_multi_esalt_t *) esalt_buf;

  memset (esalt, 0, sizeof (*esalt));

  for (int i = 0; i < line_len; i++)
  {
    const u8 c = (u8) line_buf[i];

    esalt->target_buf[i] = ((c >= 'A') && (c <= 'F')) ? (u8) (c + ('a' - 'A')) : c;
  }

  esalt->target_len = (u32) line_len;

  md4_ctx_t target_ctx;

  md4_init (&target_ctx);
  md4_update (&target_ctx, (const u32 *) esalt->target_buf, esalt->target_len);
  md4_final (&target_ctx);

  u32 *digest = (u32 *) digest_buf;

  digest[0] = target_ctx.h[0];
  digest[1] = target_ctx.h[1];
  digest[2] = target_ctx.h[2];
  digest[3] = target_ctx.h[3];

  memset (salt, 0, sizeof (*salt));

  salt->salt_len = 4;
  salt->salt_iter = 1;

  return PARSER_OK;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, const int line_size)
{
  const shooter_multi_esalt_t *esalt = (const shooter_multi_esalt_t *) esalt_buf;

  if ((int) esalt->target_len >= line_size) return -1;

  memcpy (line_buf, esalt->target_buf, esalt->target_len);

  line_buf[esalt->target_len] = 0;

  return (int) esalt->target_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;
  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
