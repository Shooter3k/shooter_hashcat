/**
 * Private Hashcat module for the KoreLogic CMIYC 2026 memory-hard SHA-512 KDF.
 *
 * Mode 29990 is a local/private number.  HashMob's public algorithm identifier
 * for this format is h1297; the two namespaces must not be mixed.
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_GENERIC_KDF;
static const char *HASH_NAME      = "CMIYC 2026 memory-hard SHA-512 (private)";
static const u64   KERN_TYPE      = 29990;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_USES_BITS_64;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "Always";
static const char *ST_HASH        = "$cmiyc$2026$1$10$AAECAwQFBgcICQoLDA0ODw$PeDdIxtm9EBCX5W2QI9GTX9UVM4Vp-iPT-ntbNzcd_Q";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;   }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;     }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;     }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;     }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;     }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;     }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY; }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;     }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;     }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;     }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;     }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;     }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;       }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;       }

static const char *SIGNATURE_CMIYC = "$cmiyc$";

static int b64url_value (const u8 c)
{
  if ((c >= 'A') && (c <= 'Z')) return c - 'A';
  if ((c >= 'a') && (c <= 'z')) return c - 'a' + 26;
  if ((c >= '0') && (c <= '9')) return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;

  return -1;
}

static int b64url_decode (const u8 *src, const int src_len, u8 *dst, const int dst_size)
{
  u32 acc = 0;
  int bits = 0;
  int out = 0;

  for (int i = 0; i < src_len; i++)
  {
    const int v = b64url_value (src[i]);

    if (v < 0) return -1;

    acc = (acc << 6) | (u32) v;
    bits += 6;

    if (bits >= 8)
    {
      bits -= 8;

      if (out >= dst_size) return -1;

      dst[out++] = (u8) (acc >> bits);

      acc &= (1u << bits) - 1u;
    }
  }

  if ((bits != 0) && (acc != 0)) return -1;

  return out;
}

static int b64url_encode (const u8 *src, const int src_len, char *dst)
{
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  u32 acc = 0;
  int bits = 0;
  int out = 0;

  for (int i = 0; i < src_len; i++)
  {
    acc = (acc << 8) | src[i];
    bits += 8;

    while (bits >= 6)
    {
      bits -= 6;
      dst[out++] = alphabet[(acc >> bits) & 63];
      acc &= (1u << bits) - 1u;
    }
  }

  if (bits != 0) dst[out++] = alphabet[(acc << (6 - bits)) & 63];

  dst[out] = 0;

  return out;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 64;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1024;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1024;
}

u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1;
}

static u64 cmiyc_blocks_from_salt (const salt_t *salt)
{
  return (u64) salt->scrypt_N * 2;
}

static u64 cmiyc_largest_blocks (const hashconfig_t *hashconfig, const hashes_t *hashes)
{
  u64 blocks = 0;

  if (((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0) && (hashes->st_salts_buf[0].scrypt_N != 0))
  {
    blocks = cmiyc_blocks_from_salt (&hashes->st_salts_buf[0]);
  }

  for (u32 i = 0; i < hashes->salts_cnt; i++)
  {
    blocks = MAX (blocks, cmiyc_blocks_from_salt (&hashes->salts_buf[i]));
  }

  return blocks;
}

const char *module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  const u64 size_per_job = cmiyc_largest_blocks (hashconfig, hashes) * 64;
  const u64 fixed_mem = 256ULL * 1024 * 1024;
  const u64 single_alloc_max = device_param->device_maxmem_alloc / 4;
  const u64 available_mem = MIN (device_param->device_available_mem, single_alloc_max) - fixed_mem;
  const u32 accel_limit = (u32) MIN ((u64) KERNEL_ACCEL_MAX, available_mem / size_per_job);
  u32 accel = accel_limit;

  if (kernel_accel_user != 0) accel = MIN (accel, kernel_accel_user);
  if (accel == 0) accel = 1;

  char *device_name = hcstrdup (device_param->device_name);

  for (size_t i = 0; i < strlen (device_name); i++) if (device_name[i] == ' ') device_name[i] = '_';

  char *line = hcmalloc (4096);

  snprintf (line, 4096, "%s * %u 1 %u A\n", device_name, user_options->hash_mode, accel);

  hcfree (device_name);

  return line;
}

u64 module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u64 size_per_job = cmiyc_largest_blocks (hashconfig, hashes) * 64;

  return device_param->kernel_accel_max * size_per_job;
}

u64 module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  return 0;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *options = NULL;

  hc_asprintf (&options, "-D FIXED_LOCAL_SIZE=1 -D CMIYC_STRIDE_BLOCKS=%" PRIu64, cmiyc_largest_blocks (hashconfig, hashes));

  return options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (token));

  token.token_cnt = 6;
  token.signatures_cnt = 1;
  token.signatures_buf[0] = SIGNATURE_CMIYC;

  token.len[0]  = 7;
  token.sep[0]  = 0;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 4;
  token.sep[1]  = '$';
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 1;
  token.len_max[2] = 2;
  token.sep[2] = '$';
  token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3] = 2;
  token.len_max[3] = 2;
  token.sep[3] = '$';
  token.attr[3] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.len[4]  = 22;
  token.sep[4]  = '$';
  token.attr[4] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[5]  = 43;
  token.sep[5]  = '$';
  token.attr[5] = TOKEN_ATTR_FIXED_LENGTH;

  const int rc = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc != PARSER_OK) return rc;
  if (memcmp (token.buf[1], "2026", 4) != 0) return PARSER_SIGNATURE_UNMATCHED;

  const u32 rounds = hc_strtoul ((const char *) token.buf[2], NULL, 10);
  const u32 memlog = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if ((rounds < 1) || (rounds > 32)) return PARSER_SALT_ITERATION;
  if ((memlog < 10) || (memlog > 24)) return PARSER_SALT_VALUE;

  u8 salt_raw[16];
  u8 digest_raw[32];

  if (b64url_decode (token.buf[4], token.len[4], salt_raw, sizeof (salt_raw)) != 16) return PARSER_SALT_VALUE;
  if (b64url_decode (token.buf[5], token.len[5], digest_raw, sizeof (digest_raw)) != 32) return PARSER_HASH_VALUE;

  memcpy (salt->salt_buf, salt_raw, 16);
  salt->salt_len = 16;

  /* Reuse generic scrypt fields solely as compact host-to-device parameters. */
  salt->scrypt_N = 1u << (memlog - 1);
  salt->scrypt_r = memlog;
  salt->scrypt_p = rounds;
  salt->salt_iter = (u32) (((u64) 1 << memlog) * (1 + 2 * rounds));

  memcpy (digest_buf, digest_raw, 32);

  return PARSER_OK;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  char salt_b64[24];
  char digest_b64[48];

  b64url_encode ((const u8 *) salt->salt_buf, 16, salt_b64);
  b64url_encode ((const u8 *) digest_buf, 32, digest_b64);

  u32 memlog = 1;

  for (u32 blocks = salt->scrypt_N * 2; blocks > 2; blocks >>= 1) memlog++;

  return snprintf (line_buf, line_size, "$cmiyc$2026$%u$%u$%s$%s", salt->scrypt_p, memlog, salt_b64, digest_b64);
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;
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
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size        = module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = module_extra_tuningdb_block;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
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
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = module_kernel_threads_max;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
