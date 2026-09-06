/**
 * mdxfind named hash-mode namespace.
 *
 * mdxfind calls its built-in algorithms e1 through e1001.  Hashcat keeps
 * hash modes as integers internally, so named modes are translated into a
 * private, collision-free range while they move through the existing core.
 * The module loader translates that range back to module_eN.{dll,so}.
 */

#ifndef HASHCAT_MDXFIND_MODES_H
#define HASHCAT_MDXFIND_MODES_H

#define MDXFIND_HASH_MODE_BASE 90000
#define MDXFIND_HASH_MODE_MIN  (MDXFIND_HASH_MODE_BASE + 1)
#define MDXFIND_HASH_MODE_MAX  (MDXFIND_HASH_MODE_BASE + 1001)

#define MDXFIND_HASH_MODE_FROM_ID(id) (MDXFIND_HASH_MODE_BASE + (id))
#define MDXFIND_HASH_MODE_TO_ID(mode)  ((mode) - MDXFIND_HASH_MODE_BASE)

#define MDXFIND_HASH_MODE_IS_NAMED(mode) \
  (((mode) >= MDXFIND_HASH_MODE_MIN) && ((mode) <= MDXFIND_HASH_MODE_MAX))

// Private module used when --multi-hash-modes can evaluate a compatible raw
// hash family in one GPU pass.  Keep it below MODULE_HASH_MODES_MAXIMUM and
// outside both the public native modes and the mdxfind alias range.

#define SHOOTER_MULTI_HASH_SHARED_MODE 79997

#endif
