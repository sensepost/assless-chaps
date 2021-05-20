/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_md4.cl"
#endif

void print_hash(const u32 r0, const u32 r1, const u32 r2, const u32 r3)
{
  // Convert to vector to switch endianess
  uchar4 x0 = as_uchar4(r0).wzyx;
  uchar4 x1 = as_uchar4(r1).wzyx;
  uchar4 x2 = as_uchar4(r2).wzyx;
  uchar4 x3 = as_uchar4(r3).wzyx;

  // Print all generated hashes
  //printf("%02x%02x%02x%02x\n", x0, x3, x2, x1);

  // Print all generated hashes in .csv
  // last_twobytes, first_chunk, second_chunk
  printf("%02x%02x,%02x%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x%02x\n",
    x1[1],x1[0],
    x0[3],x0[2],x0[1],x0[0],x3[3],x3[2],x3[1],
    x3[0],x2[3],x2[2],x2[1],x2[0],x1[3],x1[2]);
}

KERNEL_FQ void m01000_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t ctx;

    md4_init (&ctx);

    md4_update_utf16le (&ctx, tmp.i, tmp.pw_len);

    md4_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    print_hash(r0, r1, r2, r3);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m01000_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t ctx;

    md4_init (&ctx);

    md4_update_utf16le (&ctx, tmp.i, tmp.pw_len);

    md4_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    print_hash(r0, r1, r2, r3);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
