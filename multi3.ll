; SPDX-License-Identifier: GPL-2.0
;
; 128-bit multiply for BPF using only 64-bit operations.
; Provides __multi3 libcall needed by LLVM BPF backend.

target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i128 @__multi3(i128 %a, i128 %b) {
  %a_lo = trunc i128 %a to i64
  %a_shr = lshr i128 %a, 64
  %a_hi = trunc i128 %a_shr to i64
  %b_lo = trunc i128 %b to i64
  %b_shr = lshr i128 %b, 64
  %b_hi = trunc i128 %b_shr to i64
  %al_lo = and i64 %a_lo, 4294967295
  %al_hi = lshr i64 %a_lo, 32
  %bl_lo = and i64 %b_lo, 4294967295
  %bl_hi = lshr i64 %b_lo, 32
  %t0 = mul i64 %al_lo, %bl_lo
  %t1 = mul i64 %al_hi, %bl_lo
  %t2 = mul i64 %al_lo, %bl_hi
  %t3 = mul i64 %al_hi, %bl_hi
  %t0_hi = lshr i64 %t0, 32
  %mid1 = add i64 %t1, %t0_hi
  %mid1_lo = and i64 %mid1, 4294967295
  %mid1_hi = lshr i64 %mid1, 32
  %mid2 = add i64 %mid1_lo, %t2
  %mid2_hi = lshr i64 %mid2, 32
  %t0_lo = and i64 %t0, 4294967295
  %mid2_shifted = shl i64 %mid2, 32
  %result_lo = or i64 %t0_lo, %mid2_shifted
  %hi_part = add i64 %t3, %mid1_hi
  %mulhu = add i64 %hi_part, %mid2_hi
  %cross1 = mul i64 %a_hi, %b_lo
  %cross2 = mul i64 %a_lo, %b_hi
  %result_hi_1 = add i64 %mulhu, %cross1
  %result_hi = add i64 %result_hi_1, %cross2
  %res_lo_ext = zext i64 %result_lo to i128
  %res_hi_ext = zext i64 %result_hi to i128
  %res_hi_shifted = shl i128 %res_hi_ext, 64
  %result = or i128 %res_lo_ext, %res_hi_shifted
  ret i128 %result
}
