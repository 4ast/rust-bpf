// SPDX-License-Identifier: GPL-2.0
//! core: integer arithmetic of every width.
#![no_std]
#![no_main]
use rt::{bb, check, check_eq, test};

test!(int_checked, {
    check_eq!(bb(250u8).checked_add(5), Some(255));
    check_eq!(bb(250u8).checked_add(6), None);
    check_eq!(bb(i32::MIN).checked_sub(1), None);
    check_eq!(bb(i64::MAX).checked_mul(2), None);
    check_eq!(bb(1u64 << 32).checked_mul(1 << 31), Some(1 << 63));
    check_eq!(bb(7u32).checked_div(0), None);
    check_eq!(bb(i32::MIN).checked_div(-1), None);
    check_eq!(bb(i32::MIN).checked_neg(), None);
    check_eq!(bb(i16::MIN).checked_abs(), None);
    check_eq!(bb(2u32).checked_pow(31), Some(1 << 31));
    check_eq!(bb(2u32).checked_pow(32), None);
    check_eq!(bb(1u32).checked_shl(32), None);
    check_eq!(bb(17u64).checked_rem(5), Some(2));
    check_eq!(bb(100u64).checked_next_power_of_two(), Some(128));
});

test!(int_wrapping, {
    check_eq!(bb(255u8).wrapping_add(2), 1);
    check_eq!(bb(0u16).wrapping_sub(1), 0xffff);
    check_eq!(bb(i32::MAX).wrapping_add(1), i32::MIN);
    check_eq!(bb(0x1_0000_0001u64).wrapping_mul(0x1_0000_0001), 0x2_0000_0001);
    check_eq!(bb(i64::MIN).wrapping_neg(), i64::MIN);
    check_eq!(bb(i8::MIN).wrapping_abs(), i8::MIN);
    check_eq!(bb(1u32).wrapping_shl(33), 2);
    check_eq!(bb(3u8).wrapping_pow(6), 217);
    check_eq!(bb(i32::MIN).wrapping_div(-1), i32::MIN);
    check_eq!(bb(i32::MIN).wrapping_rem(-1), 0);
});

test!(int_saturating, {
    check_eq!(bb(250u8).saturating_add(10), 255);
    check_eq!(bb(5u32).saturating_sub(6), 0);
    check_eq!(bb(i8::MIN).saturating_sub(1), i8::MIN);
    check_eq!(bb(i8::MAX).saturating_add(1), i8::MAX);
    check_eq!(bb(i64::MAX).saturating_mul(-2), i64::MIN);
    check_eq!(bb(i32::MIN).saturating_neg(), i32::MAX);
    check_eq!(bb(10u16).saturating_pow(5), u16::MAX);
    check_eq!(bb(-100i8).saturating_add_unsigned(255), 127);
});

test!(int_overflowing, {
    check_eq!(bb(u64::MAX).overflowing_add(1), (0, true));
    check_eq!(bb(5u64).overflowing_sub(6), (u64::MAX, true));
    check_eq!(bb(1u64 << 63).overflowing_mul(2), (0, true));
    check_eq!(bb(i32::MIN).overflowing_neg(), (i32::MIN, true));
    check_eq!(bb(1i32).overflowing_shl(36), (16, true));
    let (lo, carry) = bb(u64::MAX).carrying_add_(1, true);
    check!(lo == 1 && carry);
});

trait Carry: Sized {
    fn carrying_add_(self, rhs: Self, c: bool) -> (Self, bool);
}
impl Carry for u64 {
    fn carrying_add_(self, rhs: u64, c: bool) -> (u64, bool) {
        let (a, b) = self.overflowing_add(rhs);
        let (d, e) = a.overflowing_add(c as u64);
        (d, b | e)
    }
}

test!(int_bits, {
    check_eq!(bb(1u64).leading_zeros(), 63);
    check_eq!(bb(0u64).leading_zeros(), 64);
    check_eq!(bb(0u32).trailing_zeros(), 32);
    check_eq!(bb(0x80u8).trailing_zeros(), 7);
    check_eq!(bb(1u16).leading_zeros(), 15);
    check_eq!(bb(-1i32).leading_ones(), 32);
    check_eq!(bb(0b0111u8).trailing_ones(), 3);
    check_eq!(bb(0xf0f0_f0f0_f0f0_f0f0u64).count_ones(), 32);
    check_eq!(bb(0xffu8).count_zeros(), 0);
    check_eq!(bb(-1i128).count_ones(), 128);
    check_eq!(bb(0x1234u16).swap_bytes(), 0x3412);
    check_eq!(bb(0x12345678u32).swap_bytes(), 0x78563412);
    check_eq!(bb(0x0102030405060708u64).swap_bytes(), 0x0807060504030201);
    check_eq!(bb(0x1u8).reverse_bits(), 0x80);
    check_eq!(bb(0x1u64).reverse_bits(), 1 << 63);
    check_eq!(bb(0x12345678u32).reverse_bits(), 0x1e6a2c48);
    check_eq!(bb(0x80000001u32).rotate_left(1), 3);
    check_eq!(bb(0x1u64).rotate_right(4), 1 << 60);
    check_eq!(bb(0x81u8).rotate_left(4), 0x18);
    check!(bb(64u64).is_power_of_two() && !bb(65u64).is_power_of_two());
    check_eq!(bb(65u32).next_power_of_two(), 128);
    check_eq!(bb(1000u32).ilog2(), 9);
    check_eq!(bb(1000u32).ilog10(), 3);
    check_eq!(bb(1000u64).ilog(7), 3);
});

test!(int_signed_div, {
    check_eq!(bb(-7i32) / bb(2), -3);
    check_eq!(bb(-7i32) % bb(2), -1);
    check_eq!(bb(-7i64) / bb(-2), 3);
    check_eq!(bb(7i64) % bb(-3), 1);
    check_eq!(bb(-7i32).div_euclid(2), -4);
    check_eq!(bb(-7i32).rem_euclid(2), 1);
    check_eq!(bb(-7i64).rem_euclid(-3), 2);
    check_eq!(bb(-128i8) / bb(3), -42);
    check_eq!(bb(-32768i16) % bb(1000), -768);
    check_eq!(bb(-9i64) >> 1, -5);
    check_eq!(bb(-1i32) as u32 >> 28, 15);
    check_eq!(bb(7u32).div_ceil(2), 4);
    check_eq!(bb(13u64).next_multiple_of(8), 16);
});

test!(int_misc, {
    check_eq!(bb(3u64).pow(20), 3486784401);
    check_eq!(bb(-2i64).pow(63), i64::MIN);
    check_eq!(bb(99u64).isqrt(), 9);
    check_eq!(bb(u64::MAX).isqrt(), 0xffff_ffff);
    check_eq!(bb(5u8).abs_diff(250), 245);
    check_eq!(bb(-100i8).abs_diff(100), 200);
    check_eq!(bb(-5i32).signum(), -1);
    check_eq!(bb(-5i32).unsigned_abs(), 5);
    check_eq!(bb(i64::MIN).unsigned_abs(), 1 << 63);
    check_eq!(bb(5i32).clamp(-1, 3), 3);
    check_eq!(bb(5u32).min(3).max(4), 4);
    check_eq!(bb(200u8).midpoint(100), 150);
    check_eq!(bb(300i32) as u8, 44);
    check_eq!(bb(-1i8) as u64, u64::MAX);
    check_eq!(bb(0xffu8) as i8 as i32, -1);
    check_eq!(u8::try_from(bb(256u32)).is_err(), true);
    check_eq!(i8::try_from(bb(-128i64)), Ok(-128));
    check_eq!(u64::from(bb(7u8)) + u64::from(bb(true)), 8);
});

test!(int_bytes, {
    check_eq!(bb(0x01020304u32).to_be_bytes(), [1, 2, 3, 4]);
    check_eq!(bb(0x01020304u32).to_le_bytes(), [4, 3, 2, 1]);
    check_eq!(u64::from_be_bytes(bb([1, 2, 3, 4, 5, 6, 7, 8])), 0x0102030405060708);
    check_eq!(i16::from_le_bytes(bb([0xfe, 0xff])), -2);
    check_eq!(bb(0x1234u16).to_be(), 0x3412);
    check_eq!(u128::from_be_bytes(bb([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2])), (1 << 64) + 2);
});

test!(int_u128_addsub, {
    let a = bb(u64::MAX as u128);
    check_eq!(a + 1, 1u128 << 64);
    check_eq!((a + 1) - 1, u64::MAX as u128);
    check_eq!(bb(0u128).wrapping_sub(1), u128::MAX);
    check_eq!(bb(u128::MAX).checked_add(1), None);
    check_eq!(bb(i128::MIN).checked_sub(1), None);
    check_eq!(bb(-1i128) + bb(1i128), 0);
    check!(bb(1u128 << 64) > bb(u64::MAX as u128));
    check!(bb(-1i128) < bb(0i128));
});

test!(int_u128_shift, {
    check_eq!(bb(1u128) << bb(100u32), 0x10_0000_0000_0000_0000_0000_0000u128);
    check_eq!(bb(1u128 << 100) >> bb(37u32), 1u128 << 63);
    check_eq!(bb(-1i128) >> bb(127u32), -1);
    check_eq!(bb(i128::MIN) >> bb(64u32), i64::MIN as i128);
    check_eq!(bb(1u128 << 127).leading_zeros(), 0);
    check_eq!(bb(1u128 << 70).trailing_zeros(), 70);
    check_eq!(bb(1u128).rotate_right(1), 1u128 << 127);
    check_eq!(bb(0x0102u128).swap_bytes(), 0x0201u128 << 112);
});

test!(int_u128_mul, {
    check_eq!(bb(u64::MAX as u128) * bb(u64::MAX as u128), 0xffff_ffff_ffff_fffe_0000_0000_0000_0001u128);
    check_eq!(bb(-3i128) * bb(1i128 << 100), -(3i128 << 100));
    check_eq!(bb(1u128 << 64).checked_mul(1 << 64), None);
    check_eq!(bb(1u128 << 64).wrapping_mul((1 << 64) + 5), 5u128 << 64);
    check_eq!(bb(10u128).pow(30), 1_000_000_000_000_000_000_000_000_000_000u128);
});

test!(int_u128_div, {
    check_eq!(bb(10u128.pow(30)) / bb(10u128.pow(15)), 10u128.pow(15));
    check_eq!(bb(10u128.pow(30) + 7) % bb(10u128.pow(15)), 7);
    check_eq!(bb(u128::MAX) / bb(3u128), 0x5555_5555_5555_5555_5555_5555_5555_5555u128);
    check_eq!(bb(-(10i128.pow(20))) / bb(7i128), -14285714285714285714i128);
    check_eq!(bb(-(10i128.pow(20))) % bb(7i128), -2);
    check_eq!(bb(5u128).checked_div(0), None);
});

test!(int_widening, {
    let p = bb(0xdead_beef_dead_beefu64) as u128 * bb(0xcafe_babe_cafe_babeu64) as u128;
    check_eq!((p >> 64) as u64, 0xb092_ab7c_e9f4_b259);
    check_eq!(p as u64, 0xc231_623f_88cf_5b62);
    let q = bb(-5i64) as i128 * bb(i64::MAX) as i128;
    check_eq!(q, -46116860184273879035i128);
});

test!(int_parse, {
    check_eq!("12345".parse::<u32>(), Ok(12345));
    check_eq!(bb("-12345").parse::<i64>(), Ok(-12345));
    check_eq!(bb("+7").parse::<i8>(), Ok(7));
    check!(bb("256").parse::<u8>().is_err());
    check!(bb("").parse::<u8>().is_err());
    check!(bb("12a").parse::<u32>().is_err());
    check!(bb("-").parse::<i32>().is_err());
    check_eq!(u64::from_str_radix(bb("ffff_ffff").trim_end_matches("_ffff"), 16), Ok(0xffff));
    check_eq!(i32::from_str_radix(bb("-1010"), 2), Ok(-10));
    check_eq!(u32::from_str_radix(bb("zz"), 36), Ok(1295));
    check_eq!(bb("340282366920938463463374607431768211455").parse::<u128>(), Ok(u128::MAX));
    check!(bb("340282366920938463463374607431768211456").parse::<u128>().is_err());
    check_eq!(bb("-170141183460469231731687303715884105728").parse::<i128>(), Ok(i128::MIN));
});

test!(int_nonzero_wrapping_types, {
    use core::num::{NonZeroU32, Saturating, Wrapping};
    check!(NonZeroU32::new(bb(0)).is_none());
    let n = NonZeroU32::new(bb(8)).unwrap();
    check_eq!(n.get() + n.trailing_zeros(), 11);
    check_eq!(core::mem::size_of::<Option<NonZeroU32>>(), 4);
    let w = Wrapping(bb(250u8)) + Wrapping(10);
    check_eq!(w.0, 4);
    let s = Saturating(bb(250u8)) + Saturating(10);
    check_eq!(s.0, 255);
});
