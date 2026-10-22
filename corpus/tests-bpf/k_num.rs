// SPDX-License-Identifier: GPL-2.0
//! crates: num-traits, num-integer
#![no_std]
#![no_main]
extern crate alloc;
use num_integer::{Integer, Roots};
use num_traits::{
    Bounded, CheckedAdd, CheckedMul, FromPrimitive, Num, NumCast, One, PrimInt, Saturating, Signed, ToPrimitive, Unsigned,
    WrappingAdd, Zero,
};
use rt::{bb, check, check_eq, test};

fn sum_all<T: Zero + Copy + core::ops::Add<Output = T>>(v: &[T]) -> T {
    v.iter().fold(T::zero(), |a, &b| a + b)
}
fn power<T: One + Copy + core::ops::Mul<Output = T>>(b: T, n: u32) -> T {
    (0..n).fold(T::one(), |a, _| a * b)
}
fn mean<T: Num + NumCast + Copy>(v: &[T]) -> Option<T> {
    let n: T = NumCast::from(v.len())?;
    if n.is_zero() {
        return None;
    }
    Some(v.iter().fold(T::zero(), |a, &b| a + b) / n)
}
fn bits_set<T: PrimInt>(v: T) -> u32 {
    v.count_ones() + v.leading_zeros()
}
fn largest<T: Bounded + Unsigned>() -> T {
    T::max_value()
}

test!(num_traits_generic, {
    check_eq!(sum_all(bb(&[1u8, 2, 3])), 6);
    check_eq!(sum_all(bb(&[-1i64, 2, -3])), -2);
    check_eq!(sum_all(bb(&[1u128 << 100, 1])), (1u128 << 100) + 1);
    check_eq!(power(bb(3u32), 4), 81);
    check_eq!(power(bb(-2i64), 5), -32);
    check_eq!(mean(bb(&[2u32, 4, 9])), Some(5));
    check_eq!(mean::<i16>(bb(&[])), None);
    check_eq!(bits_set(bb(0x00f0u16)), 12);
    check_eq!(largest::<u16>(), 65535);
});

test!(num_traits_checked_cast, {
    check_eq!(CheckedAdd::checked_add(&bb(250u8), &5), Some(255));
    check_eq!(CheckedAdd::checked_add(&bb(250u8), &6), None);
    check_eq!(CheckedMul::checked_mul(&bb(1i32 << 20), &(1 << 12)), None);
    check_eq!(WrappingAdd::wrapping_add(&bb(255u8), &2), 1);
    check_eq!(Saturating::saturating_add(bb(250u8), 10), 255);
    check_eq!(bb(300i32).to_u8(), None);
    check_eq!(bb(200i32).to_u8(), Some(200));
    check_eq!(bb(-1i64).to_u64(), None);
    check_eq!(u16::from_i64(bb(65535)), Some(65535));
    check_eq!(u16::from_i64(bb(65536)), None);
    check_eq!(<i8 as NumCast>::from(bb(127u64)), Some(127));
    check_eq!(num_traits::cast::<u64, i8>(bb(128)), None);
    check_eq!(<u32 as Num>::from_str_radix(bb("ff"), 16), Ok(255));
    check!(<u8 as Num>::from_str_radix(bb("100"), 16).is_err());
});

test!(num_traits_misc, {
    check_eq!(Signed::abs(&bb(-5i32)), 5);
    check_eq!(Signed::signum(&bb(-5i32)), -1);
    check!(bb(-5i32).is_negative() && bb(5i32).is_positive());
    check_eq!(num_traits::pow(bb(2u64), 40), 1 << 40);
    check_eq!(num_traits::checked_pow(bb(2u8), 8), None);
    check_eq!(num_traits::clamp(bb(15), 0, 10), 10);
    check_eq!(num_traits::clamp_min(bb(-3), 0), 0);
    check_eq!(PrimInt::swap_bytes(bb(0x1234u16)), 0x3412);
    check_eq!(PrimInt::rotate_left(bb(0x81u8), 1), 3);
    check_eq!(PrimInt::pow(bb(3i32), 3), 27);
    check_eq!(PrimInt::unsigned_shr(bb(-1i8), 7), 1);
    check!(u8::zero().is_zero() && i64::one().is_one());
    check_eq!(<i16 as Bounded>::min_value(), -32768);
    check_eq!(num_traits::Euclid::rem_euclid(&bb(-7i32), &3), 2);
    check_eq!(num_traits::ops::bytes::ToBytes::to_be_bytes(&bb(0x0102u16)), [1, 2]);
});

test!(num_traits_float, {
    use num_traits::float::FloatCore;
    check_eq!(FloatCore::floor(bb(2.7f64)), 2.0);
    check_eq!(FloatCore::ceil(bb(2.1f64)), 3.0);
    check_eq!(FloatCore::round(bb(-2.5f64)), -3.0);
    check_eq!(FloatCore::trunc(bb(-2.7f32)), -2.0);
    check_eq!(FloatCore::fract(bb(2.25f64)), 0.25);
    check_eq!(FloatCore::powi(bb(2.0f64), 10), 1024.0);
    check_eq!(FloatCore::abs(bb(-1.5f32)), 1.5);
    check_eq!(FloatCore::integer_decode(bb(1.0f64)), (1 << 52, -52, 1));
    check!(FloatCore::is_nan(f64::nan()) && FloatCore::is_infinite(f32::infinity()));
    check_eq!(bb(2.9f64).to_i32(), Some(2));
    check_eq!(bb(1e10f64).to_i32(), None);
    check_eq!(f64::from_u32(bb(7)), Some(7.0));
});

test!(num_integer_division, {
    check_eq!(bb(12u32).gcd(&18), 6);
    check_eq!(bb(4u32).lcm(&6), 12);
    check_eq!(bb(-12i32).gcd(&18), 6);
    check_eq!(bb(0u32).gcd(&5), 5);
    check_eq!(num_integer::gcd_lcm(bb(10u64), 4), (2, 20));
    let e = bb(240i64).extended_gcd(&46);
    check!(e.gcd == 2 && 240 * e.x + 46 * e.y == 2);
    check_eq!(bb(-7i32).div_floor(&2), -4);
    check_eq!(bb(-7i32).mod_floor(&2), 1);
    check_eq!(Integer::div_ceil(&bb(7i32), &2), 4);
    check_eq!(bb(-7i32).div_rem(&2), (-3, -1));
    check_eq!(bb(-7i32).div_mod_floor(&2), (-4, 1));
    check!(bb(6u8).is_even() && bb(7u8).is_odd() && Integer::is_multiple_of(&bb(9u8), &3));
    check_eq!(Integer::next_multiple_of(&bb(13u32), &5), 15);
    check_eq!(bb(13u32).prev_multiple_of(&5), 10);
    check_eq!(num_integer::average_floor(bb(u8::MAX), 253), 254);
});

test!(num_integer_roots_binomial, {
    check_eq!(bb(99u32).sqrt(), 9);
    check_eq!(bb(100u64).sqrt(), 10);
    check_eq!(bb(u64::MAX).sqrt(), 0xffff_ffff);
    check_eq!(bb(1000u32).cbrt(), 10);
    check_eq!(bb(-27i32).cbrt(), -3);
    check_eq!(bb(1024u32).nth_root(5), 4);
    check_eq!(bb(1u128 << 100).sqrt(), 1 << 50);
    check_eq!(num_integer::binomial(bb(10u64), 3), 120);
    check_eq!(num_integer::binomial(bb(50u64), 25), 126410606437752);
    check_eq!(num_integer::multinomial(bb(&[2u32, 3, 4])), 1260);
    check_eq!(num_integer::IterBinomial::new(bb(5u32)).sum::<u32>(), 32);
});
