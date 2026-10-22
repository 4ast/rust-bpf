// SPDX-License-Identifier: GPL-2.0
//! core: what the other files left out.
#![no_std]
#![no_main]
#![feature(portable_simd)]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::error::Error;
use core::fmt;
use core::ops::{Bound, ControlFlow, RangeBounds};
use core::time::Duration;
use rt::{bb, check, check_eq, test};

test!(misc_duration, {
    let d = Duration::new(bb(5), 500_000_000);
    check_eq!(d.as_millis(), 5500);
    check_eq!(d.as_secs(), 5);
    check_eq!(d.subsec_micros(), 500_000);
    check_eq!(d + Duration::from_millis(600), Duration::new(6, 100_000_000));
    check_eq!(d * 3, Duration::from_millis(16500));
    check_eq!(d / 2, Duration::from_micros(2_750_000));
    check_eq!(d.checked_sub(Duration::from_secs(6)), None);
    check_eq!(d.saturating_sub(Duration::from_secs(6)), Duration::ZERO);
    check_eq!(Duration::from_nanos(bb(1_000_000_001)).as_nanos(), 1_000_000_001);
    check!(Duration::from_secs(1) < Duration::from_millis(1001));
    check_eq!(d.as_secs_f64(), 5.5);
    check_eq!(Duration::from_secs_f32(bb(0.25)), Duration::from_millis(250));
    check_eq!([d, d].iter().sum::<Duration>(), Duration::from_secs(11));
});

test!(misc_control_flow_bounds, {
    let r = bb([1, 2, 30, 4]).iter().try_for_each(|&x| if x > 10 { ControlFlow::Break(x) } else { ControlFlow::Continue(()) });
    check_eq!(r, ControlFlow::Break(30));
    check!(r.is_break());
    check_eq!(r.break_value(), Some(30));
    fn width(r: impl RangeBounds<u32>) -> Option<u32> {
        let lo = match r.start_bound() {
            Bound::Included(&x) => x,
            Bound::Excluded(&x) => x + 1,
            Bound::Unbounded => 0,
        };
        match r.end_bound() {
            Bound::Included(&x) => Some(x + 1 - lo),
            Bound::Excluded(&x) => Some(x - lo),
            Bound::Unbounded => None,
        }
    }
    check_eq!(width(bb(2)..5), Some(3));
    check_eq!(width(bb(2)..=5), Some(4));
    check_eq!(width(..bb(5)), Some(5));
    check_eq!(width(bb(2)..), None);
    check!((bb(1)..5).contains(&4) && !(..=bb(3)).contains(&4));
});

#[derive(Debug)]
struct Low(u8);
#[derive(Debug)]
enum High {
    FromLow(Low),
    Parse(core::num::ParseIntError),
}
impl fmt::Display for Low {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "low {}", self.0)
    }
}
impl fmt::Display for High {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("high")
    }
}
impl Error for Low {}
impl Error for High {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            High::FromLow(l) => Some(l),
            High::Parse(p) => Some(p),
        }
    }
}
impl From<Low> for High {
    fn from(l: Low) -> High {
        High::FromLow(l)
    }
}
impl From<core::num::ParseIntError> for High {
    fn from(p: core::num::ParseIntError) -> High {
        High::Parse(p)
    }
}
fn low(v: u8) -> Result<u8, Low> {
    if v < 10 { Ok(v) } else { Err(Low(v)) }
}
fn high(s: &str) -> Result<u8, High> {
    Ok(low(s.parse()?)? + 1)
}
fn boxed(s: &str) -> Result<u8, Box<dyn Error>> {
    if s.is_empty() {
        return Err("empty".into());
    }
    Ok(high(s)?)
}

test!(misc_error_trait, {
    check_eq!(high(bb("5")).ok(), Some(6));
    let e = high(bb("50")).unwrap_err();
    check!(matches!(e, High::FromLow(Low(50))));
    check_eq!(e.source().map(|s| s.to_string()), Some(String::from("low 50")));
    check!(matches!(high(bb("x")), Err(High::Parse(_))));
    check_eq!(boxed(bb("")).unwrap_err().to_string(), "empty");
    let b = boxed(bb("99")).unwrap_err();
    check_eq!(b.to_string(), "high");
    check!(b.downcast_ref::<High>().is_some() && b.downcast_ref::<Low>().is_none());
    check!(b.source().is_some_and(|s| s.is::<Low>()));
});

trait Base {
    fn id(&self) -> u32;
}
trait Derived: Base {
    fn twice(&self) -> u32 {
        self.id() * 2
    }
}
struct T(u32);
impl Base for T {
    fn id(&self) -> u32 {
        self.0
    }
}
impl Derived for T {}
trait Assoc {
    type Out: Default + core::ops::Add<Output = Self::Out> + From<u8>;
    const K: u8;
    fn get(&self) -> Self::Out {
        Self::Out::default() + Self::Out::from(Self::K)
    }
}
impl Assoc for T {
    type Out = u64;
    const K: u8 = 9;
}
fn hrtb<F: for<'a> Fn(&'a [u8]) -> &'a u8>(f: F, v: &[u8]) -> u8 {
    *f(v)
}

test!(misc_traits, {
    let d: &dyn Derived = bb(&T(21));
    check_eq!(d.twice(), 42);
    let b: &dyn Base = d;
    check_eq!(b.id(), 21);
    let bx: Box<dyn Derived> = Box::new(T(bb(4)));
    let up: Box<dyn Base> = bx;
    check_eq!(up.id(), 4);
    check_eq!(T(0).get(), 9u64);
    check_eq!(hrtb(|s| &s[1], bb(&[1, 2, 3])), 2);
    fn gen_sum<I>(it: I) -> I::Item
    where
        I: IntoIterator,
        I::Item: core::iter::Sum<I::Item>,
    {
        it.into_iter().sum()
    }
    check_eq!(gen_sum(bb([1u8, 2, 3])), 6);
    check_eq!(gen_sum(alloc::vec![bb(1.5f64), 2.5]), 4.0);
});

test!(misc_let_else_if_let_chains, {
    fn first_digit(s: &str) -> u32 {
        let Some(c) = s.chars().find(|c| c.is_ascii_digit()) else {
            return 99;
        };
        c.to_digit(10).unwrap_or(98)
    }
    check_eq!(first_digit(bb("ab7c")), 7);
    check_eq!(first_digit(bb("abc")), 99);
    let v = bb(Some(5));
    let r = if let Some(x) = v
        && x > 3
    {
        x * 2
    } else {
        0
    };
    check_eq!(r, 10);
    let t = bb((1, (2, [3, 4])));
    let (a, (b, [c, d])) = t;
    check_eq!(a + b + c + d, 10);
    let n @ 1..=9 = bb(5) else { return 1 };
    check_eq!(n, 5);
});

test!(misc_simd, {
    use core::simd::Select;
    use core::simd::prelude::*;
    let a = u32x4::from_array(bb([1, 2, 3, 4]));
    let b = u32x4::splat(bb(10));
    check_eq!((a + b).to_array(), [11, 12, 13, 14]);
    check_eq!((a * a).reduce_sum(), 30);
    check_eq!((a * b).reduce_max(), 40);
    check_eq!(a.simd_gt(u32x4::splat(2)).to_bitmask(), 0b1100);
    check_eq!(a.simd_max(u32x4::splat(3)).to_array(), [3, 3, 3, 4]);
    check_eq!(a.reverse().to_array(), [4, 3, 2, 1]);
    check_eq!(a.rotate_elements_left::<1>().to_array(), [2, 3, 4, 1]);
    let m = a.simd_lt(u32x4::splat(3));
    check_eq!(m.select(a, b).to_array(), [1, 2, 10, 10]);
    let w = u8x16::from_array(bb([7; 16]));
    check_eq!(w.cast::<u16>().reduce_sum(), 112);
    let f = f32x4::from_array(bb([1.0, 2.0, 3.0, 4.0]));
    check_eq!((f * f32x4::splat(0.5)).reduce_sum(), 5.0);
});

#[cfg(target_arch = "bpf")]
fn asm_add(a: u64, b: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("{0} = {1}", "{0} += {2}", out(reg) r, in(reg) a, in(reg) b) };
    r
}
#[cfg(not(target_arch = "bpf"))]
fn asm_add(a: u64, b: u64) -> u64 {
    a + b
}

test!(misc_inline_asm, {
    check_eq!(asm_add(bb(40), bb(2)), 42);
});

static mut TABLE: [fn(u32) -> u32; 3] = [|x| x + 1, |x| x * 2, |x| x * x];
static NAMES: &[(&str, &[u8])] = &[("a", &[1]), ("bc", &[2, 3]), ("def", &[4, 5, 6])];
static BIG: [u16; 4096] = {
    let mut t = [0u16; 4096];
    let mut i = 0;
    while i < 4096 {
        t[i] = (i * 7 % 4099) as u16;
        i += 1;
    }
    t
};

#[allow(static_mut_refs)]
test!(misc_statics, {
    let t = unsafe { TABLE };
    check_eq!(t[bb(0usize)](5) + t[bb(1usize)](5) + t[bb(2usize)](5), 41);
    unsafe { TABLE[bb(0usize)] = |x| x + 100 };
    check_eq!(unsafe { TABLE[bb(0usize)] }(5), 105);
    unsafe { TABLE[0] = |x| x + 1 };
    check_eq!(bb(NAMES).iter().map(|(n, b)| n.len() + b.len()).sum::<usize>(), 12);
    check_eq!(NAMES[bb(2usize)].1[2], 6);
    check_eq!(BIG[bb(4095usize)], (4095 * 7 % 4099) as u16);
    check_eq!(bb(&BIG).iter().map(|&x| x as u64).sum::<u64>(), (0..4096u64).map(|i| i * 7 % 4099).sum::<u64>());
});

test!(misc_convert, {
    fn len<T: AsRef<[u8]>>(t: T) -> usize {
        t.as_ref().len()
    }
    check_eq!(len(bb("abc")) + len(bb([1u8, 2])) + len(String::from("x")) + len(alloc::vec![1u8]), 7);
    let mut a = bb([3u8, 1, 2]);
    fn sort<T: AsMut<[u8]>>(mut t: T) {
        t.as_mut().sort_unstable();
    }
    sort(&mut a);
    check_eq!(a, [1, 2, 3]);
    check_eq!(i64::from(bb(-5i32)) + i64::from(bb(5u32)), 0);
    check_eq!(u16::try_from(bb(70000u32)).is_err(), true);
    check_eq!(char::from(bb(65u8)), 'A');
    check_eq!(u32::from(bb('A')), 65);
    check_eq!(<[u8; 2]>::try_from(bb(&[1u8, 2][..])).ok(), Some([1, 2]));
    check!(<[u8; 2]>::try_from(bb(&[1u8][..])).is_err());
    let s: Box<str> = bb("boxed").into();
    let st: String = s.into();
    check_eq!(st, "boxed");
    check_eq!(core::convert::identity(bb(7)), 7);
    check!(char::decode_utf16(bb([0x68, 0xd83e, 0xdd80])).map(|r| r.unwrap_or('?')).eq(['h', '🦀']));
});
