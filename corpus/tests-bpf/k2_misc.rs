// SPDX-License-Identifier: GPL-2.0
//! crates: thiserror, anyhow, futures-util, libm, fixed, minicbor, strum, num_enum, glam, num-bigint, num-rational
#![no_std]
#![no_main]
extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::error::Error;
use rt::{bb, check, check_eq, test};

#[derive(thiserror::Error, Debug)]
enum ConfigError {
    #[error("missing key {0}")]
    Missing(&'static str),
    #[error("bad value for {key}: {source}")]
    Bad {
        key: &'static str,
        #[source]
        source: core::num::ParseIntError,
    },
    #[error(transparent)]
    Utf8(#[from] core::str::Utf8Error),
}
fn port(s: Option<&[u8]>) -> Result<u16, ConfigError> {
    let s = core::str::from_utf8(s.ok_or(ConfigError::Missing("port"))?)?;
    s.parse().map_err(|source| ConfigError::Bad { key: "port", source })
}

test!(thiserror_derive, {
    check_eq!(port(bb(Some(&b"8080"[..]))).ok(), Some(8080));
    let e = port(bb(None)).unwrap_err();
    check_eq!(e.to_string(), "missing key port");
    check!(e.source().is_none());
    let e = port(bb(Some(&b"80x"[..]))).unwrap_err();
    check_eq!(e.to_string(), "bad value for port: invalid digit found in string");
    check!(e.source().is_some_and(|s| s.is::<core::num::ParseIntError>()));
    let e = port(bb(Some(&b"\xff"[..]))).unwrap_err();
    check!(matches!(e, ConfigError::Utf8(_)));
});

fn step(n: i32) -> anyhow::Result<i32> {
    anyhow::ensure!(n >= 0, "negative: {n}");
    if n > 100 {
        anyhow::bail!("too big");
    }
    Ok(n * 2)
}
fn outer(s: &str) -> anyhow::Result<i32> {
    use anyhow::Context;
    let n: i32 = s.parse().context("not a number")?;
    step(n).with_context(|| format!("step({n}) failed"))
}

test!(anyhow_chain, {
    check_eq!(outer(bb("21")).ok(), Some(42));
    let e = outer(bb("x")).unwrap_err();
    check_eq!(e.to_string(), "not a number");
    check_eq!(e.chain().count(), 2);
    check!(e.downcast_ref::<core::num::ParseIntError>().is_some());
    let e = outer(bb("-1")).unwrap_err();
    check_eq!(format!("{e:#}"), "step(-1) failed: negative: -1");
    check_eq!(e.root_cause().to_string(), "negative: -1");
    check_eq!(outer(bb("101")).unwrap_err().root_cause().to_string(), "too big");
    let b: alloc::boxed::Box<dyn Error + Send + Sync> = anyhow::anyhow!("boxed {}", bb(1)).into();
    check_eq!(b.to_string(), "boxed 1");
});

fn block_on<F: core::future::Future>(f: F) -> F::Output {
    let mut f = core::pin::pin!(f);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    loop {
        if let core::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

test!(futures_combinators, {
    use futures_util::future::{self, FutureExt, TryFutureExt};
    use futures_util::stream::{self, StreamExt};
    check_eq!(block_on(future::ready(bb(1)).map(|x| x + 1)), 2);
    check_eq!(block_on(future::join(future::ready(bb(1)), async { 2 })), (1, 2));
    check_eq!(block_on(future::join_all((0..bb(4)).map(|i| async move { i * i }))), [0, 1, 4, 9]);
    check_eq!(block_on(future::ok::<u8, u8>(bb(1)).and_then(|x| future::ok(x + 1))), Ok(2));
    check_eq!(block_on(future::try_join(future::ok::<u8, u8>(1), future::err::<u8, u8>(bb(9)))), Err(9));
    check_eq!(block_on(stream::iter(1..=bb(5)).map(|x| x * 2).filter(|x| future::ready(x % 4 != 0)).collect::<Vec<u32>>()), [2, 6, 10]);
    check_eq!(block_on(stream::iter(1..=bb(4u32)).fold(0, |a, x| async move { a + x })), 10);
    check_eq!(block_on(stream::unfold(bb(1u32), |s| async move { if s < 50 { Some((s, s * 3)) } else { None } }).count()), 4);
    check_eq!(block_on(stream::iter(0..bb(6)).chunks(4).map(|c| c.len()).collect::<Vec<_>>()), [4, 2]);
    let e = block_on(future::select(future::pending::<u8>(), future::ready(bb(3))));
    check!(matches!(e, future::Either::Right((3, _))));
    check_eq!(block_on(stream::iter((0..bb(3u32)).map(|i| async move { i + 1 })).buffered(2).collect::<Vec<_>>()), [1, 2, 3]);
});

test!(libm_functions, {
    check_eq!(libm::sqrt(bb(2.25)), 1.5);
    check_eq!(libm::floor(bb(-2.5)), -3.0);
    check_eq!(libm::pow(bb(2.0), bb(0.5)), core::f64::consts::SQRT_2);
    check!((libm::sin(bb(core::f64::consts::FRAC_PI_6)) - 0.5).abs() < 1e-15);
    check!((libm::cos(bb(core::f64::consts::PI)) + 1.0).abs() < 1e-15);
    check!((libm::atan2(bb(1.0), bb(1.0)) - core::f64::consts::FRAC_PI_4).abs() < 1e-15);
    check!((libm::exp(bb(1.0)) - core::f64::consts::E).abs() < 1e-15);
    check!((libm::log2(bb(1024.0)) - 10.0).abs() < 1e-12);
    check_eq!(libm::hypot(bb(3.0), bb(4.0)), 5.0);
    check_eq!(libm::fmod(bb(7.5), bb(2.0)), 1.5);
    check_eq!(libm::cbrtf(bb(27.0f32)), 3.0);
    check_eq!(libm::roundf(bb(2.5f32)), 3.0);
    check!((libm::tanh(bb(0.5)) - 0.46211715726000974).abs() < 1e-15);
});

test!(fixed_point, {
    use fixed::types::{I16F16, U8F8};
    let a = I16F16::from_num(bb(3.25));
    let b = I16F16::from_num(bb(-1.5));
    check_eq!(a + b, I16F16::from_num(1.75));
    check_eq!(a * b, I16F16::from_num(-4.875));
    check!((a / b - I16F16::from_num(-3.25 / 1.5)).abs() <= I16F16::DELTA);
    check_eq!(a.to_bits(), 0x34000);
    check_eq!(a.int().to_num::<i32>(), 3);
    check_eq!(a.frac(), I16F16::from_num(0.25));
    check_eq!(b.abs().ceil().to_num::<i32>(), 2);
    check_eq!(U8F8::from_num(bb(255)).checked_add(U8F8::from_num(1)), None);
    check_eq!(U8F8::from_num(bb(255)).saturating_add(U8F8::from_num(1)), U8F8::MAX);
    check_eq!(format!("{}", a), "3.25");
    check_eq!(bb("2.5").parse::<I16F16>().ok(), Some(I16F16::from_num(2.5)));
});

#[derive(minicbor::Encode, minicbor::Decode, Debug, PartialEq)]
struct Rec {
    #[n(0)]
    id: u32,
    #[n(1)]
    name: String,
    #[n(2)]
    vals: Vec<i16>,
    #[n(3)]
    opt: Option<bool>,
}

test!(minicbor_round_trip, {
    check_eq!(minicbor::to_vec(bb(10u8)).unwrap(), [0x0a]);
    check_eq!(minicbor::to_vec(bb(500u32)).unwrap(), [0x19, 0x01, 0xf4]);
    check_eq!(minicbor::to_vec(bb(-1i8)).unwrap(), [0x20]);
    check_eq!(minicbor::to_vec(bb("a")).unwrap(), [0x61, 0x61]);
    let r = Rec { id: bb(7), name: "n".to_string(), vals: alloc::vec![1, -2, 300], opt: Some(true) };
    let b = minicbor::to_vec(&r).unwrap();
    check_eq!(minicbor::decode::<Rec>(&b).ok(), Some(r));
    check!(minicbor::decode::<Rec>(&b[..b.len() - 1]).is_err());
    check!(minicbor::decode::<u8>(bb(&[0x19, 0x01, 0xf4])).is_err());
});

#[derive(strum::Display, strum::EnumString, strum::EnumIter, strum::EnumCount, strum::IntoStaticStr, strum::FromRepr, Debug, PartialEq, Clone, Copy)]
enum Color {
    Red,
    #[strum(serialize = "verde", to_string = "green")]
    Green,
    Blue,
}
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
enum Op {
    Nop = 0,
    Load = 0x10,
    Store = 0x20,
}

test!(strum_num_enum, {
    use core::str::FromStr;
    use strum::{EnumCount, IntoEnumIterator};
    check_eq!(bb(Color::Red).to_string(), "Red");
    check_eq!(bb(Color::Green).to_string(), "green");
    check_eq!(Color::from_str(bb("Blue")), Ok(Color::Blue));
    check_eq!(Color::from_str(bb("verde")), Ok(Color::Green));
    check!(Color::from_str(bb("pink")).is_err());
    check_eq!(Color::iter().collect::<Vec<_>>(), [Color::Red, Color::Green, Color::Blue]);
    check_eq!(Color::COUNT, 3);
    check_eq!(<&'static str>::from(bb(Color::Blue)), "Blue");
    check_eq!(Color::from_repr(bb(1)), Some(Color::Green));
    check_eq!(Color::from_repr(bb(3)), None);
    check_eq!(Op::try_from(bb(0x10u8)).ok(), Some(Op::Load));
    check!(Op::try_from(bb(0x11u8)).is_err());
    check_eq!(u8::from(bb(Op::Store)), 0x20);
    check_eq!(Op::try_from(bb(0u8)).ok(), Some(Op::Nop));
});

test!(glam_vectors, {
    use glam::{Mat3, Mat4, Quat, Vec2, Vec3};
    let a = bb(Vec3::new(1.0, 2.0, 3.0));
    let b = bb(Vec3::new(4.0, 5.0, 6.0));
    check_eq!(a + b, Vec3::new(5.0, 7.0, 9.0));
    check_eq!(a.dot(b), 32.0);
    check_eq!(a.cross(b), Vec3::new(-3.0, 6.0, -3.0));
    check_eq!(bb(Vec2::new(3.0, 4.0)).length(), 5.0);
    check!((bb(Vec3::new(0.0, 3.0, 4.0)).normalize() - Vec3::new(0.0, 0.6, 0.8)).length() < 1e-6);
    check_eq!(Mat3::from_diagonal(bb(Vec3::new(1.0, 2.0, 3.0))) * a, Vec3::new(1.0, 4.0, 9.0));
    check_eq!(Mat4::from_translation(b).transform_point3(a), Vec3::new(5.0, 7.0, 9.0));
    check_eq!(Mat3::from_diagonal(bb(Vec3::new(2.0, 2.0, 2.0))).determinant(), 8.0);
    let q = Quat::from_rotation_z(bb(core::f32::consts::FRAC_PI_2));
    check!((q * Vec3::X - Vec3::Y).length() < 1e-6);
    check_eq!(bb(Vec2::new(3.0, -4.0)).abs().max_element(), 4.0);
    check_eq!(a.lerp(b, 0.5), Vec3::new(2.5, 3.5, 4.5));
});

test!(num_bigint_rational, {
    use num_bigint::{BigInt, BigUint};
    use num_rational::Ratio;
    let f: BigUint = (1..=bb(30u32)).map(BigUint::from).product();
    check_eq!(f.to_string(), "265252859812191058636308480000000");
    check_eq!(f.bits(), 108);
    check_eq!((&f / BigUint::from(1u64 << 26)).to_string(), "3952575621190533915703125");
    check_eq!((&f % BigUint::from(1_000_003u32)).to_string(), "90317");
    let p = BigUint::from(bb(2u32)).pow(200);
    check_eq!(p.to_str_radix(16).len(), 51);
    check_eq!(BigUint::from(bb(3u32)).modpow(&BigUint::from(1000u32), &BigUint::from(1_000_007u32)).to_string(), "297623");
    let n: BigInt = bb("-123456789012345678901234567890").parse().unwrap();
    check_eq!((&n * &n).to_string(), "15241578753238836750495351562536198787501905199875019052100");
    check!(n < BigInt::from(0));
    check_eq!(p.sqrt(), BigUint::from(2u32).pow(100));
    let r = Ratio::new(bb(6i64), 8) + Ratio::new(1, 6);
    check_eq!(r, Ratio::new(11, 12));
    check_eq!((r * Ratio::new(12, 11)).to_integer(), 1);
    check_eq!(format!("{}", Ratio::new(bb(-4i32), 6)), "-2/3");
    check!(Ratio::new(bb(1i32), 3) < Ratio::new(1, 2));
});
