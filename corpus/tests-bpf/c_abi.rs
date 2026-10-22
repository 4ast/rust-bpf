// SPDX-License-Identifier: GPL-2.0
//! How values get in and out of functions: many arguments, wide ones, aggregates.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::format;
use rt::{bb, check, check_eq, test};

#[inline(never)]
fn args6(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6
}
#[inline(never)]
fn args8(a: u8, b: i16, c: u32, d: i64, e: u8, f: i16, g: u32, h: i64) -> i64 {
    a as i64 - b as i64 + c as i64 - d + e as i64 - f as i64 + g as i64 - h
}
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn args12(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64) -> u64 {
    a ^ b << 1 ^ c << 2 ^ d << 3 ^ e << 4 ^ f << 5 ^ g << 6 ^ h << 7 ^ i << 8 ^ j << 9 ^ k << 10 ^ l << 11
}

test!(abi_many_args, {
    check_eq!(args6(bb(1), 2, 3, 4, 5, bb(6)), 91);
    check_eq!(args8(bb(1), -2, 3, -4, 5, -6, 7, bb(-8)), 36);
    check_eq!(args12(bb(1), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, bb(1)), 0xfff);
});

#[inline(never)]
fn wide(a: u128, b: u8, c: i128, d: u64) -> i128 {
    (a >> 64) as i128 + b as i128 + c + d as i128
}
#[inline(never)]
fn wide3(a: u128, b: u128, c: u128) -> u128 {
    a + (b << 1) + (c << 2)
}

test!(abi_u128_args, {
    check_eq!(wide(bb(5u128 << 64), 1, bb(-10), 100), 96);
    check_eq!(wide3(bb(1u128 << 100), bb(1), bb(1u128 << 64)), (1 << 100) + 2 + (1 << 66));
});

#[inline(never)]
fn pair(a: u64) -> (u64, u64) {
    (a + 1, a * 2)
}
#[inline(never)]
fn triple(a: u64) -> (u64, u64, u64) {
    (a, a + 1, a + 2)
}
#[inline(never)]
fn mixed(a: u8) -> (u8, u64, bool, char) {
    (a, a as u64 * 1000, a > 5, (b'a' + a) as char)
}
#[inline(never)]
fn opt64(a: u64) -> Option<u64> {
    if a > 5 { Some(a) } else { None }
}
#[inline(never)]
fn opt128(a: u64) -> Option<u128> {
    if a > 5 { Some((a as u128) << 64) } else { None }
}
#[inline(never)]
fn res(a: i32) -> Result<[u8; 32], (i32, &'static str)> {
    if a >= 0 { Ok([a as u8; 32]) } else { Err((a, "negative")) }
}
#[inline(never)]
fn slice_of(v: &[u32], n: usize) -> &[u32] {
    &v[n..]
}
#[inline(never)]
fn text(n: u8) -> &'static str {
    match n {
        0 => "zero",
        1 => "one",
        _ => "many",
    }
}

test!(abi_returns, {
    check_eq!(pair(bb(10)), (11, 20));
    check_eq!(triple(bb(10)), (10, 11, 12));
    check_eq!(mixed(bb(7)), (7, 7000, true, 'h'));
    check_eq!(opt64(bb(6)), Some(6));
    check_eq!(opt64(bb(5)), None);
    check_eq!(opt128(bb(6)), Some(6u128 << 64));
    check_eq!(opt128(bb(1)), None);
    check_eq!(res(bb(3)).map(|a| a[31]), Ok(3));
    check_eq!(res(bb(-3)).map(|a| a[0]), Err((-3, "negative")));
    check_eq!(slice_of(bb(&[1, 2, 3, 4]), bb(2)), &[3, 4]);
    check_eq!(text(bb(1)), "one");
    check_eq!(text(bb(9)).len(), 4);
});

#[derive(Clone, Copy, PartialEq, Debug)]
struct S8(u64);
#[derive(Clone, Copy, PartialEq, Debug)]
struct S16 {
    a: u64,
    b: u32,
    c: u16,
}
#[derive(Clone, Copy, PartialEq, Debug)]
struct S24 {
    a: u64,
    b: u64,
    c: u64,
}
#[derive(Clone, Copy, PartialEq, Debug)]
struct Small(u8, u8, u8);

#[inline(never)]
fn s8(s: S8) -> S8 {
    S8(s.0 + 1)
}
#[inline(never)]
fn s16(s: S16, k: u64) -> S16 {
    S16 { a: s.a + k, b: s.b + 1, c: s.c + 2 }
}
#[inline(never)]
fn s24(s: S24, t: S24) -> S24 {
    S24 { a: s.a + t.c, b: s.b + t.b, c: s.c + t.a }
}
#[inline(never)]
fn small(s: Small) -> Small {
    Small(s.2, s.1, s.0)
}
#[inline(never)]
fn zst(_: (), a: u32, _: [u8; 0], b: u32, _: core::marker::PhantomData<u64>) -> u32 {
    a * b
}

test!(abi_structs_by_value, {
    check_eq!(s8(bb(S8(1))), S8(2));
    check_eq!(s16(bb(S16 { a: 1, b: 2, c: 3 }), bb(10)), S16 { a: 11, b: 3, c: 5 });
    check_eq!(s24(bb(S24 { a: 1, b: 2, c: 3 }), bb(S24 { a: 10, b: 20, c: 30 })), S24 { a: 31, b: 22, c: 13 });
    check_eq!(small(bb(Small(1, 2, 3))), Small(3, 2, 1));
    check_eq!(zst((), bb(6), [], bb(7), core::marker::PhantomData), 42);
});

#[inline(never)]
extern "C" fn c_abi(a: u32, b: i8, p: *const u64, s: S8) -> i64 {
    a as i64 + b as i64 + unsafe { *p } as i64 + s.0 as i64
}
#[inline(never)]
extern "C" fn c_abi_big(s: S24) -> S24 {
    S24 { a: s.c, b: s.b, c: s.a }
}
#[inline(never)]
extern "C" fn c_abi_u128(a: u128, b: u128) -> u128 {
    a * 2 + b
}

test!(abi_extern_c, {
    let v = bb(100u64);
    check_eq!(c_abi(bb(1), -2, &v, S8(1000)), 1099);
    check_eq!(c_abi_big(bb(S24 { a: 1, b: 2, c: 3 })), S24 { a: 3, b: 2, c: 1 });
    check_eq!(c_abi_u128(bb(1u128 << 70), bb(5)), (1u128 << 71) + 5);
    let f: extern "C" fn(S24) -> S24 = bb(c_abi_big);
    check_eq!(f(S24 { a: 7, b: 8, c: 9 }).a, 9);
});

#[inline(never)]
fn through_ptrs(f: fn(u64, u64, u64, u64, u64, u64) -> u64, g: fn(u64) -> (u64, u64, u64)) -> u64 {
    let t = g(1);
    f(t.0, t.1, t.2, t.0, t.1, t.2)
}
trait Wide {
    fn call(&self, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> (u64, u128);
}
struct W(u64);
impl Wide for W {
    fn call(&self, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> (u64, u128) {
        (self.0 + a + b + c, (d + e + f) as u128)
    }
}

test!(abi_indirect_calls, {
    check_eq!(through_ptrs(bb(args6), bb(triple)), 1 + 4 + 9 + 4 + 10 + 18);
    let w: &dyn Wide = bb(&W(100));
    check_eq!(w.call(1, 2, 3, 4, 5, bb(6)), (106, 15));
});

#[inline(never)]
fn make_adder(k: u64) -> impl Fn(u64) -> u64 {
    move |x| x + k
}
#[inline(never)]
fn make_big_closure(a: [u64; 8]) -> impl Fn(usize) -> u64 {
    move |i| a[i] * 2
}
#[inline(never)]
fn apply<F: FnOnce([u64; 8]) -> [u64; 8]>(f: F, v: [u64; 8]) -> [u64; 8] {
    f(v)
}

test!(abi_closures_by_value, {
    check_eq!(make_adder(bb(5))(10), 15);
    check_eq!(make_big_closure(bb([1, 2, 3, 4, 5, 6, 7, 8]))(bb(7)), 16);
    let k = bb(3);
    let r = apply(|mut v| { v[0] += k; v }, bb([1; 8]));
    check!(r[0] == 4 && r[7] == 1);
});

// More than 12 registers: the kernel has 5 registers and 7 slots for arguments.
// The rest goes through the frame of the caller.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn args16(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64, n: u64, o: u64, p: u64) -> u64 {
    a + b * 3 + c * 5 + d * 7 + e * 11 + f * 13 + g * 17 + h * 19 + i * 23 + j * 29 + k * 31 + l * 37 + m * 41 + n * 43 + o * 47 + p * 53
}

test!(abi_sixteen_args, {
    check_eq!(args16(bb(1), bb(2), bb(3), bb(4), bb(5), bb(6), bb(7), bb(8), bb(9), bb(10), bb(11), bb(12), bb(13), bb(14), bb(15), bb(16)), 4424);
    check_eq!(args16(bb(16), bb(15), bb(14), bb(13), bb(12), bb(11), bb(10), bb(9), bb(8), bb(7), bb(6), bb(5), bb(4), bb(3), bb(2), bb(1)), 2036);
});

// The halves of w: the last slot and the frame.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn split(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64, a11: u64, w: u128, t: u32, s: &str) -> u128 {
    let unused = a2 ^ a3 ^ a4 ^ a5 ^ a6 ^ a7 ^ a8 ^ a9 ^ a10;
    (w ^ (a1 + a11 + unused) as u128) + ((t as u128) << 100) + s.len() as u128 + s.as_bytes()[1] as u128
}

test!(abi_wide_arg_across_the_limit, {
    let w = bb(0x0123456789abcdef_fedcba9876543210u128);
    let r = split(bb(5), bb(1), bb(1), bb(2), bb(2), bb(3), bb(3), bb(4), bb(4), bb(0), bb(9), w, bb(7), bb("hey"));
    check_eq!(r, 0x12345d789abcdeffedcba9876543286u128);
});

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn rot14(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64) -> u64 {
    if n == 0 {
        return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8 + i * 9 + j * 10 + k * 11 + l * 12 + m * 13;
    }
    // bb: or it becomes a loop
    bb(rot14(n - 1, b, c, d, e, f, g, h, i, j, k, l, m, a)) + n
}

test!(abi_many_args_recursion, {
    check_eq!(rot14(bb(0), bb(101), bb(102), bb(103), bb(104), bb(105), bb(106), bb(107), bb(108), bb(109), bb(110), bb(111), bb(112), bb(113)), 9919);
    check_eq!(rot14(bb(5), bb(101), bb(102), bb(103), bb(104), bb(105), bb(106), bb(107), bb(108), bb(109), bb(110), bb(111), bb(112), bb(113)), 9674);
});

trait Many {
    fn call(&self, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64) -> u64;
}
struct Sum(u64);
struct Alt(u64);
impl Many for Sum {
    #[inline(never)]
    fn call(&self, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64) -> u64 {
        self.0 + a + b + c + d + e + f + g + h + i + j + k + l + m
    }
}
impl Many for Alt {
    #[inline(never)]
    fn call(&self, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64) -> u64 {
        self.0 + a - b + c - d + e - f + g - h + i - j + k - l + m
    }
}

test!(abi_many_args_dyn, {
    let (s, a) = (Sum(bb(1)), Alt(bb(2)));
    let v: [&dyn Many; 2] = [&s, &a];
    let want = [92, 9];
    for n in 0..2 {
        check_eq!(v[bb(n)].call(bb(1), bb(2), bb(3), bb(4), bb(5), bb(6), bb(7), bb(8), bb(9), bb(10), bb(11), bb(12), bb(13)), want[n]);
    }
});

#[inline(never)]
fn fill(buf: &mut [u64; 64], from: u64) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = from + i as u64;
    }
}
// A frame of its own, a call with arguments in it, and the arguments are read after that.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn framed(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64, m: u64, n: u64) -> u64 {
    let mut buf = [0u64; 64];
    fill(&mut buf, a);
    let x = args16(a, b, c, d, e, f, g, h, i, j, k, l, m, n, buf[3], buf[5]);
    x + m * 1000 + n * 100000 + buf[63]
}

test!(abi_many_args_and_a_frame, {
    check_eq!(framed(bb(1), bb(2), bb(3), bb(4), bb(5), bb(6), bb(7), bb(8), bb(9), bb(10), bb(11), bb(12), bb(13), bb(14)), 1416441);
});

// What derive(Debug) calls: 3 + 4 registers per field of a struct, 3 + 2 per field of a tuple.
#[derive(Debug)]
#[allow(dead_code)]
struct D3 { a: u32, b: &'static str, c: bool }
#[derive(Debug)]
#[allow(dead_code)]
struct D4 { a: u8, b: i64, c: char, d: Option<u8> }
#[derive(Debug)]
#[allow(dead_code)]
struct D5 { a: u8, b: u16, c: u32, d: u64, e: i8 }
#[derive(Debug)]
#[allow(dead_code)]
struct T5(u8, i8, bool, char, &'static str);
// The helpers are inlined when there is one user.
macro_rules! more {
    ($($n:ident { $($f:ident),* })*) => { $(
        #[derive(Debug)]
        #[allow(dead_code)]
        struct $n { $($f: u32),* }
    )* };
}
more! {
    M3a { x, y, z } M3b { x, y, z } M3c { x, y, z }
    M4a { x, y, z, w } M4b { x, y, z, w } M4c { x, y, z, w }
    M5a { x, y, z, w, v } M5b { x, y, z, w, v } M5c { x, y, z, w, v }
}

test!(abi_derive_debug, {
    check_eq!(format!("{:?}", bb(D3 { a: 7, b: "x", c: true })), "D3 { a: 7, b: \"x\", c: true }");
    check_eq!(format!("{:?}", bb(D4 { a: 1, b: -2, c: 'z', d: Some(4) })), "D4 { a: 1, b: -2, c: 'z', d: Some(4) }");
    check_eq!(format!("{:?}", bb(D5 { a: 1, b: 2, c: 3, d: 4, e: -5 })), "D5 { a: 1, b: 2, c: 3, d: 4, e: -5 }");
    check_eq!(format!("{:?}", bb(T5(1, -1, false, 'q', "s"))), "T5(1, -1, false, 'q', \"s\")");
    check_eq!(format!("{:#?}", bb(D3 { a: 7, b: "x", c: true })), "D3 {\n    a: 7,\n    b: \"x\",\n    c: true,\n}");
    check_eq!(format!("{:?}", bb(M3a { x: 1, y: 2, z: 3 })), "M3a { x: 1, y: 2, z: 3 }");
    check_eq!(format!("{:?}", bb(M3b { x: 4, y: 5, z: 6 })), "M3b { x: 4, y: 5, z: 6 }");
    check_eq!(format!("{:?}", bb(M3c { x: 7, y: 8, z: 9 })), "M3c { x: 7, y: 8, z: 9 }");
    check_eq!(format!("{:?}", bb(M4a { x: 1, y: 2, z: 3, w: 4 })), "M4a { x: 1, y: 2, z: 3, w: 4 }");
    check_eq!(format!("{:?}", bb(M4b { x: 5, y: 6, z: 7, w: 8 })), "M4b { x: 5, y: 6, z: 7, w: 8 }");
    check_eq!(format!("{:?}", bb(M4c { x: 9, y: 8, z: 7, w: 6 })), "M4c { x: 9, y: 8, z: 7, w: 6 }");
    check_eq!(format!("{:?}", bb(M5a { x: 1, y: 2, z: 3, w: 4, v: 5 })), "M5a { x: 1, y: 2, z: 3, w: 4, v: 5 }");
    check_eq!(format!("{:?}", bb(M5b { x: 6, y: 7, z: 8, w: 9, v: 0 })), "M5b { x: 6, y: 7, z: 8, w: 9, v: 0 }");
    check_eq!(format!("{:?}", bb(M5c { x: 5, y: 4, z: 3, w: 2, v: 1 })), "M5c { x: 5, y: 4, z: 3, w: 2, v: 1 }");
});
