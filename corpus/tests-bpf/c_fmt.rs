// SPDX-License-Identifier: GPL-2.0
//! core::fmt into a buffer on the stack. No allocation.
#![no_std]
#![no_main]
use core::fmt::{self, Write};
use rt::{bb, check, test};

struct Buf {
    b: [u8; 256],
    n: usize,
}
impl Buf {
    fn new() -> Buf {
        Buf { b: [0; 256], n: 0 }
    }
    fn s(&self) -> &str {
        // from_utf8() has tests of its own
        unsafe { core::str::from_utf8_unchecked(&self.b[..self.n]) }
    }
}
impl Write for Buf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.n + s.len();
        if end > self.b.len() {
            return Err(fmt::Error);
        }
        self.b[self.n..end].copy_from_slice(s.as_bytes());
        self.n = end;
        Ok(())
    }
}

/// f!("want", "format", args...): the text is what is wanted
macro_rules! f {
    ($want:expr, $($arg:tt)*) => {{
        let mut b = Buf::new();
        check!(write!(b, $($arg)*).is_ok());
        check!(b.s() == $want);
    }};
}

test!(fmt_int_display, {
    f!("0", "{}", bb(0u8));
    f!("255", "{}", bb(255u8));
    f!("-128", "{}", bb(-128i8));
    f!("65535 -32768", "{} {}", bb(65535u16), bb(-32768i16));
    f!("4294967295", "{}", bb(u32::MAX));
    f!("-2147483648", "{}", bb(i32::MIN));
    f!("18446744073709551615", "{}", bb(u64::MAX));
    f!("-9223372036854775808", "{}", bb(i64::MIN));
    f!("12345", "{}", bb(12345usize));
    f!("-1", "{}", bb(-1isize));
});

test!(fmt_int128, {
    f!("340282366920938463463374607431768211455", "{}", bb(u128::MAX));
    f!("-170141183460469231731687303715884105728", "{}", bb(i128::MIN));
    f!("10000000000000000000000", "{}", bb(10u128.pow(22)));
    f!("ffffffffffffffffffffffffffffffff", "{:x}", bb(u128::MAX));
    f!("7", "{}", bb(7u128));
});

test!(fmt_radix, {
    f!("ff", "{:x}", bb(255u8));
    f!("FF", "{:X}", bb(255u8));
    f!("0xff", "{:#x}", bb(255u8));
    f!("377", "{:o}", bb(255u8));
    f!("0o377", "{:#o}", bb(255u8));
    f!("11111111", "{:b}", bb(255u8));
    f!("0b101", "{:#b}", bb(5u8));
    f!("ff", "{:x}", bb(-1i8));
    f!("ffffffff", "{:x}", bb(-1i32));
    f!("deadbeefcafebabe", "{:x}", bb(0xdeadbeefcafebabeu64));
    f!("0x00ff", "{:#06x}", bb(255u32));
    f!("00000101", "{:08b}", bb(5u8));
    f!("1e3", "{:e}", bb(1000u32));
    f!("1.234E3", "{:E}", bb(1234u32));
});

test!(fmt_width_align, {
    f!("      42", "{:8}", bb(42));
    f!("      42", "{:>8}", bb(42));
    f!("42      ", "{:<8}", bb(42));
    f!("   42   ", "{:^8}", bb(42));
    f!("***42***", "{:*^8}", bb(42));
    f!("00000042", "{:08}", bb(42));
    f!("-0000042", "{:08}", bb(-42));
    f!("+42", "{:+}", bb(42));
    f!("-42", "{:+}", bb(-42));
    f!("+0000042", "{:+08}", bb(42));
    f!("   42", "{:1$}", bb(42), bb(5usize));
    f!("   42", "{:w$}", bb(42), w = bb(5usize));
    f!("42", "{:1}", bb(42));
    f!("ab      |", "{:8}|", bb("ab"));
    f!("      ab|", "{:>8}|", bb("ab"));
    f!("--ab---|", "{:-^7}|", bb("ab"));
    f!("x    |", "{:5}|", bb('x'));
    f!("true |false", "{:5}|{}", bb(true), bb(false));
    f!("→→é→→", "{:→^5}", bb("é"));
});

test!(fmt_str_precision, {
    f!("abc", "{:.3}", bb("abcdef"));
    f!("abcdef", "{:.10}", bb("abcdef"));
    f!("abc  ", "{:5.3}", bb("abcdef"));
    f!("ab", "{:.*}", bb(2usize), bb("abcdef"));
    f!("hé", "{:.2}", bb("héllo"));
    f!("", "{:.0}", bb("abc"));
});

test!(fmt_args, {
    f!("a b a", "{0} {1} {0}", bb("a"), bb("b"));
    f!("x=1 y=2", "x={x} y={y}", y = bb(2), x = bb(1));
    let name = bb("inline");
    let n = bb(3);
    f!("inline:3:003", "{name}:{n}:{n:03}");
    f!("{}", "{{}}");
    f!("{1}", "{{{}}}", bb(1));
    f!("100%", "{}%", bb(100));
    f!("", "");
    f!("only text", "only text");
    f!("1 2 3 4 5 6 7 8 9 10", "{} {} {} {} {} {} {} {} {} {}", bb(1), 2, 3, 4, 5, 6, 7, 8, 9, bb(10));
});

#[derive(Debug, Clone, Copy)]
struct Point {
    x: i32,
    y: i32,
}
#[derive(Debug)]
struct Unit;
#[derive(Debug)]
struct Tuple(u8, &'static str);
#[derive(Debug)]
#[allow(dead_code)]
enum Kind {
    Empty,
    One(u8),
    Named { p: Point, ok: bool },
}
#[derive(Debug)]
#[allow(dead_code)]
struct Nested<'a> {
    name: &'a str,
    pts: [Point; 2],
    opt: Option<Kind>,
}

test!(fmt_debug_derive, {
    f!("Point { x: 1, y: -2 }", "{:?}", bb(Point { x: 1, y: -2 }));
    f!("Unit", "{:?}", Unit);
    f!("Tuple(7, \"s\")", "{:?}", bb(Tuple(7, "s")));
    f!("Empty One(3)", "{:?} {:?}", bb(Kind::Empty), bb(Kind::One(3)));
    f!("Named { p: Point { x: 0, y: 5 }, ok: true }", "{:?}", bb(Kind::Named { p: Point { x: 0, y: 5 }, ok: true }));
    let n = Nested { name: bb("n"), pts: [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }], opt: Some(Kind::One(9)) };
    f!("Nested { name: \"n\", pts: [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }], opt: Some(One(9)) }", "{:?}", n);
});

test!(fmt_debug_pretty, {
    f!("Point {\n    x: 1,\n    y: -2,\n}", "{:#?}", bb(Point { x: 1, y: -2 }));
    f!("Tuple(\n    7,\n    \"s\",\n)", "{:#?}", bb(Tuple(7, "s")));
    f!("[\n    1,\n    2,\n]", "{:#?}", bb([1, 2]));
    f!("Some(\n    Point {\n        x: 1,\n        y: 2,\n    },\n)", "{:#?}", bb(Some(Point { x: 1, y: 2 })));
});

test!(fmt_debug_std_types, {
    f!("\"a\\n\\\"b\\\"\"", "{:?}", bb("a\n\"b\""));
    f!("'x' '\\'' '\\n'", "{:?} {:?} {:?}", bb('x'), bb('\''), bb('\n'));
    f!("\"é世\\u{7f}\"", "{:?}", bb("é世\u{7f}"));
    f!("[1, 2, 3]", "{:?}", bb([1, 2, 3]));
    f!("[]", "{:?}", bb(&[0u8; 0][..]));
    f!("(1, \"a\", 'c', true)", "{:?}", bb((1, "a", 'c', true)));
    f!("()", "{:?}", ());
    f!("Some(1) None", "{:?} {:?}", bb(Some(1)), bb(None::<u8>));
    f!("Ok(1) Err(\"e\")", "{:?} {:?}", bb(Ok::<u8, &str>(1)), bb(Err::<u8, &str>("e")));
    f!("1..5 1..=5 ..", "{:?} {:?} {:?}", bb(1..5), bb(1..=5), ..);
    f!("Less", "{:?}", bb(1).cmp(&2));
    f!("[ff, 0a]", "{:02x?}", bb([255u8, 10]));
    f!("[  1,   2]", "{:3?}", bb([1, 2]));
    f!("Cell { value: 5 }", "{:?}", core::cell::Cell::new(bb(5)));
    f!("RefCell { value: 5 }", "{:?}", core::cell::RefCell::new(bb(5)));
    f!("1.5s 20ms", "{:?} {:?}", core::time::Duration::from_millis(bb(1500)), core::time::Duration::from_millis(20));
    f!("ParseIntError { kind: InvalidDigit }", "{:?}", bb("x").parse::<u8>().unwrap_err());
    f!("invalid digit found in string", "{}", bb("x").parse::<u8>().unwrap_err());
    f!("10.0.0.1:80", "{}", core::net::SocketAddrV4::new(core::net::Ipv4Addr::new(10, 0, 0, bb(1)), 80));
    f!("fe80::1", "{}", core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, bb(1)));
});

struct Money(i64);
impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (sign, v) = if self.0 < 0 { ("-", -self.0) } else { ("", self.0) };
        write!(f, "{}${}.{:02}", sign, v / 100, v % 100)
    }
}
struct Padded(&'static str);
impl fmt::Display for Padded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.0)
    }
}
struct Flags;
impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?},{:?},{},{},{}", f.width(), f.precision(), f.alternate(), f.sign_plus(), f.fill())
    }
}
struct List<'a>(&'a [u32]);
impl fmt::Debug for List<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter().map(|x| x * 2)).finish()
    }
}
struct Map<'a>(&'a [(&'a str, u32)]);
impl fmt::Debug for Map<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter().map(|(k, v)| (k, v))).finish()
    }
}
struct Manual;
impl fmt::Debug for Manual {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manual").field("a", &1).field("b", &"two").finish_non_exhaustive()
    }
}
impl fmt::LowerHex for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

test!(fmt_custom_impls, {
    f!("$12.05 -$0.99", "{} {}", Money(bb(1205)), Money(bb(-99)));
    f!("[  ab]", "[{:>4}]", Padded(bb("ab")));
    f!("[a]", "[{:.1}]", Padded(bb("ab")));
    f!("Some(7),Some(2),true,true,_", "{:_>+#7.2}", Flags);
    f!("None,None,false,false, ", "{}", Flags);
    f!("[2, 4, 6]", "{:?}", List(bb(&[1, 2, 3])));
    f!("{\"a\": 1, \"b\": 2}", "{:?}", Map(bb(&[("a", 1), ("b", 2)])));
    f!("Manual { a: 1, b: \"two\", .. }", "{:?}", Manual);
    f!("0x4b5", "{:#x}", Money(bb(1205)));
});

test!(fmt_dyn_and_errors, {
    let items: [&dyn fmt::Display; 4] = [&bb(1u8), &bb("two"), &bb('3'), &Money(bb(400))];
    let mut b = Buf::new();
    for (i, it) in items.iter().enumerate() {
        check!(write!(b, "{}{}", if i > 0 { "," } else { "" }, it).is_ok());
    }
    check!(b.s() == "1,two,3,$4.00");
    let mut b = Buf::new();
    let mut failed = false;
    for _ in 0..bb(40) {
        if write!(b, "{:8}", 1).is_err() {
            failed = true;
            break;
        }
    }
    check!(failed && b.n == 256);
    let mut b = Buf::new();
    check!(b.write_char(bb('é')).is_ok() && b.write_str("x").is_ok() && b.s() == "éx");
    let mut b = Buf::new();
    check!(fmt::write(&mut b, format_args!("{}-{}", bb(1), bb(2))).is_ok() && b.s() == "1-2");
    check!(format_args!("const").as_str() == Some("const"));
});

test!(fmt_pointer, {
    let mut b = Buf::new();
    check!(write!(b, "{:p}", bb(0x1234usize) as *const u8).is_ok());
    check!(b.s() == "0x1234");
    let x = bb(5u32);
    let mut b = Buf::new();
    check!(write!(b, "{:p}", &x).is_ok());
    check!(b.s().starts_with("0x") && b.n > 2);
});
