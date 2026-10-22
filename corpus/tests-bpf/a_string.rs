// SPDX-License-Identifier: GPL-2.0
//! alloc::string::String, format!, Cow
#![no_std]
#![no_main]
extern crate alloc;
use alloc::borrow::{Cow, ToOwned};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;
use rt::{bb, check, check_eq, test};

test!(string_build, {
    let mut s = String::new();
    check!(s.is_empty());
    s.push_str(bb("hello"));
    s.push(' ');
    s.push('w');
    s += "orld";
    check_eq!(s, "hello world");
    check_eq!(s.len(), 11);
    s.insert(0, '>');
    s.insert_str(1, "> ");
    check_eq!(s, ">> hello world");
    check_eq!(s.pop(), Some('d'));
    check_eq!(s.remove(0), '>');
    s.truncate(bb(7));
    check_eq!(s, "> hello");
    s.clear();
    check!(s.is_empty() && s.capacity() > 0);
    let t = String::from(bb("a")) + "b" + &String::from("c");
    check_eq!(t, "abc");
});

test!(string_unicode, {
    let mut s = String::from(bb("héllo"));
    s.push('→');
    s.push('🦀');
    check_eq!(s.len(), 13);
    check_eq!(s.chars().count(), 7);
    check_eq!(s.pop(), Some('🦀'));
    check_eq!(s.remove(1), 'é');
    check_eq!(s, "hllo→");
    check_eq!(s.chars().rev().collect::<String>(), "→ollh");
    check_eq!(bb("Straße").to_uppercase(), "STRASSE");
    check_eq!(bb("ÀÉÎ").to_lowercase(), "àéî");
    check_eq!(bb("mIxEd").to_ascii_uppercase(), "MIXED");
    check_eq!(String::from_utf8_lossy(bb(b"a\xffb")), "a\u{fffd}b");
    check!(String::from_utf8(bb(b"a\xffb").to_vec()).is_err());
    check_eq!(String::from_utf8(bb("é").as_bytes().to_vec()).as_deref(), Ok("é"));
    check_eq!(String::from_utf16(bb(&[0x68, 0xd83e, 0xdd80])).ok().as_deref(), Some("h🦀"));
});

test!(string_edit, {
    let s = String::from(bb("one two one three one"));
    check_eq!(s.replace("one", "1"), "1 two 1 three 1");
    check_eq!(s.replacen("one", "1", 2), "1 two 1 three one");
    check_eq!(s.replace(' ', ""), "onetwoonethreeone");
    check_eq!(s.replace("zzz", "y"), s);
    check_eq!(bb("ab").repeat(3), "ababab");
    let mut m = s.clone();
    m.retain(|c| c != 'e');
    check_eq!(m, "on two on thr on");
    m.replace_range(bb(0)..2, "ON");
    check_eq!(&m[..6], "ON two");
    let d: String = m.drain(..bb(3)).collect();
    check!(d == "ON " && m.starts_with("two"));
    let tail = m.split_off(bb(3));
    check!(m == "two" && tail == " on thr on");
    m.extend(['!', '?']);
    m.extend(["a", "b"]);
    check_eq!(m, "two!?ab");
});

test!(string_split_join, {
    let s = bb("a,b;c,d");
    let parts: Vec<&str> = s.split(|c| c == ',' || c == ';').collect();
    check_eq!(parts, ["a", "b", "c", "d"]);
    check_eq!(parts.join("+"), "a+b+c+d");
    check_eq!(parts.concat(), "abcd");
    let owned: Vec<String> = parts.iter().map(|p| p.to_uppercase()).collect();
    check_eq!(owned.join(""), "ABCD");
    let words: Vec<String> = bb("  the  quick fox ").split_whitespace().map(String::from).collect();
    check_eq!(words.len(), 3);
    let mut sorted = words.clone();
    sorted.sort_by_key(|w| core::cmp::Reverse(w.len()));
    check_eq!(sorted[0], "quick");
    let cs: Vec<char> = bb("héy").chars().collect();
    check_eq!(cs, ['h', 'é', 'y']);
    check_eq!(cs.iter().collect::<String>(), "héy");
    check_eq!(bb("x=1;y=2").split(';').filter_map(|kv| kv.split_once('=')).map(|(_, v)| v.parse::<u32>().unwrap()).sum::<u32>(), 3);
});

test!(string_format, {
    check_eq!(format!("{}-{}", bb(1), bb("two")), "1-two");
    check_eq!(format!("{:>5}|{:<5}|{:^5}", bb(1), bb(2), bb(3)), "    1|2    |  3  ");
    check_eq!(format!("{:05}", bb(-42)), "-0042");
    check_eq!(format!("{:#x} {:#b} {:o}", bb(255), bb(5), bb(8)), "0xff 0b101 10");
    check_eq!(format!("{:?}", bb("q\"")), "\"q\\\"\"");
    check_eq!(format!("{:?}", alloc::vec![bb(1), 2]), "[1, 2]");
    check_eq!(format!("{:?}", bb(Some("x"))), "Some(\"x\")");
    check_eq!(format!("{}", bb(u128::MAX)), "340282366920938463463374607431768211455");
    let name = bb("n");
    check_eq!(format!("{name}={v:03}", v = bb(7)), "n=007");
    check_eq!(format!("{}", String::from(bb("s"))), "s");
    check_eq!(format!("{0}{0}{1}", bb('a'), bb('b')), "aab");
});

test!(string_to_string_write, {
    check_eq!(bb(42).to_string(), "42");
    check_eq!(bb(-7i8).to_string(), "-7");
    check_eq!(bb('c').to_string(), "c");
    check_eq!(bb(true).to_string(), "true");
    check_eq!(bb("s").to_string(), "s");
    check_eq!(bb(u64::MAX).to_string(), "18446744073709551615");
    let mut s = String::new();
    for i in 0..bb(5) {
        check!(write!(s, "{i},").is_ok());
    }
    check!(writeln!(s, "end").is_ok());
    check_eq!(s, "0,1,2,3,4,end\n");
    check_eq!(s.parse::<u32>().is_err(), true);
    check_eq!(bb(12345u32).to_string().parse::<u32>(), Ok(12345));
});

fn shout(s: &str) -> Cow<'_, str> {
    if s.chars().any(|c| c.is_lowercase()) { Cow::Owned(s.to_uppercase()) } else { Cow::Borrowed(s) }
}

test!(cow, {
    let n = rt::allocs();
    let a = shout(bb("LOUD"));
    check!(matches!(a, Cow::Borrowed(_)));
    check_eq!(rt::allocs(), n);
    let b = shout(bb("quiet"));
    check!(matches!(b, Cow::Owned(_)));
    check!(a == "LOUD" && b == "QUIET");
    check_eq!(b.len(), 5);
    let mut c = Cow::Borrowed(bb("x"));
    c.to_mut().push('y');
    check_eq!(c, "xy");
    check_eq!(c.into_owned(), "xy");
    let mut v: Cow<[u32]> = Cow::Borrowed(bb(&[1, 2, 3]));
    check_eq!(v.iter().sum::<u32>(), 6);
    v.to_mut()[0] = 10;
    check_eq!(&*v, &[10, 2, 3]);
    let o: String = bb("abc").to_owned();
    check_eq!(o, "abc");
    check_eq!(a + "!", "LOUD!");
});

test!(string_capacity_convert, {
    let mut s = String::with_capacity(bb(32));
    let n = rt::allocs();
    for _ in 0..32 {
        s.push('x');
    }
    check_eq!(rt::allocs(), n);
    s.shrink_to(bb(0));
    check_eq!(s.len(), 32);
    let b = s.into_bytes();
    check_eq!(b.len(), 32);
    let bs: alloc::boxed::Box<str> = String::from(bb("boxed")).into_boxed_str();
    check_eq!(&*bs, "boxed");
    check_eq!(bs.into_string(), "boxed");
    let cmp = [String::from("b"), String::from("a")];
    check!(cmp[0] > cmp[1] && cmp[1] == "a" && "b" == cmp[0]);
    check_eq!(String::from(bb('z')), "z");
    check_eq!(String::from_iter([bb("a"), "b"]), "ab");
});
