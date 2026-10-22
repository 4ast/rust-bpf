// SPDX-License-Identifier: GPL-2.0
//! core: str and char. No allocation.
#![no_std]
#![no_main]
use rt::{bb, check, check_eq, test};

const TEXT: &str = "The quick brown fox, jumps over: the lazy dog";
const UNI: &str = "héllo wörld → 世界 🦀!";

test!(str_basic, {
    let s = bb(TEXT);
    check_eq!(s.len(), 45);
    check!(!s.is_empty());
    check!(s.starts_with("The") && s.ends_with("dog") && !s.starts_with("the"));
    check!(s.contains("brown") && !s.contains("red") && s.contains('z'));
    check_eq!(&s[4..9], "quick");
    check_eq!(s.get(4..9), Some("quick"));
    check_eq!(s.get(40..50), None);
    check_eq!(s.as_bytes()[0], b'T');
    check!(s.is_ascii());
    check!(s.eq_ignore_ascii_case(bb("THE QUICK BROWN FOX, JUMPS OVER: THE LAZY DOG")));
    check!(bb("abc") < bb("abd") && bb("abc") < bb("abcd") && bb("Z") < bb("a"));
});

test!(str_find, {
    let s = bb(TEXT);
    check_eq!(s.find("quick"), Some(4));
    check_eq!(s.find("the"), Some(33));
    check_eq!(s.rfind("he"), Some(34));
    check_eq!(s.find('o'), Some(12));
    check_eq!(s.rfind('o'), Some(43));
    check_eq!(s.find("cat"), None);
    check_eq!(s.find(|c: char| c == ',' || c == ':'), Some(19));
    check_eq!(s.find(char::is_whitespace), Some(3));
    check_eq!(s.find(&['x', 'z'][..]), Some(18));
    check_eq!(s.matches("o").count(), 4);
    check_eq!(s.match_indices("the").count(), 1);
    check_eq!(s.rmatches(char::is_uppercase).count(), 1);
    check_eq!(bb("aaaa").matches("aa").count(), 2);
});

test!(str_split, {
    let s = bb(TEXT);
    check_eq!(s.split(' ').count(), 9);
    check_eq!(s.split(' ').nth(3), Some("fox,"));
    check_eq!(s.split(", ").last(), Some("jumps over: the lazy dog"));
    check_eq!(s.split_whitespace().map(|w| w.len()).max(), Some(5));
    check_eq!(s.rsplit(' ').next(), Some("dog"));
    check_eq!(s.splitn(3, ' ').last(), Some("brown fox, jumps over: the lazy dog"));
    check_eq!(s.rsplitn(2, ' ').last(), Some("The quick brown fox, jumps over: the lazy"));
    check_eq!(s.split_once(": "), Some(("The quick brown fox, jumps over", "the lazy dog")));
    check_eq!(s.rsplit_once('x').map(|p| p.0.len()), Some(18));
    check_eq!(s.split_once('#'), None);
    check_eq!(s.split(|c: char| !c.is_alphabetic()).filter(|w| !w.is_empty()).count(), 9);
    check_eq!(bb("a,b,,c,").split(',').count(), 5);
    check_eq!(bb("a,b,,c,").split_terminator(',').count(), 4);
    check_eq!(bb("a,b,,c,").split_inclusive(',').count(), 4);
    check_eq!(bb("l1\nl2\r\nl3\n").lines().count(), 3);
    check_eq!(bb("l1\nl2\r\nl3\n").lines().nth(1), Some("l2"));
    check_eq!(s.split_at(3), ("The", " quick brown fox, jumps over: the lazy dog"));
});

test!(str_trim, {
    let s = bb("  \t x y \n");
    check_eq!(s.trim(), "x y");
    check_eq!(s.trim_start(), "x y \n");
    check_eq!(s.trim_end(), "  \t x y");
    check_eq!(bb("xxabxx").trim_matches('x'), "ab");
    check_eq!(bb("xxabxx").trim_start_matches("xx"), "abxx");
    check_eq!(bb("123abc456").trim_matches(char::is_numeric), "abc");
    check_eq!(bb("prefix-body").strip_prefix("prefix-"), Some("body"));
    check_eq!(bb("prefix-body").strip_suffix("nope"), None);
    check_eq!(bb("\u{3000}x\u{a0}").trim(), "x");
});

test!(str_utf8_chars, {
    let s = bb(UNI);
    check_eq!(s.len(), 30);
    check_eq!(s.chars().count(), 19);
    check!(!s.is_ascii());
    check_eq!(s.chars().nth(1), Some('é'));
    check_eq!(s.chars().rev().nth(1), Some('🦀'));
    check_eq!(s.char_indices().nth(2), Some((3, 'l')));
    check_eq!(s.char_indices().filter(|(_, c)| c.len_utf8() == 3).map(|(i, _)| i).sum::<usize>(), 14 + 18 + 21);
    check_eq!(s.chars().map(|c| c.len_utf8()).max(), Some(4));
    check_eq!(s.chars().map(|c| c as u32).max(), Some(0x1f980));
    check!(s.is_char_boundary(1) && !s.is_char_boundary(2) && s.is_char_boundary(3));
    check_eq!(s.get(1..2), None);
    check_eq!(s.find('世'), Some(18));
    check_eq!(s.find("界"), Some(21));
    check_eq!(s.bytes().filter(|b| *b >= 0x80).count(), 17);
    check_eq!(s.chars().filter(|c| c.is_alphabetic()).count(), 12);
    check_eq!(s.encode_utf16().count(), 20);
});

test!(str_from_utf8, {
    check_eq!(core::str::from_utf8(bb(b"plain")), Ok("plain"));
    check_eq!(core::str::from_utf8(bb(&[0xe4, 0xb8, 0x96])), Ok("世"));
    let e = core::str::from_utf8(bb(&[b'a', b'b', 0xff, b'c'])).unwrap_err();
    check_eq!(e.valid_up_to(), 2);
    check_eq!(e.error_len(), Some(1));
    let e = core::str::from_utf8(bb(&[b'a', 0xe4, 0xb8])).unwrap_err();
    check_eq!(e.valid_up_to(), 1);
    check_eq!(e.error_len(), None);
    check!(core::str::from_utf8(bb(&[0xc0, 0x80])).is_err());
    check!(core::str::from_utf8(bb(&[0xed, 0xa0, 0x80])).is_err());
    check!(core::str::from_utf8(bb(&[0xf4, 0x90, 0x80, 0x80])).is_err());
    let long = bb([b'x'; 100]);
    check_eq!(core::str::from_utf8(&long).map(|s| s.len()), Ok(100));
    let chunks = bb(&b"ab\xffcd\xf0\x90"[..]).utf8_chunks();
    check_eq!(chunks.count(), 2);
});

test!(char_methods, {
    check_eq!(bb('7').to_digit(10), Some(7));
    check_eq!(bb('f').to_digit(16), Some(15));
    check_eq!(bb('g').to_digit(16), None);
    check_eq!(char::from_digit(bb(11), 16), Some('b'));
    check_eq!(char::from_u32(bb(0x41)), Some('A'));
    check_eq!(char::from_u32(bb(0xd800)), None);
    check_eq!(char::from_u32(bb(0x110000)), None);
    check_eq!(bb('a') as u32 + 1, 'b' as u32);
    check_eq!((bb(b'a') + 2) as char, 'c');
    check_eq!(bb('a').to_ascii_uppercase(), 'A');
    check_eq!(bb('[').to_ascii_lowercase(), '[');
    check!(bb('x').is_ascii_lowercase() && bb('9').is_ascii_digit() && bb('_').is_ascii_punctuation());
    check!(bb(' ').is_ascii_whitespace() && bb('\x07').is_ascii_control() && bb('F').is_ascii_hexdigit());
    check_eq!(bb('ß').len_utf8() + bb('€').len_utf8() + bb('𝄞').len_utf8(), 9);
    check_eq!(bb('𝄞').len_utf16(), 2);
    let mut buf = [0u8; 4];
    check_eq!(bb('€').encode_utf8(&mut buf).as_bytes(), &[0xe2, 0x82, 0xac]);
    check_eq!(u8::try_from(bb('é')), Ok(0xe9));
    check!(u8::try_from(bb('€')).is_err());
});

test!(char_unicode_tables, {
    check!(bb('é').is_alphabetic() && bb('世').is_alphabetic() && !bb('→').is_alphabetic());
    check!(bb('É').is_uppercase() && bb('é').is_lowercase() && !bb('世').is_lowercase());
    check!(bb('٣').is_numeric() && bb('½').is_numeric() && !bb('x').is_numeric());
    check!(bb('\u{2003}').is_whitespace() && !bb('\u{200b}').is_whitespace());
    check!(bb('\u{9f}').is_control() && bb('Ж').is_alphanumeric());
    check!(bb('é').to_uppercase().eq(['É']));
    check!(bb('Σ').to_lowercase().eq(['σ']));
    check!(bb('ß').to_uppercase().eq(['S', 'S']));
    check!(bb('ŉ').to_uppercase().count() == 2);
    check!(bb('1').to_uppercase().eq(['1']));
});

test!(str_escape, {
    check!(bb("a\n\"'\\\t").escape_default().eq("a\\n\\\"\\'\\\\\\t".chars()));
    check!(bb("é").escape_unicode().eq("\\u{e9}".chars()));
    check!(bb("a\u{7f}é").escape_debug().eq("a\\u{7f}é".chars()));
    check!(bb('\r').escape_default().eq("\\r".chars()));
    check!(bb(0xffu8).escape_ascii().eq(*b"\\xff"));
    check!(bb(&b"a\0"[..]).escape_ascii().eq(*b"a\\x00"));
});

test!(str_parse_other, {
    check_eq!(bb("true").parse::<bool>(), Ok(true));
    check!(bb("True").parse::<bool>().is_err());
    check_eq!(bb("x").parse::<char>(), Ok('x'));
    check!(bb("xy").parse::<char>().is_err());
    check_eq!(bb("世").parse::<char>(), Ok('世'));
    let ip: core::net::Ipv4Addr = bb("192.168.1.20").parse().unwrap();
    check_eq!(ip.octets(), [192, 168, 1, 20]);
    check!(ip.is_private() && !ip.is_loopback());
    check!(bb("192.168.1.256").parse::<core::net::Ipv4Addr>().is_err());
    let ip6: core::net::Ipv6Addr = bb("fe80::1:2").parse().unwrap();
    check_eq!(ip6.segments(), [0xfe80, 0, 0, 0, 0, 0, 1, 2]);
    let sa: core::net::SocketAddrV4 = bb("10.0.0.1:8080").parse().unwrap();
    check_eq!(sa.port(), 8080);
});

test!(str_mut_bytes, {
    let mut buf = bb(*b"hello world");
    let s = core::str::from_utf8_mut(&mut buf).unwrap();
    s.make_ascii_uppercase();
    check_eq!(s, "HELLO WORLD");
    s[6..].make_ascii_lowercase();
    check_eq!(s, "HELLO world");
    let (a, b) = s.split_at_mut(5);
    a.make_ascii_lowercase();
    check!(a == "hello" && b == " world");
    check_eq!(bb(&b"  x "[..]).trim_ascii(), b"x");
    check!(bb(&b"AbC"[..]).eq_ignore_ascii_case(b"aBc"));
});

test!(cstr, {
    use core::ffi::CStr;
    let c = CStr::from_bytes_until_nul(bb(&b"abc\0def\0"[..])).unwrap();
    check_eq!(c.to_bytes(), b"abc");
    check_eq!(c.count_bytes(), 3);
    check_eq!(c.to_str(), Ok("abc"));
    check!(CStr::from_bytes_with_nul(bb(&b"ab\0c\0"[..])).is_err());
    check!(CStr::from_bytes_until_nul(bb(&b"abc"[..])).is_err());
    check_eq!(bb(c"lit").to_bytes_with_nul(), b"lit\0");
    let p = bb(c"pointer").as_ptr();
    check_eq!(unsafe { CStr::from_ptr(p) }.to_bytes().len(), 7);
});
