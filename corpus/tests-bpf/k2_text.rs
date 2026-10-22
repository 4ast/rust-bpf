// SPDX-License-Identifier: GPL-2.0
//! crates: serde_json, base64, hex, uuid, semver, smol_str, ryu, unicode-*, aho-corasick, regex-automata
#![no_std]
#![no_main]
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Item {
    id: u32,
    name: String,
    tags: Vec<String>,
    price: Option<i64>,
    on: bool,
}

test!(json_serialize, {
    let it = Item { id: bb(7), name: "pen \"x\"".to_string(), tags: vec!["a".to_string(), "b".to_string()], price: None, on: true };
    check_eq!(serde_json::to_string(&it).unwrap(), r#"{"id":7,"name":"pen \"x\"","tags":["a","b"],"price":null,"on":true}"#);
    check_eq!(serde_json::to_string(&bb([1, 2, 3])).unwrap(), "[1,2,3]");
    check_eq!(serde_json::to_string(&bb(-5i64)).unwrap(), "-5");
    check_eq!(serde_json::to_string(bb("é\n")).unwrap(), "\"é\\n\"");
    let mut m = BTreeMap::new();
    m.insert("k", bb(1));
    check_eq!(serde_json::to_string(&m).unwrap(), r#"{"k":1}"#);
});

test!(json_deserialize, {
    let it: Item = serde_json::from_str(bb(r#" { "id": 7, "name": "pen", "tags": ["a"], "price": -12, "on": false } "#)).unwrap();
    check_eq!(it, Item { id: 7, name: "pen".to_string(), tags: vec!["a".to_string()], price: Some(-12), on: false });
    check_eq!(serde_json::from_str::<Vec<u8>>(bb("[1, 2, 255]")).unwrap(), [1, 2, 255]);
    check!(serde_json::from_str::<Vec<u8>>(bb("[1, 2, 256]")).is_err());
    check!(serde_json::from_str::<Item>(bb(r#"{"id": 7}"#)).is_err());
    check!(serde_json::from_str::<u32>(bb("12x")).is_err());
    check_eq!(serde_json::from_str::<String>(bb(r#""aé\n""#)).unwrap(), "aé\n");
    check_eq!(serde_json::from_slice::<(u8, bool)>(bb(b"[1,true]")).unwrap(), (1, true));
});

test!(json_value, {
    let v: serde_json::Value = serde_json::from_str(bb(r#"{"a": [1, {"b": "x"}, null], "n": -3, "t": true}"#)).unwrap();
    check_eq!(v["a"][0].as_u64(), Some(1));
    check_eq!(v["a"][1]["b"].as_str(), Some("x"));
    check!(v["a"][2].is_null() && v["missing"].is_null());
    check_eq!(v["n"].as_i64(), Some(-3));
    check_eq!(v["a"].as_array().map(|a| a.len()), Some(3));
    check_eq!(v.pointer("/a/1/b").and_then(|x| x.as_str()), Some("x"));
    let j = serde_json::json!({"x": bb(1), "y": [true, null]});
    check_eq!(j.to_string(), r#"{"x":1,"y":[true,null]}"#);
});

test!(json_floats, {
    check_eq!(serde_json::to_string(&bb(1.5f64)).unwrap(), "1.5");
    check_eq!(serde_json::from_str::<f64>(bb("2.25e2")).unwrap(), 225.0);
    check_eq!(serde_json::from_str::<f64>(bb("0.1")).unwrap(), 0.1);
});

test!(base64_hex, {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
    check_eq!(STANDARD.encode(bb(b"hello world!?")), "aGVsbG8gd29ybGQhPw==");
    check_eq!(STANDARD_NO_PAD.encode(bb(b"hello world!?")), "aGVsbG8gd29ybGQhPw");
    check_eq!(URL_SAFE.encode(bb([0xfb, 0xff, 0xfe])), "-__-");
    check_eq!(STANDARD.decode(bb("aGVsbG8gd29ybGQhPw==")).unwrap(), b"hello world!?");
    check!(STANDARD.decode(bb("a$b=")).is_err());
    check!(STANDARD.decode(bb("aGVsbG8")).is_err());
    let mut out = [0u8; 8];
    check_eq!(STANDARD.encode_slice(bb(b"abc"), &mut out), Ok(4));
    check_eq!(&out[..4], b"YWJj");
    check_eq!(hex::encode(bb([0xde, 0xad, 0x01])), "dead01");
    check_eq!(hex::encode_upper(bb([0xbe, 0xef])), "BEEF");
    check_eq!(hex::decode(bb("DEad01")).unwrap(), [0xde, 0xad, 0x01]);
    check!(hex::decode(bb("abc")).is_err() && hex::decode(bb("zz")).is_err());
    let mut b = [0u8; 2];
    check!(hex::decode_to_slice(bb("0aff"), &mut b).is_ok() && b == [10, 255]);
});

test!(uuid_semver, {
    use semver::{Version, VersionReq};
    use uuid::Uuid;
    let u = Uuid::parse_str(bb("67e55044-10b1-426f-9247-bb680e5fe0c8")).unwrap();
    check_eq!(u.as_bytes()[0], 0x67);
    check_eq!(u.get_version_num(), 4);
    check_eq!(u.to_string(), "67e55044-10b1-426f-9247-bb680e5fe0c8");
    check_eq!(u.simple().to_string(), "67e5504410b1426f9247bb680e5fe0c8");
    check_eq!(Uuid::from_u128(u.as_u128()), u);
    check!(Uuid::parse_str(bb("67e55044-10b1-426f-9247")).is_err());
    check!(Uuid::nil().is_nil() && Uuid::nil() < u);
    let v = Version::parse(bb("1.2.3-beta.1+build5")).unwrap();
    check!(v.major == 1 && v.minor == 2 && v.patch == 3 && v.pre.as_str() == "beta.1" && v.build.as_str() == "build5");
    check!(v < Version::new(1, 2, 3) && Version::new(1, 10, 0) > Version::new(1, 9, 9));
    check_eq!(v.to_string(), "1.2.3-beta.1+build5");
    let r = VersionReq::parse(bb(">=1.2, <2.0")).unwrap();
    check!(r.matches(&Version::new(1, 5, 0)) && !r.matches(&Version::new(2, 0, 0)) && !r.matches(&Version::new(1, 1, 9)));
    check!(VersionReq::parse(bb("^0.3.1")).unwrap().matches(&Version::new(0, 3, 9)));
    check!(Version::parse(bb("1.2")).is_err());
});

test!(smol_str_ryu, {
    use smol_str::SmolStr;
    let n = rt::allocs();
    let s = SmolStr::new(bb("short"));
    check!(!s.is_heap_allocated());
    check_eq!(rt::allocs(), n);
    let l = SmolStr::new(bb("a string that is too long to be kept inline"));
    check!(l.is_heap_allocated());
    let c = l.clone();
    check!(c == l && s == "short" && s.len() == 5);
    check_eq!(smol_str::format_smolstr!("{}-{}", bb(1), bb(2)), "1-2");
    let mut b = ryu::Buffer::new();
    check_eq!(b.format(bb(1.5f64)), "1.5");
    check_eq!(b.format(bb(0.1f64)), "0.1");
    check_eq!(b.format(bb(1e21f64)), "1e21");
    check_eq!(b.format(bb(-2.5e-7f64)), "-2.5e-7");
    check_eq!(b.format(bb(3.4028235e38f32)), "3.4028235e38");
    check_eq!(b.format(bb(f64::NAN)), "NaN");
});

test!(unicode_segmentation, {
    use unicode_segmentation::UnicodeSegmentation;
    let s = bb("a\u{310}e\u{301}o\u{308}\u{332}\r\n🇷🇺🇸🇹");
    check_eq!(s.graphemes(true).count(), 6);
    check_eq!(s.graphemes(true).next(), Some("a\u{310}"));
    check_eq!(bb("The quick (\"brown\") fox can't jump 32.3 feet").unicode_words().count(), 8);
    check_eq!(bb("Hi there. How are you? Fine!").unicode_sentences().count(), 3);
    check_eq!(bb("héllo").grapheme_indices(true).nth(2), Some((3, "l")));
});

test!(unicode_normalization, {
    use unicode_normalization::UnicodeNormalization;
    check_eq!(bb("é").nfd().collect::<String>(), "e\u{301}");
    check_eq!(bb("e\u{301}").nfc().collect::<String>(), "é");
    check_eq!(bb("ﬁ①").nfkc().collect::<String>(), "fi1");
    check_eq!(bb("Å").nfd().count(), 2);
    check_eq!(bb("한").nfd().count(), 3);
    check!(unicode_normalization::is_nfc(bb("é")) && !unicode_normalization::is_nfc(bb("e\u{301}")));
});

test!(aho_corasick, {
    use aho_corasick::{AhoCorasick, MatchKind};
    let ac = AhoCorasick::new(bb(["apple", "maple", "snapple"])).unwrap();
    let hay = bb("Nobody likes maple in their apple flavored Snapple.");
    let m: Vec<(usize, usize, usize)> = ac.find_iter(hay).map(|m| (m.pattern().as_usize(), m.start(), m.end())).collect();
    check_eq!(m, [(1, 13, 18), (0, 28, 33), (0, 45, 50)]);
    check!(ac.is_match(hay) && !ac.is_match(bb("nothing here")));
    check_eq!(ac.replace_all(bb("apple maple"), &["A", "M", "S"]), "A M");
    let lm = AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).ascii_case_insensitive(true).build(["app", "apple"]).unwrap();
    check_eq!(lm.find(bb("an APPLE")).map(|m| (m.start(), m.end())), Some((3, 8)));
});

test!(regex_automata, {
    use regex_automata::meta::Regex;
    let re = Regex::new(bb(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")).unwrap();
    let hay = bb("from 2026-10-22 to 2026-11-06, not 26-1-1");
    check_eq!(re.find_iter(hay).map(|m| m.range()).collect::<Vec<_>>(), [5..15, 19..29]);
    check!(re.is_match(hay) && !re.is_match(bb("no dates")));
    let cap = Regex::new(bb(r"(?<key>[a-z]+)=(?<val>[0-9]+)")).unwrap();
    let mut caps = cap.create_captures();
    cap.captures(bb("x, abc=123;"), &mut caps);
    check!(caps.is_match());
    check_eq!(caps.get_group_by_name("key").map(|s| s.range()), Some(3..6));
    check_eq!(caps.get_group_by_name("val").map(|s| s.range()), Some(7..10));
    check!(Regex::new(bb(r"(unclosed")).is_err());
    let alt = Regex::new(bb(r"^(foo|ba+r)+$")).unwrap();
    check!(alt.is_match(bb("foobaaarfoo")) && !alt.is_match(bb("foobr")));
});
