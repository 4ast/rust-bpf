// SPDX-License-Identifier: GPL-2.0
//! crates: memchr, byteorder, itoa
#![no_std]
#![no_main]
extern crate alloc;
use byteorder::{BigEndian, ByteOrder, LittleEndian, NetworkEndian};
use rt::{bb, check, check_eq, test};

const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog, then the dog sleeps";

test!(memchr_bytes, {
    let t = bb(TEXT);
    check_eq!(memchr::memchr(b'q', t), Some(4));
    check_eq!(memchr::memchr(b'Q', t), None);
    check_eq!(memchr::memrchr(b'o', t), Some(55));
    check_eq!(memchr::memchr2(b'x', b'z', t), Some(18));
    check_eq!(memchr::memchr3(b'1', b'2', b',', t), Some(43));
    check_eq!(memchr::memrchr2(b'x', b'z', t), Some(37));
    check_eq!(memchr::memchr_iter(b'o', t).count(), 5);
    check_eq!(memchr::memchr_iter(b' ', t).rev().next(), Some(57));
    check_eq!(memchr::memchr(b'a', bb(b"")), None);
});

test!(memchr_memmem, {
    let t = bb(TEXT);
    check_eq!(memchr::memmem::find(t, b"the"), Some(0));
    check_eq!(memchr::memmem::rfind(t, b"the"), Some(50));
    check_eq!(memchr::memmem::find(t, b"dog sleeps"), Some(54));
    check_eq!(memchr::memmem::find(t, b"cat"), None);
    check_eq!(memchr::memmem::find(t, b""), Some(0));
    check_eq!(memchr::memmem::find_iter(t, b"the").count(), 4);
    check_eq!(memchr::memmem::find_iter(t, b"dog").count(), 2);
    let f = memchr::memmem::Finder::new(bb(&b"lazy"[..]));
    check_eq!(f.find(t), Some(35));
    check_eq!(f.find(&t[36..]), None);
});

test!(byteorder_rw, {
    let b = bb([1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    check_eq!(BigEndian::read_u16(&b), 0x0102);
    check_eq!(LittleEndian::read_u16(&b), 0x0201);
    check_eq!(BigEndian::read_u32(&b[1..]), 0x02030405);
    check_eq!(LittleEndian::read_u64(&b), 0x0807060504030201);
    check_eq!(NetworkEndian::read_u24(&b), 0x010203);
    check_eq!(LittleEndian::read_u48(&b), 0x060504030201);
    check_eq!(BigEndian::read_uint(&b, bb(5)), 0x0102030405);
    check_eq!(BigEndian::read_u128(&b), 0x0102030405060708090a0b0c0d0e0f10);
    check_eq!(BigEndian::read_i16(bb(&[0xff, 0xfe])), -2);
    let mut o = bb([0u8; 8]);
    BigEndian::write_u32(&mut o, bb(0xdeadbeef));
    LittleEndian::write_u16(&mut o[4..], 0x1234);
    BigEndian::write_i16(&mut o[6..], -2);
    check_eq!(o, [0xde, 0xad, 0xbe, 0xef, 0x34, 0x12, 0xff, 0xfe]);
    let mut v = [0u32; 2];
    LittleEndian::read_u32_into(&b[..8], &mut v);
    check_eq!(v, [0x04030201, 0x08070605]);
    BigEndian::from_slice_u32(&mut v);
    check_eq!(v[0], 0x01020304);
    check!(rt::catch(|| BigEndian::read_u32(bb(&[1u8, 2][..]))).is_err());
});

test!(itoa_buffer, {
    let mut b = itoa::Buffer::new();
    check_eq!(b.format(bb(0u8)), "0");
    check_eq!(b.format(bb(-128i8)), "-128");
    check_eq!(b.format(bb(65535u16)), "65535");
    check_eq!(b.format(bb(i32::MIN)), "-2147483648");
    check_eq!(b.format(bb(u64::MAX)), "18446744073709551615");
    check_eq!(b.format(bb(i64::MIN)), "-9223372036854775808");
    check_eq!(b.format(bb(u128::MAX)), "340282366920938463463374607431768211455");
    check_eq!(b.format(bb(1234567usize)), "1234567");
});
