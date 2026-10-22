// SPDX-License-Identifier: GPL-2.0
//! crates: fnv, ahash, hash32, siphasher, crc32fast, crc. Expected values are computed elsewhere.
#![no_std]
#![no_main]
extern crate alloc;
use core::hash::{BuildHasher, Hash, Hasher};
use rt::{bb, check, check_eq, test};

test!(fnv_hasher, {
    let mut h = fnv::FnvHasher::default();
    h.write(bb(b"hello"));
    check_eq!(h.finish(), 0xa430d84680aabd0b);
    let mut k = fnv::FnvHasher::with_key(bb(0));
    k.write(b"a");
    check_eq!(k.finish(), 97u64.wrapping_mul(0x100000001b3));
    let b = fnv::FnvBuildHasher::default();
    check_eq!(b.hash_one(bb(1u32)), b.hash_one(bb(1u32)));
    check!(b.hash_one(bb(1u32)) != b.hash_one(bb(2u32)));
});

test!(ahash_seeded, {
    let s = ahash::RandomState::with_seeds(bb(1), 2, 3, 4);
    let t = ahash::RandomState::with_seeds(bb(1), 2, 3, 5);
    check_eq!(s.hash_one(bb("key")), s.hash_one(bb("key")));
    check!(s.hash_one(bb("key")) != s.hash_one(bb("kez")));
    check!(s.hash_one(bb("key")) != t.hash_one(bb("key")));
    check!(s.hash_one(bb(1u64)) != s.hash_one(bb(2u64)));
    let mut h = s.build_hasher();
    (bb(1u8), "x", [1u32, 2]).hash(&mut h);
    check!(h.finish() != 0);
    let long = bb([7u8; 100]);
    check_eq!(s.hash_one(&long[..]), s.hash_one(&long[..]));
    check!(s.hash_one(&long[..]) != s.hash_one(&long[..99]));
    let mut spread = 0u64;
    for i in 0..bb(64u64) {
        spread |= 1 << (s.hash_one(i) & 63);
    }
    check!(spread.count_ones() > 30);
});

test!(ahash_in_hashbrown, {
    let mut m = hashbrown::HashMap::with_hasher(ahash::RandomState::with_seeds(bb(9), 8, 7, 6));
    for i in 0..bb(200u32) {
        m.insert(i, i + 1);
    }
    check_eq!(m.len(), 200);
    check_eq!(m.get(&150), Some(&151));
    check_eq!(m.values().sum::<u32>(), 20100);
});

test!(hash32_hashers, {
    use hash32::Hasher as _;
    let mut f = hash32::FnvHasher::default();
    f.write(bb(b"hello"));
    check_eq!(f.finish32(), 0x4f9f2cab);
    let mut m = hash32::Murmur3Hasher::default();
    m.write(bb(b"hello"));
    check_eq!(m.finish32(), 0x248bfa47);
    let mut e = hash32::Murmur3Hasher::default();
    e.write(bb(b""));
    check_eq!(e.finish32(), 0);
});

test!(siphasher_vectors, {
    use siphasher::sip::{SipHasher13, SipHasher24};
    use siphasher::sip128::{Hasher128, SipHasher24 as Sip128};
    let data = bb([0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    let mut h = SipHasher24::new_with_keys(bb(0x0706050403020100), 0x0f0e0d0c0b0a0908);
    h.write(&data);
    check_eq!(h.finish(), 0xa129ca6149be45e5);
    let mut e = SipHasher24::new_with_keys(bb(0x0706050403020100), 0x0f0e0d0c0b0a0908);
    e.write(&data[..0]);
    check_eq!(e.finish(), 0x726fdb47dd0e0e31);
    let mut a = SipHasher13::new_with_keys(bb(1), 2);
    let mut b = SipHasher13::new_with_keys(bb(1), 2);
    a.write(&data);
    b.write(&data[..7]);
    b.write(&data[7..]);
    check_eq!(a.finish(), b.finish());
    let mut w = Sip128::new_with_keys(bb(0x0706050403020100), 0x0f0e0d0c0b0a0908);
    w.write(&data[..0]);
    check_eq!(w.finish128().as_bytes(), [0xa3, 0x81, 0x7f, 0x04, 0xba, 0x25, 0xa8, 0xe6, 0x6d, 0xf6, 0x72, 0x14, 0xc7, 0x55, 0x02, 0x93]);
});

test!(crc32fast_hash, {
    check_eq!(crc32fast::hash(bb(b"123456789")), 0xcbf43926);
    check_eq!(crc32fast::hash(bb(b"")), 0);
    let m: [u8; 200] = core::array::from_fn(|i| i as u8);
    check_eq!(crc32fast::hash(bb(&m)), 0xed086180);
    let mut h = crc32fast::Hasher::new();
    h.update(&m[..bb(77)]);
    h.update(&m[77..]);
    check_eq!(h.finalize(), 0xed086180);
    let mut a = crc32fast::Hasher::new();
    a.update(&m[..100]);
    let mut b = crc32fast::Hasher::new();
    b.update(&m[100..]);
    a.combine(&b);
    check_eq!(a.finalize(), 0xed086180);
});

test!(crc_catalog, {
    use crc::{CRC_8_SMBUS, CRC_16_IBM_SDLC, CRC_16_XMODEM, CRC_32_ISCSI, CRC_32_ISO_HDLC, CRC_64_XZ, Crc};
    let d = bb(b"123456789");
    check_eq!(Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(d), 0xcbf43926);
    check_eq!(Crc::<u32>::new(&CRC_32_ISCSI).checksum(d), 0xe3069283);
    check_eq!(Crc::<u16>::new(&CRC_16_IBM_SDLC).checksum(d), 0x906e);
    check_eq!(Crc::<u16>::new(&CRC_16_XMODEM).checksum(d), 0x31c3);
    check_eq!(Crc::<u8>::new(&CRC_8_SMBUS).checksum(d), 0xf4);
    check_eq!(Crc::<u64>::new(&CRC_64_XZ).checksum(d), 0x995dc9bbdf1939fa);
    let c = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut g = c.digest();
    g.update(&d[..4]);
    g.update(&d[4..]);
    check_eq!(g.finalize(), 0xcbf43926);
});
