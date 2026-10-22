// SPDX-License-Identifier: GPL-2.0
//! core::hash
#![no_std]
#![no_main]
#![allow(deprecated)]
use core::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher, SipHasher};
use rt::{bb, check, check_eq, test};

#[derive(Default)]
struct Fnv(u64);
impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.0 == 0 { 0xcbf29ce484222325 } else { self.0 };
        for b in bytes {
            h = (h ^ *b as u64).wrapping_mul(0x100000001b3);
        }
        self.0 = h;
    }
}
fn fnv<T: Hash + ?Sized>(v: &T) -> u64 {
    let mut h = Fnv::default();
    v.hash(&mut h);
    h.finish()
}

test!(hash_fnv_bytes, {
    let mut h = Fnv::default();
    h.write(bb(b"hello"));
    check_eq!(h.finish(), 0xa430d84680aabd0b);
    let mut h = Fnv::default();
    h.write(bb(b""));
    check_eq!(h.finish(), 0xcbf29ce484222325);
});

#[derive(Hash, PartialEq)]
struct Key {
    id: u32,
    name: &'static str,
    tags: [u8; 3],
    opt: Option<i16>,
}
#[derive(Hash)]
enum E {
    A,
    B(u8),
    C { x: u64 },
}

test!(hash_derive, {
    let a = Key { id: bb(1), name: "n", tags: [1, 2, 3], opt: Some(-1) };
    let b = Key { id: bb(1), name: "n", tags: [1, 2, 3], opt: Some(-1) };
    let c = Key { id: bb(1), name: "n", tags: [1, 2, 3], opt: None };
    check_eq!(fnv(&a), fnv(&b));
    check!(fnv(&a) != fnv(&c));
    check!(fnv(&E::A) != fnv(&E::B(0)) && fnv(&E::B(0)) != fnv(&E::B(1)) && fnv(&E::C { x: 0 }) != fnv(&E::A));
    check_eq!(fnv(&bb(1u32)), fnv(&bb(1i32)));
    check!(fnv(&bb(1u32)) != fnv(&bb(1u64)));
    check!(fnv(bb("ab")) != fnv(bb("a")));
    check!(fnv(&("a", "bc")) != fnv(&("ab", "c")));
    check_eq!(fnv(&bb([1u8, 2])[..]), fnv(&bb([1u8, 2])[..]));
    check!(fnv(&bb('x')) != fnv(&bb('y')) && fnv(&bb(true)) != fnv(&bb(false)));
    check_eq!(fnv(&()), 0);
});

test!(hash_siphasher, {
    let mut h = SipHasher::new_with_keys(bb(0x0706050403020100), bb(0x0f0e0d0c0b0a0908));
    h.write(bb(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]));
    check_eq!(h.finish(), 0xa129ca6149be45e5);
    let mut h = SipHasher::new_with_keys(bb(0x0706050403020100), bb(0x0f0e0d0c0b0a0908));
    h.write(bb(&[]));
    check_eq!(h.finish(), 0x726fdb47dd0e0e31);
    let mut a = SipHasher::new();
    let mut b = SipHasher::new();
    a.write_u32(bb(5));
    b.write(&bb(5u32).to_ne_bytes());
    check_eq!(a.finish(), b.finish());
});

test!(hash_build_hasher, {
    let bh = BuildHasherDefault::<Fnv>::default();
    check_eq!(bh.hash_one(bb(7u64)), fnv(&7u64));
    let mut h = bh.build_hasher();
    bb("k").hash(&mut h);
    check_eq!(h.finish(), fnv("k"));
    let mut h = Fnv::default();
    Hash::hash_slice(bb(&[1u16, 2, 3]), &mut h);
    check!(h.finish() != 0);
});
