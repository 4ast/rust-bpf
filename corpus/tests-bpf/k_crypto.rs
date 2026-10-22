// SPDX-License-Identifier: GPL-2.0
//! crates: sha2, blake2. Expected values are those of python's hashlib.
#![no_std]
#![no_main]
extern crate alloc;
use blake2::{Blake2b512, Blake2s256};
use rt::{bb, check, check_eq, test};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

fn hex(b: &[u8], want: &str) -> bool {
    if b.len() * 2 != want.len() {
        return false;
    }
    let w = want.as_bytes();
    let d = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
    b.iter().enumerate().all(|(i, x)| *x == d(w[2 * i]) << 4 | d(w[2 * i + 1]))
}

test!(sha256_vectors, {
    check!(hex(&Sha256::digest(bb(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    check!(hex(&Sha256::digest(bb(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    check!(!hex(&Sha256::digest(bb(b"abd")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
});

test!(sha256_incremental, {
    let m: [u8; 200] = core::array::from_fn(|i| i as u8);
    let want = "1901da1c9f699b48f6b2636e65cbf73abf99d0441ef67f5c540a42f7051dec6f";
    check!(hex(&Sha256::digest(bb(&m)), want));
    let mut h = Sha256::new();
    h.update(&m[..bb(1)]);
    h.update(&m[1..bb(65)]);
    h.update(&m[65..]);
    check!(hex(&h.finalize(), want));
    let mut r = Sha256::new();
    r.update(b"junk");
    r.reset();
    r.update(&m);
    check!(hex(&r.finalize_reset(), want));
    check_eq!(<Sha256 as Digest>::output_size(), 32);
});

test!(sha224_vector, {
    check!(hex(&Sha224::digest(bb(b"abc")), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
});

test!(sha512_vectors, {
    check!(hex(
        &Sha512::digest(bb(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    ));
    check!(hex(&Sha384::digest(bb(b"abc"))[..16], "cb00753f45a35e8bb5a03d699ac65007"));
});

test!(blake2b_vector, {
    check!(hex(
        &Blake2b512::digest(bb(b"abc")),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    ));
});

test!(blake2s_vectors, {
    check!(hex(&Blake2s256::digest(bb(b"abc")), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
    let m: [u8; 200] = core::array::from_fn(|i| i as u8);
    let mut h = Blake2s256::new();
    h.update(&m[..bb(100)]);
    h.update(&m[100..]);
    check!(hex(&h.finalize(), "6d244e1a06ce4ef578dd0f63aff0936706735119ca9c8d22d86c801414ab9741"));
});
