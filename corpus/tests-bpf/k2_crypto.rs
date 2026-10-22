// SPDX-License-Identifier: GPL-2.0
//! crates: sha1, md-5, sha3, hmac, chacha20, aes, rand, rand_chacha. Expected values: RFCs, FIPS, python's hashlib.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};
use sha2::Digest;

fn hex(b: &[u8], want: &str) -> bool {
    if b.len() * 2 != want.len() {
        return false;
    }
    let w = want.as_bytes();
    let d = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
    b.iter().enumerate().all(|(i, x)| *x == d(w[2 * i]) << 4 | d(w[2 * i + 1]))
}

test!(sha1_md5, {
    check!(hex(&sha1::Sha1::digest(bb(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d"));
    check!(hex(&md5::Md5::digest(bb(b"abc")), "900150983cd24fb0d6963f7d28e17f72"));
});

test!(sha3_256, {
    check!(hex(&sha3::Sha3_256::digest(bb(b"abc")), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
});

test!(hmac_sha256, {
    use hmac::{Hmac, KeyInit, Mac};
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(bb(b"key")).unwrap();
    m.update(bb(b"The quick brown fox jumps over the lazy dog"));
    let tag = m.finalize().into_bytes();
    check!(hex(&tag, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
    let mut v = Hmac::<sha2::Sha256>::new_from_slice(bb(b"key")).unwrap();
    v.update(b"The quick brown fox jumps over the lazy dog");
    check!(v.verify_slice(&tag).is_ok());
    let mut w = Hmac::<sha2::Sha256>::new_from_slice(bb(b"kez")).unwrap();
    w.update(b"The quick brown fox jumps over the lazy dog");
    check!(w.verify_slice(&tag).is_err());
});

test!(chacha20_rfc8439, {
    use chacha20::ChaCha20;
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce = bb([0u8, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
    let text = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut buf = bb(*text);
    let mut c = ChaCha20::new(&key.into(), &nonce.into());
    c.seek(64u32);
    c.apply_keystream(&mut buf);
    check!(hex(&buf[..16], "6e2e359a2568f98041ba0728dd0d6981"));
    check!(hex(&buf[buf.len() - 10..], "b40b8eedf2785e42874d"));
    let mut d = ChaCha20::new(&key.into(), &nonce.into());
    d.seek(64u32);
    d.apply_keystream(&mut buf);
    check_eq!(&buf, text);
});

test!(aes128_fips197, {
    use aes::Aes128;
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let plain: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
    let c = Aes128::new(&bb(key).into());
    let mut b = bb(plain).into();
    c.encrypt_block(&mut b);
    check!(hex(&b, "69c4e0d86a7b0430d8cdb78070b4c55a"));
    c.decrypt_block(&mut b);
    check_eq!(&b[..], &plain[..]);
});

test!(aes256_fips197, {
    use aes::Aes256;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let plain: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
    let mut b = bb(plain).into();
    Aes256::new(&bb(key).into()).encrypt_block(&mut b);
    check!(hex(&b, "8ea2b7ca516745bfeafc49904b496089"));
});

test!(rand_chacha_stream, {
    use rand::{Rng, SeedableRng};
    use rand_chacha::{ChaCha8Rng, ChaCha20Rng};
    // the key stream of ChaCha20 with a zero key and nonce
    let mut r = ChaCha20Rng::from_seed(bb([0u8; 32]));
    let mut out = [0u8; 16];
    r.fill_bytes(&mut out);
    check!(hex(&out, "76b8e0ada0f13d90405d6ae55386bd28"));
    let mut a = ChaCha8Rng::seed_from_u64(bb(1));
    let mut b = ChaCha8Rng::seed_from_u64(bb(1));
    let mut c = ChaCha8Rng::seed_from_u64(bb(2));
    check_eq!(a.next_u64(), b.next_u64());
    check!(a.next_u64() != c.next_u64());
});

test!(rand_ranges_shuffle, {
    use rand::seq::{IndexedRandom, SliceRandom};
    use rand::{RngExt, SeedableRng};
    let mut r = rand_pcg::Pcg64::seed_from_u64(bb(42));
    let mut seen = [0u32; 6];
    for _ in 0..600 {
        let d: usize = r.random_range(0..6);
        seen[d] += 1;
    }
    check!(seen.iter().all(|&c| c > 60 && c < 140));
    for _ in 0..100 {
        let v: i32 = r.random_range(-5..=5);
        check!((-5..=5).contains(&v));
    }
    let heads = (0..1000).filter(|_| r.random_bool(0.25)).count();
    check!(heads > 180 && heads < 320);
    let mut v: Vec<u32> = (0..50).collect();
    v.shuffle(&mut r);
    check!(!v.is_sorted());
    v.sort_unstable();
    check!(v.iter().copied().eq(0..50));
    check!(v.choose(&mut r).is_some_and(|x| *x < 50));
    let f: f64 = r.random();
    check!((0.0..1.0).contains(&f));
    let arr: [u8; 8] = r.random();
    check!(arr.iter().any(|x| *x != arr[0]));
});
