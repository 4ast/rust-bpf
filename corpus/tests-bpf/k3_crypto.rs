// SPDX-License-Identifier: GPL-2.0
//! Curve arithmetic and an AEAD, vectors from the RFCs.
#![no_std]
#![no_main]
extern crate alloc;
use rt::{bb, check, check_eq, test};

fn hex32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    hex::decode_to_slice(s, &mut o).unwrap();
    o
}

// RFC 7748, 6.1
test!(x25519_rfc7748, {
    use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
    let a = bb(hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    let b = bb(hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    let pa = x25519(a, X25519_BASEPOINT_BYTES);
    let pb = x25519(b, X25519_BASEPOINT_BYTES);
    check_eq!(pa, hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    check_eq!(pb, hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    let k = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    check_eq!(x25519(a, pb), k);
    check_eq!(x25519(b, pa), k);
});

// RFC 8439, 2.8.2
test!(chacha20poly1305_rfc8439, {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let mut key = [0u8; 32];
    for (i, k) in key.iter_mut().enumerate() {
        *k = 0x80 + i as u8;
    }
    let nonce = bb([0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
    let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
    let msg: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let c = ChaCha20Poly1305::new(&bb(key).into());
    let ct = c.encrypt(&nonce.into(), Payload { msg, aad: &aad }).unwrap();
    check_eq!(ct.len(), msg.len() + 16);
    check_eq!(ct[..16], [0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2]);
    check_eq!(ct[msg.len()..], [0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91]);
    let pt = c.decrypt(&nonce.into(), Payload { msg: &ct, aad: &aad }).unwrap();
    check_eq!(pt, msg);
    let mut bad = ct.clone();
    bad[5] ^= 1;
    check!(c.decrypt(&nonce.into(), Payload { msg: &bad, aad: &aad }).is_err());
});
