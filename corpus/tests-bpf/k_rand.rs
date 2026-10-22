// SPDX-License-Identifier: GPL-2.0
//! crates: rand_core, rand_xoshiro, rand_pcg
#![no_std]
#![no_main]
extern crate alloc;
use rand_core::{Rng, SeedableRng};
use rand_pcg::{Pcg32, Pcg64, Pcg64Mcg};
use rand_xoshiro::{SplitMix64, Xoroshiro128StarStar, Xoshiro128PlusPlus, Xoshiro256PlusPlus, Xoshiro256StarStar};
use rt::{bb, check, check_eq, test};

test!(rand_splitmix_reference, {
    let mut r = SplitMix64::seed_from_u64(bb(1234567));
    check_eq!(r.next_u64(), 0x599ed017fb08fc85);
    check_eq!(r.next_u64(), 0x2c73f08458540fa5);
    check_eq!(r.next_u64(), 0x883ebce5a3f27c77);
});

test!(rand_pcg32_reference, {
    let mut r = Pcg32::new(bb(42), bb(54));
    check_eq!(r.next_u32(), 0xa15c02b7);
    check_eq!(r.next_u32(), 0x7b47f409);
    check_eq!(r.next_u32(), 0xba1d3330);
});

test!(rand_xoshiro256_reference, {
    // s = [1, 2, 3, 4]: the vector of the reference implementation
    let mut seed = [0u8; 32];
    for i in 0..4 {
        seed[i * 8] = bb(i as u8 + 1);
    }
    let mut r = Xoshiro256PlusPlus::from_seed(seed);
    check_eq!(r.next_u64(), 41943041);
    check_eq!(r.next_u64(), 58720359);
    check_eq!(r.next_u64(), 3588806011781223);
    let mut s = Xoshiro256StarStar::from_seed(seed);
    check_eq!(s.next_u64(), 11520);
    check_eq!(s.next_u64(), 0);
    check_eq!(s.next_u64(), 1509978240);
});

fn looks_random<R: Rng>(r: &mut R) -> bool {
    let mut ones = 0;
    let mut seen = 0u64;
    for _ in 0..256 {
        let v = r.next_u64();
        ones += v.count_ones();
        seen |= 1 << (v >> 58);
    }
    // 256 * 32 = 8192 expected
    ones > 7800 && ones < 8600 && seen.count_ones() > 55
}

test!(rand_statistics, {
    check!(looks_random(&mut Xoshiro256PlusPlus::seed_from_u64(bb(1))));
    check!(looks_random(&mut Xoroshiro128StarStar::seed_from_u64(bb(2))));
    check!(looks_random(&mut Xoshiro128PlusPlus::seed_from_u64(bb(3))));
    check!(looks_random(&mut Pcg32::seed_from_u64(bb(4))));
    check!(looks_random(&mut Pcg64::seed_from_u64(bb(5))));
    check!(looks_random(&mut Pcg64Mcg::seed_from_u64(bb(6))));
});

test!(rand_fill_clone_jump, {
    let mut a = Xoshiro256PlusPlus::seed_from_u64(bb(7));
    let mut b = a.clone();
    check_eq!(a.next_u64(), b.next_u64());
    let mut buf = [0u8; 37];
    a.fill_bytes(&mut buf);
    check!(buf.iter().any(|x| *x != 0) && buf[36] != buf[35]);
    let mut buf2 = [0u8; 37];
    b.fill_bytes(&mut buf2);
    check_eq!(buf, buf2);
    b.jump();
    check!(a.next_u64() != b.next_u64());
    let mut p = Pcg32::seed_from_u64(bb(8));
    let mut q = p.clone();
    for _ in 0..10 {
        p.next_u32();
    }
    q.advance(10);
    check_eq!(p.next_u32(), q.next_u32());
    let d: &mut dyn Rng = &mut p;
    check!(d.next_u32() != d.next_u32());
});

struct Counter(u64);
impl rand_core::TryRng for Counter {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 += 1;
        Ok(self.0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for b in dst {
            *b = self.try_next_u64()? as u8;
        }
        Ok(())
    }
}

test!(rand_core_own_rng, {
    let mut c = Counter(bb(10));
    check_eq!(c.next_u64(), 11);
    check_eq!(c.next_u32(), 12);
    let mut b = [0u8; 3];
    c.fill_bytes(&mut b);
    check_eq!(b, [13, 14, 15]);
    let mut x = Xoshiro256PlusPlus::from_rng(&mut c);
    check!(x.next_u64() != 0);
});
