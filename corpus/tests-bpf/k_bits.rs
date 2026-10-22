// SPDX-License-Identifier: GPL-2.0
//! crates: bitflags, fixedbitset, bitvec
#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct Perm: u8 {
        const R = 0b001;
        const W = 0b010;
        const X = 0b100;
        const RW = Self::R.bits() | Self::W.bits();
    }
}

test!(bitflags_ops, {
    let mut p = bb(Perm::R) | Perm::X;
    check_eq!(p.bits(), 0b101);
    check!(p.contains(Perm::R) && !p.contains(Perm::W) && !p.contains(Perm::RW));
    check!(p.intersects(Perm::RW));
    p.insert(Perm::W);
    check!(p.is_all() && p.contains(Perm::RW));
    p.remove(Perm::X);
    check_eq!(p, Perm::RW);
    p.toggle(Perm::R);
    check_eq!(p, Perm::W);
    p.set(Perm::X, bb(true));
    check_eq!(!p, Perm::R);
    check_eq!(p & Perm::X, Perm::X);
    check_eq!(p - Perm::X, Perm::W);
    check_eq!(p ^ Perm::all(), Perm::R);
    check!(Perm::empty().is_empty());
    check_eq!(Perm::from_bits(bb(0b011)), Some(Perm::RW));
    check_eq!(Perm::from_bits(bb(0b1000)), None);
    check_eq!(Perm::from_bits_truncate(bb(0b1001)), Perm::R);
    check_eq!(Perm::from_name(bb("X")), Some(Perm::X));
    check_eq!(p.iter().count(), 2);
    check_eq!(Perm::all().iter_names().map(|(_, f)| f.bits()).fold(0, |a, b| a | b), 0b111);
});

test!(bitflags_fmt, {
    let s = alloc::format!("{:?}", bb(Perm::R | Perm::X));
    check_eq!(s, "Perm(R | X)");
    check_eq!(alloc::format!("{:?}", Perm::empty()), "Perm(0x0)");
});

test!(fixedbitset_ops, {
    use fixedbitset::FixedBitSet;
    let mut a = FixedBitSet::with_capacity(bb(200));
    for i in (0..200).step_by(3) {
        a.insert(i);
    }
    check_eq!(a.len(), 200);
    check_eq!(a.count_ones(..), 67);
    check!(a.contains(99) && !a.contains(100) && !a.contains(1000));
    check_eq!(a.count_ones(10..20), 3);
    a.set(99, false);
    a.toggle(100);
    check!(!a[99] && a[100]);
    check!(!a.put(101) && a.put(101));
    check_eq!(a.ones().take(3).collect::<Vec<_>>(), [0, 3, 6]);
    check_eq!(a.zeroes().next(), Some(1));
    check_eq!(a.minimum(), Some(0));
    check_eq!(a.maximum(), Some(198));
    let mut b = FixedBitSet::with_capacity(200);
    b.insert_range(bb(50)..60);
    check_eq!(b.count_ones(..), 10);
    check_eq!(a.intersection(&b).count(), 3);
    check_eq!(a.union(&b).count(), 68 + 10 - 3);
    check_eq!(b.difference(&a).count(), 7);
    check!(!a.is_disjoint(&b) && !b.is_subset(&a));
    a.intersect_with(&b);
    check_eq!(a.ones().collect::<Vec<_>>(), [51, 54, 57]);
    a.grow(300);
    check_eq!(a.len(), 300);
    a.clear();
    check!(a.is_clear());
});

test!(bitvec_vec, {
    use bitvec::prelude::*;
    let mut v: BitVec<u8, Lsb0> = BitVec::new();
    for i in 0..bb(20) {
        v.push(i % 3 == 0);
    }
    check_eq!(v.len(), 20);
    check_eq!(v.count_ones(), 7);
    check_eq!(v.count_zeros(), 13);
    check!(v[0] && !v[1] && v[18]);
    check_eq!(v.first_one(), Some(0));
    check_eq!(v.last_one(), Some(18));
    check_eq!(v.first_zero(), Some(1));
    v.set(bb(1), true);
    check_eq!(v.leading_ones(), 2);
    check_eq!(v.pop(), Some(false));
    check_eq!(v.iter_ones().take(3).collect::<Vec<_>>(), [0, 1, 3]);
    check!(v.any() && !v.all() && v.some());
    v.truncate(8);
    check_eq!(v.as_raw_slice(), &[0b0100_1011]);
    v.fill(false);
    check!(v.not_any());
});

test!(bitvec_slices_fields, {
    use bitvec::prelude::*;
    let mut raw = bb([0u8; 4]);
    let bits = raw.view_bits_mut::<Msb0>();
    bits[4..12].store_be(bb(0xabu8));
    check_eq!(bits[4..12].load_be::<u8>(), 0xab);
    bits.set(31, true);
    check_eq!(raw, [0x0a, 0xb0, 0, 1]);
    let a = bitarr![u16, Lsb0; 1, 0, 1, 1];
    check_eq!(a.count_ones(), 3);
    let x = bits![1, 1, 0, 0];
    let y = bits![1, 0, 1, 0];
    let and = x.to_bitvec() & y;
    let or = x.to_bitvec() | y;
    let xor = x.to_bitvec() ^ y;
    check!(and == bits![1, 0, 0, 0] && or == bits![1, 1, 1, 0] && xor == bits![0, 1, 1, 0]);
    let n = bb(0b1011_0000u8);
    check_eq!(n.view_bits::<Lsb0>().iter_ones().collect::<Vec<_>>(), [4, 5, 7]);
    let mut r = bitvec![0, 0, 1, 1, 0];
    r.rotate_left(2);
    check_eq!(r, bits![1, 1, 0, 0, 0]);
    r.reverse();
    check_eq!(r, bits![0, 0, 0, 1, 1]);
});
