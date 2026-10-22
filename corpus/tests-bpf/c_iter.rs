// SPDX-License-Identifier: GPL-2.0
//! core: iterators. No allocation.
#![no_std]
#![no_main]
use rt::{bb, check, check_eq, test};

static DATA: [i64; 12] = [5, -3, 8, 0, 13, -7, 2, 2, 9, -1, 4, 6];

test!(iter_map_filter_sum, {
    let d = bb(&DATA);
    check_eq!(d.iter().sum::<i64>(), 38);
    check_eq!(d.iter().map(|x| x * x).sum::<i64>(), 458);
    check_eq!(d.iter().filter(|x| **x < 0).count(), 3);
    check_eq!(d.iter().filter(|x| **x > 0).map(|x| x * 2).sum::<i64>(), 98);
    check_eq!(d.iter().filter_map(|&x| if x > 5 { Some(x - 5) } else { None }).product::<i64>(), 3 * 8 * 4);
    check_eq!(d.iter().copied().fold(0i64, |a, x| a * 3 + x), 890280);
});

test!(iter_minmax, {
    let d = bb(&DATA);
    check_eq!(d.iter().max(), Some(&13));
    check_eq!(d.iter().min(), Some(&-7));
    check_eq!(d.iter().max_by_key(|x| x.abs()), Some(&13));
    check_eq!(d.iter().min_by_key(|x| (**x - 3).abs()), Some(&2));
    check_eq!(d.iter().min_by(|a, b| b.cmp(a)), Some(&13));
    check_eq!(d.iter().position(|&x| x == 13), Some(4));
    check_eq!(d.iter().rposition(|&x| x == 2), Some(7));
    check_eq!(d[..0].iter().max(), None);
});

test!(iter_any_all_find, {
    let d = bb(&DATA);
    check!(d.iter().any(|&x| x == 9));
    check!(!d.iter().any(|&x| x == 10));
    check!(d.iter().all(|&x| x > -8));
    check_eq!(d.iter().find(|&&x| x > 8), Some(&13));
    check_eq!(d.iter().find_map(|&x| if x < -3 { Some(x * 2) } else { None }), Some(-14));
    check_eq!(d.iter().rev().find(|&&x| x < 0), Some(&-1));
});

test!(iter_zip_enumerate_chain, {
    let d = bb(&DATA);
    check_eq!(d.iter().zip(d.iter().skip(1)).filter(|(a, b)| a < b).count(), 6);
    check_eq!(d.iter().enumerate().map(|(i, x)| i as i64 * x).sum::<i64>(), 225);
    check_eq!(d[..3].iter().chain(d[9..].iter()).sum::<i64>(), 19);
    check_eq!(d.iter().zip(d.iter().rev()).map(|(a, b)| a * b).sum::<i64>(), 44);
    let (mut a, mut b) = (0, 0);
    for (i, x) in d.iter().enumerate() {
        if i % 2 == 0 { a += x } else { b += x }
    }
    check!(a == 41 && b == -3);
});

test!(iter_skip_take_step, {
    let d = bb(&DATA);
    check_eq!(d.iter().skip(2).take(3).sum::<i64>(), 21);
    check_eq!(d.iter().step_by(5).sum::<i64>(), 5 - 7 + 4);
    check_eq!(d.iter().skip_while(|x| **x != 13).count(), 8);
    check_eq!(d.iter().take_while(|x| **x != 13).count(), 4);
    check_eq!(d.iter().map_while(|&x| if x != 0 { Some(x) } else { None }).sum::<i64>(), 10);
    check_eq!(d.iter().nth(5), Some(&-7));
    check_eq!(d.iter().nth(12), None);
    check_eq!(d.iter().last(), Some(&6));
    check_eq!(d.iter().rev().skip(1).step_by(2).count(), 6);
    check_eq!((0..bb(100u32)).step_by(7).sum::<u32>(), 735);
});

test!(iter_scan_flat_peek, {
    let d = bb(&DATA);
    check_eq!(d.iter().scan(0i64, |s, &x| { *s += x; Some(*s) }).max(), Some(38));
    check_eq!(d.chunks(4).flat_map(|c| c.iter().take(2)).sum::<i64>(), 5 - 3 + 13 - 7 + 9 - 1);
    check_eq!(d.chunks(5).map(|c| c.iter()).flatten().count(), 12);
    let mut it = d.iter().peekable();
    let mut runs = 0;
    while let Some(x) = it.next() {
        if it.peek() == Some(&x) {
            runs += 1;
        }
    }
    check_eq!(runs, 1);
    let mut it = d.iter().peekable();
    check_eq!(it.next_if(|x| **x == 5), Some(&5));
    check_eq!(it.next_if(|x| **x == 5), None);
    let mut seen = 0;
    check_eq!(d.iter().inspect(|_| seen += 1).take(4).count(), 4);
    check_eq!(seen, 4);
});

test!(iter_cycle_repeat_sources, {
    let d = bb(&DATA);
    check_eq!(d[..3].iter().cycle().take(7).sum::<i64>(), 25);
    check_eq!(core::iter::repeat(bb(3u64)).take(5).sum::<u64>(), 15);
    check_eq!(core::iter::once(bb(3u64)).chain(core::iter::empty()).count(), 1);
    let mut n = 0u64;
    check_eq!(core::iter::repeat_with(|| { n += 1; n * n }).take(bb(4)).sum::<u64>(), 30);
    check_eq!(core::iter::successors(Some(bb(1u64)), |x| x.checked_mul(10)).count(), 20);
    let mut st = (0u64, 1u64);
    let fib = core::iter::from_fn(|| { st = (st.1, st.0 + st.1); Some(st.0) });
    check_eq!(fib.take_while(|&x| x < bb(1000)).last(), Some(987));
    check_eq!(core::iter::zip(0..bb(4u8), 4..8u8).map(|(a, b)| a * b).sum::<u8>(), 38);
});

test!(iter_ranges, {
    check_eq!((1..=bb(100u64)).sum::<u64>(), 5050);
    check_eq!((1..=bb(20u64)).product::<u64>(), 2432902008176640000);
    check_eq!((bb(0i32)..10).rev().map(|x| x - 5).filter(|x| x % 2 == 0).sum::<i32>(), 0);
    check_eq!((bb(10u8)..5).count(), 0);
    check_eq!((bb(250u8)..=255).count(), 6);
    check_eq!((bb('a')..='e').count(), 5);
    check!((0..bb(10)).contains(&9) && !(0..bb(10)).contains(&10));
    check_eq!((0..bb(10usize)).len(), 10);
    check_eq!((0..bb(1u128 << 70)).nth(5), Some(5));
});

test!(iter_cmp, {
    let d = bb(&DATA);
    check!(d[..3].iter().lt(d[4..].iter()));
    check!(d.iter().eq(DATA.iter()));
    check!(d.iter().ne(d.iter().rev()));
    check_eq!(d[..2].iter().cmp(d[..3].iter()), core::cmp::Ordering::Less);
    check!(!d.is_sorted());
    check!(d.iter().map(|x| x * 0).is_sorted());
    check!(d[6..9].is_sorted());
});

test!(iter_try_fold, {
    let d = bb(&DATA);
    let r = d.iter().try_fold(0i8, |a, &x| a.checked_add((x as i8).checked_mul(10)?));
    check_eq!(r, None);
    let r: Option<i64> = d.iter().map(|&x| if x > -10 { Some(x) } else { None }).sum();
    check_eq!(r, Some(38));
    let r: Result<i64, i64> = d.iter().map(|&x| if x >= 0 { Ok(x) } else { Err(x) }).sum();
    check_eq!(r, Err(-3));
    let mut n = 0;
    let r = d.iter().try_for_each(|&x| { n += 1; if x == 0 { Err(n) } else { Ok(()) } });
    check_eq!(r, Err(4));
    check_eq!(d.iter().copied().reduce(|a, b| a.max(b)), Some(13));
});

test!(iter_arrays, {
    let a: [u32; 8] = core::array::from_fn(|i| (i * i) as u32 + bb(1));
    check_eq!(a.iter().sum::<u32>(), 148);
    let b = a.map(|x| x as u64 * 2);
    check_eq!(b[7], 100);
    let mut s = 0;
    for x in b {
        s += x;
    }
    check_eq!(s, 296);
    check_eq!(a.into_iter().rev().next(), Some(50));
    let [x, y, ..] = a;
    check_eq!(x + y, 3);
    check_eq!(a.as_chunks::<4>().0.len(), 2);
    check_eq!(a.first_chunk::<2>(), Some(&[1, 2]));
});

struct Countdown(u32);
impl Iterator for Countdown {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.0 == 0 {
            return None;
        }
        self.0 -= 1;
        Some(self.0)
    }
}
impl DoubleEndedIterator for Bits {
    fn next_back(&mut self) -> Option<u32> {
        if self.0 == 0 {
            return None;
        }
        let b = 63 - self.0.leading_zeros();
        self.0 &= !(1 << b);
        Some(b)
    }
}
struct Bits(u64);
impl Iterator for Bits {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.0 == 0 {
            return None;
        }
        let b = self.0.trailing_zeros();
        self.0 &= self.0 - 1;
        Some(b)
    }
}

test!(iter_custom, {
    check_eq!(Countdown(bb(10)).sum::<u32>(), 45);
    check_eq!(Countdown(bb(10)).zip(Countdown(5)).map(|(a, b)| a * b).sum::<u32>(), 36 + 24 + 14 + 6);
    check_eq!(Bits(bb(0x8000_0000_0000_1011)).sum::<u32>(), 63 + 12 + 4);
    check_eq!(Bits(bb(0x8000_0000_0000_1011)).rev().nth(1), Some(12));
    let mut it = Countdown(bb(5));
    check_eq!(it.by_ref().take(2).count(), 2);
    check_eq!(it.next(), Some(2));
    let it: &mut dyn Iterator<Item = u32> = &mut Countdown(bb(4));
    check_eq!(it.map(|x| x + 1).product::<u32>(), 24);
});

test!(iter_fuse_size_hint, {
    let d = bb(&DATA);
    check_eq!(d.iter().size_hint(), (12, Some(12)));
    check_eq!(d.iter().filter(|x| **x > 0).size_hint(), (0, Some(12)));
    check_eq!(d.iter().chain(d.iter()).size_hint(), (24, Some(24)));
    let mut it = Countdown(bb(1)).fuse();
    check!(it.next() == Some(0) && it.next().is_none() && it.next().is_none());
    check_eq!(d.iter().len(), 12);
});
