// SPDX-License-Identifier: GPL-2.0
//! core: slices. No allocation.
#![no_std]
#![no_main]
use rt::{bb, check, check_eq, test};

const D: [i32; 16] = [9, -4, 7, 0, 15, 3, -8, 12, 1, 6, -2, 11, 5, 14, -6, 10];
const SORTED: [i32; 16] = [-8, -6, -4, -2, 0, 1, 3, 5, 6, 7, 9, 10, 11, 12, 14, 15];

test!(slice_sort_unstable, {
    let mut v = bb(D);
    v.sort_unstable();
    check_eq!(v, SORTED);
    v.sort_unstable_by(|a, b| b.cmp(a));
    check!(v[0] == 15 && v[15] == -8 && v.is_sorted_by(|a, b| a >= b));
    v.sort_unstable_by_key(|x| x.abs());
    check!(v[0] == 0 && v[1] == 1 && v[15] == 15);
});

test!(slice_sort_unstable_long, {
    let mut v = [0u32; 200];
    let mut x = bb(12345u32);
    for e in v.iter_mut() {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        *e = x >> 16;
    }
    let sum: u64 = v.iter().map(|&e| e as u64).sum();
    v.sort_unstable();
    check!(v.is_sorted());
    check_eq!(v.iter().map(|&e| e as u64).sum::<u64>(), sum);
});

test!(slice_select_nth, {
    let mut v = bb(D);
    let (lo, mid, hi) = v.select_nth_unstable(bb(8));
    check_eq!(*mid, 6);
    check!(lo.iter().all(|x| *x <= 6) && hi.iter().all(|x| *x >= 6));
});

test!(slice_binary_search, {
    let v = bb(SORTED);
    check_eq!(v.binary_search(&7), Ok(9));
    check_eq!(v.binary_search(&-8), Ok(0));
    check_eq!(v.binary_search(&15), Ok(15));
    check_eq!(v.binary_search(&8), Err(10));
    check_eq!(v.binary_search(&100), Err(16));
    check_eq!(v.binary_search(&-100), Err(0));
    check_eq!(v.binary_search_by(|p| p.cmp(&bb(3))), Ok(6));
    check_eq!(v.binary_search_by_key(&bb(20), |x| x * 2), Ok(11));
    check_eq!(v.partition_point(|x| *x < 0), 4);
    check_eq!(v[..0].binary_search(&1), Err(0));
});

test!(slice_chunks_windows, {
    let v = bb(D);
    check_eq!(v.chunks(5).count(), 4);
    check_eq!(v.chunks(5).last().map(|c| c.len()), Some(1));
    check_eq!(v.chunks_exact(5).count(), 3);
    check_eq!(v.chunks_exact(5).remainder(), &[10]);
    check_eq!(v.rchunks(5).next(), Some(&[11, 5, 14, -6, 10][..]));
    check_eq!(v.chunks(4).map(|c| c.iter().sum::<i32>()).max(), Some(23));
    check_eq!(v.windows(3).count(), 14);
    check_eq!(v.windows(2).filter(|w| w[0] < w[1]).count(), 7);
    check_eq!(v.windows(3).map(|w| w.iter().sum::<i32>()).max(), Some(30));
    check_eq!(v.windows(17).count(), 0);
    let mut m = bb(D);
    for c in m.chunks_mut(4) {
        c[0] = 0;
    }
    check_eq!(m[0] + m[4] + m[8] + m[12], 0);
    check_eq!(v.chunk_by(|a, b| a.signum() == b.signum()).count(), 11);
});

test!(slice_rotate_reverse_swap, {
    let mut v = bb([1, 2, 3, 4, 5, 6, 7]);
    v.rotate_left(bb(2));
    check_eq!(v, [3, 4, 5, 6, 7, 1, 2]);
    v.rotate_right(bb(3));
    check_eq!(v, [7, 1, 2, 3, 4, 5, 6]);
    v.reverse();
    check_eq!(v, [6, 5, 4, 3, 2, 1, 7]);
    v.swap(bb(0), bb(6));
    check_eq!(v, [7, 5, 4, 3, 2, 1, 6]);
    let (a, b) = v.split_at_mut(3);
    a.swap_with_slice(&mut b[1..]);
    check_eq!(v, [2, 1, 6, 3, 7, 5, 4]);
    v[1..6].reverse();
    check_eq!(v, [2, 5, 7, 3, 6, 1, 4]);
});

test!(slice_fill_copy, {
    let mut v = bb([0u16; 8]);
    v.fill(bb(7));
    check_eq!(v, [7; 8]);
    v[2..5].fill(1);
    check_eq!(v, [7, 7, 1, 1, 1, 7, 7, 7]);
    let mut n = 0;
    v.fill_with(|| {
        n += 1;
        n
    });
    check_eq!(v, [1, 2, 3, 4, 5, 6, 7, 8]);
    v[..3].copy_from_slice(bb(&[9, 9, 9]));
    v.copy_within(bb(0)..3, 5);
    check_eq!(v, [9, 9, 9, 4, 5, 9, 9, 9]);
    v.copy_within(1..7, 0);
    check_eq!(v, [9, 9, 4, 5, 9, 9, 9, 9]);
    let mut w = [0u16; 8];
    w.clone_from_slice(&v);
    check_eq!(w, v);
});

test!(slice_queries, {
    let v = bb(D);
    check!(v.contains(&15) && !v.contains(&16));
    check!(v.starts_with(&[9, -4]) && v.ends_with(&[-6, 10]) && !v.starts_with(&[9, 4]));
    check!(v.starts_with(&[]));
    check_eq!(v.first(), Some(&9));
    check_eq!(v.last(), Some(&10));
    check_eq!(v.get(bb(16)), None);
    check_eq!(v.get(bb(3)..bb(5)), Some(&[0, 15][..]));
    check_eq!(v.split_first().map(|(a, r)| (*a, r.len())), Some((9, 15)));
    check_eq!(v.split_last().map(|(a, r)| (*a, r.len())), Some((10, 15)));
    check_eq!(v[..0].first(), None);
    check_eq!(v.iter().rev().take(2).sum::<i32>(), 4);
    check_eq!(v.strip_prefix(&[9, -4]).map(|r| r.len()), Some(14));
    check_eq!(unsafe { *v.get_unchecked(bb(4)) }, 15);
});

test!(slice_split, {
    let v = bb(D);
    check_eq!(v.split(|x| *x < 0).count(), 5);
    check_eq!(v.split(|x| *x < 0).map(|s| s.len()).max(), Some(4));
    check_eq!(v.splitn(2, |x| *x == 0).last().map(|s| s.len()), Some(12));
    check_eq!(v.rsplit(|x| *x < 0).next(), Some(&[10][..]));
    check_eq!(v.split_inclusive(|x| *x < 0).next(), Some(&[9, -4][..]));
    let (a, b) = v.split_at(bb(10));
    check!(a.len() == 10 && b[0] == -2);
    check!(v.split_at_checked(bb(17)).is_none());
});

test!(slice_cmp, {
    check!(bb([1, 2, 3]) < bb([1, 2, 4]));
    check!(bb(&[1, 2][..]) < bb(&[1, 2, 0][..]));
    check!(bb(&[2][..]) > bb(&[1, 9, 9][..]));
    check!(bb(&b"abc"[..]) == bb(&b"abc"[..]));
    check!(bb(&b"abc"[..]) != bb(&b"abd"[..]));
    check_eq!(bb(&[1u8, 2][..]).cmp(bb(&[1u8, 2][..])), core::cmp::Ordering::Equal);
    let long_a = bb([7u8; 100]);
    let mut long_b = bb([7u8; 100]);
    check!(long_a == long_b);
    long_b[bb(99)] = 8;
    check!(long_a < long_b);
});

test!(slice_of_structs, {
    #[derive(Clone, Copy, PartialEq, Debug)]
    struct P {
        k: u8,
        v: u64,
    }
    let mut v = bb([P { k: 3, v: 30 }, P { k: 1, v: 10 }, P { k: 2, v: 20 }, P { k: 1, v: 11 }]);
    v.sort_unstable_by_key(|p| (p.k, p.v));
    check_eq!(v.map(|p| p.v), [10, 11, 20, 30]);
    check_eq!(v.iter().position(|p| p.k == 2), Some(2));
    for p in v.iter_mut() {
        p.v += p.k as u64;
    }
    check_eq!(v.iter().map(|p| p.v).sum::<u64>(), 78);
    check_eq!(v.iter().max_by_key(|p| p.v).map(|p| p.k), Some(3));
});

test!(slice_2d, {
    let mut g = bb([[0u8; 6]; 4]);
    for (y, row) in g.iter_mut().enumerate() {
        for (x, c) in row.iter_mut().enumerate() {
            *c = (y * 6 + x) as u8;
        }
    }
    check_eq!(g[bb(3)][bb(5)], 23);
    check_eq!(g.iter().map(|r| r[2] as u32).sum::<u32>(), 2 + 8 + 14 + 20);
    check_eq!(g.as_flattened().len(), 24);
    check_eq!(g.as_flattened()[bb(13)], 13);
    check_eq!(g.concat_sum(), 276);
});

trait ConcatSum {
    fn concat_sum(&self) -> u32;
}
impl<const W: usize, const H: usize> ConcatSum for [[u8; W]; H] {
    fn concat_sum(&self) -> u32 {
        self.iter().flatten().map(|&x| x as u32).sum()
    }
}
