// SPDX-License-Identifier: GPL-2.0
//! crates: itertools, either
#![no_std]
#![no_main]
extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use either::Either;
use itertools::{Itertools, MinMaxResult};
use rt::{bb, check, check_eq, test};

test!(itertools_no_alloc, {
    let d = bb([3, 1, 4, 1, 5, 9, 2, 6]);
    check_eq!(d.iter().tuple_windows().filter(|(a, b)| a < b).count(), 4);
    check_eq!(d.iter().tuples().map(|(a, b)| a * b).sum::<i32>(), 3 + 4 + 45 + 12);
    check_eq!(d.iter().interleave(d.iter().rev()).take(4).copied().sum::<i32>(), 3 + 6 + 1 + 2);
    check_eq!(d.iter().minmax(), MinMaxResult::MinMax(&1, &9));
    check_eq!(d.iter().position_max(), Some(5));
    check_eq!(d.iter().position_min(), Some(1));
    check_eq!(d.iter().dedup().count(), 8);
    check_eq!(bb([1, 1, 2, 2, 2, 1]).iter().dedup().count(), 3);
    check_eq!(bb([1, 1, 2, 2, 2, 1]).iter().dedup_with_count().map(|(c, _)| c).max(), Some(3));
    check!(bb([2, 2, 2]).iter().all_equal() && !d.iter().all_equal());
    check_eq!(d.iter().copied().fold_while(0, |a, x| {
        if a + x > 10 { itertools::FoldWhile::Done(a) } else { itertools::FoldWhile::Continue(a + x) }
    }).into_inner(), 9);
    check_eq!(d.iter().step_by(3).copied().collect_tuple(), Some((3, 1, 2)));
    check_eq!(d.iter().take_while_inclusive(|x| **x != 4).count(), 3);
    check_eq!(d.iter().with_position().filter(|(p, _)| !p.is_first && !p.is_last).count(), 6);
    check_eq!(d.iter().copied().coalesce(|a, b| if a < b { Ok(a + b) } else { Err((a, b)) }).count(), 4);
    check_eq!(itertools::iterate(bb(1u32), |x| x * 2).nth(10), Some(1024));
    check_eq!(itertools::zip_eq(0..3, 3..6).map(|(a, b)| a * b).sum::<i32>(), 14);
    check_eq!(d.iter().at_most_one().is_err(), true);
    check_eq!(d[..1].iter().exactly_one().ok(), Some(&3));
    check_eq!(d.iter().pad_using(10, |_| &0).count(), 10);
    check_eq!(d.iter().cartesian_product(d[..2].iter()).count(), 16);
    check_eq!(d.iter().merge(d.iter()).count(), 16);
    check_eq!(d.iter().zip_longest(d[..3].iter()).filter(|e| e.is_both()).count(), 3);
});

test!(itertools_sorted_unique, {
    let d = bb([3, 1, 4, 1, 5, 9, 2, 6, 5, 3]);
    check_eq!(d.iter().copied().sorted().collect_vec(), [1, 1, 2, 3, 3, 4, 5, 5, 6, 9]);
    check_eq!(d.iter().copied().sorted_by(|a, b| b.cmp(a)).next(), Some(9));
    check_eq!(d.iter().copied().sorted_by_key(|x| (x % 3, *x)).collect_vec(), [3, 3, 6, 9, 1, 1, 4, 2, 5, 5]);
    check_eq!(d.iter().copied().k_smallest(3).collect_vec(), [1, 1, 2]);
    check_eq!(d.iter().copied().sorted().dedup().count(), 7);
    check_eq!(d.iter().copied().sorted().rev().collect_vec()[0], 9);
});

test!(itertools_join_format, {
    let d = bb([1, 2, 3]);
    check_eq!(d.iter().join(", "), "1, 2, 3");
    check_eq!(alloc::format!("[{}]", d.iter().format("-")), "[1-2-3]");
    check_eq!(alloc::format!("{:02}", d.iter().format("|")), "01|02|03");
    check_eq!(bb(["a", "b"]).iter().join(""), "ab");
    check_eq!(Itertools::intersperse(d.iter().map(|x| x * 2), 0).collect_vec(), [2, 0, 4, 0, 6]);
    check_eq!(core::iter::empty::<u8>().join(","), String::new());
});

test!(itertools_groups, {
    let d = bb([1, 1, 2, 3, 3, 3, 1]);
    let groups: Vec<(i32, usize)> = d.iter().chunk_by(|x| **x).into_iter().map(|(k, g)| (k, g.count())).collect();
    check_eq!(groups, [(1, 2), (2, 1), (3, 3), (1, 1)]);
    let sums: Vec<i32> = d.iter().chunks(3).into_iter().map(|c| c.sum()).collect();
    check_eq!(sums, [4, 9, 1]);
    let (ev, od): (Vec<i32>, Vec<i32>) = d.iter().partition_map(|&x| if x % 2 == 0 { Either::Left(x) } else { Either::Right(x) });
    check!(ev == [2] && od.len() == 6);
    let (a, b) = d.iter().tee();
    check_eq!(a.zip(b.skip(1)).filter(|(x, y)| x == y).count(), 3);
    check_eq!(d.iter().multipeek().peek(), Some(&&1));
});

test!(itertools_combinatorics, {
    let d = bb([1, 2, 3, 4]);
    check_eq!(d.iter().combinations(2).count(), 6);
    check_eq!(d.iter().combinations(2).map(|c| c[0] * c[1]).sum::<i32>(), 35);
    check_eq!(d.iter().permutations(2).count(), 12);
    check_eq!(d[..3].iter().permutations(3).map(|p| *p[0] * 100 + *p[1] * 10 + *p[2]).max(), Some(321));
    check_eq!(d[..3].iter().powerset().count(), 8);
    check_eq!(d[..2].iter().combinations_with_replacement(2).count(), 3);
    check_eq!(d.iter().tuple_combinations().filter(|(a, b, c)| *a + *b > **c).count(), 1);
    check_eq!(vec![0..2, 0..3].into_iter().multi_cartesian_product().count(), 6);
    check_eq!(vec![vec![1, 4], vec![2, 3]].into_iter().kmerge().collect_vec(), [1, 2, 3, 4]);
});

fn pick(left: bool) -> Either<u32, &'static str> {
    if left { Either::Left(5) } else { Either::Right("five") }
}
fn evens_or_all(ev: bool, n: u32) -> impl Iterator<Item = u32> {
    if ev { Either::Left((0..n).step_by(2)) } else { Either::Right(0..n) }
}

test!(either_ops, {
    let l = pick(bb(true));
    let r = pick(bb(false));
    check!(l.is_left() && r.is_right());
    check_eq!(l.left(), Some(5));
    check_eq!(l.right(), None);
    check_eq!(r.flip().left(), Some("five"));
    check_eq!(l.map_left(|x| x * 2).left(), Some(10));
    check_eq!(r.either(|n| n as usize, |s| s.len()), 4);
    check_eq!(l.left_or(0) + r.left_or(1), 6);
    check_eq!(evens_or_all(bb(true), 10).sum::<u32>(), 20);
    check_eq!(evens_or_all(bb(false), 10).sum::<u32>(), 45);
    let same: Either<u8, u8> = if bb(true) { Either::Left(1) } else { Either::Right(2) };
    check_eq!(same.into_inner(), 1);
    check_eq!(either::for_both!(r, v => core::mem::size_of_val(&v)), 16);
});
