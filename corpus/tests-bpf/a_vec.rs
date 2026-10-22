// SPDX-License-Identifier: GPL-2.0
//! alloc::vec::Vec
#![no_std]
#![no_main]
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};

test!(vec_push_pop, {
    let mut v = Vec::new();
    check!(v.is_empty() && v.capacity() == 0);
    for i in 0..bb(100u64) {
        v.push(i * i);
    }
    check_eq!(v.len(), 100);
    check!(v.capacity() >= 100);
    check_eq!(v[99], 9801);
    check_eq!(v.iter().sum::<u64>(), 328350);
    check_eq!(v.pop(), Some(9801));
    check_eq!(v.last(), Some(&9604));
    while v.pop().is_some() {}
    check!(v.is_empty());
    check_eq!(v.pop(), None);
});

test!(vec_insert_remove, {
    let mut v = vec![1, 2, 3, 4, 5];
    v.insert(bb(0), 0);
    v.insert(bb(6), 6);
    v.insert(bb(3), 99);
    check_eq!(v, [0, 1, 2, 99, 3, 4, 5, 6]);
    check_eq!(v.remove(bb(3)), 99);
    check_eq!(v.remove(0), 0);
    check_eq!(v.swap_remove(bb(1)), 2);
    check_eq!(v, [1, 6, 3, 4, 5]);
    v.truncate(bb(2));
    check_eq!(v, [1, 6]);
    v.clear();
    check!(v.is_empty());
});

test!(vec_capacity, {
    let mut v: Vec<u32> = Vec::with_capacity(bb(10));
    check!(v.capacity() >= 10 && v.len() == 0);
    let n = rt::allocs();
    for i in 0..10 {
        v.push(i);
    }
    check_eq!(rt::allocs(), n);
    v.reserve(bb(100));
    check!(v.capacity() >= 110);
    v.shrink_to_fit();
    check!(v.capacity() >= 10 && v.capacity() < 110);
    v.reserve_exact(bb(5));
    check!(v.capacity() >= 15);
    check!(v.try_reserve(bb(10)).is_ok());
    check!(v.try_reserve(bb(usize::MAX)).is_err());
    check_eq!(v.iter().sum::<u32>(), 45);
});

test!(vec_extend_append, {
    let mut v = vec![1u32, 2];
    v.extend([3, 4].iter());
    v.extend(bb(5)..8);
    v.extend_from_slice(bb(&[8, 9]));
    check_eq!(v, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let mut w = vec![10, 11];
    v.append(&mut w);
    check!(w.is_empty() && v.len() == 11);
    v.extend_from_within(bb(0)..2);
    check_eq!(&v[9..], &[10, 11, 1, 2]);
    let tail = v.split_off(bb(10));
    check!(v.len() == 10 && tail == [11, 1, 2]);
    v.resize(bb(12), 7);
    check_eq!(&v[9..], &[10, 7, 7]);
    v.resize(bb(1), 0);
    check_eq!(v, [1]);
    let mut n = 0;
    v.resize_with(3, || {
        n += 10;
        n
    });
    check_eq!(v, [1, 10, 20]);
});

test!(vec_retain_dedup_drain, {
    let mut v: Vec<i32> = (1..=bb(20)).collect();
    v.retain(|x| x % 3 != 0);
    check_eq!(v.len(), 14);
    v.retain_mut(|x| {
        *x *= 2;
        *x < 30
    });
    check_eq!(v, [2, 4, 8, 10, 14, 16, 20, 22, 26, 28]);
    let d: Vec<i32> = v.drain(bb(2)..5).collect();
    check_eq!(d, [8, 10, 14]);
    check_eq!(v, [2, 4, 16, 20, 22, 26, 28]);
    v.drain(..bb(2));
    v.drain(bb(3)..);
    check_eq!(v, [16, 20, 22]);
    let mut w = vec![1, 1, 2, 2, 2, 3, 1, 1];
    w.dedup();
    check_eq!(w, [1, 2, 3, 1]);
    let mut k = vec![10, 11, 20, 25, 30];
    k.dedup_by_key(|x| *x / 10);
    check_eq!(k, [10, 20, 30]);
    let mut s = vec![1, 2, 3, 4, 5];
    let removed: Vec<i32> = s.splice(bb(1)..3, [7, 8, 9]).collect();
    check_eq!(removed, [2, 3]);
    check_eq!(s, [1, 7, 8, 9, 4, 5]);
    let ev: Vec<i32> = s.extract_if(.., |x| *x % 2 == 0).collect();
    check_eq!(ev, [8, 4]);
    check_eq!(s, [1, 7, 9, 5]);
});

test!(vec_sort_stable, {
    let mut v = vec![(3, 'a'), (1, 'b'), (3, 'c'), (2, 'd'), (1, 'e'), (3, 'f')];
    v.sort_by_key(|p| bb(p.0));
    check_eq!(v, [(1, 'b'), (1, 'e'), (2, 'd'), (3, 'a'), (3, 'c'), (3, 'f')]);
    v.sort_by(|a, b| b.1.cmp(&a.1));
    check_eq!(v[0], (3, 'f'));
    v.sort();
    check_eq!(v[0], (1, 'b'));
    let mut n: Vec<u32> = (0..bb(100)).map(|i| (i * 37 + 11) % 101).collect();
    n.sort();
    check!(n.is_sorted());
    n.sort_by_cached_key(|x| 1000 - x);
    check!(n.is_sorted_by(|a, b| a >= b));
});

test!(vec_from_into, {
    let v: Vec<u8> = Vec::from(bb([1, 2, 3]));
    let b: Box<[u8]> = v.into_boxed_slice();
    check_eq!(b.len(), 3);
    let v = b.into_vec();
    check_eq!(v, [1, 2, 3]);
    let v2 = bb(&[4u8, 5][..]).to_vec();
    let c = [v.as_slice(), v2.as_slice()].concat();
    check_eq!(c, [1, 2, 3, 4, 5]);
    let j = [v.as_slice(), v2.as_slice()].join(&0);
    check_eq!(j, [1, 2, 3, 0, 4, 5]);
    check_eq!(v2.repeat(bb(3)), [4, 5, 4, 5, 4, 5]);
    let a: [u8; 3] = v.try_into().unwrap();
    check_eq!(a, [1, 2, 3]);
    let s: Vec<u8> = Vec::from(bb("hi"));
    check_eq!(s, b"hi");
    check_eq!(vec![bb(7u16); 4], [7, 7, 7, 7]);
    let cl = c.clone();
    check!(cl == c && cl.as_ptr() != c.as_ptr());
});

test!(vec_into_iter, {
    let v = vec![1u32, 2, 3, 4, 5, 6];
    let mut it = v.into_iter();
    check_eq!(it.next(), Some(1));
    check_eq!(it.next_back(), Some(6));
    check_eq!(it.as_slice(), &[2, 3, 4, 5]);
    check_eq!(it.len(), 4);
    let rest: Vec<u32> = it.rev().collect();
    check_eq!(rest, [5, 4, 3, 2]);
    let (ev, od): (Vec<u32>, Vec<u32>) = rest.into_iter().partition(|x| x % 2 == 0);
    check!(ev == [4, 2] && od == [5, 3]);
    let (a, b): (Vec<u32>, Vec<char>) = vec![(1, 'x'), (2, 'y')].into_iter().unzip();
    check!(a == [1, 2] && b == ['x', 'y']);
    let r: Result<Vec<u32>, u32> = vec![Ok(1), Err(bb(7)), Ok(3)].into_iter().collect();
    check_eq!(r, Err(7));
    let o: Option<Vec<u32>> = vec![Some(1), Some(bb(2))].into_iter().collect();
    check_eq!(o, Some(vec![1, 2]));
});

test!(vec_nested, {
    let mut g: Vec<Vec<u32>> = Vec::new();
    for i in 0..bb(8u32) {
        g.push((0..i).collect());
    }
    check_eq!(g.iter().map(|r| r.len()).sum::<usize>(), 28);
    check_eq!(g[7][6], 6);
    g[3].push(100);
    check_eq!(g.iter().flatten().sum::<u32>(), 56 + 100);
    g.retain(|r| r.len() % 2 == 0);
    check_eq!(g.len(), 5);
    let flat: Vec<u32> = g.concat();
    check_eq!(flat.len(), 0 + 2 + 4 + 4 + 6);
    let t = vec![vec![bb(1); 3]; 2];
    check_eq!(t[1][2], 1);
});

static mut DROPS: u32 = 0;
struct D(u32);
impl Drop for D {
    fn drop(&mut self) {
        unsafe { DROPS += self.0 };
    }
}
fn drops() -> u32 {
    unsafe { core::ptr::read_volatile(&raw const DROPS) }
}

test!(vec_drops_elements, {
    let d = drops();
    let mut v: Vec<D> = (1..=bb(5)).map(D).collect();
    drop(v.pop());
    check_eq!(drops() - d, 5);
    v.truncate(3);
    check_eq!(drops() - d, 9);
    drop(v.remove(0));
    check_eq!(drops() - d, 10);
    let mut it = v.into_iter();
    drop(it.next());
    check_eq!(drops() - d, 12);
    drop(it);
    check_eq!(drops() - d, 15);
});

test!(vec_of_boxes_and_strings, {
    let mut v: Vec<Box<u64>> = (0..bb(10)).map(Box::new).collect();
    v.sort_by(|a, b| b.cmp(a));
    check_eq!(*v[0], 9);
    v.swap(0, 9);
    check_eq!(v.iter().map(|b| **b).sum::<u64>(), 45);
    let s: Vec<String> = ["b", "a", "c"].iter().map(|x| String::from(bb(*x))).collect();
    let mut t = s.clone();
    t.sort();
    check_eq!(t.join("-"), "a-b-c");
    check_eq!(s.concat(), "bac");
    check!(s.contains(&String::from("c")));
});

test!(vec_zst_and_big, {
    let mut z = Vec::new();
    let n = rt::allocs();
    for _ in 0..bb(1000) {
        z.push(());
    }
    check_eq!(z.len(), 1000);
    check_eq!(rt::allocs(), n);
    check_eq!(z.capacity(), usize::MAX);
    let mut big: Vec<[u64; 32]> = Vec::new();
    for i in 0..bb(20u64) {
        big.push([i; 32]);
    }
    check_eq!(big.iter().map(|a| a[31]).sum::<u64>(), 190);
    let zeroed = vec![0u8; bb(100000)];
    check_eq!(zeroed.iter().map(|&b| b as u32).sum::<u32>(), 0);
});

test!(leaks vec_leak, {
    let v = vec![bb(1u32), 2, 3];
    let s: &'static mut [u32] = v.leak();
    s[0] = 10;
    check_eq!(s.iter().sum::<u32>(), 15);
});

test!(vec_raw_parts, {
    let mut v = core::mem::ManuallyDrop::new(vec![bb(1u32), 2, 3]);
    let (p, len, cap) = (v.as_mut_ptr(), v.len(), v.capacity());
    unsafe {
        *p.add(1) = 20;
        let w = Vec::from_raw_parts(p, len, cap);
        check_eq!(w, [1, 20, 3]);
    }
    let mut u: Vec<u8> = Vec::with_capacity(4);
    u.spare_capacity_mut()[0].write(bb(9));
    unsafe { u.set_len(1) };
    check_eq!(u, [9]);
});
