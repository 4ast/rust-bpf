// SPDX-License-Identifier: GPL-2.0
//! Recursion that goes deep at run time. What counts is the result.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};

/// Not a tail call and not something LLVM can turn into a loop
#[inline(never)]
fn sum_to(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    bb(sum_to(bb(n - 1))) + n
}

test!(deep_sum_8, {
    check_eq!(sum_to(bb(8)), 36);
});
test!(deep_sum_16, {
    check_eq!(sum_to(bb(16)), 136);
});
test!(deep_sum_32, {
    check_eq!(sum_to(bb(32)), 528);
});
test!(deep_sum_64, {
    check_eq!(sum_to(bb(64)), 2080);
});
test!(deep_sum_128, {
    check_eq!(sum_to(bb(128)), 8256);
});
test!(deep_sum_1000, {
    check_eq!(sum_to(bb(1000)), 500500);
});

#[inline(never)]
fn fib(n: u32) -> u64 {
    if n < 2 { n as u64 } else { bb(fib(n - 1)) + bb(fib(n - 2)) }
}

test!(deep_fib_20, {
    check_eq!(fib(bb(20)), 6765);
});

#[inline(never)]
fn with_frame(n: u32) -> u64 {
    let mut a = [n as u64; 16];
    if n > 0 {
        a[(n & 15) as usize] += with_frame(n - 1);
    }
    bb(&mut a);
    a.iter().sum::<u64>() & 0xffff_ffff
}
fn with_frame_ref(n: u32) -> u64 {
    let mut r = 0u64;
    for i in 0..=n {
        r = (16 * i as u64 + r) & 0xffff_ffff;
    }
    r
}

test!(deep_frames_128_bytes_10, {
    check_eq!(with_frame(bb(10)), with_frame_ref(10));
});
test!(deep_frames_128_bytes_40, {
    check_eq!(with_frame(bb(40)), with_frame_ref(40));
});

enum List {
    Nil,
    Cons(u32, Box<List>),
}
fn list(n: u32) -> List {
    let mut l = List::Nil;
    for i in 0..n {
        l = List::Cons(i, Box::new(l));
    }
    l
}
#[inline(never)]
fn len(l: &List) -> u32 {
    match l {
        List::Nil => 0,
        List::Cons(_, t) => 1 + bb(len(t)),
    }
}

// drop of a list is recursive: the harness sees what was not freed
test!(deep_list_drop_10, {
    check_eq!(len(&list(bb(10))), 10);
});
test!(deep_list_drop_100, {
    let l = list(bb(100));
    let mut n = 0;
    let mut p = &l;
    while let List::Cons(_, t) = p {
        n += 1;
        p = t;
    }
    check_eq!(n, 100);
});
test!(deep_list_len_100, {
    let l = list(bb(100));
    let n = len(&l);
    // take it apart in a loop: this test is about len()
    let mut l = l;
    while let List::Cons(_, t) = l {
        l = *t;
    }
    check_eq!(n, 100);
});

struct Tree {
    v: u32,
    l: Option<Box<Tree>>,
    r: Option<Box<Tree>>,
}
impl Tree {
    fn insert(&mut self, v: u32) {
        let slot = if v < self.v { &mut self.l } else { &mut self.r };
        match slot {
            Some(t) => t.insert(v),
            None => *slot = Some(Box::new(Tree { v, l: None, r: None })),
        }
    }
    fn walk(&self, out: &mut Vec<u32>) {
        if let Some(l) = &self.l {
            l.walk(out);
        }
        out.push(self.v);
        if let Some(r) = &self.r {
            r.walk(out);
        }
    }
}

test!(deep_tree_balanced_127, {
    let mut t = Tree { v: 64, l: None, r: None };
    let mut step = 32;
    while step >= 1 {
        let mut v = step;
        while v < 128 {
            t.insert(bb(v));
            v += step * 2;
        }
        step /= 2;
    }
    let mut out = Vec::new();
    t.walk(&mut out);
    check!(out.iter().copied().eq(1..128));
});
test!(deep_tree_degenerate_30, {
    let mut t = Tree { v: 0, l: None, r: None };
    for v in 1..bb(30) {
        t.insert(v);
    }
    let mut out = Vec::new();
    t.walk(&mut out);
    check!(out.iter().copied().eq(0..30));
});

#[derive(Debug)]
#[allow(dead_code)]
enum Nest {
    Leaf(u8),
    Wrap(Box<Nest>),
}
fn nest(n: u32) -> Nest {
    (0..n).fold(Nest::Leaf(7), |a, _| Nest::Wrap(Box::new(a)))
}
fn nest_text(n: usize) -> String {
    let mut s = "Wrap(".repeat(n);
    s.push_str("Leaf(7)");
    s.push_str(&")".repeat(n));
    s
}

test!(deep_debug_2, {
    check_eq!(format!("{:?}", nest(bb(2))), nest_text(2));
});
test!(deep_debug_5, {
    check_eq!(format!("{:?}", nest(bb(5))), nest_text(5));
});
test!(deep_debug_20, {
    check_eq!(format!("{:?}", nest(bb(20))), nest_text(20));
});

fn noise(n: usize) -> Vec<u32> {
    let mut x = bb(12345u32);
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            x >> 8
        })
        .collect()
}
fn check_sorted(v: &[u32], sum: u64) -> bool {
    v.is_sorted() && v.iter().map(|&e| e as u64).sum::<u64>() == sum
}

test!(deep_sort_unstable_2000, {
    let mut v = noise(2000);
    let sum = v.iter().map(|&e| e as u64).sum::<u64>();
    v.sort_unstable();
    check!(check_sorted(&v, sum));
});
test!(deep_sort_stable_2000, {
    let mut v = noise(2000);
    let sum = v.iter().map(|&e| e as u64).sum::<u64>();
    v.sort();
    check!(check_sorted(&v, sum));
});

#[inline(never)]
fn quick(v: &mut [u32]) {
    if v.len() < 2 {
        return;
    }
    let p = v[v.len() / 2];
    let (mut i, mut j) = (0, v.len() - 1);
    loop {
        while v[i] < p {
            i += 1;
        }
        while v[j] > p {
            j -= 1;
        }
        if i >= j {
            break;
        }
        v.swap(i, j);
        i += 1;
        j -= 1;
    }
    let (a, b) = v.split_at_mut(i);
    quick(a);
    quick(b);
}

test!(deep_quicksort_500, {
    let mut v = noise(500);
    let sum = v.iter().map(|&e| e as u64).sum::<u64>();
    quick(&mut v);
    check!(check_sorted(&v, sum));
});

#[inline(never)]
fn parens(s: &[u8], pos: &mut usize) -> Option<u32> {
    // depth of "((()))"
    if s.get(*pos) != Some(&b'(') {
        return Some(0);
    }
    *pos += 1;
    let d = parens(s, pos)?;
    if s.get(*pos) != Some(&b')') {
        return None;
    }
    *pos += 1;
    Some(d + 1)
}

test!(deep_parser_50, {
    let mut s = Vec::new();
    s.resize(bb(50), b'(');
    s.resize(100, b')');
    let mut pos = 0;
    check_eq!(parens(&s, &mut pos), Some(50));
    check_eq!(pos, 100);
});

#[inline(never)]
fn unwinds_from(n: u32) -> u32 {
    struct G;
    impl Drop for G {
        fn drop(&mut self) {
            unsafe { PADS += 1 };
        }
    }
    let _g = G;
    if n == 0 {
        panic!();
    }
    unwinds_from(n - 1) + 1
}
static mut PADS: u32 = 0;

test!(deep_unwind_15, {
    unsafe { PADS = 0 };
    check!(rt::catch(|| unwinds_from(bb(15))).is_err());
    check_eq!(unsafe { core::ptr::read_volatile(&raw const PADS) }, 16);
});
test!(deep_unwind_100, {
    unsafe { PADS = 0 };
    check!(rt::catch(|| unwinds_from(bb(100))).is_err());
    check_eq!(unsafe { core::ptr::read_volatile(&raw const PADS) }, 101);
});
