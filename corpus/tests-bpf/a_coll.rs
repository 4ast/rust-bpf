// SPDX-License-Identifier: GPL-2.0
//! alloc::collections: VecDeque, BinaryHeap, LinkedList
#![no_std]
#![no_main]
extern crate alloc;
use alloc::collections::{BinaryHeap, LinkedList, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;
use rt::{bb, check, check_eq, test};

test!(deque_ends, {
    let mut d = VecDeque::new();
    for i in 0..bb(10) {
        d.push_back(i);
        d.push_front(-i);
    }
    check_eq!(d.len(), 20);
    check_eq!(d.front(), Some(&-9));
    check_eq!(d.back(), Some(&9));
    check_eq!(d[10], 0);
    check_eq!(d.pop_front(), Some(-9));
    check_eq!(d.pop_back(), Some(9));
    check_eq!(d.iter().sum::<i32>(), 0);
    check_eq!(d.get(bb(100)), None);
    *d.front_mut().unwrap() = 100;
    check_eq!(d[0], 100);
});

test!(deque_wraps_around, {
    let mut d: VecDeque<u32> = VecDeque::with_capacity(8);
    let mut next = 0;
    let mut expect = 0;
    for _ in 0..bb(100) {
        while d.len() < 6 {
            d.push_back(next);
            next += 1;
        }
        for _ in 0..4 {
            check_eq!(d.pop_front(), Some(expect));
            expect += 1;
        }
    }
    let (a, b) = d.as_slices();
    check_eq!(a.len() + b.len(), 2);
    d.make_contiguous();
    check_eq!(d.as_slices().1.len(), 0);
});

test!(deque_middle, {
    let mut d: VecDeque<u32> = (0..bb(10)).collect();
    d.rotate_left(bb(3));
    check_eq!(d.iter().copied().collect::<Vec<_>>(), [3, 4, 5, 6, 7, 8, 9, 0, 1, 2]);
    d.rotate_right(bb(1));
    check_eq!(d[0], 2);
    d.insert(bb(5), 100);
    check_eq!(d.remove(bb(5)), Some(100));
    check_eq!(d.swap_remove_back(bb(1)), Some(3));
    check_eq!(d.swap_remove_front(bb(1)), Some(1));
    d.retain(|x| x % 2 == 0);
    check_eq!(d, [2, 4, 6, 8, 0]);
    d.truncate(3);
    let t = d.split_off(1);
    check!(d == [2] && t == [4, 6]);
    d.extend(t.iter());
    d.swap(0, 2);
    check_eq!(d, [6, 4, 2]);
    check!(d.contains(&4));
    let dr: Vec<u32> = d.drain(1..).collect();
    check_eq!(dr, [4, 2]);
    check_eq!(Vec::from(d), [6]);
});

test!(deque_iter_sort, {
    let mut d: VecDeque<i32> = VecDeque::new();
    for i in [5, 3, 8, 1] {
        d.push_front(bb(i));
    }
    check_eq!(d.iter().rev().copied().collect::<Vec<_>>(), [5, 3, 8, 1]);
    for x in d.iter_mut() {
        *x *= 2;
    }
    d.make_contiguous().sort();
    check_eq!(d, [2, 6, 10, 16]);
    check_eq!(d.binary_search(&10), Ok(2));
    check_eq!(d.range(1..3).sum::<i32>(), 16);
    check_eq!(d.into_iter().map(|x| x / 2).collect::<Vec<_>>(), [1, 3, 5, 8]);
});

test!(heap_max, {
    let mut h = BinaryHeap::new();
    for x in [5, 1, 8, 3, 9, 2, 7] {
        h.push(bb(x));
    }
    check_eq!(h.len(), 7);
    check_eq!(h.peek(), Some(&9));
    let mut out = Vec::new();
    while let Some(x) = h.pop() {
        out.push(x);
    }
    check_eq!(out, [9, 8, 7, 5, 3, 2, 1]);
});

test!(heap_min_and_tuples, {
    let mut h = BinaryHeap::new();
    for (p, n) in [(5, 'e'), (1, 'a'), (3, 'c'), (1, 'b')] {
        h.push(Reverse((bb(p), n)));
    }
    check_eq!(h.pop(), Some(Reverse((1, 'a'))));
    check_eq!(h.pop(), Some(Reverse((1, 'b'))));
    check_eq!(h.peek(), Some(&Reverse((3, 'c'))));
    if let Some(mut top) = h.peek_mut() {
        top.0.0 = 10;
    }
    check_eq!(h.pop(), Some(Reverse((5, 'e'))));
});

test!(heap_from_vec, {
    let h = BinaryHeap::from(vec![bb(4), 9, 1, 7, 3]);
    check_eq!(h.clone().into_sorted_vec(), [1, 3, 4, 7, 9]);
    let mut a = h;
    let mut b = BinaryHeap::from(vec![bb(10), 0]);
    a.append(&mut b);
    check!(b.is_empty() && a.len() == 7 && a.peek() == Some(&10));
    a.retain(|x| x % 2 == 1);
    check_eq!(a.into_sorted_vec(), [1, 3, 7, 9]);
    let big: BinaryHeap<u32> = (0..bb(200)).map(|i| (i * 7919) % 1009).collect();
    let v = big.into_sorted_vec();
    check!(v.is_sorted() && v.len() == 200);
});

test!(list_basic, {
    let mut l = LinkedList::new();
    l.push_back(bb(2));
    l.push_back(3);
    l.push_front(1);
    check_eq!(l.len(), 3);
    check_eq!(l.front(), Some(&1));
    check_eq!(l.back(), Some(&3));
    check_eq!(l.iter().sum::<i32>(), 6);
    check_eq!(l.iter().rev().copied().collect::<Vec<_>>(), [3, 2, 1]);
    check!(l.contains(&2));
    for x in l.iter_mut() {
        *x *= 10;
    }
    check_eq!(l.pop_front(), Some(10));
    check_eq!(l.pop_back(), Some(30));
    check_eq!(l.pop_back(), Some(20));
    check_eq!(l.pop_back(), None);
});

test!(list_split_append, {
    let mut a: LinkedList<u32> = (0..bb(10)).collect();
    let mut b = a.split_off(bb(6));
    check!(a.len() == 6 && b.len() == 4);
    check_eq!(b.front(), Some(&6));
    b.append(&mut a);
    check!(a.is_empty());
    check_eq!(b.into_iter().collect::<Vec<_>>(), [6, 7, 8, 9, 0, 1, 2, 3, 4, 5]);
    let mut c: LinkedList<u32> = LinkedList::new();
    c.extend([1, 2, 3]);
    c.clear();
    check!(c.is_empty());
});
