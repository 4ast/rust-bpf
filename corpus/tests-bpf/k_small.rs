// SPDX-License-Identifier: GPL-2.0
//! crates: smallvec, arrayvec, tinyvec, heapless, slab
#![no_std]
#![no_main]
extern crate alloc;
use core::fmt::Write;
use rt::{bb, check, check_eq, test};

test!(smallvec_inline_and_spilled, {
    use smallvec::{SmallVec, smallvec};
    let n = rt::allocs();
    let mut v: SmallVec<[u32; 4]> = SmallVec::new();
    for i in 0..bb(4) {
        v.push(i);
    }
    check!(!v.spilled());
    check_eq!(rt::allocs(), n);
    v.push(4);
    check!(v.spilled());
    check!(rt::allocs() > n);
    check_eq!(&v[..], &[0, 1, 2, 3, 4]);
    v.insert(bb(1), 9);
    check_eq!(v.remove(bb(0)), 0);
    check_eq!(v.pop(), Some(4));
    v.retain(|x| *x != 2);
    check_eq!(&v[..], &[9, 1, 3]);
    v.shrink_to_fit();
    check!(!v.spilled());
    v.extend_from_slice(bb(&[7, 8]));
    v.sort_unstable();
    check_eq!(v.iter().sum::<u32>(), 28);
    let w: SmallVec<[u8; 2]> = smallvec![bb(1), 2, 3];
    check_eq!(w.into_vec(), [1, 2, 3]);
    let d: SmallVec<[u32; 8]> = v.drain(1..3).collect();
    check_eq!(&d[..], &[3, 7]);
});

test!(arrayvec_vec, {
    use arrayvec::ArrayVec;
    let mut v: ArrayVec<u32, 4> = ArrayVec::new();
    for i in 0..bb(4) {
        v.push(i * 10);
    }
    check!(v.is_full());
    check!(v.try_push(99).is_err());
    check_eq!(v.remaining_capacity(), 0);
    check_eq!(v.pop(), Some(30));
    v.insert(bb(0), 5);
    check_eq!(&v[..], &[5, 0, 10, 20]);
    check_eq!(v.swap_remove(bb(1)), 0);
    check_eq!(v.remove(0), 5);
    check_eq!(&v[..], &[20, 10]);
    check!(v.try_extend_from_slice(bb(&[1, 2, 3])).is_err());
    check!(v.try_extend_from_slice(bb(&[1, 2])).is_ok());
    v.sort_unstable();
    check_eq!(v.into_inner().ok(), Some([1, 2, 10, 20]));
    let c: ArrayVec<u8, 8> = (0..bb(5)).collect();
    check_eq!(c.len(), 5);
    check!(rt::catch(|| {
        let mut f: ArrayVec<u8, 1> = ArrayVec::new();
        f.push(bb(1));
        f.push(bb(2));
    })
    .is_err());
});

test!(arrayvec_string, {
    use arrayvec::ArrayString;
    let mut s = ArrayString::<16>::new();
    s.push_str(bb("hello"));
    s.push(' ');
    check!(write!(s, "{}", bb(12345)).is_ok());
    check_eq!(&s[..], "hello 12345");
    check!(s.try_push_str(bb("too long for it")).is_err());
    check_eq!(s.pop(), Some('5'));
    s.truncate(5);
    check_eq!(s.as_str(), "hello");
    check_eq!(s.remaining_capacity(), 11);
    check_eq!(ArrayString::<4>::from(bb("abcd")).map(|s| s.len()), Ok(4));
    check!(ArrayString::<4>::from(bb("abcde")).is_err());
});

test!(tinyvec_both, {
    use tinyvec::{ArrayVec, TinyVec, array_vec, tiny_vec};
    let mut a: ArrayVec<[u16; 4]> = array_vec!();
    a.push(bb(3));
    a.push(1);
    a.extend([2]);
    a.sort_unstable();
    check_eq!(a.as_slice(), &[1, 2, 3]);
    check_eq!(a.try_push(4), None);
    check_eq!(a.try_push(5), Some(5));
    check_eq!(a.remove(bb(0)), 1);
    let n = rt::allocs();
    let mut t: TinyVec<[u8; 4]> = tiny_vec!(1, 2, 3);
    check!(t.is_inline());
    t.push(bb(4));
    check_eq!(rt::allocs(), n);
    t.push(5);
    check!(t.is_heap());
    check_eq!(t.iter().map(|&x| x as u32).sum::<u32>(), 15);
    t.retain(|x| x % 2 == 1);
    check_eq!(&t[..], &[1, 3, 5]);
});

test!(heapless_vec_string, {
    use heapless::{String, Vec};
    let n = rt::allocs();
    let mut v: Vec<u32, 8> = Vec::new();
    for i in 0..bb(8) {
        check!(v.push(i).is_ok());
    }
    check_eq!(v.push(8), Err(8));
    check!(v.is_full());
    check_eq!(v.pop(), Some(7));
    check_eq!(v.swap_remove(bb(0)), 0);
    check!(v.insert(bb(1), 100).is_ok());
    v.retain(|x| x % 2 == 0);
    check_eq!(&v[..], &[6, 100, 2, 4]);
    check!(v.extend_from_slice(bb(&[1; 5])).is_err());
    v.sort_unstable();
    check_eq!(v.binary_search(&6), Ok(2));
    let mut s: String<16> = String::new();
    check!(s.push_str(bb("ab")).is_ok() && s.push('c').is_ok());
    check!(write!(s, "-{:03}", bb(7)).is_ok());
    check_eq!(s.as_str(), "abc-007");
    check!(s.push_str("0123456789").is_err());
    check_eq!(rt::allocs(), n);
});

test!(heapless_queues, {
    use heapless::binary_heap::{BinaryHeap, Max, Min};
    use heapless::spsc::Queue;
    use heapless::{Deque, HistoryBuf};
    let mut d: Deque<i32, 4> = Deque::new();
    check!(d.push_back(bb(1)).is_ok() && d.push_back(2).is_ok() && d.push_front(0).is_ok() && d.push_front(-1).is_ok());
    check_eq!(d.push_back(3), Err(3));
    check_eq!(d.pop_front(), Some(-1));
    check_eq!(d.pop_back(), Some(2));
    check_eq!(d.iter().sum::<i32>(), 1);
    let mut h: BinaryHeap<u32, Max, 8> = BinaryHeap::new();
    for x in bb([3, 9, 1, 7]) {
        check!(h.push(x).is_ok());
    }
    check_eq!(h.pop(), Some(9));
    check_eq!(h.peek(), Some(&7));
    let mut m: BinaryHeap<u32, Min, 8> = BinaryHeap::new();
    for x in bb([3, 9, 1, 7]) {
        check!(m.push(x).is_ok());
    }
    check_eq!(m.pop(), Some(1));
    let mut q: Queue<u8, 4> = Queue::new();
    check!(q.enqueue(bb(1)).is_ok() && q.enqueue(2).is_ok() && q.enqueue(3).is_ok());
    check_eq!(q.enqueue(4), Err(4));
    check_eq!(q.dequeue(), Some(1));
    let (mut p, mut c) = q.split();
    check!(p.enqueue(5).is_ok());
    check_eq!(c.dequeue(), Some(2));
    let mut hb: HistoryBuf<u32, 3> = HistoryBuf::new();
    for x in 1..=bb(5) {
        hb.write(x);
    }
    check_eq!(hb.recent(), Some(&5));
    check!(hb.oldest_ordered().copied().eq([3, 4, 5]));
});

test!(heapless_maps, {
    use heapless::LinearMap;
    use heapless::index_map::FnvIndexMap;
    use heapless::index_set::FnvIndexSet;
    let mut m: FnvIndexMap<&str, u32, 8> = FnvIndexMap::new();
    check_eq!(m.insert(bb("a"), 1), Ok(None));
    check_eq!(m.insert("b", 2), Ok(None));
    check_eq!(m.insert("a", 3), Ok(Some(1)));
    check_eq!(m.get("a"), Some(&3));
    check_eq!(m.remove("b"), Some(2));
    check_eq!(m.len(), 1);
    for (i, k) in ["c", "d", "e", "f", "g", "h", "i"].iter().enumerate() {
        check!(m.insert(k, i as u32).is_ok());
    }
    check!(m.insert("overflow", 0).is_err());
    check_eq!(m.values().sum::<u32>(), 24);
    let mut l: LinearMap<u8, u8, 2> = LinearMap::new();
    check!(l.insert(bb(1), 10).is_ok() && l.insert(2, 20).is_ok() && l.insert(3, 30).is_err());
    check_eq!(l.get(&2), Some(&20));
    let mut s: FnvIndexSet<u32, 4> = FnvIndexSet::new();
    check_eq!(s.insert(bb(5)), Ok(true));
    check_eq!(s.insert(5), Ok(false));
    check!(s.contains(&5));
});

test!(slab_keys, {
    use slab::Slab;
    let mut s = Slab::new();
    let a = s.insert(bb("a"));
    let b = s.insert("b");
    let c = s.insert("c");
    check_eq!((a, b, c), (0, 1, 2));
    check_eq!(s[b], "b");
    check_eq!(s.remove(b), "b");
    check!(!s.contains(b) && s.get(b).is_none());
    check_eq!(s.len(), 2);
    check_eq!(s.insert("d"), 1);
    check_eq!(s.vacant_key(), 3);
    let e = s.vacant_entry();
    let k = e.key();
    e.insert("e");
    check_eq!(s[k], "e");
    check_eq!(s.iter().map(|(k, _)| k).sum::<usize>(), 6);
    s.retain(|k, _| k % 2 == 0);
    check_eq!(s.len(), 2);
    check_eq!(s.try_remove(1), None);
    s.clear();
    check!(s.is_empty());
});
