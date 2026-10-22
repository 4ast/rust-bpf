// SPDX-License-Identifier: GPL-2.0
//! Collections made of raw pointers, persistent ones, arenas.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;
use core::hash::Hasher;
use core::num::NonZeroUsize;
use intrusive_collections::{intrusive_adapter, Bound, KeyAdapter, LinkedList, LinkedListLink, RBTree, RBTreeLink};
use rt::{bb, check, check_eq, test};

struct Node {
    link: LinkedListLink,
    v: u32,
}
intrusive_adapter!(NodeAdapter = Box<Node>: Node { link => LinkedListLink });

fn node(v: u32) -> Box<Node> {
    Box::new(Node { link: LinkedListLink::new(), v })
}

test!(intrusive_linked_list, {
    let mut l = LinkedList::new(NodeAdapter::new());
    for i in 0..10 {
        l.push_back(node(bb(i)));
    }
    l.push_front(node(100));
    check_eq!(l.iter().map(|n| n.v).sum::<u32>(), 145);
    let mut c = l.front_mut();
    while let Some(n) = c.get() {
        if n.v % 2 == 0 {
            c.remove();
        } else {
            c.move_next();
        }
    }
    let v: Vec<u32> = l.iter().map(|n| n.v).collect();
    check_eq!(v, [1, 3, 5, 7, 9]);
    check_eq!(l.pop_back().map(|n| n.v), Some(9));
    check_eq!(l.iter().rev().map(|n| n.v).next(), Some(7));
});

struct TNode {
    link: RBTreeLink,
    k: u32,
    v: u32,
}
intrusive_adapter!(TAdapter = Box<TNode>: TNode { link => RBTreeLink });
impl<'a> KeyAdapter<'a> for TAdapter {
    type Key = u32;
    fn get_key(&self, n: &'a TNode) -> u32 {
        n.k
    }
}

test!(intrusive_rbtree, {
    let mut t = RBTree::new(TAdapter::new());
    for i in 0..64u32 {
        let k = bb(i) * 37 % 64;
        t.insert(Box::new(TNode { link: RBTreeLink::new(), k, v: k * 2 }));
    }
    let first: Vec<u32> = t.iter().take(5).map(|n| n.k).collect();
    check_eq!(first, [0, 1, 2, 3, 4]);
    check_eq!(t.find(&10).get().map(|n| n.v), Some(20));
    check!(t.find(&64).is_null());
    check_eq!(t.lower_bound(Bound::Excluded(&60)).get().map(|n| n.k), Some(61));
    for k in (0..64).step_by(2) {
        check!(t.find_mut(&k).remove().is_some());
    }
    check_eq!(t.iter().count(), 32);
    check_eq!(t.iter().map(|n| n.k).sum::<u32>(), 1024);
    check_eq!(t.back().get().map(|n| n.k), Some(63));
});

test!(lru_cache, {
    let mut c = lru::LruCache::new(NonZeroUsize::new(3).unwrap());
    c.put(bb(1), "a");
    c.put(2, "b");
    c.put(3, "c");
    check_eq!(c.get(&1), Some(&"a"));
    c.put(4, "d");
    check!(c.get(&2).is_none());
    check_eq!(c.len(), 3);
    let keys: Vec<i32> = c.iter().map(|(k, _)| *k).collect();
    check_eq!(keys, [4, 1, 3]);
    check_eq!(c.pop_lru(), Some((3, "c")));
    check_eq!(c.peek(&4), Some(&"d"));
    for i in 10..200 {
        c.put(i, "x");
    }
    check_eq!(c.len(), 3);
    check!(c.contains(&199) && c.contains(&197) && !c.contains(&196));
});

test!(rpds_persistent, {
    let v1 = rpds::Vector::new().push_back(bb(1)).push_back(2);
    let v2 = v1.push_back(3);
    let v3 = v2.set(0, 10).unwrap();
    check_eq!(v1.len(), 2);
    check_eq!(v2.iter().sum::<i32>(), 6);
    check_eq!(v3.iter().sum::<i32>(), 15);
    check_eq!(v2[0], 1);
    let mut big = rpds::Vector::new();
    for i in 0..100u32 {
        big = big.push_back(i);
    }
    check_eq!(big.iter().sum::<u32>(), 4950);
    let m1 = rpds::RedBlackTreeMap::new().insert(bb(1), "one").insert(2, "two");
    let m2 = m1.remove(&1);
    check_eq!(m1.get(&1), Some(&"one"));
    check!(m2.get(&1).is_none());
    check_eq!(m2.size(), 1);
    let l = rpds::List::new().push_front(1).push_front(bb(2));
    check_eq!(l.first(), Some(&2));
    check_eq!(l.drop_first().unwrap().first(), Some(&1));
    check_eq!(l.len(), 2);
});

struct Cyc<'a> {
    v: u32,
    next: Cell<Option<&'a Cyc<'a>>>,
}

test!(typed_arena_cycle, {
    let a = typed_arena::Arena::new();
    let x = a.alloc(Cyc { v: bb(1), next: Cell::new(None) });
    let y = a.alloc(Cyc { v: 2, next: Cell::new(Some(x)) });
    x.next.set(Some(y));
    check_eq!(x.next.get().unwrap().next.get().unwrap().v, 1);
    let mut last: &Cyc = y;
    for i in 0..100 {
        last = a.alloc(Cyc { v: i, next: Cell::new(Some(last)) });
    }
    let (mut n, mut sum, mut p) = (0, 0, Some(last));
    while let Some(c) = p {
        if n == 102 {
            break;
        }
        sum += c.v;
        n += 1;
        p = c.next.get();
    }
    check_eq!(sum, 4950 + 3);
    check_eq!(a.len(), 102);
});

test!(fxhash_map, {
    let mut m: hashbrown::HashMap<u32, u32, rustc_hash::FxBuildHasher> = Default::default();
    for i in 0..100 {
        m.insert(bb(i), i * i);
    }
    check_eq!(m[&9], 81);
    check_eq!(m.values().sum::<u32>(), 328350);
    let h = |x: u64| {
        let mut s = rustc_hash::FxHasher::default();
        s.write_u64(x);
        s.finish()
    };
    check!(h(1) != h(2));
    check_eq!(h(7), h(bb(7)));
});
