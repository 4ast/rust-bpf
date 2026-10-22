// SPDX-License-Identifier: GPL-2.0
//! alloc::collections: BTreeMap, BTreeSet
#![no_std]
#![no_main]
extern crate alloc;
use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Bound::{Excluded, Included, Unbounded};
use rt::{bb, check, check_eq, test};

fn map(n: u32) -> BTreeMap<u32, u32> {
    (0..n).map(|i| ((i * 37) % n, i)).collect()
}

test!(btree_insert_get, {
    let mut m = BTreeMap::new();
    check_eq!(m.insert(bb(3), "c"), None);
    check_eq!(m.insert(1, "a"), None);
    check_eq!(m.insert(2, "b"), None);
    check_eq!(m.insert(bb(3), "C"), Some("c"));
    check_eq!(m.len(), 3);
    check_eq!(m.get(&3), Some(&"C"));
    check_eq!(m.get(&4), None);
    check!(m.contains_key(&1) && !m.contains_key(&0));
    check_eq!(m[&2], "b");
    *m.get_mut(&2).unwrap() = "B";
    check_eq!(m.get_key_value(&2), Some((&2, &"B")));
    check_eq!(m.remove(&1), Some("a"));
    check_eq!(m.remove(&1), None);
    check_eq!(m.remove_entry(&3), Some((3, "C")));
    check_eq!(m.len(), 1);
});

test!(btree_many, {
    let n = bb(500);
    let mut m = map(n);
    check_eq!(m.len(), 500);
    check!(m.keys().copied().eq(0..n));
    check_eq!(m.values().map(|&v| v as u64).sum::<u64>(), 499 * 500 / 2);
    for k in (0..n).step_by(2) {
        check!(m.remove(&k).is_some());
    }
    check_eq!(m.len(), 250);
    check!(m.keys().all(|k| k % 2 == 1));
    for k in (0..n).step_by(2) {
        m.insert(k, 0);
    }
    check_eq!(m.len(), 500);
    m.clear();
    check!(m.is_empty());
});

test!(btree_first_last, {
    let mut m = map(bb(50));
    check_eq!(m.first_key_value().map(|p| *p.0), Some(0));
    check_eq!(m.last_key_value().map(|p| *p.0), Some(49));
    check_eq!(m.pop_first().map(|p| p.0), Some(0));
    check_eq!(m.pop_last().map(|p| p.0), Some(49));
    check_eq!(m.len(), 48);
    *m.first_entry().unwrap().get_mut() = 1000;
    check_eq!(m[&1], 1000);
    check_eq!(*m.last_entry().unwrap().key(), 48);
});

test!(btree_range, {
    let m = map(bb(100));
    check_eq!(m.range(10..20).count(), 10);
    check_eq!(m.range(10..=20).count(), 11);
    check_eq!(m.range(..5).map(|p| *p.0).sum::<u32>(), 10);
    check_eq!(m.range(95..).count(), 5);
    check_eq!(m.range(50..).next().map(|p| *p.0), Some(50));
    check_eq!(m.range(..50).next_back().map(|p| *p.0), Some(49));
    check_eq!(m.range((Excluded(10), Included(12))).count(), 2);
    check_eq!(m.range((Unbounded, Excluded(3))).count(), 3);
    check_eq!(m.range(200..300).count(), 0);
    check_eq!(m.range(20..30).rev().map(|p| *p.0).next(), Some(29));
    let mut m = m;
    for (_, v) in m.range_mut(0..10) {
        *v = 1;
    }
    check_eq!(m.range(0..10).map(|p| *p.1).sum::<u32>(), 10);
});

test!(btree_entry, {
    let mut m: BTreeMap<&str, u32> = BTreeMap::new();
    for w in bb("a b a c b a").split(' ') {
        *m.entry(w).or_insert(0) += 1;
    }
    check_eq!(m.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(), [("a", 3), ("b", 2), ("c", 1)]);
    m.entry("a").and_modify(|v| *v += 10).or_insert(0);
    m.entry("z").and_modify(|v| *v += 10).or_insert(7);
    check!(m["a"] == 13 && m["z"] == 7);
    check_eq!(*m.entry("y").or_default(), 0);
    check_eq!(*m.entry("x").or_insert_with(|| bb(5)), 5);
    match m.entry("b") {
        Entry::Occupied(e) => check_eq!(e.remove(), 2),
        Entry::Vacant(_) => return 1,
    }
    match m.entry("b") {
        Entry::Occupied(_) => return 2,
        Entry::Vacant(e) => {
            check_eq!(*e.key(), "b");
            e.insert(1);
        }
    }
    check_eq!(m.len(), 6);
});

test!(btree_split_append_retain, {
    let mut a = map(bb(100));
    let mut b = a.split_off(&bb(60));
    check!(a.len() == 60 && b.len() == 40);
    check_eq!(b.first_key_value().map(|p| *p.0), Some(60));
    b.retain(|k, _| k % 10 == 0);
    check_eq!(b.keys().copied().collect::<Vec<_>>(), [60, 70, 80, 90]);
    a.append(&mut b);
    check!(b.is_empty() && a.len() == 64);
    let odd: BTreeMap<u32, u32> = a.extract_if(.., |k, _| k % 2 == 1).collect();
    check!(odd.len() == 30 && a.len() == 34);
});

test!(btree_iter, {
    let mut m = map(bb(30));
    check!(m.iter().map(|p| *p.0).is_sorted());
    check_eq!(m.iter().rev().next().map(|p| *p.0), Some(29));
    check_eq!(m.iter().len(), 30);
    for (k, v) in m.iter_mut() {
        *v = k * 2;
    }
    for v in m.values_mut() {
        *v += 1;
    }
    check_eq!(m[&10], 21);
    let c = m.clone();
    check!(c == m);
    check_eq!(c.into_keys().sum::<u32>(), 435);
    check_eq!(m.clone().into_values().sum::<u32>(), 900);
    let mut it = m.into_iter();
    check_eq!(it.next(), Some((0, 1)));
    check_eq!(it.next_back(), Some((29, 59)));
    check_eq!(it.len(), 28);
});

test!(btree_string_keys, {
    let mut m: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for (i, w) in bb("pear apple fig apple pear apple").split(' ').enumerate() {
        m.entry(String::from(w)).or_default().push(i as u32);
    }
    check_eq!(m.len(), 3);
    check_eq!(m["apple"], [1, 3, 5]);
    check_eq!(m.keys().map(|s| s.as_str()).collect::<Vec<_>>(), ["apple", "fig", "pear"]);
    check_eq!(m.range::<str, _>((Included("b"), Excluded("g"))).count(), 1);
    check_eq!(m.remove("fig"), Some(alloc::vec![2]));
});

test!(btree_set_basic, {
    let mut s = BTreeSet::new();
    check!(s.insert(bb(3)) && s.insert(1) && s.insert(2) && !s.insert(bb(3)));
    check_eq!(s.len(), 3);
    check!(s.contains(&2) && !s.contains(&5));
    check_eq!(s.first(), Some(&1));
    check_eq!(s.last(), Some(&3));
    check!(s.remove(&2) && !s.remove(&2));
    check_eq!(s.take(&1), Some(1));
    check_eq!(s.replace(3), Some(3));
    check_eq!(s.pop_first(), Some(3));
    check!(s.is_empty());
});

test!(btree_set_ops, {
    let a: BTreeSet<u32> = (0..bb(20)).filter(|x| x % 2 == 0).collect();
    let b: BTreeSet<u32> = (0..bb(20)).filter(|x| x % 3 == 0).collect();
    check_eq!(a.intersection(&b).copied().collect::<Vec<_>>(), [0, 6, 12, 18]);
    check_eq!(a.union(&b).count(), 13);
    check_eq!(a.difference(&b).count(), 6);
    check_eq!(a.symmetric_difference(&b).count(), 9);
    check_eq!((&a & &b).len(), 4);
    check_eq!((&a | &b).len(), 13);
    check_eq!((&a - &b).len(), 6);
    check_eq!((&a ^ &b).len(), 9);
    check!(!a.is_disjoint(&b) && !a.is_subset(&b));
    let c: BTreeSet<u32> = [0, 6].into_iter().collect();
    check!(c.is_subset(&a) && a.is_superset(&c));
    check_eq!(a.range(5..11).copied().collect::<Vec<_>>(), [6, 8, 10]);
    check!(a < b);
});
