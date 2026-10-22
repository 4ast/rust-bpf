// SPDX-License-Identifier: GPL-2.0
//! crates: hashbrown, indexmap
#![no_std]
#![no_main]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::hash::{BuildHasher, BuildHasherDefault};
use hashbrown::hash_map::Entry;
use hashbrown::{HashMap, HashSet, HashTable};
use indexmap::{IndexMap, IndexSet};
use rt::{bb, check, check_eq, test};

test!(hashbrown_basic, {
    let mut m = HashMap::new();
    check_eq!(m.insert(bb(1u32), "one"), None);
    check_eq!(m.insert(2, "two"), None);
    check_eq!(m.insert(bb(1), "uno"), Some("one"));
    check_eq!(m.len(), 2);
    check_eq!(m.get(&1), Some(&"uno"));
    check_eq!(m.get(&3), None);
    check!(m.contains_key(&2));
    check_eq!(m[&2], "two");
    *m.get_mut(&2).unwrap() = "dos";
    check_eq!(m.remove(&2), Some("dos"));
    check_eq!(m.remove(&2), None);
    check_eq!(m.remove_entry(&1), Some((1, "uno")));
    check!(m.is_empty());
});

test!(hashbrown_grows, {
    let mut m = HashMap::new();
    let n = bb(1000u64);
    for i in 0..n {
        m.insert(i, i * i);
    }
    check_eq!(m.len(), 1000);
    for i in 0..n {
        check_eq!(m.get(&i), Some(&(i * i)));
    }
    check_eq!(m.get(&n), None);
    check_eq!(m.values().sum::<u64>(), 332833500);
    for i in (0..n).step_by(2) {
        check!(m.remove(&i).is_some());
    }
    check_eq!(m.len(), 500);
    check!(m.keys().all(|k| k % 2 == 1));
    m.shrink_to_fit();
    check_eq!(m.get(&999), Some(&998001));
    m.clear();
    check!(m.is_empty());
});

test!(hashbrown_entry, {
    let mut m: HashMap<&str, u32> = HashMap::new();
    for w in bb("a b a c b a").split(' ') {
        *m.entry(w).or_insert(0) += 1;
    }
    check!(m["a"] == 3 && m["b"] == 2 && m["c"] == 1);
    m.entry("a").and_modify(|v| *v += 10).or_insert(0);
    check_eq!(*m.entry("z").or_default(), 0);
    check_eq!(*m.entry("y").or_insert_with(|| bb(5)), 5);
    match m.entry("b") {
        Entry::Occupied(e) => check_eq!(e.remove(), 2),
        Entry::Vacant(_) => return 1,
    }
    check!(matches!(m.entry("b"), Entry::Vacant(_)));
    check_eq!(m["a"], 13);
});

test!(hashbrown_iter_retain, {
    let mut m: HashMap<u32, u32> = (0..bb(100)).map(|i| (i, i * 2)).collect();
    check_eq!(m.iter().map(|(k, v)| k + v).sum::<u32>(), 3 * 4950);
    for v in m.values_mut() {
        *v += 1;
    }
    m.retain(|k, _| k % 10 == 0);
    check_eq!(m.len(), 10);
    let mut ks: Vec<u32> = m.keys().copied().collect();
    ks.sort_unstable();
    check_eq!(ks, [0, 10, 20, 30, 40, 50, 60, 70, 80, 90]);
    let big: HashMap<u32, u32> = m.extract_if(|k, _| *k >= 50).collect();
    check!(big.len() == 5 && m.len() == 5);
    check_eq!(m.drain().map(|(_, v)| v).sum::<u32>(), 205);
    check!(m.is_empty());
    let c = big.clone();
    check!(c == big);
    check_eq!(big.into_iter().count(), 5);
});

test!(hashbrown_string_keys, {
    let mut m: HashMap<String, Vec<u32>> = HashMap::new();
    for (i, w) in bb("pear apple fig apple pear apple").split(' ').enumerate() {
        m.entry(String::from(w)).or_default().push(i as u32);
    }
    check_eq!(m.len(), 3);
    check_eq!(m["apple"], [1, 3, 5]);
    check_eq!(m.get("fig").map(|v| v.len()), Some(1));
    check!(m.remove("pear").is_some());
    check!(!m.contains_key("pear"));
});

test!(hashbrown_set, {
    let a: HashSet<u32> = (0..bb(20)).filter(|x| x % 2 == 0).collect();
    let b: HashSet<u32> = (0..bb(20)).filter(|x| x % 3 == 0).collect();
    check_eq!(a.intersection(&b).count(), 4);
    check_eq!(a.union(&b).count(), 13);
    check_eq!(a.difference(&b).count(), 6);
    check_eq!(a.symmetric_difference(&b).count(), 9);
    check!(a.contains(&4) && !a.contains(&5));
    let mut s = HashSet::new();
    check!(s.insert(bb("x")) && !s.insert("x") && s.remove("x") && !s.remove("x"));
    let c: HashSet<u32> = [0, 6].into_iter().collect();
    check!(c.is_subset(&a) && a.is_superset(&c) && !a.is_disjoint(&b));
});

test!(hashbrown_table, {
    let hasher = BuildHasherDefault::<fnv::FnvHasher>::default();
    let h = |v: &(u32, u32)| hasher.hash_one(v.0);
    let mut t: HashTable<(u32, u32)> = HashTable::new();
    for i in 0..bb(50u32) {
        t.insert_unique(h(&(i, 0)), (i, i + 100), h);
    }
    check_eq!(t.len(), 50);
    check_eq!(t.find(h(&(7, 0)), |e| e.0 == 7), Some(&(7, 107)));
    check_eq!(t.find(h(&(70, 0)), |e| e.0 == 70), None);
    if let Some(e) = t.find_mut(h(&(7, 0)), |e| e.0 == 7) {
        e.1 = 0;
    }
    check!(t.find_entry(h(&(8, 0)), |e| e.0 == 8).map(|e| e.remove().0).ok() == Some((8, 108)));
    check_eq!(t.len(), 49);
    check_eq!(t.iter().map(|e| e.1).sum::<u32>(), (100..150).sum::<u32>() - 107 - 108);
});

type FnvIndexMap<K, V> = IndexMap<K, V, BuildHasherDefault<fnv::FnvHasher>>;
type FnvIndexSet<K> = IndexSet<K, BuildHasherDefault<fnv::FnvHasher>>;

test!(indexmap_order, {
    let mut m = FnvIndexMap::default();
    for (i, k) in bb(["d", "a", "c", "b"]).into_iter().enumerate() {
        m.insert(k, i);
    }
    check_eq!(m.keys().copied().collect::<Vec<_>>(), ["d", "a", "c", "b"]);
    check_eq!(m.get_index(2), Some((&"c", &2)));
    check_eq!(m.get_index_of("a"), Some(1));
    check_eq!(m.get_full("b"), Some((3, &"b", &3)));
    check_eq!(m.insert("a", 10), Some(1));
    check_eq!(m.get_index_of("a"), Some(1));
    check_eq!(m.shift_remove("a"), Some(10));
    check_eq!(m.keys().copied().collect::<Vec<_>>(), ["d", "c", "b"]);
    check_eq!(m.swap_remove("d"), Some(0));
    check_eq!(m.keys().copied().collect::<Vec<_>>(), ["b", "c"]);
    m.insert("a", 5);
    m.sort_keys();
    check_eq!(m.keys().copied().collect::<Vec<_>>(), ["a", "b", "c"]);
    check_eq!(m.first(), Some((&"a", &5)));
    check_eq!(m.pop(), Some(("c", 2)));
    m.reverse();
    check_eq!(m[0], 3);
});

test!(indexmap_many, {
    let mut m = FnvIndexMap::default();
    for i in 0..bb(300u32) {
        m.insert(i * 7 % 307, i);
    }
    check_eq!(m.len(), 300);
    check!(m.values().copied().eq(0..300));
    check_eq!(m.get(&(7 * 100 % 307)), Some(&100));
    m.retain(|_, v| *v % 3 == 0);
    check_eq!(m.len(), 100);
    check!(m.values().copied().eq((0..300).step_by(3)));
    *m.entry(1000).or_insert(0) += 1;
    check_eq!(m.last(), Some((&1000, &1)));
    m.sort_by(|_, a, _, b| b.cmp(a));
    check_eq!(m[0], 297);
});

test!(indexset, {
    let mut s = FnvIndexSet::default();
    for x in bb([3, 1, 3, 2, 1]) {
        s.insert(x);
    }
    check_eq!(s.iter().copied().collect::<Vec<_>>(), [3, 1, 2]);
    check_eq!(s.get_index_of(&2), Some(2));
    check_eq!(s.insert_full(1), (1, false));
    check!(s.shift_remove(&3));
    check_eq!(s[0], 1);
    let t: FnvIndexSet<i32> = [2, 9].into_iter().collect();
    check_eq!(s.intersection(&t).count(), 1);
    check_eq!(s.union(&t).copied().collect::<Vec<_>>(), [1, 2, 9]);
});
