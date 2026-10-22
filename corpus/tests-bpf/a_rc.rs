// SPDX-License-Identifier: GPL-2.0
//! alloc: Box, Rc, Weak, Arc, trait objects and closures on the heap
#![no_std]
#![no_main]
extern crate alloc;
use alloc::boxed::Box;
use alloc::rc::{Rc, Weak};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::cell::{Cell, RefCell};
use rt::{bb, check, check_eq, test};

test!(box_basic, {
    let live = rt::live();
    let b = bb(Box::new(5u64));
    check_eq!(rt::live(), live + 1);
    check_eq!(*b + 1, 6);
    let mut c = b.clone();
    *c += 10;
    check!(*b == 5 && *c == 15);
    let v = *c;
    check_eq!(v, 15);
    drop(b);
    check_eq!(rt::live(), live);
    let big = Box::new([bb(7u64); 1000]);
    check_eq!(big.iter().sum::<u64>(), 7000);
    let s: Box<[u32]> = vec![1, 2, 3].into_boxed_slice();
    check_eq!(s.iter().sum::<u32>(), 6);
    let z = Box::new(());
    check_eq!(*z, ());
    let p = Box::into_raw(Box::new(bb(9u8)));
    check_eq!(unsafe { *p }, 9);
    drop(unsafe { Box::from_raw(p) });
});

enum List {
    Nil,
    Cons(u32, Box<List>),
}
impl List {
    fn sum(&self) -> u32 {
        let mut s = 0;
        let mut l = self;
        while let List::Cons(v, next) = l {
            s += v;
            l = next;
        }
        s
    }
}
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
    fn depth(&self) -> u32 {
        1 + self.l.as_ref().map_or(0, |t| t.depth()).max(self.r.as_ref().map_or(0, |t| t.depth()))
    }
}

test!(box_list, {
    let mut l = List::Nil;
    for i in 1..=bb(10) {
        l = List::Cons(i, Box::new(l));
    }
    check_eq!(l.sum(), 55);
});

test!(box_tree, {
    let mut t = Tree { v: bb(50), l: None, r: None };
    for v in [30, 70, 20, 40, 60, 80, 35, 45, 65] {
        t.insert(bb(v));
    }
    let mut out = Vec::new();
    t.walk(&mut out);
    check_eq!(out, [20, 30, 35, 40, 45, 50, 60, 65, 70, 80]);
    check_eq!(t.depth(), 4);
});

trait Shape {
    fn area(&self) -> u32;
    fn name(&self) -> String {
        String::from("shape")
    }
}
struct Sq(u32);
struct Rect(u32, u32);
impl Shape for Sq {
    fn area(&self) -> u32 {
        self.0 * self.0
    }
    fn name(&self) -> String {
        String::from("sq")
    }
}
impl Shape for Rect {
    fn area(&self) -> u32 {
        self.0 * self.1
    }
}

test!(box_dyn_trait, {
    let v: Vec<Box<dyn Shape>> = vec![Box::new(Sq(bb(3))), Box::new(Rect(bb(2), 5)), Box::new(Sq(1))];
    check_eq!(v.iter().map(|s| s.area()).sum::<u32>(), 20);
    check_eq!(v[0].name(), "sq");
    check_eq!(v[1].name(), "shape");
    let biggest = v.iter().max_by_key(|s| s.area()).unwrap();
    check_eq!(biggest.area(), 10);
});

test!(box_dyn_fn, {
    let k = bb(10u32);
    let mut fs: Vec<Box<dyn Fn(u32) -> u32>> = Vec::new();
    fs.push(Box::new(move |x| x + k));
    fs.push(Box::new(|x| x * 2));
    fs.push(Box::new(move |x| x - k / 2));
    check_eq!(fs.iter().fold(1, |a, f| f(a)), 17);
    let mut total = 0;
    {
        let mut add: Box<dyn FnMut(u32)> = Box::new(|x| total += x);
        add(bb(1));
        add(2);
    }
    check_eq!(total, 3);
    let s = String::from(bb("moved"));
    let once: Box<dyn FnOnce() -> usize> = Box::new(move || s.len());
    check_eq!(once(), 5);
    fn make(n: u32) -> Box<dyn Fn() -> u32> {
        Box::new(move || n * n)
    }
    check_eq!(make(bb(9))(), 81);
});

test!(box_dyn_any, {
    let v: Vec<Box<dyn Any>> = vec![Box::new(bb(1u32)), Box::new("str"), Box::new(String::from("owned"))];
    check_eq!(v[0].downcast_ref::<u32>(), Some(&1));
    check!(v[0].downcast_ref::<u64>().is_none());
    check_eq!(v[1].downcast_ref::<&str>(), Some(&"str"));
    let mut it = v.into_iter();
    let first = it.next().unwrap();
    check_eq!(first.downcast::<u32>().map(|b| *b).ok(), Some(1));
    let second = it.next().unwrap();
    check!(second.downcast::<u32>().is_err());
});

test!(rc_counts, {
    let live = rt::live();
    let a = Rc::new(bb(5));
    check_eq!(Rc::strong_count(&a), 1);
    let b = Rc::clone(&a);
    let c = a.clone();
    check_eq!(Rc::strong_count(&a), 3);
    check!(Rc::ptr_eq(&a, &b) && *c == 5);
    drop(b);
    check_eq!(Rc::strong_count(&a), 2);
    check!(Rc::try_unwrap(a).is_err());
    check_eq!(Rc::try_unwrap(c), Ok(5));
    check_eq!(rt::live(), live);
});

test!(rc_weak, {
    let a = Rc::new(bb(7));
    let w = Rc::downgrade(&a);
    check_eq!(Rc::weak_count(&a), 1);
    check_eq!(w.upgrade().map(|r| *r), Some(7));
    check_eq!(w.strong_count(), 1);
    drop(a);
    check!(w.upgrade().is_none());
    check_eq!(w.strong_count(), 0);
    let e: Weak<u32> = Weak::new();
    check!(e.upgrade().is_none());
});

test!(rc_refcell_shared, {
    let shared = Rc::new(RefCell::new(Vec::new()));
    let a = Rc::clone(&shared);
    let b = Rc::clone(&shared);
    a.borrow_mut().push(bb(1));
    b.borrow_mut().push(2);
    shared.borrow_mut().push(3);
    check_eq!(*shared.borrow(), [1, 2, 3]);
    check_eq!(a.borrow().len(), 3);
    let counter = Rc::new(Cell::new(0));
    let fs: Vec<Box<dyn Fn()>> = (0..bb(4))
        .map(|i| {
            let c = Rc::clone(&counter);
            Box::new(move || c.set(c.get() + i)) as Box<dyn Fn()>
        })
        .collect();
    for f in &fs {
        f();
    }
    check_eq!(counter.get(), 6);
    check_eq!(Rc::strong_count(&counter), 5);
});

struct Node {
    v: u32,
    parent: RefCell<Weak<Node>>,
    kids: RefCell<Vec<Rc<Node>>>,
}

test!(rc_tree_with_parents, {
    let live = rt::live();
    {
        let root = Rc::new(Node { v: bb(1), parent: RefCell::new(Weak::new()), kids: RefCell::new(vec![]) });
        for i in 2..=4 {
            let kid = Rc::new(Node { v: i, parent: RefCell::new(Weak::new()), kids: RefCell::new(vec![]) });
            *kid.parent.borrow_mut() = Rc::downgrade(&root);
            root.kids.borrow_mut().push(kid);
        }
        check_eq!(root.kids.borrow().iter().map(|k| k.v).sum::<u32>(), 9);
        let k = Rc::clone(&root.kids.borrow()[1]);
        check_eq!(k.parent.borrow().upgrade().map(|p| p.v), Some(1));
        check_eq!(Rc::weak_count(&root), 3);
        check_eq!(Rc::strong_count(&k), 2);
    }
    check_eq!(rt::live(), live);
});

test!(rc_make_mut_unsized, {
    let mut a = Rc::new(vec![bb(1), 2]);
    let b = Rc::clone(&a);
    Rc::make_mut(&mut a).push(3);
    check!(*a == [1, 2, 3] && *b == [1, 2]);
    check!(Rc::get_mut(&mut a).is_some());
    let s: Rc<str> = Rc::from(bb("text"));
    check_eq!(&*s, "text");
    let sl: Rc<[u32]> = Rc::from(vec![bb(1), 2, 3]);
    check_eq!(sl.iter().sum::<u32>(), 6);
    let d: Rc<dyn Shape> = Rc::new(Sq(bb(4)));
    check_eq!(Rc::clone(&d).area(), 16);
    let cyc = Rc::new_cyclic(|me: &Weak<Cell<u32>>| {
        let _ = me.upgrade().is_none();
        Cell::new(bb(3))
    });
    check_eq!(cyc.get(), 3);
});

test!(arc_counts, {
    let live = rt::live();
    let a = Arc::new(bb(5u64));
    let b = Arc::clone(&a);
    check_eq!(Arc::strong_count(&a), 2);
    let w = Arc::downgrade(&a);
    check_eq!(w.upgrade().map(|x| *x), Some(5));
    drop(a);
    check_eq!(Arc::try_unwrap(b), Ok(5));
    check!(w.upgrade().is_none());
    drop(w);
    check_eq!(rt::live(), live);
    let mut m = Arc::new(String::from(bb("a")));
    let o = Arc::clone(&m);
    Arc::make_mut(&mut m).push('b');
    check!(*m == "ab" && *o == "a");
    let s: Arc<[u8]> = Arc::from(&bb(b"xyz")[..]);
    check_eq!(s.len(), 3);
    let d: Arc<dyn Shape + Send + Sync> = Arc::new(Rect(bb(2), 3));
    check_eq!(d.area(), 6);
});
