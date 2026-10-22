// SPDX-License-Identifier: GPL-2.0
//! core: the language. Option, Result, enums, generics, traits, closures.
#![no_std]
#![no_main]
use core::cmp::Ordering;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Deref, Index, IndexMut, Mul, Neg, Not, Sub};
use rt::{bb, check, check_eq, test};

test!(lang_option, {
    let s = bb(Some(5u32));
    let n = bb(None::<u32>);
    check_eq!(s.map(|x| x + 1), Some(6));
    check_eq!(n.map(|x| x + 1), None);
    check_eq!(s.and_then(|x| x.checked_sub(6)), None);
    check_eq!(n.or(Some(1)), Some(1));
    check_eq!(n.unwrap_or(9) + s.unwrap_or(9), 14);
    check_eq!(n.unwrap_or_default(), 0);
    check_eq!(s.filter(|x| *x > 5), None);
    check_eq!(s.xor(n), Some(5));
    check_eq!(s.zip(Some('a')), Some((5, 'a')));
    check_eq!(s.ok_or("none"), Ok(5));
    check_eq!(n.ok_or("none"), Err("none"));
    check_eq!(s.map_or(0, |x| x * 2), 10);
    check!(s.is_some_and(|x| x == 5) && n.is_none());
    let mut m = s;
    check_eq!(m.take(), Some(5));
    check_eq!(m, None);
    check_eq!(*m.get_or_insert(3), 3);
    check_eq!(m.replace(4), Some(3));
    if let Some(x) = m.as_mut() {
        *x += 1;
    }
    check_eq!(m, Some(5));
    check_eq!(bb(Some(Some(1))).flatten(), Some(1));
    check_eq!(s.iter().chain(n.iter()).count(), 1);
    check_eq!(m.insert(8), &8);
});

#[derive(Debug, PartialEq, Clone, Copy)]
enum Error {
    Empty,
    Bad(u8),
    Range { lo: u32, hi: u32 },
}

fn digit(b: u8) -> Result<u32, Error> {
    if b.is_ascii_digit() { Ok((b - b'0') as u32) } else { Err(Error::Bad(b)) }
}
#[inline(never)]
fn number(s: &[u8], lo: u32, hi: u32) -> Result<u32, Error> {
    if s.is_empty() {
        return Err(Error::Empty);
    }
    let mut v = 0;
    for &b in s {
        v = v * 10 + digit(b)?;
    }
    if v < lo || v > hi {
        return Err(Error::Range { lo, hi });
    }
    Ok(v)
}
fn two(a: &[u8], b: &[u8]) -> Result<u32, Error> {
    Ok(number(a, 0, 100)? + number(b, 10, 20)?)
}

test!(lang_result_question_mark, {
    check_eq!(two(bb(b"42"), bb(b"15")), Ok(57));
    check_eq!(two(bb(b""), bb(b"15")), Err(Error::Empty));
    check_eq!(two(bb(b"4x"), bb(b"15")), Err(Error::Bad(b'x')));
    check_eq!(two(bb(b"42"), bb(b"21")), Err(Error::Range { lo: 10, hi: 20 }));
    let r = two(bb(b"1"), bb(b"10"));
    check_eq!(r.map(|x| x * 2), Ok(22));
    check_eq!(r.map_err(|_| 1), Ok(11));
    check_eq!(r.and_then(|x| if x > 11 { Ok(x) } else { Err(Error::Empty) }), Err(Error::Empty));
    check_eq!(r.ok(), Some(11));
    check_eq!(r.err(), None);
    check_eq!(two(bb(b""), b"").unwrap_or(3), 3);
    check_eq!(two(bb(b""), b"").unwrap_or_else(|e| if e == Error::Empty { 4 } else { 5 }), 4);
    check_eq!(two(bb(b""), b"").or_else(|_| two(b"1", b"11")), Ok(12));
    check!(r.is_ok_and(|x| x == 11));
    check_eq!(bb(Some(Ok::<u32, Error>(1))).transpose(), Ok(Some(1)));
});

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Shape {
    Dot,
    Circle(u32),
    Rect { w: u32, h: u32 },
    Tri(u32, u32, u32),
}
impl Shape {
    #[inline(never)]
    fn measure(&self) -> u32 {
        match *self {
            Shape::Dot => 0,
            Shape::Circle(r) if r > 100 => u32::MAX,
            Shape::Circle(r) => 3 * r * r,
            Shape::Rect { w, h: 1 } => w,
            Shape::Rect { w, h } => w * h,
            Shape::Tri(a, b, c) if a == b && b == c => a * 3,
            Shape::Tri(a, ..) => a,
        }
    }
}

test!(lang_enum_match, {
    let v = bb([
        Shape::Dot,
        Shape::Circle(2),
        Shape::Circle(101),
        Shape::Rect { w: 7, h: 1 },
        Shape::Rect { w: 7, h: 3 },
        Shape::Tri(4, 4, 4),
        Shape::Tri(4, 5, 6),
    ]);
    let want = [0, 12, u32::MAX, 7, 21, 12, 4];
    for i in 0..v.len() {
        check_eq!(v[i].measure(), want[i]);
    }
    check!(v[0] < v[1] && v[1] < v[2] && v[2] < v[3] && v[5] < v[6]);
    check!(matches!(v[4], Shape::Rect { w: 5..=9, .. }));
    check_eq!(core::mem::discriminant(&v[1]), core::mem::discriminant(&v[2]));
    let x = bb(77u8);
    let c = match x {
        0 => 'z',
        1..=9 => 'd',
        b'A'..=b'Z' => 'u',
        n if n % 2 == 0 => 'e',
        _ => 'o',
    };
    check_eq!(c, 'u');
    let t = bb((1u8, -1i8, true));
    check!(matches!(t, (1, n, true) if n < 0));
    let arr = bb([1, 2, 3, 4, 5]);
    let r = match arr {
        [a, .., e] if a == e => 0,
        [_, mid @ .., _] => mid.len() as i32 + mid[1],
    };
    check_eq!(r, 6);
});

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
enum Level {
    Low = 1,
    Mid = 5,
    High = 200,
}
impl TryFrom<u8> for Level {
    type Error = u8;
    fn try_from(v: u8) -> Result<Level, u8> {
        match v {
            1 => Ok(Level::Low),
            5 => Ok(Level::Mid),
            200 => Ok(Level::High),
            x => Err(x),
        }
    }
}

test!(lang_c_like_enum, {
    check_eq!(bb(Level::High) as u8, 200);
    check_eq!(Level::try_from(bb(5)), Ok(Level::Mid));
    check_eq!(Level::try_from(bb(6)), Err(6));
    check_eq!(core::mem::size_of::<Level>(), 1);
    check_eq!(core::mem::size_of::<Option<Level>>(), 1);
    check_eq!(core::mem::size_of::<Option<&u8>>(), 8);
    let l: Result<Level, _> = bb(1u8).try_into();
    check_eq!(l, Ok(Level::Low));
});

trait Animal {
    const LEGS: u32;
    fn name(&self) -> &'static str;
    fn weight(&self) -> u32 {
        Self::LEGS * 10
    }
}
struct Dog;
struct Bird(u32);
impl Animal for Dog {
    const LEGS: u32 = 4;
    fn name(&self) -> &'static str {
        "dog"
    }
}
impl Animal for Bird {
    const LEGS: u32 = 2;
    fn name(&self) -> &'static str {
        "bird"
    }
    fn weight(&self) -> u32 {
        self.0
    }
}
#[inline(never)]
fn total<A: Animal, B: Animal>(a: &A, b: &B) -> u32 {
    a.weight() + b.weight() + A::LEGS + B::LEGS + (a.name().len() + b.name().len()) as u32
}
fn largest<T: PartialOrd + Copy>(v: &[T]) -> Option<T> {
    let mut it = v.iter();
    let mut m = *it.next()?;
    for &x in it {
        if x > m {
            m = x;
        }
    }
    Some(m)
}

test!(lang_generics_traits, {
    check_eq!(total(&Dog, &Bird(bb(3))), 40 + 3 + 6 + 7);
    check_eq!(total(&Bird(bb(1)), &Bird(bb(2))), 1 + 2 + 4 + 8);
    check_eq!(largest(bb(&[3, 9, 2])), Some(9));
    check_eq!(largest(bb(&['x', 'b'])), Some('x'));
    check_eq!(largest::<u8>(bb(&[])), None);
    check_eq!(largest(bb(&[(1, 'b'), (1, 'c'), (0, 'z')])), Some((1, 'c')));
});

trait Op {
    fn apply(&self, x: i64) -> i64;
    fn id(&self) -> u8 {
        0
    }
}
struct AddN(i64);
struct MulN(i64);
struct Chain<'a>(&'a dyn Op, &'a dyn Op);
impl Op for AddN {
    fn apply(&self, x: i64) -> i64 {
        x + self.0
    }
    fn id(&self) -> u8 {
        1
    }
}
impl Op for MulN {
    fn apply(&self, x: i64) -> i64 {
        x * self.0
    }
}
impl Op for Chain<'_> {
    fn apply(&self, x: i64) -> i64 {
        self.1.apply(self.0.apply(x))
    }
    fn id(&self) -> u8 {
        self.0.id() * 10 + self.1.id()
    }
}
static OPS: [&(dyn Op + Sync); 3] = [&AddN(1), &MulN(3), &AddN(-5)];

test!(lang_dyn_trait, {
    let (a, m) = (AddN(bb(2)), MulN(bb(10)));
    let ops: [&dyn Op; 2] = [&a, &m];
    check_eq!(ops[bb(0usize)].apply(5), 7);
    check_eq!(ops[bb(1usize)].apply(5), 50);
    let c = Chain(&a, &m);
    let cc = Chain(&c, &a);
    check_eq!(cc.apply(1), 32);
    check_eq!(cc.id(), 101);
    check_eq!(bb(&OPS).iter().fold(2, |x, o| o.apply(x)), 4);
    check_eq!(core::mem::size_of::<&dyn Op>(), 16);
    check_eq!(core::mem::size_of_val(ops[1]), 8);
});

#[derive(Clone, Copy, PartialEq, Debug, Default)]
struct V2(i32, i32);
impl Add for V2 {
    type Output = V2;
    fn add(self, o: V2) -> V2 {
        V2(self.0 + o.0, self.1 + o.1)
    }
}
impl Sub for V2 {
    type Output = V2;
    fn sub(self, o: V2) -> V2 {
        V2(self.0 - o.0, self.1 - o.1)
    }
}
impl Mul<i32> for V2 {
    type Output = V2;
    fn mul(self, k: i32) -> V2 {
        V2(self.0 * k, self.1 * k)
    }
}
impl Neg for V2 {
    type Output = V2;
    fn neg(self) -> V2 {
        V2(-self.0, -self.1)
    }
}
impl AddAssign for V2 {
    fn add_assign(&mut self, o: V2) {
        *self = *self + o;
    }
}
impl Not for V2 {
    type Output = bool;
    fn not(self) -> bool {
        self == V2::default()
    }
}
struct Grid<const W: usize, const H: usize>([[u8; W]; H]);
impl<const W: usize, const H: usize> Index<(usize, usize)> for Grid<W, H> {
    type Output = u8;
    fn index(&self, (x, y): (usize, usize)) -> &u8 {
        &self.0[y][x]
    }
}
impl<const W: usize, const H: usize> IndexMut<(usize, usize)> for Grid<W, H> {
    fn index_mut(&mut self, (x, y): (usize, usize)) -> &mut u8 {
        &mut self.0[y][x]
    }
}
impl<const W: usize, const H: usize> Grid<W, H> {
    const CELLS: usize = W * H;
    fn sum(&self) -> u32 {
        self.0.iter().flatten().map(|&x| x as u32).sum()
    }
}

test!(lang_operators_const_generics, {
    let mut v = bb(V2(1, 2)) + V2(3, 4) * 2 - V2(1, 1);
    check_eq!(v, V2(6, 9));
    v += -V2(6, 9);
    check!(!v);
    let mut g = Grid::<5, 3>([[0; 5]; 3]);
    g[(bb(4), bb(2))] = 7;
    g[(bb(0), bb(1))] = 3;
    check_eq!(g[(4, 2)] + g[(0, 1)] + g[(1, 1)], 10);
    check_eq!(g.sum(), 10);
    check_eq!(Grid::<5, 3>::CELLS, 15);
});

#[inline(never)]
fn call_fn(f: &dyn Fn(u32) -> u32, x: u32) -> u32 {
    f(x)
}
#[inline(never)]
fn call_mut(f: &mut dyn FnMut(u32), n: u32) {
    for i in 0..n {
        f(i);
    }
}
fn call_once<F: FnOnce() -> [u64; 4]>(f: F) -> u64 {
    f()[3]
}
fn compose<A, B, C>(f: impl Fn(A) -> B, g: impl Fn(B) -> C) -> impl Fn(A) -> C {
    move |x| g(f(x))
}
fn double(x: u32) -> u32 {
    x * 2
}
fn square(x: u32) -> u32 {
    x * x
}

test!(lang_closures, {
    let k = bb(10u32);
    check_eq!(call_fn(&|x| x + k, 5), 15);
    let mut sum = 0;
    call_mut(&mut |i| sum += i * k, bb(4));
    check_eq!(sum, 60);
    let arr = bb([1u64, 2, 3, 4]);
    check_eq!(call_once(move || arr), 4);
    let f = compose(|x: u32| x + 1, |y: u32| y as u64 * 1000);
    check_eq!(f(bb(1)), 2000);
    let table: [fn(u32) -> u32; 2] = [double, square];
    check_eq!(table[bb(0usize)](7) + table[bb(1usize)](7), 63);
    let p: fn(u32) -> u32 = if bb(true) { square } else { double };
    check_eq!(p(9), 81);
    let mut counter = {
        let mut c = 0;
        move || {
            c += 1;
            c
        }
    };
    check!(counter() == 1 && counter() == 2);
});

struct Meters<T>(u32, PhantomData<T>);
struct Wrapper {
    inner: [u8; 4],
}
impl Deref for Wrapper {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Default, Hash)]
struct Version {
    major: u8,
    minor: u8,
    tag: Option<char>,
}

test!(lang_derive_deref_misc, {
    check_eq!(core::mem::size_of::<Meters<u64>>(), 4);
    check_eq!(Meters::<()>(bb(3), PhantomData).0, 3);
    let w = Wrapper { inner: bb([4, 1, 3, 2]) };
    check_eq!(w.len(), 4);
    check_eq!(w.iter().max(), Some(&4));
    check!(w.contains(&3));
    let a = Version { major: 1, minor: bb(2), tag: None };
    let b = Version { minor: 3, ..a };
    let c = Version { tag: Some('b'), ..a };
    check!(a < b && a < c && c < b);
    check_eq!(a.cmp(&a.clone()), Ordering::Equal);
    check_eq!(a.max(b), b);
    check_eq!(Version::default().major, 0);
    check_eq!(bb((1, "b", 3u8)).partial_cmp(&(1, "a", 9)), Some(Ordering::Greater));
    check_eq!(core::cmp::Reverse(bb(1)).cmp(&core::cmp::Reverse(2)), Ordering::Greater);
    check_eq!(bb(1).cmp(&2).then(Ordering::Greater).reverse(), Ordering::Greater);
});

test!(lang_labeled_loops, {
    let n = bb(20u32);
    let mut found = (0, 0);
    'outer: for a in 1..n {
        for b in a..n {
            if a * a + b * b == 13 * 13 {
                found = (a, b);
                break 'outer;
            }
        }
    }
    check_eq!(found, (5, 12));
    let mut i = 0u32;
    let v = loop {
        i += 1;
        if i * i > bb(200) {
            break i;
        }
    };
    check_eq!(v, 15);
    let mut x = bb(27u64);
    let mut steps = 0;
    while x != 1 {
        x = if x % 2 == 0 { x / 2 } else { 3 * x + 1 };
        steps += 1;
    }
    check_eq!(steps, 111);
    let r = 'blk: {
        if bb(1) == 1 {
            break 'blk 5;
        }
        6
    };
    check_eq!(r, 5);
});

const fn fib(n: u32) -> u64 {
    let (mut a, mut b, mut i) = (0u64, 1u64, 0);
    while i < n {
        (a, b) = (b, a + b);
        i += 1;
    }
    a
}
const FIB50: u64 = fib(50);
static TABLE: [u64; 16] = {
    let mut t = [0; 16];
    let mut i = 0;
    while i < 16 {
        t[i] = fib(i as u32 * 2);
        i += 1;
    }
    t
};

test!(lang_const_eval_statics, {
    check_eq!(bb(FIB50), 12586269025);
    check_eq!(fib(bb(50)), FIB50);
    check_eq!(TABLE[bb(15usize)], 832040);
    check_eq!(bb(&TABLE).iter().sum::<u64>(), 1346268);
});
