// SPDX-License-Identifier: GPL-2.0
//! Recursion that is bounded at run time.
#![no_std]
#![no_main]
use rt::{bb, check_eq, test};

#[inline(never)]
fn fact(n: u64) -> u64 {
    if n <= 1 { 1 } else { n * fact(n - 1) }
}
#[inline(never)]
fn fib(n: u32) -> u64 {
    if n < 2 { n as u64 } else { fib(n - 1) + fib(n - 2) }
}
#[inline(never)]
fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}
#[inline(never)]
fn ack(m: u32, n: u32) -> u32 {
    if m == 0 {
        n + 1
    } else if n == 0 {
        ack(m - 1, 1)
    } else {
        ack(m - 1, ack(m, n - 1))
    }
}
#[inline(never)]
fn is_even(n: u32) -> bool {
    if n == 0 { true } else { is_odd(n - 1) }
}
#[inline(never)]
fn is_odd(n: u32) -> bool {
    if n == 0 { false } else { is_even(n - 1) }
}

test!(rec_factorial, {
    check_eq!(fact(bb(10)), 3628800);
});

test!(rec_fib, {
    check_eq!(fib(bb(12)), 144);
});

test!(rec_gcd, {
    check_eq!(gcd(bb(1071), bb(462)), 21);
});

test!(rec_ackermann, {
    check_eq!(ack(bb(2), bb(2)), 7);
});

test!(rec_mutual, {
    check_eq!(is_even(bb(9)), false);
    check_eq!(is_odd(bb(7)), true);
});

#[inline(never)]
fn sum_slice(v: &[u32]) -> u32 {
    match v {
        [] => 0,
        [x] => *x,
        _ => {
            let (a, b) = v.split_at(v.len() / 2);
            sum_slice(a) + sum_slice(b)
        }
    }
}

test!(rec_divide_slice, {
    check_eq!(sum_slice(bb(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])), 66);
});

#[inline(never)]
fn with_local(n: u32, acc: &mut [u32; 8]) -> u32 {
    let mut mine = [n; 8];
    if n > 0 {
        mine[0] += with_local(n - 1, &mut mine);
    }
    acc[(n & 7) as usize] += mine[0];
    mine[0] + mine[7]
}

test!(rec_frames_with_locals, {
    let mut acc = [0; 8];
    check_eq!(with_local(bb(5), &mut acc), 30);
    check_eq!(acc[5], 25);
});

enum Expr<'a> {
    Num(i64),
    Add(&'a Expr<'a>, &'a Expr<'a>),
    Mul(&'a Expr<'a>, &'a Expr<'a>),
    Neg(&'a Expr<'a>),
}
#[inline(never)]
fn eval(e: &Expr) -> i64 {
    match e {
        Expr::Num(n) => *n,
        Expr::Add(a, b) => eval(a) + eval(b),
        Expr::Mul(a, b) => eval(a) * eval(b),
        Expr::Neg(a) => -eval(a),
    }
}

test!(rec_tree_eval, {
    let (two, three, four) = (Expr::Num(bb(2)), Expr::Num(3), Expr::Num(4));
    let sum = Expr::Add(&two, &three);
    let neg = Expr::Neg(&four);
    let prod = Expr::Mul(&sum, &neg);
    let all = Expr::Add(&prod, &two);
    check_eq!(eval(bb(&all)), -18);
});

trait Node {
    fn depth(&self) -> u32;
}
struct Leaf;
struct Branch<'a>(&'a dyn Node, &'a dyn Node);
impl Node for Leaf {
    fn depth(&self) -> u32 {
        1
    }
}
impl Node for Branch<'_> {
    fn depth(&self) -> u32 {
        1 + self.0.depth().max(self.1.depth())
    }
}

test!(rec_through_dyn, {
    let l = Leaf;
    let a = Branch(&l, &l);
    let b = Branch(&a, &l);
    let c = Branch(&l, &b);
    let n: &dyn Node = bb(&c);
    check_eq!(n.depth(), 4);
});

#[inline(never)]
fn hanoi(n: u32, from: u8, to: u8, via: u8, moves: &mut u32) {
    if n == 0 {
        return;
    }
    hanoi(n - 1, from, via, to, moves);
    *moves += 1;
    hanoi(n - 1, via, to, from, moves);
}

test!(rec_hanoi, {
    let mut moves = 0;
    hanoi(bb(6), 0, 2, 1, &mut moves);
    check_eq!(moves, 63);
});
